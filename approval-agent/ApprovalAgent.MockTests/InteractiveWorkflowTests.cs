using System.Diagnostics;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.ViewModels;
using ApprovalAgent.Mock.Services;

internal static class InteractiveWorkflowTests
{
    private const long Now = 1800000002000;
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("interactive workflow assertion failed"); }
    private static OfflineReviewViewModel Vm(string method, Func<long>? clock = null, HybridPolicy? policy = null)
    {
        var vm = new OfflineReviewViewModel(clock ?? (() => Now), policy);
        Must(vm.SetPreference(method));
        Must(vm.LoadBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "golden.review.json"))));
        return vm;
    }
    private static bool Switch(OfflineReviewViewModel vm, string method)
    {
        var c = vm.Context!; return vm.SwitchMethod(method, c.RequestId, c.SessionId, c.ContextSha256, vm.ReviewGeneration);
    }
    internal static IEnumerable<(string Name, Action Run)> Cases()
    {
        foreach (var method in new[] { HybridMethods.Protected, HybridMethods.Remote })
        foreach (var outcome in new[] { "GRANT", "DENY", "CANCEL", "UNKNOWN" }) {
            var m = method; var o = outcome;
            yield return ($"7/8 interactive {m} {o} positive flow", () => {
                var vm = Vm(m); Must(vm.CanStartPreview && vm.StartInteractivePreview() && vm.CanRespondPreview);
                Must(!vm.StartInteractivePreview()); Must(vm.RespondInteractivePreview(o));
                if (o == "UNKNOWN") Must(vm.CanRecoverPreview && vm.RecoverInteractivePreview() && vm.State == OfflineMockState.Cancelled);
                else Must(vm.State == (o == "GRANT" ? OfflineMockState.ApprovedMock : o == "DENY" ? OfflineMockState.Rejected : OfflineMockState.Cancelled));
                Must(!vm.RespondInteractivePreview(o) && !vm.CanRespondPreview && !vm.CanRecoverPreview && !vm.CanStartPreview && !vm.Authorized);
            });
        }
        foreach (var method in new[] { HybridMethods.Protected, HybridMethods.Remote }) {
            var m = method;
            yield return ($"7/8 interactive {m} crash and abandonment", () => {
                var vm = Vm(m); Must(vm.StartInteractivePreview() && vm.CrashInteractivePreview());
                Must(!vm.RespondInteractivePreview("GRANT") && vm.RecoverInteractivePreview());
                Must(vm.State == OfflineMockState.Cancelled && !vm.RecoverInteractivePreview());
            });
            yield return ($"7/8 interactive {m} expiry clears method state", () => {
                long now = Now; var vm = Vm(m, () => now); Must(vm.StartInteractivePreview()); now = vm.Context!.ExpiresAt;
                Must(!vm.RespondInteractivePreview("GRANT") && vm.State == OfflineMockState.Expired && vm.Simulation.State == "Expired");
                Must(!vm.CanRespondPreview && !vm.CanRecoverPreview && !vm.CanExportBrowser && !vm.CanStartPreview);
            });
        }
        yield return ("7D both switch orders preserve action and deadline and discard delayed browser response", () => {
            foreach (var order in new[] { new[] { HybridMethods.Protected, HybridMethods.Remote, HybridMethods.Local }, new[] { HybridMethods.Remote, HybridMethods.Protected, HybridMethods.Local } }) {
                var vm = Vm(HybridMethods.Local); var original = vm.Context; string? oldFrame = null;
                foreach (var method in order) {
                    Must(Switch(vm, method)); Must(ReferenceEquals(original, vm.Context));
                    if (method != HybridMethods.Local) Must(vm.StartInteractivePreview());
                    if (method == HybridMethods.Remote) { using var package = JsonDocument.Parse(vm.ExportBrowserPackage()!); oldFrame = package.RootElement.GetProperty("responseTemplate").GetRawText(); }
                }
                Must(!vm.ImportBrowserResponse(oldFrame!) && vm.IsLocal && vm.State == OfflineMockState.Pending);
                vm.DecideCurrent(OfflineMockState.ApprovedMock); Must(!Switch(vm, HybridMethods.Remote));
            }
        });
        yield return ("7/8 policy denied default never falls back or starts preview", () => {
            var vm = Vm(HybridMethods.Protected, policy: new HybridPolicy([HybridMethods.Local]));
            Must(!vm.StartInteractivePreview() && vm.SelectedMethod == HybridMethods.Protected && !vm.CanDecide);
            Must(!Switch(vm, HybridMethods.Remote)); vm.DecideCurrent(OfflineMockState.Cancelled); Must(vm.State == OfflineMockState.Cancelled);
        });
        yield return ("7A invalid replacement preserves active interactive protocol", () => {
            var vm = Vm(HybridMethods.Protected); Must(vm.StartInteractivePreview()); var c = vm.Context; var generation = vm.ReviewGeneration;
            Must(!vm.LoadBytes("{}"u8.ToArray()) && ReferenceEquals(c, vm.Context) && generation == vm.ReviewGeneration && vm.CanRespondPreview);
            Must(vm.RespondInteractivePreview("GRANT"));
        });
        yield return ("8A serialized concurrent response and switch retain one canonical terminal result", () => {
            for (var i = 0; i < 32; i++) {
                var vm = Vm(HybridMethods.Protected); Must(vm.StartInteractivePreview()); bool grant = false, switched = false;
                Parallel.Invoke(() => grant = vm.RespondInteractivePreview("GRANT"), () => switched = Switch(vm, HybridMethods.Local));
                Must(grant != switched); Must(!vm.Authorized);
                if (grant) Must(vm.State == OfflineMockState.ApprovedMock && !vm.CanSwitch);
                else Must(vm.IsLocal && vm.State == OfflineMockState.Pending && !vm.CanRespondPreview);
            }
        });
        yield return ("8A duplicate interactive responses consumed once", () => {
            var vm = Vm(HybridMethods.Remote); Must(vm.StartInteractivePreview()); var results = new bool[16];
            Parallel.For(0, results.Length, i => results[i] = vm.RespondInteractivePreview("GRANT"));
            Must(results.Count(x => x) == 1 && vm.State == OfflineMockState.ApprovedMock);
        });
        yield return ("8D nested expiry during interactive canonical consumption rejects grant", () => {
            var armed = false; var calls = 0; long expiry = long.MaxValue;
            var vm = Vm(HybridMethods.Protected, () => !armed ? Now : ++calls <= 4 ? expiry - 1 : expiry);
            Must(vm.StartInteractivePreview()); expiry = vm.Context!.ExpiresAt; armed = true;
            Must(!vm.RespondInteractivePreview("GRANT") && vm.State == OfflineMockState.Expired && vm.Simulation.State == "Expired");
            Must(!vm.CanRespondPreview && !vm.CanStartPreview);
        });
        yield return ("8D generation exhaustion clears interactive session", () => {
            var vm = Vm(HybridMethods.Protected);
            Must(vm.StartInteractivePreview());
            typeof(OfflineReviewViewModel).GetProperty(nameof(vm.ReviewGeneration))!.SetValue(vm, long.MaxValue);
            // Test-only counter exhaustion must also clear the previously active protocol.
            Must(!Switch(vm, HybridMethods.Remote) && vm.State == OfflineMockState.Cancelled && vm.Simulation.State == "Cancelled");
            Must(!vm.CanRespondPreview && !vm.CanRecoverPreview && !vm.CanStartPreview && !vm.Authorized);
        });
        yield return ("7B unavailable and failure require explicit switching recovery", () => {
            foreach (var action in new[] { "UNAVAILABLE", "FAIL" }) {
                var vm = Vm(HybridMethods.Protected);
                if (action == "FAIL") Must(vm.StartInteractivePreview());
                Must(vm.Simulate(action, vm.SimulationToken!, vm.Simulation.FixtureId));
                Must(!vm.CanStartPreview && !vm.CanRespondPreview && !vm.RespondInteractivePreview("GRANT"));
                Must(Switch(vm, HybridMethods.Local) && Switch(vm, HybridMethods.Protected) && vm.StartInteractivePreview());
                Must(vm.RespondInteractivePreview("GRANT"));
            }
        });
        yield return ("8B browser response rejects exact expiry and old generation after return", () => {
            long now = Now; var vm = Vm(HybridMethods.Remote, () => now); Must(vm.StartInteractivePreview());
            using var package = JsonDocument.Parse(vm.ExportBrowserPackage()!);
            var response = package.RootElement.GetProperty("responseTemplate").GetRawText();
            Must(Switch(vm, HybridMethods.Local) && Switch(vm, HybridMethods.Remote) && vm.StartInteractivePreview());
            Must(!vm.ImportBrowserResponse(response)); now = vm.Context!.ExpiresAt;
            Must(!vm.ImportBrowserResponse(response) && vm.State == OfflineMockState.Expired && !vm.CanExportBrowser);
        });
        yield return ("7C bounded local browser files reject network paths and preserve existing files", () => {
            var root = Path.Combine(Path.GetTempPath(), "browser-files-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            var package = Path.Combine(root, "request.browser.json"); var response = Path.Combine(root, "test.response.json");
            static void Rejected(Action run) { try { run(); } catch { return; } throw new InvalidOperationException("expected bounded local file rejection"); }
            try {
                BrowserPreviewFiles.WritePackage(package, "{}"); Rejected(() => BrowserPreviewFiles.WritePackage(package, "forged")); Must(File.ReadAllText(package) == "{}");
                File.WriteAllText(response, "{}"); Must(BrowserPreviewFiles.ReadResponse(response) == "{}");
                File.WriteAllBytes(response, new byte[4097]); Rejected(() => BrowserPreviewFiles.ReadResponse(response));
                File.WriteAllBytes(response, [0xff]); Rejected(() => BrowserPreviewFiles.ReadResponse(response));
                Rejected(() => BrowserPreviewFiles.ReadResponse("\\\\server\\share\\test.response.json"));
                Rejected(() => BrowserPreviewFiles.WritePackage("\\\\server\\share\\request.browser.json", "{}"));
                Rejected(() => BrowserPreviewFiles.ReadResponse("relative.response.json"));
            } finally { if (File.Exists(package)) File.Delete(package); if (File.Exists(response)) File.Delete(response); Directory.Delete(root); }
        });
        yield return ("7C drive classification accepts fixed and rejects network and indeterminate volumes", () => {
            if (!OperatingSystem.IsWindows()) return;
            var root = Path.Combine(Path.GetTempPath(), "browser-drive-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try {
                var package = Path.Combine(root, "request.browser.json");
                var response = Path.Combine(root, "answer.response.json");
                File.WriteAllText(response, "{}");
                var driveRoot = Path.GetPathRoot(package);
                Must(driveRoot is not null);
                var called = false;
                BrowserPreviewFiles.CheckPath(package, ".browser.json", false, drive => {
                    called = true; Must(drive == driveRoot); return DriveType.Fixed;
                });
                Must(called);
                BrowserPreviewFiles.CheckPath(response, ".response.json", true, _ => DriveType.Fixed);
                foreach (var kind in new[] { DriveType.Network, DriveType.Unknown, DriveType.NoRootDirectory,
                    DriveType.Removable, DriveType.CDRom, DriveType.Ram }) {
                    var rejected = false;
                    try { BrowserPreviewFiles.CheckPath(package, ".browser.json", false, _ => kind); }
                    catch (InvalidDataException) { rejected = true; }
                    Must(rejected);
                    rejected = false;
                    try { BrowserPreviewFiles.CheckPath(response, ".response.json", true, _ => kind); }
                    catch (InvalidDataException) { rejected = true; }
                    Must(rejected);
                }
                foreach (var failure in new Func<string, DriveType>[] {
                    _ => throw new IOException("inaccessible"), _ => throw new UnauthorizedAccessException("denied") }) {
                    var rejected = false;
                    try { BrowserPreviewFiles.CheckPath(package, ".browser.json", false, failure); }
                    catch (InvalidDataException error) { rejected = error.Message == "LOCAL_BROWSER_PATH_REQUIRED"; }
                    Must(rejected);
                }
                foreach (var pathCase in new[] { (@"Z:\request.browser.json", ".browser.json", false),
                    (@"Z:\answer.response.json", ".response.json", true) }) {
                    var rejected = false;
                    try { BrowserPreviewFiles.CheckPath(pathCase.Item1, pathCase.Item2, pathCase.Item3, _ => DriveType.Network); }
                    catch (InvalidDataException) { rejected = true; }
                    Must(rejected);
                }                var classified = false;
                try { BrowserPreviewFiles.CheckPath(@"Z:\request.browser.json:stream", ".browser.json", false, _ => { classified = true; return DriveType.Fixed; }); }
                catch (InvalidDataException) { }
                Must(!classified);
            } finally { File.Delete(Path.Combine(root, "answer.response.json")); Directory.Delete(root); }
        });        yield return ("7A remaining time and terminal presentation use original deadline", () => {
            long now = Now; var vm = Vm(HybridMethods.Local, () => now); var c = vm.Context;
            Must(vm.RemainingDisplay.Contains("298 seconds")); now += 1000; vm.RefreshExpiry(); Must(vm.RemainingDisplay.Contains("297 seconds"));
            vm.DecideCurrent(OfflineMockState.Rejected); Must(vm.RemainingDisplay == "Rejected" && !vm.CanDecide && !vm.CanSwitch && ReferenceEquals(c, vm.Context));
        });
        yield return ("8B actual .NET browser Node round trip all outcomes and tampering", ActualBrowserInterop);
        yield return ("8A interactive rollback expires canonical review", () => {
            long now = Now; var vm = Vm(HybridMethods.Remote, () => now); Must(vm.StartInteractivePreview()); now--;
            Must(!vm.RespondInteractivePreview("GRANT") && vm.State == OfflineMockState.Expired);
        });
        yield return ("7D preference changes apply only to future requests", () => {
            var vm = Vm(HybridMethods.Protected); Must(vm.StartInteractivePreview()); var token = vm.SimulationToken;
            Must(vm.SetPreference(HybridMethods.Remote) && vm.SimulationToken == token && vm.CanRespondPreview);
            Must(vm.RespondInteractivePreview("DENY")); Must(vm.LoadBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"Fixtures","golden.review.json"))));
            Must(vm.IsRemote && vm.CanStartPreview);
        });
    }
    private static void ActualBrowserInterop()
    {
        var repo = new DirectoryInfo(AppContext.BaseDirectory);
        while (repo is not null && !File.Exists(Path.Combine(repo.FullName, "experiments/browser-preview/vector-cli.js"))) repo = repo.Parent;
        Must(repo is not null);
        var golden = File.ReadAllText(Path.Combine(repo!.FullName, "experiments/browser-preview/fixtures/golden.response.json"));
        var goldenVm = Vm(HybridMethods.Remote);
        var token = new SimulationBinding(goldenVm.Context!.RequestId, goldenVm.Context.SessionId, goldenVm.Context.ContextSha256, 7, HybridMethods.Remote, "golden-browser-v1");
        Must(golden == OfflineTrustProtocol.Build(goldenVm.Context, token, "CONSENT_RESPONSE", "GRANT"));
        Must(OfflineTrustProtocol.TryParse(golden, out var goldenDoc)); goldenDoc?.Dispose();
        foreach (var outcome in new[] { "GRANT", "DENY", "CANCEL", "UNKNOWN" }) {
            var vm = Vm(HybridMethods.Remote); Must(vm.StartInteractivePreview()); var package = vm.ExportBrowserPackage()!;
            var info = new ProcessStartInfo("node") { WorkingDirectory = repo!.FullName, UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add("experiments/browser-preview/vector-cli.js"); info.ArgumentList.Add(outcome);
            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
            process.StandardInput.Write(package); process.StandardInput.Close();
            if (!process.WaitForExit(10000)) { process.Kill(true); throw new InvalidOperationException("browser interoperability timeout"); }
            Must(process.ExitCode == 0); _ = error.GetAwaiter().GetResult(); var response = output.GetAwaiter().GetResult();
            Must(OfflineTrustProtocol.TryParse(response, out var parsed)); parsed?.Dispose();
            var expected = OfflineTrustProtocol.Build(vm.Context!, vm.SimulationToken!, "CONSENT_RESPONSE", outcome);
            Must(response == expected);
            foreach (var bad in new[] { response + " ", response.Replace("fake-device", "other-device"), response.Replace("\"authorized\":false", "\"authorized\":true"), response.Replace(vm.Context!.RequestId, "forged-request") }) Must(!vm.ImportBrowserResponse(bad));
            var other = Vm(HybridMethods.Remote); Must(other.StartInteractivePreview() && !other.ImportBrowserResponse(response));
            Must(vm.ImportBrowserResponse(response) && !vm.ImportBrowserResponse(response) && !vm.Authorized);
            if (outcome == "UNKNOWN") Must(vm.RecoverInteractivePreview() && vm.State == OfflineMockState.Cancelled);
            else Must(vm.State == (outcome == "GRANT" ? OfflineMockState.ApprovedMock : outcome == "DENY" ? OfflineMockState.Rejected : OfflineMockState.Cancelled));
        }
    }
}
