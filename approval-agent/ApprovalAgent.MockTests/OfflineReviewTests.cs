using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

internal static class OfflineReviewTests
{
    private const long Now = 1800000002000;
    private static byte[] Golden => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "golden.review.json"));
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("offline review assertion failed"); }
    private static byte[] Mutate(Action<JsonNode> change)
    { var node = JsonNode.Parse(Golden)!; change(node); return Encoding.UTF8.GetBytes(node.ToJsonString()); }
    private static void Reject(byte[] bytes, string? category = null, long now = Now)
    {
        try { OfflineReviewValidator.Validate(bytes, now); }
        catch (ReviewInputException e) { Must(category is null || e.Category == category); Must(e.Message == e.Category); return; }
        throw new InvalidOperationException("unsafe acceptance");
    }
    internal static IEnumerable<(string Name, Action Run)> Cases() => new (string, Action)[] {
        ("4C actual Node export validates in .NET and matches golden bytes", ActualInterop),
        ("4C canonical Unicode and integer vector reproduces exact Node serialization", () => {
            using var doc = ReviewJson.Parse(Golden);
            Must(Encoding.UTF8.GetString(Golden) == ReviewJson.Canonical(doc.RootElement) + "\n");
            var context = OfflineReviewValidator.Validate(Golden, Now);
            Must(context.Targets[0].Task.Contains("😀 e\u0301 café \u2028\u2029", StringComparison.Ordinal));
            Must(context.ContextSha256 == doc.RootElement.GetProperty("context").GetProperty("contextSha256").GetString());
        }),
        ("4C validated immutable display preserves exact effective task wire and order", () => {
            var vm = new OfflineReviewViewModel(() => Now); Must(vm.LoadBytes(Golden));
            using var doc = JsonDocument.Parse(Golden); var input = doc.RootElement.GetProperty("context").GetProperty("targets");
            Must(vm.State == OfflineMockState.Pending && vm.CanDecide && !vm.Authorized);
            for (var i = 0; i < vm.Targets.Count; i++) {
                Must(vm.Targets[i].Task == input[i].GetProperty("task").GetString());
                Must(vm.Targets[i].Destination == input[i].GetProperty("destination").GetString());
                using var wire = JsonDocument.Parse(vm.Targets[i].WireJson);
                Must(wire.RootElement.GetProperty("messages")[0].GetProperty("content").GetString() == vm.Targets[i].Task);
            }
            Must(ReferenceEquals(vm.Targets, vm.Context!.Targets));
            var culture = System.Globalization.CultureInfo.CurrentCulture;
            try {
                System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("th-TH");
                Must(vm.ExpiresAtDisplay == "2027-01-15 08:05:00 UTC");
            } finally { System.Globalization.CultureInfo.CurrentCulture = culture; }
            try { ((IList<OfflineReviewTarget>)vm.Context.Targets)[0] = vm.Targets[1]; throw new InvalidOperationException(); }
            catch (NotSupportedException) { }
        }),
        ("4C changed task fails independently computed task hash", () => Reject(Mutate(n => n["context"]!["targets"]![0]!["task"] += "changed"), "REVIEW_TASK_HASH_MISMATCH")),
        ("4C reordered targets cannot reuse order or batch identity", () => {
            Reject(Mutate(n => { var a=n["context"]!["targets"]!.AsArray(); var first=a[0]!.DeepClone(); a[0]=a[1]!.DeepClone(); a[1]=first; }), "REVIEW_ORDER_INVALID");
        }),
        ("4C altered destination and unsafe configured URLs reject", () => {
            Reject(Mutate(n => n["context"]!["targets"]![0]!["destination"] = "https://other.example.invalid/v1/chat/completions"), "REVIEW_URL_CONFLICT");
            foreach (var url in new[] { "http://api.example.invalid/v1", "https://user:pass@api.example.invalid/v1", "https://127.0.0.1/v1", "https://api.local/v1", "https://api.example.invalid/v1/../other", "https://api.example.invalid/v1?token=secret" })
                Reject(Mutate(n => n["context"]!["configurationSnapshot"]!["providers"]![0]!["baseUrl"] = url), "REVIEW_URL_INVALID");
        }),
        ("4C changed wire cannot disagree with displayed task", () => Reject(Mutate(n => n["context"]!["targets"]![0]!["wire"]!["messages"]![0]!["content"] = "substituted"), "REVIEW_WIRE_CONFLICT")),
        ("4C changed config fingerprint and batch digest reject", () => {
            Reject(Mutate(n => n["context"]!["configurationFingerprint"] = new string('0',64)), "REVIEW_CONFIG_HASH_MISMATCH");
            Reject(Mutate(n => n["context"]!["batchSha256"] = new string('0',64)), "REVIEW_BATCH_HASH_MISMATCH");
        }),
        ("4C context hash binds session request and timeout metadata", () => {
            Reject(Mutate(n => n["context"]!["sessionId"] = "different-session"), "REVIEW_CONTEXT_HASH_MISMATCH");
            Reject(Mutate(n => n["context"]!["requestId"] = "different-request"), "REVIEW_CONTEXT_HASH_MISMATCH");
            Reject(Mutate(n => n["context"]!["targets"]![0]!["parameters"]!["adapterTimeoutSeconds"] = 1), "REVIEW_TIMEOUT_CONFLICT");
        }),
        ("4C trusted identity and authorization claims are forbidden", () => {
            foreach(var key in new[] { "applicationIdentity", "userIdentity", "productionAuthorization", "designation" })
                Reject(Mutate(n => n["context"]![key] = "TRUSTED"), "REVIEW_AUTHORITY_INVALID");
            Reject(Mutate(n => n["context"]!["authorized"] = true), "REVIEW_AUTHORITY_INVALID");
            Reject(Mutate(n => n["producerAuthentication"] = "VERIFIED"), "REVIEW_AUTHORITY_INVALID");
        }),
        ("4C duplicate root and nested JSON properties reject", () => {
            foreach(var (find, replace) in new[] { ("\"authorized\":false", "\"authorized\":false,\"authorized\":false"), ("\"role\":\"user\"", "\"role\":\"user\",\"role\":\"user\"") })
                Reject(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Golden).Replace(find,replace)), "REVIEW_DUPLICATE_PROPERTY");
        }),
        ("4C unsupported versions unknown missing and invalid typed fields reject", () => {
            Reject(Mutate(n => n["reviewFileSchemaVersion"] = 99), "REVIEW_SCHEMA_UNSUPPORTED");
            Reject(Mutate(n => n["context"]!["schemaVersion"] = 2), "REVIEW_SCHEMA_UNSUPPORTED");
            Reject(Mutate(n => n["context"]!["proof"] = "NO_SECRET_ECHO"), "REVIEW_UNKNOWN_FIELD");
            Reject(Mutate(n => n["context"]!["createdAt"] = "wrong"), "REVIEW_TYPE_INVALID");
            Reject(Mutate(n => n["context"]!["configurationSnapshot"]!["providers"]![0]!["apiKey"] = "NO_SECRET_ECHO"), "REVIEW_UNKNOWN_FIELD");
            foreach (var key in JsonNode.Parse(Golden)!["context"]!.AsObject().Select(p => p.Key))
                Reject(Mutate(n => n["context"]!.AsObject().Remove(key)), "REVIEW_REQUIRED_FIELD");
        }),
        ("4C oversized invalid UTF8 nesting Unicode IDs and digests fail closed", () => {
            Reject(new byte[ReviewJson.MaximumBytes+1], "REVIEW_FILE_OVERSIZED");
            Reject(new byte[] {0xc3,0x28}, "REVIEW_UTF8_INVALID");
            Reject(Encoding.UTF8.GetBytes(new string('[',18)+"0"+new string(']',18)), "REVIEW_JSON_INVALID");
            Reject(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Golden).Replace("\"modelId\":\"model-alpha\"", "\"modelId\":\"\\ud800\"")));
            Reject(Mutate(n => n["context"]!["requestId"] = "../bad"), "REVIEW_ID_INVALID");
            Reject(Mutate(n => n["context"]!["contextSha256"] = new string('g',64)), "REVIEW_DIGEST_INVALID");
        }),
        ("4C stale and future files cannot be loaded or revived", () => {
            Reject(Golden, "REVIEW_TIME_INVALID", 1800000300000);
            Reject(Golden, "REVIEW_TIME_INVALID", 1799999999999);
            var time=Now; var vm=new OfflineReviewViewModel(() => time); Must(vm.LoadBytes(Golden)); time=1800000300000;
            vm.DecideCurrent(OfflineMockState.ApprovedMock); Must(vm.State==OfflineMockState.Expired && !vm.CanDecide);
            Must(!vm.LoadBytes(Golden) && vm.State==OfflineMockState.Expired);
        }),
        ("4C approve reject cancel and repeated terminal decisions stay local", () => {
            foreach(var state in new[] { OfflineMockState.ApprovedMock, OfflineMockState.Rejected, OfflineMockState.Cancelled }) {
                var vm=new OfflineReviewViewModel(() => Now); Must(vm.LoadBytes(Golden)); var c=vm.Context!;
                Must(vm.Decide(c.RequestId,c.SessionId,c.ContextSha256,vm.ReviewGeneration,state));
                Must(!vm.Decide(c.RequestId,c.SessionId,c.ContextSha256,vm.ReviewGeneration,OfflineMockState.ApprovedMock));
                Must(vm.State==state && !vm.CanDecide && !vm.Authorized && !c.Authorized && c.ProductionAuthorization=="DEFAULT_DENY");
            }
        }),
        ("4C explicit reload resets review and invalid replacement retains snapshot", () => {
            var vm=new OfflineReviewViewModel(() => Now); Must(vm.LoadBytes(Golden)); vm.DecideCurrent(OfflineMockState.ApprovedMock);
            var previous=vm.Context; Must(!vm.LoadBytes(new byte[]{0xff})); Must(ReferenceEquals(vm.Context,previous) && vm.State==OfflineMockState.ApprovedMock);
            var generation=vm.ReviewGeneration;
            Must(vm.LoadBytes(Golden) && vm.State==OfflineMockState.Pending && vm.CanDecide);
            Must(vm.ReviewGeneration==generation+1);
            Must(!vm.Decide(previous!.RequestId,previous.SessionId,previous.ContextSha256,generation,OfflineMockState.ApprovedMock));
            Must(vm.State==OfflineMockState.Pending);
        }),
        ("4C stale session context and request decisions cannot affect current review", () => {
            var vm=new OfflineReviewViewModel(() => Now); Must(vm.LoadBytes(Golden)); var c=vm.Context!;
            Must(!vm.Decide(c.RequestId,"wrong-session",c.ContextSha256,vm.ReviewGeneration,OfflineMockState.ApprovedMock));
            Must(!vm.Decide(c.RequestId,c.SessionId,new string('0',64),vm.ReviewGeneration,OfflineMockState.ApprovedMock));
            Must(!vm.Decide("wrong-request",c.SessionId,c.ContextSha256,vm.ReviewGeneration,OfflineMockState.ApprovedMock));
            Must(vm.State==OfflineMockState.Pending && vm.CanDecide);
        }),
        ("4C offline WPF contract keeps full tasks read-only decisions local and Escape reject", UiContract),
        ("4C file path and stream bounds reject before display", () => WithTemporary(root => {
            var path=Path.Combine(root,"oversized.review.json"); File.WriteAllBytes(path,new byte[ReviewJson.MaximumBytes+1]);
            try { OfflineReviewValidator.ReadFile(path,Now); throw new InvalidOperationException(); }
            catch(ReviewInputException e) { Must(e.Category=="REVIEW_FILE_OVERSIZED"); }
            try { OfflineReviewValidator.ReadFile(Path.Combine(root,"..","unsafe.review.json"),Now); throw new InvalidOperationException(); }
            catch(ReviewInputException e) { Must(e.Category=="REVIEW_PATH_INVALID"); }
        }))
    };

    private static void ActualInterop() => WithTemporary(root => {
        var repo = new DirectoryInfo(AppContext.BaseDirectory);
        while(repo is not null && !File.Exists(Path.Combine(repo.FullName,"experiments/integration-contracts/export-review-cli.js"))) repo=repo.Parent;
        Must(repo is not null);
        var output=Path.Combine(root,"actual.review.json");
        var info=new ProcessStartInfo("node") { WorkingDirectory=repo!.FullName, UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true };
        foreach(var arg in new[]{Path.Combine(repo.FullName,"experiments/integration-contracts/export-review-cli.js"),"--output",output,"--fixture"}) info.ArgumentList.Add(arg);
        using var process=Process.Start(info) ?? throw new InvalidOperationException("Node export did not start");
        var stdout=process.StandardOutput.ReadToEndAsync(); var stderr=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(10000)) { process.Kill(true); throw new InvalidOperationException("Node export timeout"); }
        Must(process.ExitCode==0); _=stdout.GetAwaiter().GetResult(); _=stderr.GetAwaiter().GetResult();
        Must(File.ReadAllBytes(output).SequenceEqual(Golden));
        var context=OfflineReviewValidator.ReadFile(output,Now); Must(context.Targets.Count==2 && !context.Authorized);
        var vm=new OfflineReviewViewModel(() => Now); Must(vm.LoadFile(output));
        Must(vm.Context!.ContextSha256==context.ContextSha256 && vm.Targets[0].Task==context.Targets[0].Task);
    });
    private static void UiContract()
    {
        var doc=XDocument.Load(Path.Combine(AppContext.BaseDirectory,"Fixtures","OfflineReviewWindow.xaml"));
        XNamespace ns="http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        Must((string?)doc.Root!.Attribute("KeyDown")=="Window_KeyDown");
        Must(doc.Descendants(ns+"ItemsControl").Single().Attribute("ItemsSource")!.Value.Contains("Targets, Mode=OneWay",StringComparison.Ordinal));
        foreach(var box in doc.Descendants(ns+"TextBox")) Must((string?)box.Attribute("IsReadOnly")=="True" && box.Attribute("Text")!.Value.Contains("Mode=OneWay",StringComparison.Ordinal));
        foreach(var action in new[]{"Reject_Click","Cancel_Click","ApproveMock_Click"})
            Must(doc.Descendants(ns+"Button").Single(e => (string?)e.Attribute("Click")==action).Attribute("IsEnabled")!.Value=="{Binding CanDecide}");
        Must(doc.Descendants(ns+"Button").Any(e => (string?)e.Attribute("Click")=="SelectFile_Click"));
        Must(doc.Descendants(ns+"ScrollViewer").Any());
    }
    private static void WithTemporary(Action<string> action)
    {
        var parent=Path.GetFullPath(Path.GetTempPath()); var root=Path.GetFullPath(Path.Combine(parent,"phase4c-interop-"+Guid.NewGuid().ToString("N")));
        Must(root.StartsWith(parent,StringComparison.OrdinalIgnoreCase)); Directory.CreateDirectory(root);
        try { action(root); } finally { Directory.Delete(root,true); }
    }
}
