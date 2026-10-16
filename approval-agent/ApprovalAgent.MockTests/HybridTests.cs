using System.Text;
using System.Xml.Linq;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

internal static class HybridTests
{
    private const long Now = 1800000002000, Expiry = 1800000300000;
    private static byte[] Golden => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "golden.review.json"));
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("hybrid assertion failed"); }
    private static OfflineReviewViewModel Review(Func<long>? clock = null, HybridPolicy? policy = null)
    { var vm = new OfflineReviewViewModel(clock ?? (() => Now), policy); Must(vm.LoadBytes(Golden)); return vm; }
    private static bool Switch(OfflineReviewViewModel vm, string id, long? generation = null)
    { var c = vm.Context!; return vm.SwitchMethod(id, c.RequestId, c.SessionId, c.ContextSha256, generation ?? vm.ReviewGeneration); }
    private static void Temporary(Action<ApprovalMethodPreferences, string> action)
    {
        var root = Path.Combine(Path.GetTempPath(), "phase4d-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try { var path = Path.Combine(root, "preference.json"); action(new ApprovalMethodPreferences(path), path); }
        finally { Directory.Delete(root, true); }
    }
    internal static IEnumerable<(string Name, Action Run)> Cases() => new (string, Action)[] {
        ("4D stable methods distinguish simulations and never establish transport identity", () => {
            Must(HybridMethods.All.Select(m => m.Id).SequenceEqual(new[] { "LOCAL_DESKTOP", "PROTECTED_WINDOWS", "REMOTE_BROWSER" }));
            Must(!HybridMethods.All[0].Simulated && HybridMethods.All.Skip(1).All(m => m.Simulated));
            Must(HybridMethods.All.All(m => !m.TransportEstablished && !m.IdentityEstablished && m.Assurance == "UNESTABLISHED / NON_AUTHORIZING"));
            Must(new HybridPolicy().Check(HybridMethods.All[0] with { IdentityEstablished = true }) == "HYBRID_METADATA_INVALID");
            Must(new HybridPolicy().Check(HybridMethods.All[1] with { Availability = HybridAvailability.OfflineFunctional }) == "HYBRID_METADATA_INVALID");
        }),
        ("4D first use explicit selection persists only minimal preference", () => Temporary((store, path) => {
            Must(store.Read().NeedsOnboarding); var vm = new OfflineReviewViewModel(() => Now);
            var selection = new ApprovalMethodSelection(vm, store, false);
            Must(!selection.Apply(null)); Must(!File.Exists(path));
            Must(selection.Apply(HybridMethods.Protected)); Must(store.Read().PreferredMethod == HybridMethods.Protected);
            Must(File.ReadAllText(path) == "{\"preferredMethod\":\"PROTECTED_WINDOWS\",\"schemaVersion\":1}\n");
            var next = new OfflineReviewViewModel(() => Now); next.SetPreference(store.Read().PreferredMethod);
            Must(next.LoadBytes(Golden) && next.SelectedMethod == HybridMethods.Protected && !next.Authorized);
        })),
        ("4D settings save deterministic reload and explicit reset do not rewrite current review", () => Temporary((store, path) => {
            var vm = Review(); var c = vm.Context; var generation = vm.ReviewGeneration;
            var settings = new ApprovalMethodSelection(vm, store, false); Must(settings.Apply(HybridMethods.Remote));
            var first = File.ReadAllBytes(path); Must(settings.Apply(HybridMethods.Remote)); Must(first.SequenceEqual(File.ReadAllBytes(path)));
            Must(vm.SelectedMethod == HybridMethods.Local && vm.ReviewGeneration == generation && ReferenceEquals(c, vm.Context));
            Must(vm.LoadBytes(Golden) && vm.SelectedMethod == HybridMethods.Remote);
            Must(settings.Reset() && store.Read().NeedsOnboarding && !File.Exists(path));
            Must(vm.SelectedMethod == HybridMethods.Remote); Must(vm.LoadBytes(Golden) && vm.SelectedMethod == HybridMethods.Local);
        })),
        ("4D hostile settings version duplicates UTF8 size types and authority fields ignored", () => Temporary((store, path) => {
            foreach (var text in new[] { "null", "{}", "{\"preferredMethod\":\"LOCAL_DESKTOP\",\"schemaVersion\":2}",
                "{\"preferredMethod\":\"LOCAL_DESKTOP\",\"schemaVersion\":1,\"authorized\":true}",
                "{\"preferredMethod\":\"LOCAL_DESKTOP\",\"preferredMethod\":\"REMOTE_BROWSER\",\"schemaVersion\":1}",
                "{\"preferredMethod\":null,\"schemaVersion\":1}", "{\"preferredMethod\":\"BAD_SECRET\",\"schemaVersion\":1}" }) {
                File.WriteAllText(path, text, new UTF8Encoding(false)); var result = store.Read(); Must(result.NeedsOnboarding && !result.Status.Contains("BAD_SECRET"));
            }
            File.WriteAllBytes(path, new byte[] { 0xc3, 0x28 }); Must(store.Read().NeedsOnboarding);
            File.WriteAllBytes(path, new byte[ApprovalMethodPreferences.MaximumBytes + 1]); Must(store.Read().NeedsOnboarding);
            Must(store.Save("BAD") == "PREFERENCE_INVALID");
        })),
        ("4D preference write failure sanitized and leaves future default unchanged", () => Temporary((store, path) => {
            Directory.CreateDirectory(path); var vm = Review();
            var settings = new ApprovalMethodSelection(vm, store, false); Must(!settings.Apply(HybridMethods.Remote));
            Must(vm.PreferredMethod is null && settings.Status.StartsWith("PREFERENCE_SAVE_FAILED", StringComparison.Ordinal));
            var picker = new ApprovalMethodSelection(vm, store, true);
            Must(!picker.Apply(HybridMethods.Protected, true));
            Must(vm.SelectedMethod == HybridMethods.Protected && vm.PreferredMethod is null && vm.State == OfflineMockState.Pending);
            Must(picker.Status.Contains("method changed locally, default unchanged", StringComparison.Ordinal));
        })),
        ("4D A to B to C to A keeps exact snapshot digest task and expiry", () => {
            var vm = Review(); var c = vm.Context!; var generation = vm.ReviewGeneration;
            foreach (var id in new[] { HybridMethods.Protected, HybridMethods.Remote, HybridMethods.Local }) {
                Must(Switch(vm, id)); Must(vm.SelectedMethod == id && vm.ReviewGeneration == ++generation);
                Must(ReferenceEquals(c, vm.Context) && c.ExpiresAt == Expiry && vm.State == OfflineMockState.Pending && vm.CanDecide);
                Must(vm.Targets[0].Task == c.Targets[0].Task && !vm.Authorized && vm.ProductionAuthorization == "DEFAULT_DENY");
            }
        }),
        ("4D same method is a no-op and invalid method does not consume generation", () => {
            var vm = Review(); var generation = vm.ReviewGeneration;
            Must(Switch(vm, HybridMethods.Local) && vm.ReviewGeneration == generation);
            Must(!Switch(vm, "ATTACKER_METHOD") && vm.ReviewGeneration == generation && vm.SelectedMethod == HybridMethods.Local);
        }),
        ("4D switching before load and after any terminal state cannot reopen review", () => {
            var empty = new OfflineReviewViewModel(() => Now); Must(!empty.SwitchMethod(HybridMethods.Protected, "r", "s", "d", 0));
            foreach (var state in new[] { OfflineMockState.ApprovedMock, OfflineMockState.Rejected, OfflineMockState.Cancelled }) {
                var vm = Review(); vm.DecideCurrent(state); Must(!Switch(vm, HybridMethods.Protected) && vm.State == state && !vm.CanSwitch);
            }
        }),
        ("4D switch just before expiry retains deadline and expiry during picker rejects", () => Temporary((store, _) => {
            var now = Now; var vm = Review(() => now); now = Expiry - 1; Must(Switch(vm, HybridMethods.Protected));
            var picker = new ApprovalMethodSelection(vm, store, true); now = Expiry;
            Must(!picker.Apply(HybridMethods.Remote, true)); Must(vm.State == OfflineMockState.Expired && vm.Context!.ExpiresAt == Expiry);
            Must(store.Read().NeedsOnboarding && !Switch(vm, HybridMethods.Local));
        })),
        ("4D previous method and same-context reload decisions are obsolete", () => {
            var vm = Review(); var c = vm.Context!; var old = vm.ReviewGeneration; Must(Switch(vm, HybridMethods.Protected));
            Must(!vm.Decide(c.RequestId, c.SessionId, c.ContextSha256, old, OfflineMockState.ApprovedMock));
            var current = vm.ReviewGeneration; Must(vm.LoadBytes(Golden));
            Must(!vm.Decide(c.RequestId, c.SessionId, c.ContextSha256, current, OfflineMockState.ApprovedMock));
            Must(vm.State == OfflineMockState.Pending && !Switch(vm, HybridMethods.Remote, old));
        }),
        ("4D invalid replacement retains selected method generation and immutable context", () => {
            var vm = Review(); Must(Switch(vm, HybridMethods.Remote)); var c = vm.Context; var generation = vm.ReviewGeneration;
            Must(!vm.LoadBytes(new byte[] { 0xff })); Must(ReferenceEquals(c, vm.Context) && vm.ReviewGeneration == generation && vm.SelectedMethod == HybridMethods.Remote);
            Must(!vm.SwitchMethod(HybridMethods.Local, c!.RequestId, "wrong-session", c.ContextSha256, generation));
            Must(!vm.SwitchMethod(HybridMethods.Local, "wrong-request", c.SessionId, c.ContextSha256, generation));
            Must(!vm.SwitchMethod(HybridMethods.Local, c.RequestId, c.SessionId, new string('0',64), generation));
        }),
        ("4D switching saves default only on explicit optional choice", () => Temporary((store, _) => {
            var vm = Review(); Must(new ApprovalMethodSelection(vm, store, true).Apply(HybridMethods.Protected));
            Must(store.Read().NeedsOnboarding && vm.PreferredMethod is null);
            Must(new ApprovalMethodSelection(vm, store, true).Apply(HybridMethods.Remote, true));
            Must(store.Read().PreferredMethod == HybridMethods.Remote && vm.PreferredMethod == HybridMethods.Remote);
            vm.DecideCurrent(OfflineMockState.Rejected); Must(!new ApprovalMethodSelection(vm, store, true).Apply(HybridMethods.Local, true));
            Must(store.Read().PreferredMethod == HybridMethods.Remote);
        })),
        ("4D policy unavailable preference never falls back and can explicitly select eligible method", () => {
            var vm = new OfflineReviewViewModel(() => Now, new HybridPolicy(new[] { HybridMethods.Local }));
            vm.SetPreference(HybridMethods.Remote); Must(vm.LoadBytes(Golden));
            Must(vm.SelectedMethod == HybridMethods.Remote && !vm.CanDecide && vm.MethodStatus == "HYBRID_METHOD_NOT_ALLOWED");
            vm.DecideCurrent(OfflineMockState.ApprovedMock); Must(vm.State == OfflineMockState.Pending);
            Must(!Switch(vm, HybridMethods.Protected)); Must(Switch(vm, HybridMethods.Local) && vm.CanDecide);
        }),
        ("4D simulated methods and preferences cannot satisfy protected or remote policy", () => {
            foreach (var requirement in new[] { HybridRequirement.ProtectedIdentity, HybridRequirement.RemoteIdentity }) {
                var vm = Review(policy: new HybridPolicy(requirement: requirement));
                foreach (var id in HybridMethods.All.Select(m => m.Id)) {
                    vm.SetPreference(id); Must(!Switch(vm, id)); Must(!vm.CanDecide && !vm.Authorized);
                }
                Must(vm.SelectedMethod == HybridMethods.Local && vm.ProductionAuthorization == "DEFAULT_DENY");
            }
            foreach (var ids in new[] { new[] { "BAD" }, new[] { HybridMethods.Local, HybridMethods.Local } }) {
                try { _ = new HybridPolicy(ids); throw new InvalidOperationException(); } catch (ArgumentException) { }
            }
        }),
        ("4D every method mock decision is terminal non-authorizing with duplicate rejection", () => {
            foreach (var id in HybridMethods.All.Select(m => m.Id)) {
                var vm = Review(); Must(Switch(vm, id)); var c = vm.Context!;
                Must(vm.Decide(c.RequestId, c.SessionId, c.ContextSha256, vm.ReviewGeneration, OfflineMockState.ApprovedMock));
                Must(!vm.Decide(c.RequestId, c.SessionId, c.ContextSha256, vm.ReviewGeneration, OfflineMockState.Rejected));
                Must(!vm.Authorized && !c.Authorized && vm.ProductionAuthorization == "DEFAULT_DENY");
            }
        }),
        ("4D broken clock expires pending review without switch or preference save", () => Temporary((store, _) => {
            var broken = false; var vm = Review(() => broken ? throw new InvalidOperationException("SECRET") : Now);
            var picker = new ApprovalMethodSelection(vm, store, true); broken = true;
            Must(!picker.Apply(HybridMethods.Protected, true)); Must(vm.State == OfflineMockState.Expired && store.Read().NeedsOnboarding);
        })),
        ("4D Hallmark hybrid controls expose explicit choices settings unchecked default and keyboard", UiContract)
    };
    private static void UiContract()
    {
        XNamespace ns = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var review = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "OfflineReviewWindow.xaml"));
        Must(review.Descendants(ns + "Button").Single(b => (string?)b.Attribute("Click") == "ChangeMethod_Click").Attribute("IsEnabled")!.Value == "{Binding CanSwitch}");
        Must(review.Descendants(ns + "Button").Any(b => (string?)b.Attribute("Click") == "MethodSettings_Click"));
        var picker = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "ApprovalMethodWindow.xaml"));
        Must(picker.Descendants(ns + "CheckBox").Single().Attribute("IsChecked")!.Value == "False");
        Must(picker.Root!.Attribute("KeyDown")!.Value == "Window_KeyDown");
        Must(picker.Descendants(ns + "ComboBox").Single().Attribute("ItemsSource")!.Value == "{Binding Options}");
        Must(picker.Descendants(ns + "ScrollViewer").Any());
        foreach (var action in new[] { "Apply_Click", "Reset_Click", "Cancel_Click" }) Must(picker.Descendants(ns + "Button").Any(b => (string?)b.Attribute("Click") == action));
    }
}
