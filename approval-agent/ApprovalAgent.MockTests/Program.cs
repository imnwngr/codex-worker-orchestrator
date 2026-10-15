using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

var tests = new (string Name, Action Run)[]
{
    ("preserves exact task text and calculates its UTF-8 SHA-256", ExactTextAndHash),
    ("allows mock approval before expiry and records no persistent result", ApproveBeforeExpiry),
    ("rejects mock approval at the expiry instant", CannotApproveAtExpiry),
    ("rejects mock approval after expiry", CannotApproveAfterExpiry),
    ("reject action changes only in-memory mock state", RejectIsLocalState),
    ("terminal states cannot be changed by later actions", TerminalStateIsStable),
    ("fixed proposal stays synthetic and cannot reach a live endpoint", SourceIsMockOnly),
    ("review model exposes a prominent complete-task warning", TransmissionWarning),
    ("reports supported API and available platform authenticator", SupportedCapability),
    ("reports supported API and unavailable platform authenticator", NoPlatformAuthenticator),
    ("does not query an unsupported API version", UnsupportedApiVersion),
    ("reports native HRESULT failures as unknown", NativeQueryError),
    ("rejects nonzero HRESULT even when positive", PositiveHResultIsNotSuccess),
    ("contains exceptions and leaves mock approval independent", DiagnosticExceptionIsIsolated),
    ("reports missing DLL and API as unavailable", MissingNativeLibrary),
    ("handles missing required native export as unavailable", MissingNativeExport),
    ("reports API version query exceptions as unknown", ApiVersionQueryFailure),
    ("reports fail-closed API-version feature gates", FeatureVersionGates),
    ("reports capability environment and operation status as structured JSON", StructuredCapabilityReport),
    ("redacts diagnostic error details from structured reports", StructuredReportRedaction),
    ("blocks all feature gates when the DLL or required exports are unavailable", ReportUnavailableGates),
    ("reports unexpected diagnostic failures safely", ViewModelReportFailure),
    ("inconsistent native diagnostic combinations fail closed", InconsistentNativeReport),
    ("unknown and unsupported runtime states remain blocked", UnknownDiagnosticVersionGates),
    ("WPF structured report uses non-writing binding", ReadOnlyWpfBindingContract),
    ("Hallmark review preserves the exact read-only task and warnings", ReviewSurfaceContract),
    ("Hallmark decision bar preserves mock-only commands and expiry gating", ReviewDecisionContract),
    ("Hallmark diagnostics remain optional and strictly read-only", ReviewDiagnosticsContract),
    ("Hallmark controls preserve keyboard focus and hit-target sizing", ReviewAccessibilityContract)
};

var failures = 0;
foreach (var (name, run) in tests)
{
    try
    {
        run();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception error)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {name}: {error.Message}");
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} mock tests passed.");
return failures == 0 ? 0 : 1;

static void ExactTextAndHash()
{
    const string task = "line one\r\nline two\n  trailing space ";
    var proposal = Proposal(task);
    var expected = Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(task))).ToLowerInvariant();

    Equal(task, proposal.Task, "Task text must be preserved byte-for-byte as a string.");
    Equal(expected, proposal.TaskSha256, "Hash must cover the exact UTF-8 task text.");
}

static void ApproveBeforeExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddSeconds(1)), () => now);

    True(viewModel.CanApprove, "Unexpired proposal should allow mock approval.");
    True(viewModel.ApproveMock(), "Mock approval should transition from Pending.");
    Equal(MockApprovalState.ApprovedMock, viewModel.State, "Expected mock-approved state.");
    True(!viewModel.CanApprove && !viewModel.CanReject,
        "Terminal state must disable both actions.");
    True(viewModel.StatusMessage.Contains("Nothing was sent.", StringComparison.Ordinal),
        "Status must confirm no transmission.");
}

static void CannotApproveAtExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now), () => now);

    True(!viewModel.ApproveMock(), "Expiry instant is no longer valid.");
    Equal(MockApprovalState.Expired, viewModel.State, "Expected expired state.");
}

static void CannotApproveAfterExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddTicks(-1)), () => now);

    True(!viewModel.CanApprove, "Expired proposal should disable approval.");
    True(!viewModel.ApproveMock(), "Expired proposal must not transition to approved.");
    Equal(MockApprovalState.Expired, viewModel.State, "Expected expired state.");
}

static void RejectIsLocalState()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);

    True(viewModel.Reject(), "Pending proposal should be rejectable.");
    Equal(MockApprovalState.Rejected, viewModel.State, "Expected rejected state.");
    True(viewModel.StatusMessage.Contains("Nothing was sent.", StringComparison.Ordinal),
        "Reject must not send data.");
}

static void TerminalStateIsStable()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);

    True(viewModel.Reject(), "Initial reject should succeed.");
    True(!viewModel.ApproveMock(), "Rejected proposal cannot later be approved.");
    True(!viewModel.Reject(), "A second reject has no effect.");
    Equal(MockApprovalState.Rejected, viewModel.State, "Rejected state must remain stable.");
}

static void SourceIsMockOnly()
{
    var proposal = new MockProposalSource().GetProposal();
    var destination = new Uri(proposal.Destination);
    True(destination.Scheme == Uri.UriSchemeHttps, "Mock destination should use HTTPS syntax.");
    True(destination.Host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase),
        "Mock proposal must not use a real external API destination.");
    True(proposal.Task.Contains("MOCK TASK", StringComparison.Ordinal),
        "Synthetic task should be clearly labeled.");
    True(proposal.TaskSha256.Length == 64, "SHA-256 should be 64 hex characters.");
}

static void TransmissionWarning()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);
    True(viewModel.ExternalTransmissionWarning.Contains("complete task", StringComparison.Ordinal),
        "Warning must describe sending the complete task.");
    True(viewModel.ExternalTransmissionWarning.Contains("external provider destination", StringComparison.Ordinal),
        "Warning must mention the external destination.");
    True(viewModel.ExternalTransmissionWarning.Contains("sends nothing", StringComparison.Ordinal),
        "Warning must clearly distinguish the mock from real dispatch.");
}

static void SupportedCapability()
{
    var native = new FakeNativeApi(new FakeSession(1, 0, true));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Available, result.LibraryAvailability, "DLL should be available.");
    Equal(CapabilityAvailability.Available, result.ApiAvailability, "API should be available.");
    Equal((uint?)1, result.ApiVersion, "Expected API version 1.");
    Equal(ApiVersionSupport.Supported, result.VersionSupport, "Version 1 is supported.");
    Equal(CapabilityAvailability.Available, result.PlatformAuthenticatorAvailability,
        "Native query reports an available platform authenticator.");
    Equal(1, native.Session!.AvailabilityQueryCount, "Availability function should be called once.");
}

static void NoPlatformAuthenticator()
{
    var native = new FakeNativeApi(new FakeSession(1, 0, false));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Unavailable, result.PlatformAuthenticatorAvailability,
        "A successful FALSE response means unavailable.");
    Equal(null, result.Error, "A successful negative result is not an API error.");
}

static void UnsupportedApiVersion()
{
    var native = new FakeNativeApi(new FakeSession(0, 0, true));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Available, result.ApiAvailability,
        "The exported API functions were found.");
    Equal(ApiVersionSupport.Unsupported, result.VersionSupport,
        "Version zero is below the supported minimum.");
    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "Do not query the authenticator on an unsupported API version.");
    Equal(0, native.Session!.AvailabilityQueryCount,
        "The unsupported platform must not be queried.");
}

static void NativeQueryError()
{
    var native = new FakeNativeApi(
        new FakeSession(1, unchecked((int)0x80004005), true));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "A failed HRESULT cannot be interpreted as an unavailable authenticator.");
    True(result.Error?.Contains("80004005", StringComparison.Ordinal) == true,
        "The HRESULT should be preserved in diagnostics.");
}

static void PositiveHResultIsNotSuccess()
{
    var native = new FakeNativeApi(new FakeSession(1, 1, true));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();
    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "Only S_OK (0) is success; other status values must not be treated as approval capability.");
    True(result.Error?.Contains("00000001", StringComparison.Ordinal) == true,
        "Unexpected positive HRESULT should be reported.");
}

static void DiagnosticExceptionIsIsolated()
{
    var diagnostic = new WindowsWebAuthnCapabilityDiagnosticService(
        new ThrowingNativeApi());
    var result = diagnostic.GetDiagnostics();
    var diagnosticsViewModel = new WebAuthnDiagnosticsViewModel();
    diagnosticsViewModel.Apply(result);

    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var approvalViewModel = new ApprovalViewModel(
        Proposal("sample", now.AddMinutes(1)), () => now);

    Equal(CapabilityAvailability.Unknown.ToString(), diagnosticsViewModel.ApiStatus,
        "A diagnostic exception should become an unknown status.");
    True(diagnosticsViewModel.ErrorStatus.Contains("could not load", StringComparison.OrdinalIgnoreCase),
        "The diagnostic error should be visible.");
    True(approvalViewModel.CanApprove,
        "A diagnostic failure must not activate or disable mock approval.");
    Equal(MockApprovalState.Pending, approvalViewModel.State,
        "A diagnostic failure must not change approval state.");
}

static void MissingNativeLibrary()
{
    var native = new FakeNativeApi(
        new WebAuthnNativeOpenResult(
            CapabilityAvailability.Unavailable,
            CapabilityAvailability.Unavailable,
            null,
            "webauthn.dll was not found."));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Unavailable, result.LibraryAvailability,
        "Missing library should be reported unavailable.");
    Equal(CapabilityAvailability.Unavailable, result.ApiAvailability,
        "Missing library means the API is unavailable.");
    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "No authenticator result is available when the API is missing.");
}

static void MissingNativeExport()
{
    var native = new FakeNativeApi(
        new WebAuthnNativeOpenResult(
            CapabilityAvailability.Available,
            CapabilityAvailability.Unavailable,
            null,
            "A required WebAuthn API function is unavailable: EntryPointNotFoundException"));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();

    Equal(CapabilityAvailability.Available, result.LibraryAvailability,
        "A missing export does not mean the DLL is absent.");
    Equal(CapabilityAvailability.Unavailable, result.ApiAvailability,
        "A missing required native export makes the API unavailable.");
    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "Do not infer authenticator availability without a complete native API.");
    True(result.Error?.Contains("required WebAuthn API function", StringComparison.Ordinal) == true,
        "The missing-export condition should be exposed in diagnostics.");
}
static void ApiVersionQueryFailure()
{
    var native = new FakeNativeApi(new FakeSession(1, 0, true, throwVersion: true));
    var result = new WindowsWebAuthnCapabilityDiagnosticService(native).GetDiagnostics();
    Equal(null, result.ApiVersion, "A failed version query must not invent a version.");
    Equal(ApiVersionSupport.Unknown, result.VersionSupport, "Version status is unknown.");
    Equal(CapabilityAvailability.Unknown, result.PlatformAuthenticatorAvailability,
        "No capability query follows a failed version query.");
}

static void FeatureVersionGates()
{
    var api3 = new WebAuthnCapabilityResult(
        CapabilityAvailability.Available, CapabilityAvailability.Available, 3,
        ApiVersionSupport.Supported, CapabilityAvailability.Available, null);
    var below = WebAuthnReadOnlyCapabilityReport.Create(
        api3, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("VERSION_GATE_MET_EXPORTS_AND_BEHAVIOR_UNVERIFIED",
        below.BasicMakeGetVersionGate, "API v3 meets only the basic header version gate.");
    Equal("UNSUPPORTED_BY_REPORTED_VERSION", below.PlatformInventoryVersionGate,
        "API v3 is below the header's inventory feature gate.");
    Equal("UNSUPPORTED_BY_REPORTED_VERSION", below.PlatformDeletionVersionGate,
        "API v3 is below the header's deletion feature gate.");

    var api4 = api3 with { ApiVersion = 4 };
    var at = WebAuthnReadOnlyCapabilityReport.Create(
        api4, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("VERSION_GATE_MET_EXPORTS_AND_BEHAVIOR_UNVERIFIED",
        at.PlatformInventoryVersionGate, "API v4 meets the header version gate only.");
    Equal("VERSION_GATE_MET_EXPORTS_AND_BEHAVIOR_UNVERIFIED",
        at.PlatformDeletionVersionGate, "API v4 does not prove deletion behavior.");

    var zero = api3 with { ApiVersion = 0, VersionSupport = ApiVersionSupport.Unsupported, PlatformAuthenticatorAvailability = CapabilityAvailability.Unknown };
    var unsupported = WebAuthnReadOnlyCapabilityReport.Create(
        zero, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("UNSUPPORTED_BY_REPORTED_VERSION", unsupported.BasicMakeGetVersionGate,
        "API v0 cannot meet the basic feature gate.");

    var inconsistent = api4 with { VersionSupport = ApiVersionSupport.Unsupported };
    var blocked = WebAuthnReadOnlyCapabilityReport.Create(
        inconsistent, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("BLOCKED_INCONSISTENT_DIAGNOSTIC", blocked.PlatformDeletionVersionGate,
        "An unsupported diagnostic status cannot turn into a positive feature gate.");
}

static void StructuredCapabilityReport()
{
    var result = new WebAuthnCapabilityResult(
        CapabilityAvailability.Available, CapabilityAvailability.Available, 4,
        ApiVersionSupport.Supported, CapabilityAvailability.Available, null);
    var timestamp = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var report = WebAuthnReadOnlyCapabilityReport.Create(
        result, timestamp, "22631", "X64");
    using var json = JsonDocument.Parse(report.ToJson());
    var root = json.RootElement;
    Equal("READ-ONLY CAPABILITY REPORT — NO CREDENTIAL OPERATION",
        root.GetProperty("Label").GetString(), "Report label.");
    Equal("22631", root.GetProperty("WindowsBuild").GetString(), "Windows build.");
    Equal("X64", root.GetProperty("ProcessArchitecture").GetString(), "Architecture.");
    Equal(timestamp, root.GetProperty("DiagnosticTimestampUtc").GetDateTimeOffset(),
        "Diagnostic timestamp is exact UTC.");
    Equal((uint)4, root.GetProperty("ReportedApiVersion").GetUInt32(), "API version.");
    Equal("Available", root.GetProperty("PlatformAuthenticatorCapability").GetString(),
        "This is only the read-only capability query result.");
    Equal("NOT PERFORMED", root.GetProperty("RealCredentialOperation").GetString(),
        "A diagnostic does not perform a ceremony.");
    True(root.GetProperty("FeatureGateEvidence").GetString()!.Contains("unverified", StringComparison.OrdinalIgnoreCase),
        "The feature gate must explicitly disavow live feature evidence.");
}

static void StructuredReportRedaction()
{
    var result = new WebAuthnCapabilityResult(
        CapabilityAvailability.Unknown, CapabilityAvailability.Unknown, null,
        ApiVersionSupport.Unknown, CapabilityAvailability.Unknown,
        "account-name=private; path=C:\\sensitive");
    var report = WebAuthnReadOnlyCapabilityReport.Create(
        result, DateTimeOffset.UnixEpoch, "22631", "X64");
    var json = report.ToJson();
    True(!json.Contains("private", StringComparison.OrdinalIgnoreCase),
        "Raw diagnostic detail must not be serialized.");
    True(!json.Contains("sensitive", StringComparison.OrdinalIgnoreCase),
        "Paths and account information must not be serialized.");
    True(json.Contains("DIAGNOSTIC_FAILED_DETAILS_REDACTED", StringComparison.Ordinal),
        "A safe error category remains available.");
}

static void ReportUnavailableGates()
{
    var result = new WebAuthnCapabilityResult(
        CapabilityAvailability.Unavailable, CapabilityAvailability.Unavailable, null,
        ApiVersionSupport.Unknown, CapabilityAvailability.Unknown, "library unavailable");
    var report = WebAuthnReadOnlyCapabilityReport.Create(
        result, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("BLOCKED_API_UNAVAILABLE", report.BasicMakeGetVersionGate, "Basic API gate.");
    Equal("BLOCKED_API_UNAVAILABLE", report.PlatformInventoryVersionGate, "Inventory gate.");
    Equal("BLOCKED_API_UNAVAILABLE", report.PlatformDeletionVersionGate, "Deletion gate.");
    Equal("UNKNOWN", report.ApiVersionState, "An absent API version is unknown.");

    var exportMissing = result with
    {
        LibraryAvailability = CapabilityAvailability.Available,
        Error = "A required WebAuthn API function is unavailable: EntryPointNotFoundException"
    };
    var missing = WebAuthnReadOnlyCapabilityReport.Create(
        exportMissing, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("DLL_OR_EXPORT_UNAVAILABLE", missing.DiagnosticErrorCategory,
        "A known missing-export error maps to an explicit safe category.");
}

static void ViewModelReportFailure()
{
    var viewModel = new WebAuthnDiagnosticsViewModel();
    viewModel.ApplyFailure();
    using var json = JsonDocument.Parse(viewModel.StructuredReportJson);
    Equal("UNKNOWN", json.RootElement.GetProperty("ApiVersionState").GetString(),
        "Unexpected diagnostic failure must report an unknown version.");
    Equal("NOT PERFORMED", json.RootElement.GetProperty("RealCredentialOperation").GetString(),
        "Unexpected diagnostic failure must not be mistaken for a ceremony.");
}

static void InconsistentNativeReport()
{
    var contradictions = new[]
    {
        new WebAuthnCapabilityResult(CapabilityAvailability.Unavailable,
            CapabilityAvailability.Available, 7, ApiVersionSupport.Supported,
            CapabilityAvailability.Available, null),
        new WebAuthnCapabilityResult(CapabilityAvailability.Available,
            CapabilityAvailability.Available, null, ApiVersionSupport.Supported,
            CapabilityAvailability.Unknown, null),
        new WebAuthnCapabilityResult(CapabilityAvailability.Available,
            CapabilityAvailability.Available, 0, ApiVersionSupport.Supported,
            CapabilityAvailability.Unknown, null),
        new WebAuthnCapabilityResult(CapabilityAvailability.Available,
            CapabilityAvailability.Available, 7, ApiVersionSupport.Unknown,
            CapabilityAvailability.Available, null),
        new WebAuthnCapabilityResult(CapabilityAvailability.Available,
            CapabilityAvailability.Available, 7, ApiVersionSupport.Supported,
            CapabilityAvailability.Available, "HRESULT 0x80000001")
    };
    foreach (var inconsistent in contradictions)
    {
        var report = WebAuthnReadOnlyCapabilityReport.Create(
            inconsistent, DateTimeOffset.UnixEpoch, "22631", "X64");
        Equal("INCONSISTENT_BLOCKED", report.DiagnosticConsistency,
            "Contradictory diagnostic must never support readiness.");
        Equal("BLOCKED_INCONSISTENT_DIAGNOSTIC", report.BasicMakeGetVersionGate,
            "Contradictory diagnostic blocks basic features.");
        Equal("BLOCKED_INCONSISTENT_DIAGNOSTIC", report.PlatformDeletionVersionGate,
            "Contradictory diagnostic blocks deletion version gate.");
    }
}

static void UnknownDiagnosticVersionGates()
{
    var unknown = new WebAuthnCapabilityResult(
        CapabilityAvailability.Available, CapabilityAvailability.Available, null,
        ApiVersionSupport.Unknown, CapabilityAvailability.Unknown, "version missing");
    var report = WebAuthnReadOnlyCapabilityReport.Create(
        unknown, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("UNKNOWN", report.PlatformInventoryVersionGate,
        "Unknown version cannot pass inventory version gate.");
    Equal("NOT_ESTABLISHED_NO_CREDENTIAL_OPERATIONS", report.PlatformOperationReadiness,
        "Version report must never claim credential operation readiness.");
    var unsupported = unknown with { ApiVersion = 0, VersionSupport = ApiVersionSupport.Unsupported };
    var below = WebAuthnReadOnlyCapabilityReport.Create(
        unsupported, DateTimeOffset.UnixEpoch, "22631", "X64");
    Equal("UNSUPPORTED_BY_REPORTED_VERSION", below.BasicMakeGetVersionGate,
        "API version zero cannot pass even the basic version gate.");
}

static void ReadOnlyWpfBindingContract()
{
    // CI is headless: this inspects the compiled project's source XAML contract,
    // not an instantiated WPF window. Building the WPF project is a separate CI step.
    var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "MainWindow.xaml");
    var window = XDocument.Load(path);
    var ns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    var matched = window.Descendants(ns + "TextBox")
        .Where(element => (string?)element.Attribute("Text") is string binding &&
            binding.Contains("StructuredReportJson", StringComparison.Ordinal)).ToArray();
    Equal(1, matched.Length, "Exactly one structured report textbox must exist.");
    var textBinding = (string?)matched[0].Attribute("Text") ?? "";
    True(textBinding.Contains("Mode=OneWay", StringComparison.Ordinal),
        "WPF TextBox must not default to TwoWay for a private setter.");
    True(!textBinding.Contains("Mode=TwoWay", StringComparison.Ordinal) &&
        !textBinding.Contains("Mode=OneWayToSource", StringComparison.Ordinal),
        "WPF report binding must never write to its source.");
    Equal("True", (string?)matched[0].Attribute("IsReadOnly"),
        "Structured report textbox must be read-only in the UI.");
    var property = typeof(WebAuthnDiagnosticsViewModel).GetProperty("StructuredReportJson");
    True(property is not null && property.GetSetMethod() is null,
        "ViewModel should not expose a public report setter.");
}

// These headless layout-contract tests complement the Windows WPF build; they
// do not substitute for visual, high-contrast, DPI or accessibility testing.
static XDocument LoadReviewWindow() => XDocument.Load(
    Path.Combine(AppContext.BaseDirectory, "Fixtures", "MainWindow.xaml"));

static void ReviewSurfaceContract()
{
    var window = LoadReviewWindow();
    var ns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    var texts = window.Descendants(ns + "TextBlock").ToArray();
    True(texts.Any(x => ((string?)x.Attribute("Text"))?.Contains(
        "MOCK PROTOTYPE — NO REAL APPROVAL OR DISPATCH", StringComparison.Ordinal) == true),
        "The exact mock-only safety label must be visible in the review content.");
    True(texts.Any(x => ((string?)x.Attribute("Text"))?.Contains(
        "LOCAL MOCK · NO DISPATCH", StringComparison.Ordinal) == true),
        "Persistent window header must explicitly identify the simulation.");
    True(texts.Any(x => ((string?)x.Attribute("Text"))?.Contains(
        "ExternalTransmissionWarning", StringComparison.Ordinal) == true),
        "The full warning must be bound to the original view model.");
    True(texts.Any(x => ((string?)x.Attribute("Text"))?.Contains(
        "reserved .invalid domain", StringComparison.Ordinal) == true),
        "The synthetic destination notice must not be removed.");

    var taskBoxes = window.Descendants(ns + "TextBox")
        .Where(x => ((string?)x.Attribute("Text"))?.Contains(
            "Proposal.Task", StringComparison.Ordinal) == true).ToArray();
    Equal(1, taskBoxes.Length, "There must be exactly one complete-task textbox.");
    Equal("True", (string?)taskBoxes[0].Attribute("IsReadOnly"),
        "The exact task text must remain read-only.");
    True(((string?)taskBoxes[0].Attribute("Text"))?.Contains(
        "Mode=OneWay", StringComparison.Ordinal) == true,
        "The task binding must not mutate its proposal.");
    True(texts.Any(x => ((string?)x.Attribute("Text"))?.Contains(
        "Proposal.TaskSha256", StringComparison.Ordinal) == true),
        "The exact task hash must remain visible.");
}

static void ReviewDecisionContract()
{
    var window = LoadReviewWindow();
    var ns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    var buttons = window.Descendants(ns + "Button").ToArray();
    Equal(2, buttons.Length, "Only Reject and Approve Mock should be actionable.");
    var approve = buttons.Single(b => (string?)b.Attribute("Click") == "ApproveMock_Click");
    var reject = buttons.Single(b => (string?)b.Attribute("Click") == "Reject_Click");
    Equal("{Binding CanApprove}", (string?)approve.Attribute("IsEnabled"),
        "Mock approval remains controlled by the view-model expiry and state.");
    Equal("{Binding CanReject}", (string?)reject.Attribute("IsEnabled"),
        "Mock rejection remains controlled by the view-model state.");
    True(((string?)approve.Attribute("Content"))?.Contains("Mock", StringComparison.Ordinal) == true,
        "The primary action must not be mistaken for a real approval.");
    Equal("Approve mock proposal only", (string?)approve.Attribute("AutomationProperties.Name"),
        "Approval must have an explicit screen-reader identity.");

    var content = window.Root!.Element(ns + "Grid")!;
    var footer = content.Elements(ns + "Border").Single(x =>
        (string?)x.Attribute("Grid.Row") == "2");
    True(footer.Descendants(ns + "Button").Count() == 2,
        "Both actions must stay in the fixed footer rather than scrolling away.");
    True(footer.Descendants(ns + "TextBlock").Any(x =>
        ((string?)x.Attribute("Text"))?.Contains("StatusMessage", StringComparison.Ordinal) == true),
        "The live mock outcome must remain visible alongside the actions.");
    Equal("Window_KeyDown", (string?)window.Root.Attribute("KeyDown"),
        "The original Escape-to-reject keyboard behavior must be retained.");
}

static void ReviewDiagnosticsContract()
{
    var window = LoadReviewWindow();
    var ns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    var xns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml";
    var section = window.Descendants(ns + "Border").Single(x =>
        (string?)x.Attribute(xns + "Name") == "WebAuthnDiagnosticsSection");
    var disclosure = section.Descendants(ns + "Expander").Single();
    Equal("False", (string?)disclosure.Attribute("IsExpanded"),
        "Read-only diagnostics should start collapsed, after the task content.");
    Equal("Window_Loaded", (string?)window.Root!.Attribute("Loaded"),
        "Read-only diagnostics should retain the existing loaded handler.");
    var report = disclosure.Descendants(ns + "TextBox").Single(x =>
        ((string?)x.Attribute("Text"))?.Contains("StructuredReportJson", StringComparison.Ordinal) == true);
    Equal("True", (string?)report.Attribute("IsReadOnly"),
        "Diagnostics must not be editable.");
    True(((string?)report.Attribute("Text"))?.Contains("Mode=OneWay", StringComparison.Ordinal) == true,
        "Structured report must preserve its non-writing binding.");
    True(disclosure.Descendants(ns + "TextBlock").Any(x =>
        ((string?)x.Attribute("Text"))?.Contains("does not prove Windows Hello enrollment",
            StringComparison.Ordinal) == true),
        "Capability limitations must remain visible when diagnostics are expanded.");
}

static void ReviewAccessibilityContract()
{
    var window = LoadReviewWindow();
    var ns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    var xns = (XNamespace)"http://schemas.microsoft.com/winfx/2006/xaml";
    var styles = window.Descendants(ns + "Style").ToArray();
    var action = styles.Single(x => (string?)x.Attribute(xns + "Key") == "ActionButton");
    True(action.Descendants(ns + "Setter").Any(x =>
        (string?)x.Attribute("Property") == "Height" &&
        int.TryParse((string?)x.Attribute("Value"), out var height) && height >= 44),
        "Action hit targets must be at least 44 WPF device-independent units tall.");
    True(action.Descendants(ns + "Setter").Any(x =>
        (string?)x.Attribute("Property") == "FocusVisualStyle"),
        "Keyboard focus must have a visible ring.");
    var footerStatus = window.Descendants(ns + "TextBlock").Single(x =>
        (string?)x.Attribute("AutomationProperties.Name") == "Mock decision status");
    Equal("Polite", (string?)footerStatus.Attribute("AutomationProperties.LiveSetting"),
        "Screen readers should be notified of completed/rejected/expired state.");
    True(action.Descendants(ns + "Trigger").Any(x =>
        (string?)x.Attribute("Property") == "IsEnabled" &&
        (string?)x.Attribute("Value") == "False"),
        "Disabled actions must have a distinct visual state.");
}

static ApprovalProposal Proposal(
    string task,
    DateTimeOffset? expiresAt = null) =>
    new(
        Provider: "Mock Provider",
        Model: "mock-model",
        Destination: "https://api.example.invalid/v1/analyze",
        Task: task,
        ExpiresAtUtc: expiresAt ?? DateTimeOffset.Parse("2030-01-02T03:05:05Z"));

static void Equal<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException(
            $"{message} Expected '{expected}', got '{actual}'.");
    }
}

static void True(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

sealed class FakeNativeApi : IWebAuthnNativeApi
{
    private readonly WebAuthnNativeOpenResult _openResult;

    public FakeNativeApi(FakeSession session)
        : this(new WebAuthnNativeOpenResult(
            CapabilityAvailability.Available, CapabilityAvailability.Available, session, null)) { }

    public FakeNativeApi(WebAuthnNativeOpenResult openResult) => _openResult = openResult;

    public FakeSession? Session => _openResult.Session as FakeSession;
    public WebAuthnNativeOpenResult Open() => _openResult;
}

sealed class FakeSession(
    uint version,
    int hresult,
    bool available,
    bool throwVersion = false) : IWebAuthnNativeSession
{
    public int AvailabilityQueryCount { get; private set; }
    public uint GetApiVersionNumber()
    {
        if (throwVersion)
            throw new InvalidOperationException("account-name=private");
        return version;
    }

    public int IsUserVerifyingPlatformAuthenticatorAvailable(out bool result)
    {
        AvailabilityQueryCount++;
        result = available;
        return hresult;
    }

    public void Dispose() { }
}

sealed class ThrowingNativeApi : IWebAuthnNativeApi
{
    public WebAuthnNativeOpenResult Open() =>
        throw new InvalidOperationException("test diagnostic failure");
}
