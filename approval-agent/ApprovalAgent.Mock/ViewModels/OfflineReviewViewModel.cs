using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;

namespace ApprovalAgent.Mock.ViewModels;

public enum OfflineMockState { NoFile, Pending, ApprovedMock, Rejected, Cancelled, Expired }

public sealed class OfflineReviewViewModel(Func<long>? clock = null, HybridPolicy? policy = null) : INotifyPropertyChanged
{
    private readonly object _lifecycleGate = new();
    private readonly string _instanceId = Guid.NewGuid().ToString("N");
    private long _lastClock = long.MinValue;
    private long ReadClock() { var now = _clock(); if (now < _lastClock) throw new InvalidOperationException("INVALID_CLOCK"); _lastClock = now; return now; }
    public HybridSimulation Simulation { get; } = new();
    private OfflineTrustSession? _previewSession;
    private OfflineTrustFakeTransport? _previewTransport;
    private SimulationBinding? _previewBinding;
    public bool IsLocal => SelectedMethod == HybridMethods.Local;
    public bool IsProtected => SelectedMethod == HybridMethods.Protected;
    public bool IsRemote => SelectedMethod == HybridMethods.Remote;
    public bool IsPreview => IsProtected || IsRemote;
    public bool CanStartPreview => CanDecide && !IsLocal && _previewSession is null && Simulation.State == "ReadyForSimulation";
    public bool CanRespondPreview => CanDecide && _previewSession?.State == "Pending" && _previewBinding == SimulationToken;
    public bool CanRecoverPreview => CanDecide && _previewSession?.State == "Unknown" && _previewBinding == SimulationToken;
    public string ProtocolDisplay => _previewSession is null
        ? (IsLocal ? "Local synthetic review; no credential operation." : "Fake component/device available for offline protocol preview.")
        : "Offline protocol: " + _previewSession.State + " / identity UNVERIFIED / DEFAULT_DENY";
    public bool CanExportBrowser => IsRemote && CanRespondPreview;
    public string SimulationDisplay => Simulation.State + " / " + Simulation.Identity + " / no network transport / DEFAULT_DENY";
    public string RemainingDisplay => Context is null ? "No active deadline" : State != OfflineMockState.Pending ? State.ToString() :
        "Remaining: " + Math.Max(0, (Context.ExpiresAt - Math.Max(Context.CreatedAt, _lastClock) + 999) / 1000) + " seconds";
    private readonly Func<long> _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    private readonly HybridPolicy _policy = policy ?? new HybridPolicy();
    public string? PreferredMethod { get; private set; }
    public string SelectedMethod { get; private set; } = HybridMethods.Local;
    public string MethodStatus => _policy.Check(HybridMethods.Find(SelectedMethod));
    public string MethodDisplay => HybridMethods.Find(SelectedMethod)?.DisplayName ?? "Unavailable";
    public string MethodDescription => HybridMethods.Find(SelectedMethod)?.Description ?? "Unavailable";
    public string PreferenceDisplay => HybridMethods.Find(PreferredMethod)?.DisplayName ?? "Not set — optional first-use setup available";
    public bool CanSwitch => Context is not null && State == OfflineMockState.Pending;
    public string ProductionAuthorization => "DEFAULT_DENY";
    public string CheckMethod(string id) => _policy.Check(HybridMethods.Find(id));
    public bool SetPreference(string? id)
    {
        if (id is not null && HybridMethods.Find(id) is null) return false;
        PreferredMethod = id; Notify(); return true; // Future loads only; never change pending method.
    }
    public event PropertyChangedEventHandler? PropertyChanged;
    public OfflineReviewContext? Context { get; private set; }
    public OfflineMockState State { get; private set; } = OfflineMockState.NoFile;
    public long ReviewGeneration { get; private set; }
    public string Status { get; private set; } = "Select a local review file. No identity or approval is established.";
    public bool CanDecide => Context is not null && State == OfflineMockState.Pending && MethodStatus == "OFFLINE_ONLY";
    public bool Authorized => false;
    public string Warning => "OFFLINE SYNTHETIC PREVIEW — NO DISPATCH";
    public string ExpiresAtDisplay => Context is null ? "No file loaded" : DateTimeOffset.FromUnixTimeMilliseconds(Context.ExpiresAt).ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
    public IReadOnlyList<OfflineReviewTarget> Targets => Context?.Targets ?? (IReadOnlyList<OfflineReviewTarget>)System.Array.Empty<OfflineReviewTarget>();
    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
    private bool Load(Func<OfflineReviewContext> validate) { lock (_lifecycleGate) { return LoadCore(validate); } }
    private bool LoadCore(Func<OfflineReviewContext> validate)
    {
        try {
            var candidate = validate(); // Publish only a fully validated immutable snapshot.
            var generation = checked(ReviewGeneration + 1);
            Context = candidate; ReviewGeneration = generation; State = OfflineMockState.Pending;
            SelectedMethod = PreferredMethod ?? HybridMethods.Local; // No fallback if preference is policy-ineligible.
            ResetSimulation();
            Status = "New explicit offline review. Mock decisions stay in memory; nothing is transmitted."; Notify(); return true;
        } catch (ReviewInputException e) { Status = e.Category + "; current review retained. No dispatch."; Notify(); return false; }
        catch { Status = "REVIEW_INPUT_INVALID; current review retained. No dispatch."; Notify(); return false; }
    }
    public bool LoadFile(string path) => Load(() => OfflineReviewValidator.ReadFile(path, ReadClock()));
    public bool LoadBytes(byte[] bytes) => Load(() => OfflineReviewValidator.Validate(bytes, ReadClock()));
    public void RefreshExpiry() { lock (_lifecycleGate) { RefreshExpiryCore(); } }
    private void RefreshExpiryCore()
    {
        if (Context is null || State != OfflineMockState.Pending) return;
        long now;
        try { now = ReadClock(); } catch { now = long.MinValue; }
        if (now < Context.CreatedAt || now >= Context.ExpiresAt) {
            State = OfflineMockState.Expired; ClearPreview(); Simulation.End("Expired"); Status = "Expired or invalid clock. No dispatch."; Notify();
        } else Notify();
    }
    public bool SwitchMethod(string id, string requestId, string sessionId, string digest, long generation) { lock (_lifecycleGate) { return SwitchMethodCore(id, requestId, sessionId, digest, generation); } }
    private bool SwitchMethodCore(string id, string requestId, string sessionId, string digest, long generation)
    {
        RefreshExpiry();
        if (!CanSwitch || Context is null) return false;
        if (requestId != Context.RequestId || sessionId != Context.SessionId || digest != Context.ContextSha256 || generation != ReviewGeneration) {
            Status = "REVIEW_CONTEXT_MISMATCH; no method change."; Notify(); return false;
        }
        var reason = CheckMethod(id);
        if (reason != "OFFLINE_ONLY") { Status = reason + "; no fallback or method change."; Notify(); return false; }
        if (id == SelectedMethod) { Status = "HYBRID_METHOD_UNCHANGED; generation retained."; Notify(); return true; }
        if (ReviewGeneration == long.MaxValue) { State = OfflineMockState.Cancelled; ClearPreview(); Simulation.End("Cancelled"); Status = "HYBRID_GENERATION_EXHAUSTED"; Notify(); return false; }
        SelectedMethod = id; ReviewGeneration++; ResetSimulation();
        Status = "Method changed for this context only. Fresh mock review; original expiry retained. No dispatch."; Notify(); return true;
    }
    public bool Decide(string requestId, string sessionId, string contextSha256, long reviewGeneration, OfflineMockState state) { lock (_lifecycleGate) { return DecideCore(requestId, sessionId, contextSha256, reviewGeneration, state); } }
    private bool DecideCore(string requestId, string sessionId, string contextSha256, long reviewGeneration, OfflineMockState state)
    {
        RefreshExpiry();
        if (Context is null || State != OfflineMockState.Pending || (state != OfflineMockState.Cancelled && !CanDecide)) return false;
        if (ReviewGeneration != reviewGeneration || Context.RequestId != requestId || Context.SessionId != sessionId || Context.ContextSha256 != contextSha256) {
            Status = "REVIEW_CONTEXT_MISMATCH; no decision recorded."; Notify(); return false;
        }
        if (state is not (OfflineMockState.ApprovedMock or OfflineMockState.Rejected or OfflineMockState.Cancelled)) return false;
        State = state; ClearPreview(); Simulation.End(state == OfflineMockState.ApprovedMock ? "SimulatedComplete" : state.ToString()); Status = state + " locally, in memory only. No grant, proof or dispatch."; Notify(); return true;
    }
    public SimulationBinding? SimulationToken => Context is null ? null : new(Context.RequestId, Context.SessionId, Context.ContextSha256, ReviewGeneration, SelectedMethod, _instanceId);
    private void ClearPreview() { _previewTransport?.Clear(); _previewTransport = null; _previewSession = null; _previewBinding = null; }
    private void ResetSimulation()
    {
        ClearPreview();
        Simulation.Reset(SimulationToken, CanDecide && SelectedMethod != HybridMethods.Local);
    }
    public bool StartInteractivePreview() { lock (_lifecycleGate) { return StartInteractivePreviewCore(); } }
    private bool StartInteractivePreviewCore()
    {
        RefreshExpiry();
        if (!CanStartPreview) return PreviewDenied();
        try {
            var token = SimulationToken!;
            var session = new OfflineTrustSession(this, _clock);
            if (IsProtected && !session.Negotiate(session.Fixture("HELLO"))) return PreviewDenied();
            if (IsRemote && !session.Register(session.Fixture("REGISTRATION"))) return PreviewDenied();
            if (!session.Start(session.Fixture("CONSENT_REQUEST"))) return PreviewDenied();
            _previewSession = session;
            _previewTransport = new OfflineTrustFakeTransport();
            _previewBinding = token;
            Status = "Fake component and request initialized; no identity or endpoint authenticated."; Notify(); return true;
        } catch { return PreviewDenied(); }
    }
    public bool RespondInteractivePreview(string outcome) { lock (_lifecycleGate) { return RespondInteractivePreviewCore(outcome); } }
    private bool RespondInteractivePreviewCore(string outcome)
    {
        RefreshExpiry();
        if (!CanRespondPreview || outcome is not ("GRANT" or "DENY" or "CANCEL" or "UNKNOWN")) return PreviewDenied();
        try {
            var transport = _previewTransport!; var session = _previewSession!;
            bool accepted = transport.Send(session.Fixture("CONSENT_RESPONSE", outcome)) && transport.Deliver(session);
            Status = accepted ? "Synthetic response consumed locally; production remains DEFAULT_DENY." :
                "Synthetic response rejected by canonical review.";
            Notify(); return accepted;
        } catch { return PreviewDenied(); }
    }
    public bool CrashInteractivePreview() { lock (_lifecycleGate) { return CrashInteractivePreviewCore(); } }
    private bool CrashInteractivePreviewCore()
    {
        RefreshExpiry();
        if (!CanRespondPreview || !_previewSession!.Crash()) return PreviewDenied();
        Status = "Fake component/device interrupted. Outcome unknown; explicit abandonment required.";
        Notify(); return true;
    }
    public bool RecoverInteractivePreview() { lock (_lifecycleGate) { return RecoverInteractivePreviewCore(); } }
    private bool RecoverInteractivePreviewCore()
    {
        RefreshExpiry();
        if (!CanRecoverPreview || !_previewSession!.Recover()) return PreviewDenied();
        Status = "Unknown outcome abandoned locally. No retransmission, proof or grant."; Notify(); return true;
    }
    public string? ExportBrowserPackage() { lock (_lifecycleGate) { return ExportBrowserPackageCore(); } }
    private string? ExportBrowserPackageCore()
    {
        RefreshExpiry();
        if (!CanExportBrowser || Context is null) { PreviewDenied(); return null; }
        try {
            var context = Context;
            using var response = JsonDocument.Parse(_previewSession!.Fixture("CONSENT_RESPONSE", "GRANT"));
            var package = new {
                schemaVersion = 1, designation = "OFFLINE_BROWSER_PREVIEW_ONLY",
                request = new {
                    context.RequestId, context.SessionId, context.ContextSha256, context.BatchSha256,
                    context.CreatedAt, context.ExpiresAt,
                    targets = context.Targets.Select(t => new { t.Id, t.ProviderId, t.ModelId, t.Destination, t.Task, t.TaskSha256 }).ToArray()
                },
                responseTemplate = response.RootElement
            };
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(package, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
            var result = ReviewJson.Canonical(json.RootElement);
            if (Encoding.UTF8.GetByteCount(result) > ReviewJson.MaximumBytes) return PreviewDeniedPackage();
            Status = "Untrusted browser request package ready; only the active .NET session can consume its response."; Notify();
            return result;
        } catch { return PreviewDeniedPackage(); }
    }
    private string? PreviewDeniedPackage() { PreviewDenied(); return null; }
    public bool ImportBrowserResponse(string json) { lock (_lifecycleGate) { return ImportBrowserResponseCore(json); } }
    private bool ImportBrowserResponseCore(string json)
    {
        RefreshExpiry();
        if (!IsRemote || !CanRespondPreview || json is null) return PreviewDenied();
        try {
            var transport = _previewTransport!; var session = _previewSession!;
            var accepted = transport.Send(json) && transport.Deliver(session);
            Status = accepted ? "Browser synthetic response consumed in the active offline session; DEFAULT_DENY remains." :
                "Browser response rejected: malformed, stale, repeated or conflicting with this session.";
            Notify(); return accepted;
        } catch { return PreviewDenied(); }
    }
    private bool PreviewDenied()
    {
        Status = "OFFLINE_PREVIEW_DENIED; stale, unavailable or invalid protocol state. No dispatch.";
        Notify(); return false;
    }
    public bool Simulate(string action, SimulationBinding token, string fixtureId) { lock (_lifecycleGate) { return SimulateCore(action, token, fixtureId); } }
    private bool SimulateCore(string action, SimulationBinding token, string fixtureId)
    {
        RefreshExpiry();
        if (!CanDecide || SelectedMethod == HybridMethods.Local || token != SimulationToken || !Simulation.Apply(action, token, fixtureId)) {
            Status = "SIMULATION_DENIED; no transition or authorization."; Notify(); return false;
        }
        var terminal = Simulation.State switch {
            "SimulatedComplete" => OfflineMockState.ApprovedMock,
            "Rejected" => OfflineMockState.Rejected,
            "Cancelled" => OfflineMockState.Cancelled,
            _ => OfflineMockState.Pending
        };
        // Canonical acceptance is authoritative; its second clock check can expire this event.
        if (terminal != OfflineMockState.Pending)
            return Decide(token.RequestId, token.SessionId, token.ContextSha256, token.Generation, terminal);
        if (Simulation.State is "Failed" or "Unavailable") ClearPreview();
        Status = "Simulation: " + Simulation.State + "; claims unverified, no dispatch."; Notify();
        return true;
    }
    public void ReportUnavailable() { Status = "OPERATION_UNAVAILABLE; explicitly load a valid review first. No dispatch."; Notify(); }
    public void ReportOperationFailure(string message) { Status = message + " No dispatch."; Notify(); }
    public void DecideCurrent(OfflineMockState state)
    { if (Context is not null) Decide(Context.RequestId, Context.SessionId, Context.ContextSha256, ReviewGeneration, state); }
}
