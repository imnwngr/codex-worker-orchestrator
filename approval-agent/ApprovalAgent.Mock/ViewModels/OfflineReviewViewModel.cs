using System.ComponentModel;
using System.Globalization;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;

namespace ApprovalAgent.Mock.ViewModels;

public enum OfflineMockState { NoFile, Pending, ApprovedMock, Rejected, Cancelled, Expired }

public sealed class OfflineReviewViewModel(Func<long>? clock = null, HybridPolicy? policy = null) : INotifyPropertyChanged
{
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
    private bool Load(Func<OfflineReviewContext> validate)
    {
        try {
            var candidate = validate(); // Publish only a fully validated immutable snapshot.
            var generation = checked(ReviewGeneration + 1);
            Context = candidate; ReviewGeneration = generation; State = OfflineMockState.Pending;
            SelectedMethod = PreferredMethod ?? HybridMethods.Local; // No fallback if preference is policy-ineligible.
            Status = "New explicit offline review. Mock decisions stay in memory; nothing is transmitted."; Notify(); return true;
        } catch (ReviewInputException e) { Status = e.Category + "; current review retained. No dispatch."; Notify(); return false; }
        catch { Status = "REVIEW_INPUT_INVALID; current review retained. No dispatch."; Notify(); return false; }
    }
    public bool LoadFile(string path) => Load(() => OfflineReviewValidator.ReadFile(path, _clock()));
    public bool LoadBytes(byte[] bytes) => Load(() => OfflineReviewValidator.Validate(bytes, _clock()));
    public void RefreshExpiry()
    {
        if (Context is null || State != OfflineMockState.Pending) return;
        long now;
        try { now = _clock(); } catch { now = long.MinValue; }
        if (now < Context.CreatedAt || now >= Context.ExpiresAt) {
            State = OfflineMockState.Expired; Status = "Expired or invalid clock. No dispatch."; Notify();
        }
    }
    public bool SwitchMethod(string id, string requestId, string sessionId, string digest, long generation)
    {
        RefreshExpiry();
        if (!CanSwitch || Context is null) return false;
        if (requestId != Context.RequestId || sessionId != Context.SessionId || digest != Context.ContextSha256 || generation != ReviewGeneration) {
            Status = "REVIEW_CONTEXT_MISMATCH; no method change."; Notify(); return false;
        }
        var reason = CheckMethod(id);
        if (reason != "OFFLINE_ONLY") { Status = reason + "; no fallback or method change."; Notify(); return false; }
        if (id == SelectedMethod) { Status = "HYBRID_METHOD_UNCHANGED; generation retained."; Notify(); return true; }
        if (ReviewGeneration == long.MaxValue) { State = OfflineMockState.Cancelled; Status = "HYBRID_GENERATION_EXHAUSTED"; Notify(); return false; }
        SelectedMethod = id; ReviewGeneration++;
        Status = "Method changed for this context only. Fresh mock review; original expiry retained. No dispatch."; Notify(); return true;
    }
    public bool Decide(string requestId, string sessionId, string contextSha256, long reviewGeneration, OfflineMockState state)
    {
        RefreshExpiry();
        if (!CanDecide || Context is null) return false;
        if (ReviewGeneration != reviewGeneration || Context.RequestId != requestId || Context.SessionId != sessionId || Context.ContextSha256 != contextSha256) {
            Status = "REVIEW_CONTEXT_MISMATCH; no decision recorded."; Notify(); return false;
        }
        if (state is not (OfflineMockState.ApprovedMock or OfflineMockState.Rejected or OfflineMockState.Cancelled)) return false;
        State = state; Status = state + " locally, in memory only. No grant, proof or dispatch."; Notify(); return true;
    }
    public void DecideCurrent(OfflineMockState state)
    { if (Context is not null) Decide(Context.RequestId, Context.SessionId, Context.ContextSha256, ReviewGeneration, state); }
}
