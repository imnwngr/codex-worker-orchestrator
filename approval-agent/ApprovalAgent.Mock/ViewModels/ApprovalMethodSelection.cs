using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;

namespace ApprovalAgent.Mock.ViewModels;

public sealed record MethodOption(HybridMethod Method, string PolicyStatus)
{ public string Label => Method.DisplayName + " — " + PolicyStatus; }

// UI-independent dialog actions. Captures the request generation before the modal picker opens.
public sealed class ApprovalMethodSelection
{
    private readonly OfflineReviewViewModel _review;
    private readonly ApprovalMethodPreferences _preferences;
    private readonly string? _request, _session, _digest;
    private readonly long _generation;
    public bool Switching { get; }
    public IReadOnlyList<MethodOption> Options { get; }
    public string Status { get; private set; } = "Preference is UX only. Every method remains non-authorizing.";
    public ApprovalMethodSelection(OfflineReviewViewModel review, ApprovalMethodPreferences preferences, bool switching)
    {
        _review = review; _preferences = preferences; Switching = switching;
        _request = review.Context?.RequestId; _session = review.Context?.SessionId; _digest = review.Context?.ContextSha256; _generation = review.ReviewGeneration;
        Options = Array.AsReadOnly(HybridMethods.All.Select(m => new MethodOption(m, review.CheckMethod(m.Id))).ToArray());
    }
    public bool Apply(string? id, bool setAsDefault = false)
    {
        if (HybridMethods.Find(id) is null) { Status = "HYBRID_SELECTION_REQUIRED"; return false; }
        if (Switching) {
            if (_request is null || !_review.SwitchMethod(id!, _request, _session!, _digest!, _generation)) {
                Status = "HYBRID_SWITCH_REJECTED; review state or policy changed. No preference saved."; return false;
            }
            if (!setAsDefault) { Status = "METHOD_SWITCHED; preference unchanged."; return true; }
        }
        var saved = _preferences.Save(id!);
        if (saved != "PREFERENCE_SAVED") { Status = saved + (Switching ? "; method changed locally, default unchanged." : "; default unchanged."); return false; }
        _review.SetPreference(id); Status = "PREFERENCE_SAVED; applies to future review loads only."; return true;
    }
    public bool Reset()
    {
        if (Switching) { Status = "PREFERENCE_RESET_NOT_AVAILABLE"; return false; }
        Status = _preferences.Reset();
        if (Status != "PREFERENCE_RESET") return false;
        _review.SetPreference(null); return true;
    }
}
