namespace ApprovalAgent.Mock.Models;

public enum HybridAvailability { OfflineFunctional, Simulated, Unavailable }
public enum HybridRequirement { OfflinePreview, ProtectedIdentity, RemoteIdentity }

public sealed record HybridMethod(string Id, string DisplayName, string Description,
    HybridAvailability Availability, string Prerequisites, string SupportedActions,
    string Assurance, bool Simulated, bool TransportEstablished, bool IdentityEstablished);

// Product choices, not three equivalent security mechanisms. Never supplied by a preference file.
public static class HybridMethods
{
    public const string Local = "LOCAL_DESKTOP", Protected = "PROTECTED_WINDOWS", Remote = "REMOTE_BROWSER";
    public static IReadOnlyList<HybridMethod> All { get; } = Array.AsReadOnly(new[] {
        new HybridMethod(Local, "A — Local Desktop", "Existing local WPF offline review.", HybridAvailability.OfflineFunctional,
            "Explicitly select a valid local review file.", "Local mock approve, reject, cancel and expire.", "UNESTABLISHED / NON_AUTHORIZING", false, false, false),
        new HybridMethod(Protected, "B — Protected Windows (simulation)", "Local simulation only; no protected component or authenticated IPC.", HybridAvailability.Simulated,
            "Real use requires reviewed installation, component identity and privilege separation.", "In-memory mock decisions only.", "UNESTABLISHED / NON_AUTHORIZING", true, false, false),
        new HybridMethod(Remote, "C — Remote / Browser (simulation)", "Local simulation only; nothing is sent to a browser or device.", HybridAvailability.Simulated,
            "Real use requires device registration, origin and authenticated channels.", "In-memory mock decisions only.", "UNESTABLISHED / NON_AUTHORIZING", true, false, false)
    });
    public static HybridMethod? Find(string? id) => All.SingleOrDefault(m => m.Id == id);
    public static bool Valid(HybridMethod? value) => value is not null && Find(value.Id) == value;
}

// Trusted code supplies policy independently of the user-editable UX preference.
public sealed class HybridPolicy
{
    private readonly HashSet<string> _allowed;
    public HybridRequirement Requirement { get; }
    public HybridPolicy(IEnumerable<string>? allowed = null, HybridRequirement requirement = HybridRequirement.OfflinePreview)
    {
        var ids = (allowed ?? HybridMethods.All.Select(m => m.Id)).Take(4).ToArray();
        if (!Enum.IsDefined(requirement) || ids.Length > 3 || ids.Distinct().Count() != ids.Length || ids.Any(id => HybridMethods.Find(id) is null))
            throw new ArgumentException("HYBRID_POLICY_INVALID");
        _allowed = new HashSet<string>(ids, StringComparer.Ordinal); Requirement = requirement;
    }
    public string Check(HybridMethod? method)
    {
        if (!HybridMethods.Valid(method)) return "HYBRID_METADATA_INVALID";
        if (!_allowed.Contains(method!.Id)) return "HYBRID_METHOD_NOT_ALLOWED";
        if (method.Availability == HybridAvailability.Unavailable) return "HYBRID_METHOD_UNAVAILABLE";
        // No current method has authenticated identity/transport, including A.
        if (Requirement != HybridRequirement.OfflinePreview) return "HYBRID_ASSURANCE_UNAVAILABLE";
        return "OFFLINE_ONLY";
    }
}
