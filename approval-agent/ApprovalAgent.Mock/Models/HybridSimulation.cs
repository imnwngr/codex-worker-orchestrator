namespace ApprovalAgent.Mock.Models;

// Bounded, in-process fixtures only. No identity, transport, proof or authorization.
public sealed record SimulationBinding(string RequestId, string SessionId, string ContextSha256, long Generation, string MethodId, string InstanceId);
public sealed class HybridSimulation
{
    private SimulationBinding? _binding;
    public string State { get; private set; } = "Unavailable";
    public string Identity => "UNVERIFIED_SIMULATION_FIXTURE";
    public string FixtureId => _binding?.MethodId == HybridMethods.Protected ? "fake-component-v1" : "fake-device-v1";
    public bool Authorized => false;
    public string ProductionAuthorization => "DEFAULT_DENY";
    public string Prerequisites => "FAKE_FIXTURE_ID_MATCH_ONLY; INSTALLATION_SIGNATURE_ENDPOINT_TRUST_NOT_ESTABLISHED";
    public string Origin => "UNVERIFIED: https://simulation.invalid";
    public string Channel => "IN_PROCESS_FAKE_ONLY";
    public bool Registered { get; private set; }
    internal void Reset(SimulationBinding? binding, bool eligible)
    {
        _binding = binding; Registered = eligible;
        State = eligible ? "ReadyForSimulation" : "Unavailable";
    }
    internal bool Apply(string action, SimulationBinding binding, string fixtureId)
    {
        if (_binding is null || binding != _binding || fixtureId != FixtureId || !Registered) return false;
        var next = (State, action) switch {
            ("ReadyForSimulation", "UNAVAILABLE") => "Unavailable",
            ("ReadyForSimulation", "START") => "Pending",
            ("Pending", "DELIVER") when binding.MethodId == HybridMethods.Remote => "AwaitingResponse",
            ("Pending", "COMPLETE") when binding.MethodId == HybridMethods.Protected => "SimulatedComplete",
            ("AwaitingResponse", "COMPLETE") => "SimulatedComplete",
            ("Pending" or "AwaitingResponse", "REJECT") => "Rejected",
            ("ReadyForSimulation" or "Pending" or "AwaitingResponse" or "Unknown", "CANCEL") => "Cancelled",
            ("Pending" or "AwaitingResponse", "FAIL") => "Failed",
            ("AwaitingResponse", "UNKNOWN") => "Unknown",
            ("Unknown", "RECOVER") => "Cancelled", // Local abandonment only; never resend or infer success.
            ("ReadyForSimulation" or "Pending" or "AwaitingResponse" or "Unknown", "REVOKE") => "Cancelled",
            _ => null
        };
        if (next is null) return false;
        if (action is "REVOKE" or "UNAVAILABLE") Registered = false;
        State = next; return true;
    }
    internal void End(string state)
    {
        _binding = null; Registered = false;
        State = state;
    }
}
