using System.Text;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.ViewModels;

namespace ApprovalAgent.Mock.Services;

// Offline, in-process design contract: validated shape is NEVER authenticated consent.
public static class OfflineTrustProtocol
{
    public const string Scheme = "offline-trust/v1";
    private static readonly string[] Keys = ["version", "kind", "methodId", "requestId", "sessionId", "contextSha256", "batchSha256", "instanceId", "generation", "expiresAt", "challenge", "nonce", "requesterClaim", "actorClaim", "accountClaim", "deviceClaim", "originClaim", "peerRole", "trustStatus", "outcome", "consentStatement", "endpointTrust", "channelTrust", "authorized", "productionAuthorization"];
    private static readonly string[] Kinds = ["CONSENT_REQUEST", "CONSENT_RESPONSE", "HELLO", "REGISTRATION", "REVOCATION"];
    private static readonly string[] Outcomes = ["NONE", "GRANT", "DENY", "CANCEL", "UNKNOWN"];
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public static string Build(OfflineReviewContext context, SimulationBinding token, string kind, string outcome = "NONE", string challenge = "fake-challenge-v1", string nonce = "fake-nonce-v1")
    {
        var role = token.MethodId switch { HybridMethods.Local => "FAKE_LOCAL_UI", HybridMethods.Protected => "FAKE_PROTECTED_COMPONENT", HybridMethods.Remote => "FAKE_REMOTE_DEVICE", _ => "INVALID" };
        var data = new Dictionary<string, object> {
            ["version"] = 1, ["kind"] = kind, ["methodId"] = token.MethodId, ["requestId"] = context.RequestId,
            ["sessionId"] = context.SessionId, ["contextSha256"] = context.ContextSha256, ["batchSha256"] = context.BatchSha256,
            ["instanceId"] = token.InstanceId, ["generation"] = token.Generation, ["expiresAt"] = context.ExpiresAt,
            ["challenge"] = challenge, ["nonce"] = nonce, ["requesterClaim"] = "fake-requester", ["actorClaim"] = "fake-approver",
            ["accountClaim"] = "fake-account", ["deviceClaim"] = "fake-device", ["originClaim"] = "UNVERIFIED: https://simulation.invalid",
            ["peerRole"] = role, ["trustStatus"] = "UNVERIFIED_SIMULATION_ONLY", ["outcome"] = outcome,
            ["consentStatement"] = $"SIMULATION ONLY: action context {context.ContextSha256} expires at {context.ExpiresAt}; no production authorization.",
            ["endpointTrust"] = "UNESTABLISHED", ["channelTrust"] = "FAKE_IN_PROCESS",
            ["authorized"] = false, ["productionAuthorization"] = "DEFAULT_DENY"
        };
        using var raw = JsonDocument.Parse(JsonSerializer.Serialize(data, JsonOptions));
        var output = ReviewJson.Canonical(raw.RootElement);
        if (!TryParse(output, out var validated)) throw new InvalidOperationException("OFFLINE_PROTOCOL_INVALID");
        using var validation = validated;
        return output;
    }
    private static bool IsId(JsonElement e) => e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 and <= 96 } value && value.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or ':' or '-');
    private static bool IsHex(JsonElement e) => e.ValueKind == JsonValueKind.String && e.GetString() is { Length: 64 } value && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    public static bool TryParse(string? json, out JsonDocument? document)
    {
        document = null;
        if (json is null) return false;
        int bytes;
        try { bytes = new UTF8Encoding(false, true).GetByteCount(json); } catch (EncoderFallbackException) { return false; }
        if (bytes is < 1 or > 4096) return false;
        try {
            using var parsed = ReviewJson.Parse(new UTF8Encoding(false, true).GetBytes(json));
            if (ReviewJson.Canonical(parsed.RootElement) != json) return false;
            var item = parsed.RootElement;
            if (item.ValueKind != JsonValueKind.Object) return false;
            var props = item.EnumerateObject().ToArray();
            if (props.Length != Keys.Length || props.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != Keys.Length || props.Any(p => !Keys.Contains(p.Name, StringComparer.Ordinal))) return false;
            JsonElement Get(string key) => item.GetProperty(key);
            string S(string key) => Get(key).GetString() ?? "";
            if (Get("version").ValueKind != JsonValueKind.Number || !Get("version").TryGetInt32(out var version) || version != 1 ||
                !Kinds.Contains(S("kind")) || !HybridMethods.All.Any(m => m.Id == S("methodId")) ||
                !Outcomes.Contains(S("outcome")) ||
                (S("kind") == "CONSENT_RESPONSE" ? S("outcome") == "NONE" : S("outcome") != "NONE") ||
                !new[] { "requestId", "sessionId", "instanceId", "challenge", "nonce", "requesterClaim", "actorClaim", "accountClaim", "deviceClaim" }.All(k => IsId(Get(k))) ||
                !IsHex(Get("contextSha256")) || !IsHex(Get("batchSha256")) ||
                Get("generation").ValueKind != JsonValueKind.Number || !Get("generation").TryGetInt64(out var generation) || generation <= 0 || generation > 9_007_199_254_740_991L ||
                Get("expiresAt").ValueKind != JsonValueKind.Number || !Get("expiresAt").TryGetInt64(out var expiry) || expiry <= 0 || expiry > 9_007_199_254_740_991L ||
                S("originClaim") != "UNVERIFIED: https://simulation.invalid" ||
                S("peerRole") != (S("methodId") switch { HybridMethods.Local => "FAKE_LOCAL_UI", HybridMethods.Protected => "FAKE_PROTECTED_COMPONENT", HybridMethods.Remote => "FAKE_REMOTE_DEVICE", _ => "INVALID" }) ||
                S("trustStatus") != "UNVERIFIED_SIMULATION_ONLY" ||
                S("consentStatement") != $"SIMULATION ONLY: action context {S("contextSha256")} expires at {expiry}; no production authorization." ||
                S("endpointTrust") != "UNESTABLISHED" || S("channelTrust") != "FAKE_IN_PROCESS" || Get("authorized").ValueKind != JsonValueKind.False ||
                S("productionAuthorization") != "DEFAULT_DENY") return false;
            document = JsonDocument.Parse(json); return true;
        } catch (JsonException) { return false; } catch (InvalidOperationException) { return false; } catch (ReviewInputException) { return false; }
    }

}

public sealed class OfflineTrustSession
{
    private readonly OfflineReviewViewModel _model;
    private readonly OfflineReviewContext _context;
    private readonly SimulationBinding _token;
    private readonly Func<long> _clock;
    private readonly string _challenge, _nonce;
    private long _last;
    private bool _seen;
    private readonly object _gate = new();
    public string State { get; private set; } = "Ready";
    public bool Registered { get; private set; }
    public bool Authorized => false;
    public string ProductionAuthorization => "DEFAULT_DENY";
    public OfflineTrustSession(OfflineReviewViewModel model, Func<long> clock, string challenge = "fake-challenge-v1", string nonce = "fake-nonce-v1")
    {
        _model = model; _context = model.Context ?? throw new InvalidOperationException("OFFLINE_BINDING_INVALID");
        _token = model.SimulationToken ?? throw new InvalidOperationException("OFFLINE_BINDING_INVALID");
        _clock = clock; _last = _context.CreatedAt; _challenge = challenge; _nonce = nonce;
        if (!model.CanDecide || !OfflineTrustProtocol.TryParse(Fixture("CONSENT_REQUEST"), out var checkedDoc)) throw new InvalidOperationException("OFFLINE_BINDING_INVALID");
        checkedDoc?.Dispose();
    }
    public string Fixture(string kind, string outcome = "NONE") => OfflineTrustProtocol.Build(_context, _token, kind, outcome, _challenge, _nonce);
    private bool Active()
    {
        if (State is "Expired" or "ApprovedMock" or "Rejected" or "Cancelled" or "Abandoned") return false;
        long now;
        try { now = _clock(); } catch { State = "Expired"; return false; }
        if (now < _last || now < _context.CreatedAt || now >= _context.ExpiresAt) { State = "Expired"; return false; }
        _last = now;
        _model.RefreshExpiry();
        if (_model.State != OfflineMockState.Pending || !_model.CanDecide || _model.SimulationToken != _token) {
            State = _model.State == OfflineMockState.Expired ? "Expired" : "Abandoned"; return false;
        }
        return true;
    }
    private bool Check(string json, string kind)
    {
        if (!OfflineTrustProtocol.TryParse(json, out var doc)) return false;
        using (doc) {
            var root = doc!.RootElement;
            if (root.GetProperty("kind").GetString() != kind) return false;
            var expected = Fixture(kind, root.GetProperty("outcome").GetString()!);
            return json == expected;
        }
    }
    public bool Negotiate(string json) { lock (_gate) { if (!Active() || State != "Ready" || _token.MethodId != HybridMethods.Protected || !Check(json, "HELLO")) return false; State = "Negotiated"; return true; } }
    public bool Register(string json) { lock (_gate) { if (!Active() || State != "Ready" || _token.MethodId != HybridMethods.Remote || !Check(json, "REGISTRATION")) return false; Registered = true; State = "Registered"; return true; } }
    public bool Revoke(string json) { lock (_gate) { if (!Active() || _token.MethodId != HybridMethods.Remote || !Registered || !Check(json, "REVOCATION")) return false; Registered = false; State = "Unknown"; return true; } }
    public bool Start(string json)
    {
        lock (_gate) {
        if (!Active() || !Check(json, "CONSENT_REQUEST")) return false;
        if (State != (_token.MethodId switch { HybridMethods.Protected => "Negotiated", HybridMethods.Remote => "Registered", _ => "Ready" })) return false;
        if (_token.MethodId != HybridMethods.Local && !_model.Simulate("START", _token, _model.Simulation.FixtureId)) return false;
        if (_token.MethodId == HybridMethods.Remote && !_model.Simulate("DELIVER", _token, _model.Simulation.FixtureId)) return false;
        State = "Pending"; return true;
        }
    }
    public bool Receive(string json)
    {
        lock (_gate) {
        if (!Active() || State != "Pending" || _seen || !Check(json, "CONSENT_RESPONSE")) return false;
        _seen = true;
        using var doc = JsonDocument.Parse(json);
        var outcome = doc.RootElement.GetProperty("outcome").GetString();
        if (outcome == "UNKNOWN") { State = "Unknown"; return true; }
        var action = outcome switch { "GRANT" => OfflineMockState.ApprovedMock, "DENY" => OfflineMockState.Rejected, _ => OfflineMockState.Cancelled };
        bool ok = _token.MethodId == HybridMethods.Local ? _model.Decide(_token.RequestId, _token.SessionId, _token.ContextSha256, _token.Generation, action)
            : _model.Simulate(outcome switch { "GRANT" => "COMPLETE", "DENY" => "REJECT", _ => "CANCEL" }, _token, _model.Simulation.FixtureId);
        State = ok ? action.ToString() : _model.State == OfflineMockState.Expired ? "Expired" : "Abandoned";
        return ok;
        }
    }
    public bool Crash() { lock (_gate) { if (!Active() || State != "Pending") return false; State = "Unknown"; return true; } }
    public bool Recover()
    {
        lock (_gate) {
        if (!Active() || State != "Unknown") return false;
        var ok = _model.Decide(_token.RequestId, _token.SessionId, _token.ContextSha256, _token.Generation, OfflineMockState.Cancelled);
        State = ok ? "Abandoned" : _model.State == OfflineMockState.Expired ? "Expired" : "Abandoned";
        return ok;
        }
    }
}


/// <summary>Bounded, in-process fake channel. It proves framing/ordering only, never endpoint identity.</summary>
public sealed class OfflineTrustFakeTransport
{
    private const int Capacity = 4;
    private readonly Queue<string> _frames = new();
    private readonly object _gate = new();
    public bool Online { get; private set; } = true;
    public int Pending { get { lock (_gate) return _frames.Count; } }
    public void Disconnect() { lock (_gate) Online = false; }
    public void Reconnect() { lock (_gate) Online = true; }
    public void Clear() { lock (_gate) _frames.Clear(); }
    public bool Send(string? frame)
    {
        lock (_gate) {
            if (!Online || _frames.Count == Capacity || !OfflineTrustProtocol.TryParse(frame, out var parsed)) return false;
            using (parsed) {
                if (parsed!.RootElement.GetProperty("kind").GetString() != "CONSENT_RESPONSE") return false;
                _frames.Enqueue(frame!);
                return true;
            }
        }
    }
    public bool Deliver(OfflineTrustSession session)
    {
        lock (_gate) {
            if (!Online || _frames.Count == 0) return false;
            // Always consume the frame, even if the canonical review rejects it.
            return session.Receive(_frames.Dequeue());
        }
    }
}
