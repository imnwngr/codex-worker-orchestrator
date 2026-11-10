using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DesktopAgent.Core;

public sealed record SessionIdentity(int SessionId, string Station, string Desktop, bool InputDesktop);
public sealed record TargetPolicy(int ProcessId, string StartTicks, string ExecutableSha256);
public sealed record AgentPolicy(bool Enabled, int SessionId, string Desktop, TargetPolicy[] Targets,
    string[] Actions, string[] AutomationIds, string EvidenceRoot, bool SyntheticOnly);
public sealed record Command(int Version, string Id, string TaskId, string CorrelationId, string Action,
    int TimeoutMs, string? Window = null, string? Element = null, string? Key = null, string? File = null);
public sealed record ElementState(string Id, string Kind, string Name, bool Focused, bool Enabled,
    bool Offscreen, double X, double Y, double Width, double Height);
public sealed record WindowState(string Token, int ProcessId, bool Active, bool Dialog, string Title,
    ElementState[] Elements);
public sealed record Observation(SessionIdentity Session, WindowState[] Windows, string StateSha256);
public sealed record Evidence(string Path, string Sha256, long Bytes, string Method);
public sealed record ActionData(Observation Observation, Evidence? Evidence = null);
public sealed record Result(int Version, string WorkerId, string Id, string TaskId, string CorrelationId,
    string Status, string Code, long DurationMs, int RetryCount, ActionData? Data, Evidence? ObservationEvidence = null,
    bool Authorized = false, string Production = "DEFAULT_DENY");
public sealed record Envelope(string Payload, string Mac);
public sealed record Bootstrap(int Version, string Key, AgentPolicy Policy);
public sealed class AgentException(string code) : Exception(code) { public string Code { get; } = code; }

public static class Protocol
{
    public const int MaximumFrame = 1048576;
    public static readonly JsonSerializerOptions Json = new() {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };
    public static readonly HashSet<string> Actions = ["heartbeat", "observe", "capture", "focus", "key", "click", "setFile"];
    public static readonly HashSet<string> Keys = ["Tab", "ShiftTab", "Enter", "Escape", "Space", "Up", "Down", "Left", "Right", "Home", "End"];
    public static bool IsMutation(string action) => action is "focus" or "key" or "click" or "setFile";
    public static string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    public static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
    public static T Parse<T>(byte[] bytes)
    {
        if (bytes.Length > MaximumFrame) throw new AgentException("FRAME_TOO_LARGE");
        try {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            CheckUnique(doc.RootElement);
            return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new AgentException("MALFORMED");
        } catch (JsonException) { throw new AgentException("MALFORMED"); }
    }
    private static void CheckUnique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object) {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject()) {
                if (!names.Add(property.Name)) throw new AgentException("DUPLICATE_PROPERTY");
                CheckUnique(property.Value);
            }
        } else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) CheckUnique(item);
    }
    public static Envelope Seal<T>(T value, byte[] key)
    {
        var bytes = Bytes(value);
        return new(Convert.ToBase64String(bytes), Convert.ToHexString(HMACSHA256.HashData(key, bytes)).ToLowerInvariant());
    }
    public static T Open<T>(Envelope envelope, byte[] key)
    {
        try {
            var bytes = Convert.FromBase64String(envelope.Payload);
            var mac = Convert.FromHexString(envelope.Mac);
            if (mac.Length != 32 || !CryptographicOperations.FixedTimeEquals(mac, HMACSHA256.HashData(key, bytes)))
                throw new AgentException("AUTHENTICATION_DENIED");
            return Parse<T>(bytes);
        } catch (Exception e) when (e is FormatException or ArgumentNullException) {
            throw new AgentException("AUTHENTICATION_DENIED");
        }
    }
    public static void Validate(Command c)
    {
        if (c.Version != 1 || !Guid.TryParseExact(c.Id, "D", out _) ||
            !Guid.TryParseExact(c.TaskId, "D", out _) || !Guid.TryParseExact(c.CorrelationId, "D", out _) ||
            !Actions.Contains(c.Action ?? "") || c.TimeoutMs is < 100 or > 10000)
            throw new AgentException("INVALID_COMMAND");
        bool target = c.Action is not ("heartbeat" or "observe");
        if (target && (!Guid.TryParseExact(c.Window, "D", out _))) throw new AgentException("TARGET_REQUIRED");
        if (!target && (c.Window != null || c.Element != null || c.Key != null || c.File != null))
            throw new AgentException("UNEXPECTED_ARGUMENT");
        if (c.Action == "key" && !Keys.Contains(c.Key ?? "")) throw new AgentException("KEY_DENIED");
        if (c.Action != "key" && c.Key != null || c.Action != "setFile" && c.File != null)
            throw new AgentException("UNEXPECTED_ARGUMENT");
        if (c.Action is "click" or "focus" or "setFile" && string.IsNullOrEmpty(c.Element))
            throw new AgentException("ELEMENT_REQUIRED");
        if (c.Element?.Length > 128 || c.File?.Length > 240) throw new AgentException("ARGUMENT_TOO_LONG");
        if (c.Action == "capture" && c.Element != null) throw new AgentException("UNEXPECTED_ARGUMENT");
        if (c.Action == "setFile" && (c.File == null ||
            !System.Text.RegularExpressions.Regex.IsMatch(c.File, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,90}\.json$") ||
            System.Text.RegularExpressions.Regex.IsMatch(c.File, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\.", System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
            throw new AgentException("FILE_PATH_DENIED");
    }
}
