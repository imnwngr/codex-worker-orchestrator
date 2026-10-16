using System.IO;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using ApprovalAgent.Mock.Models;
using static ApprovalAgent.Mock.Services.ReviewJson;

namespace ApprovalAgent.Mock.Services;

public static class OfflineReviewValidator
{
    private sealed record Provider(string Id, string BaseUrl, long Timeout, string[] Models, bool Enabled);
    private static void Equal(string actual, string expected, string category = "REVIEW_BINDING_MISMATCH")
    { if (!StringComparer.Ordinal.Equals(actual, expected)) Fail(category); }
    private static bool Match(string s, string pattern) => Regex.IsMatch(s, "\\A(?:" + pattern + ")\\z", RegexOptions.CultureInvariant);
    private static string Id(JsonElement e, string key) {
        var s = Str(e, key, 64); if (!Match(s, "[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) Fail("REVIEW_ID_INVALID"); return s;
    }
    private static string HashField(JsonElement e, string key) {
        var s = Str(e, key, 64); if (!Match(s, "[a-f0-9]{64}")) Fail("REVIEW_DIGEST_INVALID"); return s;
    }
    private static void False(JsonElement e, string key) { if (e.GetProperty(key).ValueKind != JsonValueKind.False) Fail("REVIEW_AUTHORITY_INVALID"); }
    private static void Version(JsonElement e, string key) { if (Int(e, key, 0, 100) != 1) Fail("REVIEW_SCHEMA_UNSUPPORTED"); }
    private static bool Bool(JsonElement e, string key) {
        var v = e.GetProperty(key); if (v.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) Fail("REVIEW_TYPE_INVALID"); return v.GetBoolean();
    }
    private static string BaseUrl(JsonElement e)
    {
        var s = Str(e, "baseUrl", 2048);
        if (!Match(s, "https://[a-z0-9.-]+(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9._~-]+)*") ||
            !Uri.TryCreate(s, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) { Fail("REVIEW_URL_INVALID"); return ""; }
        var host = uri.Host;
        if (IPAddress.TryParse(host, out _) || host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal) ||
            host.EndsWith(".local", StringComparison.Ordinal) || host.EndsWith(".internal", StringComparison.Ordinal) ||
            !Match(host, "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*")) Fail("REVIEW_URL_INVALID");
        var authority = host + (uri.IsDefaultPort ? "" : ":" + uri.Port.ToString(CultureInfo.InvariantCulture));
        var pathStart = s.IndexOf('/', 8);
        var path = pathStart < 0 ? "" : s[pathStart..];
        if (s != "https://" + authority + path || path.Split('/').Any(p => p is "." or "..")) Fail("REVIEW_URL_INVALID");
        return s;
    }
    private static Provider[] Configuration(JsonElement cfg)
    {
        Obj(cfg, "version", "defaultProvider", "providers"); Version(cfg, "version"); var defaultId = Id(cfg, "defaultProvider");
        var ids = new HashSet<string>(StringComparer.Ordinal); var providers = new List<Provider>();
        foreach (var p in Array(cfg, "providers", 1, 16)) {
            Obj(p, "id", "kind", "enabled", "baseUrl", "timeoutSeconds", "models", "defaultModel", "credentialEnv");
            Equal(Str(p, "kind"), "api", "REVIEW_CONFIG_UNSUPPORTED"); var id = Id(p, "id");
            if (!ids.Add(id)) Fail("REVIEW_CONFIG_INVALID");
            var env = Str(p, "credentialEnv"); if (!Match(env, "[A-Z][A-Z0-9_]{0,127}")) Fail("REVIEW_CONFIG_INVALID");
            var models = Array(p, "models", 1, 32).Select(v => {
                if (v.ValueKind != JsonValueKind.String) Fail("REVIEW_TYPE_INVALID");
                var s = v.GetString()!; if (!Match(s, "[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")) Fail("REVIEW_CONFIG_INVALID"); return s;
            }).ToArray();
            if (models.Distinct(StringComparer.Ordinal).Count() != models.Length || !models.Contains(Str(p, "defaultModel"), StringComparer.Ordinal)) Fail("REVIEW_CONFIG_INVALID");
            providers.Add(new(id, BaseUrl(p), Int(p, "timeoutSeconds", 1, 600), models, Bool(p, "enabled")));
        }
        if (!providers.Any(p => p.Id == defaultId && p.Enabled)) Fail("REVIEW_CONFIG_INVALID");
        return providers.ToArray();
    }

    public static OfflineReviewContext Validate(byte[] bytes, long now)
    {
        try { return ValidateCore(bytes, now); }
        catch (ReviewInputException) { throw; }
        catch { throw new ReviewInputException("REVIEW_INPUT_INVALID"); }
    }
    private static OfflineReviewContext ValidateCore(byte[] bytes, long now)
    {
        using var doc = Parse(bytes); var root = doc.RootElement;
        Obj(root, "reviewFileSchemaVersion", "designation", "producerAuthentication", "context"); Version(root, "reviewFileSchemaVersion");
        Equal(Str(root, "designation"), "SYNTHETIC_DESIGN_ONLY", "REVIEW_AUTHORITY_INVALID");
        Equal(Str(root, "producerAuthentication"), "NONE", "REVIEW_AUTHORITY_INVALID");
        var c = root.GetProperty("context");
        Obj(c, "schemaVersion", "designation", "requestId", "batchId", "sessionId", "createdAt", "expiresAt", "applicationIdentity", "userIdentity", "authorized", "productionAuthorization", "normalization", "orderedTargetIds", "targets", "configurationSnapshot", "configurationFingerprint", "batchSha256", "contextSha256");
        Version(c, "schemaVersion"); Equal(Str(c, "designation"), "SYNTHETIC_DESIGN_ONLY", "REVIEW_AUTHORITY_INVALID");
        Equal(Str(c, "applicationIdentity"), "UNESTABLISHED", "REVIEW_AUTHORITY_INVALID"); Equal(Str(c, "userIdentity"), "UNESTABLISHED", "REVIEW_AUTHORITY_INVALID");
        False(c, "authorized"); Equal(Str(c, "productionAuthorization"), "DEFAULT_DENY", "REVIEW_AUTHORITY_INVALID");
        Equal(Str(c, "normalization"), "ECMASCRIPT_TRIM_UTF8_V1");
        var request = Id(c, "requestId"); var batch = Id(c, "batchId"); var session = Id(c, "sessionId");
        var created = Int(c, "createdAt", 1, 253402300799999); var expires = Int(c, "expiresAt", 1, 253402300799999);
        if (now < created || expires <= created || expires - created > 300000 || now >= expires) Fail("REVIEW_TIME_INVALID");
        var fingerprint = HashField(c, "configurationFingerprint"); var batchHash = HashField(c, "batchSha256"); var contextHash = HashField(c, "contextSha256");
        var cfg = c.GetProperty("configurationSnapshot"); var providers = Configuration(cfg);
        var ordered = Array(c, "orderedTargetIds", 1, 8); var targets = Array(c, "targets", 1, 8);
        if (ordered.Length != targets.Length) Fail("REVIEW_ORDER_INVALID");
        var ids = new HashSet<string>(StringComparer.Ordinal); var result = new List<OfflineReviewTarget>();
        var routing = new List<object>(); var digestTargets = new List<object>();
        for (var i = 0; i < targets.Length; i++) {
            var t = targets[i]; Obj(t, "id", "providerId", "modelId", "destination", "task", "taskSha256", "wire", "parameters", "metadata");
            var id = Id(t, "id"); var provider = Id(t, "providerId"); var model = Str(t, "modelId");
            if (!Match(model, "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) Fail("REVIEW_ID_INVALID");
            if (!ids.Add(id) || ordered[i].ValueKind != JsonValueKind.String || ordered[i].GetString() != id) Fail("REVIEW_ORDER_INVALID");
            var entry = providers.SingleOrDefault(p => p.Id == provider);
            if (entry is null || !entry.Enabled || !entry.Models.Contains(model, StringComparer.Ordinal)) { Fail("REVIEW_TARGET_INVALID"); return null!; }
            var destination = Str(t, "destination", 2048); Equal(destination, entry.BaseUrl + "/chat/completions", "REVIEW_URL_CONFLICT");
            var task = Str(t, "task", 50000); var taskHash = HashField(t, "taskSha256");
            // Do not renormalize displayed text. Check the declared effective normalization independently.
            if (EcmaTrim(task) != task || task.Length == 0) Fail("REVIEW_TASK_INVALID");
            Equal(Hash(task), taskHash, "REVIEW_TASK_HASH_MISMATCH");
            var wire = t.GetProperty("wire"); Obj(wire, "model", "messages"); Equal(Str(wire, "model"), model);
            var messages = Array(wire, "messages", 1, 1); Obj(messages[0], "role", "content");
            Equal(Str(messages[0], "role"), "user"); Equal(Str(messages[0], "content", 50000), task, "REVIEW_WIRE_CONFLICT");
            var parameters = t.GetProperty("parameters"); Obj(parameters, "effectiveTimeoutSeconds", "adapterTimeoutSeconds");
            var timeout = Int(parameters, "effectiveTimeoutSeconds", 1, entry.Timeout); var adapterTimeout = Int(parameters, "adapterTimeoutSeconds", 1, 600);
            if (adapterTimeout != entry.Timeout) Fail("REVIEW_TIMEOUT_CONFLICT");
            var metadata = t.GetProperty("metadata"); Obj(metadata, "requestedEffort", "effortTransmission");
            var effort = Str(metadata, "requestedEffort"); if (!new[] { "low", "medium", "high", "xhigh", "max" }.Contains(effort)) Fail("REVIEW_METADATA_INVALID");
            Equal(Str(metadata, "effortTransmission"), "NOT_SENT_BY_API_ADAPTER");
            routing.Add(new { id, providerId = provider, modelId = model, destination, effort, timeoutSeconds = timeout });
            digestTargets.Add(new { providerId = provider, modelId = model, taskSha256 = taskHash });
            result.Add(new(id, provider, model, destination, task, taskHash, Canonical(wire), timeout, adapterTimeout, effort));
        }
        Equal(Hash(Canonical(Element(new { configuration = cfg, targets = routing }))), fingerprint, "REVIEW_CONFIG_HASH_MISMATCH");
        Equal(Hash("orchestrator-approval-batch-v1\0" + Canonical(Element(digestTargets))), batchHash, "REVIEW_BATCH_HASH_MISMATCH");
        Equal(Hash(Canonical(c, "contextSha256")), contextHash, "REVIEW_CONTEXT_HASH_MISMATCH");
        return new(request, batch, session, contextHash, fingerprint, batchHash, created, expires, result.ToArray());
    }
    private static string EcmaTrim(string value)
    {
        static bool Space(char c) => c is '\u0009' or '\u000a' or '\u000b' or '\u000c' or '\u000d' or '\u0020' or '\u00a0' or '\u1680' or >= '\u2000' and <= '\u200a' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff';
        var a = 0; var b = value.Length; while (a < b && Space(value[a])) a++; while (b > a && Space(value[b - 1])) b--; return value[a..b];
    }
    public static OfflineReviewContext ReadFile(string path, long now)
    {
        try {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Contains("..") ||
                path.Any(char.IsControl) || Regex.IsMatch(Path.GetFileName(path), @"\A(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
                (OperatingSystem.IsWindows() && path[2..].Contains(':')) || !path.EndsWith(".review.json", StringComparison.OrdinalIgnoreCase)) Fail("REVIEW_PATH_INVALID");
            var file = new FileInfo(path);
            if ((file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) Fail("REVIEW_PATH_INVALID");
            for (var dir = file.Directory; dir is not null; dir = dir.Parent)
                if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) Fail("REVIEW_PATH_INVALID");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaximumBytes) Fail("REVIEW_FILE_OVERSIZED");
            var bytes = new byte[MaximumBytes + 1]; var count = 0;
            while (count < bytes.Length) { var n = stream.Read(bytes, count, bytes.Length - count); if (n == 0) break; count += n; }
            if (count > MaximumBytes) Fail("REVIEW_FILE_OVERSIZED");
            return Validate(bytes.AsSpan(0, count).ToArray(), now);
        } catch (ReviewInputException) { throw; }
        catch { throw new ReviewInputException("REVIEW_FILE_READ_FAILED"); }
    }
}
