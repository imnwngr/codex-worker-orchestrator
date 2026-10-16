using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApprovalAgent.Mock.Services;

public sealed class ReviewInputException(string category) : Exception(category)
{ public string Category { get; } = category; }

// Port of approval-core.canonicalJson for this contract's JSON values and safe integer numbers.
// One algorithm: ordinal UTF-16 keys + ECMAScript JSON.stringify string escaping, UTF-8, SHA-256.
internal static class ReviewJson
{
    internal const int MaximumBytes = 262144;
    internal static void Fail(string category) => throw new ReviewInputException(category);
    internal static JsonDocument Parse(byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) Fail("REVIEW_FILE_OVERSIZED");
        string text;
        try { text = new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { throw new ReviewInputException("REVIEW_UTF8_INVALID"); }
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 16 }); }
        catch (JsonException) { throw new ReviewInputException("REVIEW_JSON_INVALID"); }
        try { Inspect(doc.RootElement); return doc; }
        catch { doc.Dispose(); throw; }
    }
    private static void Unicode(string value)
    {
        for (var i = 0; i < value.Length; i++)
            if (char.IsHighSurrogate(value[i])) {
                if (++i >= value.Length || !char.IsLowSurrogate(value[i])) Fail("REVIEW_UNICODE_INVALID");
            } else if (char.IsLowSurrogate(value[i])) Fail("REVIEW_UNICODE_INVALID");
    }
    private static void Inspect(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Object) {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in e.EnumerateObject()) {
                Unicode(p.Name);
                if (!names.Add(p.Name)) Fail("REVIEW_DUPLICATE_PROPERTY");
                Inspect(p.Value);
            }
        } else if (e.ValueKind == JsonValueKind.Array) foreach (var child in e.EnumerateArray()) Inspect(child);
        else if (e.ValueKind == JsonValueKind.String) Unicode(e.GetString()!);
        else if (e.ValueKind == JsonValueKind.Number && (!e.TryGetInt64(out var n) || Math.Abs((decimal)n) > 9007199254740991m)) Fail("REVIEW_NUMBER_INVALID");
    }
    internal static string Canonical(JsonElement value, string? omitRootProperty = null)
    {
        var text = new StringBuilder();
        Write(value, text, omitRootProperty); return text.ToString();
    }
    private static void Write(JsonElement value, StringBuilder text, string? omit = null)
    {
        switch (value.ValueKind) {
        case JsonValueKind.Object:
            text.Append('{'); var first = true;
            foreach (var p in value.EnumerateObject().Where(p => p.Name != omit).OrderBy(p => p.Name, StringComparer.Ordinal)) {
                if (!first) text.Append(','); first = false;
                Quote(p.Name, text); text.Append(':'); Write(p.Value, text);
            }
            text.Append('}'); break;
        case JsonValueKind.Array:
            text.Append('['); var index = 0;
            foreach (var child in value.EnumerateArray()) { if (index++ > 0) text.Append(','); Write(child, text); }
            text.Append(']'); break;
        case JsonValueKind.String: Quote(value.GetString()!, text); break;
        case JsonValueKind.Number: text.Append(value.GetInt64().ToString(CultureInfo.InvariantCulture)); break;
        case JsonValueKind.True: text.Append("true"); break;
        case JsonValueKind.False: text.Append("false"); break;
        case JsonValueKind.Null: text.Append("null"); break;
        default: Fail("REVIEW_TYPE_INVALID"); break;
        }
    }
    private static void Quote(string value, StringBuilder text)
    {
        Unicode(value); text.Append('"');
        foreach (var c in value) {
            switch (c) {
            case '"': text.Append("\\\""); break; case '\\': text.Append("\\\\"); break;
            case '\b': text.Append("\\b"); break; case '\f': text.Append("\\f"); break;
            case '\n': text.Append("\\n"); break; case '\r': text.Append("\\r"); break; case '\t': text.Append("\\t"); break;
            default: if (c < 32) text.Append("\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture)); else text.Append(c); break;
            }
        }
        text.Append('"');
    }
    internal static string Hash(string value) => Convert.ToHexString(SHA256.HashData(new UTF8Encoding(false, true).GetBytes(value))).ToLowerInvariant();
    internal static JsonElement Element(object value) => JsonSerializer.SerializeToElement(value);
    internal static void Obj(JsonElement e, params string[] keys)
    {
        if (e.ValueKind != JsonValueKind.Object) Fail("REVIEW_TYPE_INVALID");
        if (e.EnumerateObject().Any(p => !keys.Contains(p.Name, StringComparer.Ordinal))) Fail("REVIEW_UNKNOWN_FIELD");
        if (keys.Any(k => !e.TryGetProperty(k, out _))) Fail("REVIEW_REQUIRED_FIELD");
    }
    internal static string Str(JsonElement e, string key, int max = 128)
    {
        var v = e.GetProperty(key);
        if (v.ValueKind != JsonValueKind.String) Fail("REVIEW_TYPE_INVALID");
        var s = v.GetString()!; if (s.Length == 0 || s.Length > max) Fail("REVIEW_STRING_INVALID"); return s;
    }
    internal static long Int(JsonElement e, string key, long min, long max)
    {
        if (e.GetProperty(key).ValueKind != JsonValueKind.Number) Fail("REVIEW_TYPE_INVALID");
        if (!e.GetProperty(key).TryGetInt64(out var n) || n < min || n > max) Fail("REVIEW_NUMBER_INVALID"); return n;
    }
    internal static JsonElement[] Array(JsonElement e, string key, int min, int max)
    {
        var a = e.GetProperty(key);
        if (a.ValueKind != JsonValueKind.Array || a.GetArrayLength() < min || a.GetArrayLength() > max) Fail("REVIEW_COLLECTION_INVALID");
        return a.EnumerateArray().ToArray();
    }
}
