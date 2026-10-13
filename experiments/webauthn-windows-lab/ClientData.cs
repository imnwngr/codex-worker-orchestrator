using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebAuthn.WindowsLab;

internal sealed record ParsedClientData(
    byte[] OriginalBytes,
    string Type,
    string Challenge,
    string Origin);

internal static class StrictClientData
{
    public const string TestOrigin = "https://approval.lab.example.test";

    public static ParsedClientData Parse(
        ReadOnlySpan<byte> input,
        string expectedType,
        string expectedChallenge,
        string expectedOrigin)
    {
        if (input.Length is < 2 or > 8192)
            throw new InvalidDataException("client_data_length");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? type = null;
        string? challenge = null;
        string? origin = null;
        var propertyCount = 0;

        try
        {
            var reader = new Utf8JsonReader(input, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 2
            });

            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                throw new InvalidDataException("client_data_object_required");

            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName)
                    throw new InvalidDataException("client_data_property_required");
                var name = reader.GetString()!;
                if (!seen.Add(name))
                    throw new InvalidDataException("duplicate_client_data_property");
                if (!reader.Read())
                    throw new InvalidDataException("truncated_client_data");
                propertyCount++;

                switch (name)
                {
                    case "type":
                        type = ReadString(reader, "type");
                        break;
                    case "challenge":
                        challenge = ReadString(reader, "challenge");
                        break;
                    case "origin":
                        origin = ReadString(reader, "origin");
                        break;
                    case "crossOrigin":
                        if (reader.TokenType != JsonTokenType.False)
                            throw new InvalidDataException("cross_origin_rejected");
                        break;
                    default:
                        throw new InvalidDataException("unknown_client_data_property");
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject || reader.Read())
                throw new InvalidDataException("invalid_client_data_json");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("invalid_client_data_json", error);
        }

        if (type is null || challenge is null || origin is null ||
            propertyCount is < 3 or > 4)
            throw new InvalidDataException("client_data_required_property_missing");
        if (!StringComparer.Ordinal.Equals(type, expectedType) ||
            !StringComparer.Ordinal.Equals(challenge, expectedChallenge) ||
            !StringComparer.Ordinal.Equals(origin, expectedOrigin))
            throw new InvalidDataException("client_data_binding_mismatch");

        // Do not parse and reserialize these bytes for any later check.
        return new ParsedClientData(input.ToArray(), type, challenge, origin);
    }

    private static string ReadString(Utf8JsonReader reader, string name)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new InvalidDataException($"client_data_{name}_must_be_string");
        return reader.GetString()!;
    }
}

internal sealed record TaskByteBinding(
    string DisplayedEffectiveText,
    byte[] EffectiveUtf8Bytes,
    string Sha256);

internal static class TaskByteBindingFactory
{
    public static TaskByteBinding Create(string rawTask)
    {
        ArgumentNullException.ThrowIfNull(rawTask);
        var effective = EcmaScriptTrim(rawTask);
        if (effective.Length == 0)
            throw new InvalidDataException("empty_effective_task");
        var bytes = Encoding.UTF8.GetBytes(effective);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return new TaskByteBinding(effective, bytes, hash);
    }

    // Mirrors ECMAScript String.prototype.trim's boundary whitespace set.
    // This is test code and does not change Broker normalization.
    private static string EcmaScriptTrim(string value)
    {
        var start = 0;
        var end = value.Length;
        while (start < end && IsEcmaWhitespace(value[start])) start++;
        while (end > start && IsEcmaWhitespace(value[end - 1])) end--;
        return value[start..end];
    }

    private static bool IsEcmaWhitespace(char value) =>
        value is '\u0009' or '\u000A' or '\u000B' or '\u000C' or '\u000D' or
            '\u0020' or '\u00A0' or '\u1680' or '\u2028' or '\u2029' or
            '\u202F' or '\u205F' or '\u3000' or '\uFEFF' ||
        value is >= '\u2000' and <= '\u200A';
}
