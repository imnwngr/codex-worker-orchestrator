using System.Text;

namespace WebAuthn.OfflineAssurance;

internal static class BoundedInput
{
    internal static string Read(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > StrictJson.MaximumBytes) throw new AssuranceInputException("INPUT_OVERSIZED");
        var bytes = new byte[StrictJson.MaximumBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var n = stream.Read(bytes, count, bytes.Length - count);
            if (n == 0) break;
            count += n;
        }
        if (count > StrictJson.MaximumBytes) throw new AssuranceInputException("INPUT_OVERSIZED");
        return Decode(bytes.AsSpan(0, count));
    }

    internal static string Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > StrictJson.MaximumBytes) throw new AssuranceInputException("INPUT_OVERSIZED");
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { throw new AssuranceInputException("INPUT_UTF8_INVALID"); }
    }
}
