using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace WebAuthn.WindowsLab;

internal sealed class BoundedCborReader
{
    public const int MaximumInputBytes = 16384;
    private const int MaximumItems = 256;
    private const int MaximumDepth = 8;
    private const int MaximumContainerItems = 64;

    private readonly byte[] _bytes;
    private int _offset;
    private int _items;

    private BoundedCborReader(ReadOnlySpan<byte> input)
    {
        if (input.Length is < 1 or > MaximumInputBytes)
            throw new InvalidDataException("cbor_input_length");
        _bytes = input.ToArray();
    }

    public static object? ReadSingle(ReadOnlySpan<byte> input)
    {
        var reader = new BoundedCborReader(input);
        var value = reader.ReadValue(0);
        if (reader._offset != reader._bytes.Length)
            throw new InvalidDataException("trailing_cbor_bytes");
        return value;
    }

    private object? ReadValue(int depth)
    {
        if (depth > MaximumDepth) throw new InvalidDataException("cbor_depth_limit");
        if (++_items > MaximumItems) throw new InvalidDataException("cbor_item_limit");
        if (_offset >= _bytes.Length) throw new InvalidDataException("truncated_cbor");

        var initial = _bytes[_offset++];
        var major = initial >> 5;
        var additional = initial & 31;
        if (major == 7)
        {
            return additional switch
            {
                20 => false,
                21 => true,
                22 => null,
                _ => throw new InvalidDataException("unsupported_cbor_simple_value")
            };
        }

        var length = ReadLength(additional);
        switch (major)
        {
            case 0:
                if (length > long.MaxValue)
                    throw new InvalidDataException("cbor_integer_overflow");
                return (long)length;
            case 1:
                if (length > long.MaxValue)
                    throw new InvalidDataException("cbor_integer_overflow");
                return -1 - (long)length;
            case 2:
                return ReadBytes(length);
            case 3:
                try
                {
                    return new UTF8Encoding(false, true).GetString(ReadBytes(length));
                }
                catch (DecoderFallbackException error)
                {
                    throw new InvalidDataException("invalid_cbor_utf8", error);
                }
            case 4:
                if (length > MaximumContainerItems)
                    throw new InvalidDataException("cbor_array_limit");
                var array = new List<object?>(checked((int)length));
                for (var i = 0; i < (int)length; i++)
                    array.Add(ReadValue(depth + 1));
                return array;
            case 5:
                if (length > MaximumContainerItems)
                    throw new InvalidDataException("cbor_map_limit");
                var map = new Dictionary<object, object?>();
                for (var i = 0; i < (int)length; i++)
                {
                    var key = ReadValue(depth + 1);
                    if (key is not (long or string))
                        throw new InvalidDataException("unsupported_cbor_map_key");
                    if (map.ContainsKey(key))
                        throw new InvalidDataException("duplicate_cbor_map_key");
                    map.Add(key, ReadValue(depth + 1));
                }
                return map;
            default:
                throw new InvalidDataException("unsupported_cbor_major_type");
        }
    }

    private ulong ReadLength(int additional)
    {
        if (additional < 24) return (ulong)additional;
        var size = additional switch
        {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => throw new InvalidDataException("indefinite_or_reserved_cbor_length")
        };
        if (_offset + size > _bytes.Length)
            throw new InvalidDataException("truncated_cbor");

        ulong value = 0;
        for (var i = 0; i < size; i++)
            value = (value << 8) | _bytes[_offset++];
        if ((size == 1 && value < 24) ||
            (size == 2 && value <= byte.MaxValue) ||
            (size == 4 && value <= ushort.MaxValue) ||
            (size == 8 && value <= uint.MaxValue))
            throw new InvalidDataException("non_minimal_cbor_integer");
        return value;
    }

    private byte[] ReadBytes(ulong length)
    {
        if (length > MaximumInputBytes || length > (ulong)(_bytes.Length - _offset))
            throw new InvalidDataException("truncated_or_oversized_cbor_string");
        var result = _bytes.AsSpan(_offset, checked((int)length)).ToArray();
        _offset += (int)length;
        return result;
    }
}

internal sealed record ParsedCoseKey(
    int Algorithm,
    string KeyType,
    string Curve,
    string PublicKeySha256);

internal static class CoseKeyParser
{
    public static ParsedCoseKey Parse(ReadOnlySpan<byte> encoded)
    {
        var value = BoundedCborReader.ReadSingle(encoded);
        if (value is not Dictionary<object, object?> map)
            throw new InvalidDataException("cose_key_not_map");

        var keyType = Integer(map, 1);
        var algorithm = Integer(map, 3);
        if (keyType == 2 && algorithm == -7)
            return ParseEs256(map, encoded);
        if (keyType == 3 && algorithm == -257)
            return ParseRs256(map, encoded);
        throw new InvalidDataException("unsupported_cose_algorithm_or_key_type");
    }

    private static ParsedCoseKey ParseEs256(
        Dictionary<object, object?> map, ReadOnlySpan<byte> encoded)
    {
        ExactKeys(map, 1, 3, -1, -2, -3);
        if (Integer(map, -1) != 1 ||
            map.GetValueOrDefault(-2L) is not byte[] x || x.Length != 32 ||
            map.GetValueOrDefault(-3L) is not byte[] y || y.Length != 32)
            throw new InvalidDataException("invalid_es256_curve_or_coordinates");

        try
        {
            using var key = ECDsa.Create();
            key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
        }
        catch (CryptographicException error)
        {
            throw new InvalidDataException("invalid_es256_point", error);
        }

        return new ParsedCoseKey(-7, "EC2", "P-256", Fingerprint(encoded));
    }

    private static ParsedCoseKey ParseRs256(
        Dictionary<object, object?> map, ReadOnlySpan<byte> encoded)
    {
        ExactKeys(map, 1, 3, -1, -2);
        if (map.GetValueOrDefault(-1L) is not byte[] modulus ||
            map.GetValueOrDefault(-2L) is not byte[] exponent ||
            modulus.Length is < 256 or > 512 || modulus[0] == 0 ||
            exponent.Length is < 1 or > 4 || exponent[0] == 0)
            throw new InvalidDataException("invalid_rs256_key_size");

        var bits = modulus.Length * 8;
        var first = modulus[0];
        while ((first & 0x80) == 0)
        {
            bits--;
            first <<= 1;
        }
        var exponentValue = new BigInteger(exponent, isUnsigned: true, isBigEndian: true);
        if (bits is < 2048 or > 4096 ||
            exponentValue < 3 || exponentValue.IsEven)
            throw new InvalidDataException("invalid_rs256_parameters");

        return new ParsedCoseKey(-257, "RSA", "", Fingerprint(encoded));
    }

    private static long Integer(Dictionary<object, object?> map, long key)
    {
        if (map.GetValueOrDefault(key) is not long value)
            throw new InvalidDataException("cose_integer_required");
        return value;
    }

    private static void ExactKeys(
        Dictionary<object, object?> map, params long[] expected)
    {
        if (map.Count != expected.Length ||
            expected.Any(key => !map.ContainsKey(key)))
            throw new InvalidDataException("unexpected_cose_key_fields");
    }

    private static string Fingerprint(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}

internal static class SyntheticCbor
{
    public static byte[] EncodeMap(params (long Key, object Value)[] items)
    {
        var output = new List<byte>();
        WriteHead(output, 5, (ulong)items.Length);
        foreach (var (key, value) in items)
        {
            WriteInteger(output, key);
            WriteValue(output, value);
        }
        return output.ToArray();
    }

    public static byte[] Es256Key()
    {
        var x = Convert.FromHexString(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        var y = Convert.FromHexString(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        return EncodeMap((1, 2), (3, -7), (-1, 1), (-2, x), (-3, y));
    }

    public static byte[] Rs256Key()
    {
        var modulus = Enumerable.Repeat((byte)0x80, 256).ToArray();
        return EncodeMap((1, 3), (3, -257), (-1, modulus),
            (-2, new byte[] { 1, 0, 1 }));
    }

    private static void WriteValue(List<byte> output, object value)
    {
        switch (value)
        {
            case byte[] bytes:
                WriteHead(output, 2, (ulong)bytes.Length);
                output.AddRange(bytes);
                break;
            case int number:
                WriteInteger(output, number);
                break;
            case long longNumber:
                WriteInteger(output, longNumber);
                break;
            case string text:
                var encoded = Encoding.UTF8.GetBytes(text);
                WriteHead(output, 3, (ulong)encoded.Length);
                output.AddRange(encoded);
                break;
            default:
                throw new ArgumentException("Unsupported synthetic CBOR value.");
        }
    }

    private static void WriteInteger(List<byte> output, long value)
    {
        if (value >= 0) WriteHead(output, 0, (ulong)value);
        else WriteHead(output, 1, (ulong)(-1 - value));
    }

    private static void WriteHead(List<byte> output, int major, ulong value)
    {
        if (value < 24)
        {
            output.Add((byte)((major << 5) | (int)value));
        }
        else if (value <= byte.MaxValue)
        {
            output.Add((byte)((major << 5) | 24));
            output.Add((byte)value);
        }
        else if (value <= ushort.MaxValue)
        {
            output.Add((byte)((major << 5) | 25));
            output.Add((byte)(value >> 8));
            output.Add((byte)value);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }
}
