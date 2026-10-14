namespace WebAuthn.WindowsLab;

/// <summary>
/// Validates synthetic inventory snapshots only. This is not an authenticator
/// inventory API or proof of real credential deletion.
/// </summary>
internal static class SyntheticInventory
{
    private const int MaximumEntries = 128;

    public static HashSet<string> Validate(IReadOnlyCollection<string>? inventory)
    {
        if (inventory is null || inventory.Count > MaximumEntries)
            throw new InvalidDataException("fake_inventory_missing_or_oversized");

        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var identity in inventory)
        {
            if (!IsCanonicalCredentialId(identity) || !identities.Add(identity!))
                throw new InvalidDataException("fake_inventory_invalid_or_duplicate_id");
        }
        return identities;
    }

    private static bool IsCanonicalCredentialId(string? id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 683 ||
            id.Any(character => !((character >= 'A' && character <= 'Z') ||
                (character >= 'a' && character <= 'z') ||
                (character >= '0' && character <= '9') ||
                character is '-' or '_')))
            return false;

        try
        {
            var standard = id.Replace('-', '+').Replace('_', '/');
            var bytes = Convert.FromBase64String(standard +
                new string('=', (4 - standard.Length % 4) % 4));
            if (bytes.Length is < 16 or > 512) return false;
            return StringComparer.Ordinal.Equals(id,
                Convert.ToBase64String(bytes).TrimEnd('=')
                    .Replace('+', '-').Replace('/', '_'));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
