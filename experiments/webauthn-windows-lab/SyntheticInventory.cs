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
        if (inventory is null)
            throw new InvalidDataException("fake_inventory_missing_or_oversized");

        // IReadOnlyCollection is an interface contract, not a trusted count.
        // Check the declared value, then independently bound enumeration and
        // require the two counts to agree before accepting the snapshot.
        var declaredCount = inventory.Count;
        if (declaredCount is < 0 or > MaximumEntries)
            throw new InvalidDataException("fake_inventory_missing_or_oversized");

        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var identity in inventory)
        {
            if (identities.Count >= MaximumEntries || identities.Count >= declaredCount)
                throw new InvalidDataException("fake_inventory_count_mismatch_or_oversized");
            if (!IsCanonicalCredentialId(identity) || !identities.Add(identity!))
                throw new InvalidDataException("fake_inventory_invalid_or_duplicate_id");
        }
        if (identities.Count != declaredCount)
            throw new InvalidDataException("fake_inventory_count_mismatch");
        return identities;
    }

    internal static bool IsCanonicalCredentialId(string? id)
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
