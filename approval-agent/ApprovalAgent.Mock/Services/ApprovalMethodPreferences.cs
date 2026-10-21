using System.IO;
using System.Text;
using System.Text.Json;
using ApprovalAgent.Mock.Models;

namespace ApprovalAgent.Mock.Services;

public sealed record MethodPreference(string? PreferredMethod, string Status)
{ public bool NeedsOnboarding => PreferredMethod is null; }

// Non-secret UX data only. No review/context, policy, identities, permissions or decisions.
public sealed class ApprovalMethodPreferences(string path)
{
    public const int MaximumBytes = 1024;
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ApprovalAgent.Mock", "approval-method.json");
    private void CheckLocation()
    {
        if (!Path.IsPathFullyQualified(path) || !path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("\\",StringComparison.Ordinal) || path.Any(char.IsControl) ||
            path.Split(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar).Any(part => part is "." or "..") ||
            (OperatingSystem.IsWindows() && (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2..].Contains(':') ||
                new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed)))
            throw new IOException("PREFERENCE_LOCATION_INVALID");
        for (var dir = new FileInfo(path).Directory; dir is not null; dir = dir.Parent)
            if (Directory.Exists(dir.FullName) && (dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("PREFERENCE_LOCATION_INVALID");
        if (File.Exists(path) && (File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("PREFERENCE_LOCATION_INVALID");
    }
    public MethodPreference Read()
    {
        try {
            CheckLocation();
            if (!File.Exists(path)) return new(null, "PREFERENCE_NOT_SET");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaximumBytes) return new(null, "PREFERENCE_INVALID");
            var bytes = new byte[MaximumBytes + 1]; var count = 0;
            while (count < bytes.Length) { var n = stream.Read(bytes, count, bytes.Length - count); if (n == 0) break; count += n; }
            if (count > MaximumBytes) return new(null, "PREFERENCE_INVALID");
            using var doc = ReviewJson.Parse(bytes[..count]); var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new(null, "PREFERENCE_INVALID");
            var names = root.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
            if (!names.SequenceEqual(new[] { "preferredMethod", "schemaVersion" })) return new(null, "PREFERENCE_INVALID");
            if (root.GetProperty("schemaVersion").GetRawText() != "1") return new(null, "PREFERENCE_VERSION_UNSUPPORTED");
            var id = root.GetProperty("preferredMethod");
            if (id.ValueKind != JsonValueKind.String || HybridMethods.Find(id.GetString()) is null) return new(null, "PREFERENCE_INVALID");
            return new(id.GetString(), "PREFERENCE_LOADED");
        } catch { return new(null, "PREFERENCE_INVALID"); }
    }
    public string Save(string id)
    {
        if (HybridMethods.Find(id) is null) return "PREFERENCE_INVALID";
        string? temporary = null;
        try {
            CheckLocation();
            var full = Path.GetFullPath(path); var directory = Path.GetDirectoryName(full)!;
            Directory.CreateDirectory(directory);
            temporary = Path.Combine(directory, ".approval-method-" + Guid.NewGuid().ToString("N") + ".tmp");
            var bytes = Encoding.UTF8.GetBytes("{\"preferredMethod\":\"" + id + "\",\"schemaVersion\":1}\n");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes); stream.Flush(true); }
            CheckLocation();
            File.Move(temporary, full, true); return "PREFERENCE_SAVED";
        } catch { return "PREFERENCE_SAVE_FAILED"; }
        finally { if (temporary is not null) try { File.Delete(temporary); } catch { /* No raw diagnostics. */ } }
    }
    public string Reset()
    { try { CheckLocation(); File.Delete(path); return "PREFERENCE_RESET"; } catch { return "PREFERENCE_SAVE_FAILED"; } }
}
