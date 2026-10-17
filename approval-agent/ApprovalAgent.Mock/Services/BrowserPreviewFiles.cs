using System.IO;
using System.Text;

namespace ApprovalAgent.Mock.Services;

public static class BrowserPreviewFiles
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal static void CheckPath(string path, string suffix, bool existing, Func<string, DriveType>? driveType = null)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || path.Any(char.IsControl) ||
            !path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Contains("..") ||
            (OperatingSystem.IsWindows() && (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2..].Contains(':'))))
            throw new InvalidDataException("LOCAL_BROWSER_PATH_REQUIRED");
        if (OperatingSystem.IsWindows()) {
            try {
                var root = Path.GetPathRoot(path);
                if (root is null || (driveType ?? (drive => new DriveInfo(drive).DriveType))(root) != DriveType.Fixed)
                    throw new InvalidDataException("LOCAL_BROWSER_PATH_REQUIRED");
            } catch (Exception error) when (error is not InvalidDataException) {
                throw new InvalidDataException("LOCAL_BROWSER_PATH_REQUIRED", error);
            }
        }
        for (var dir = new FileInfo(path).Directory; dir is not null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("LOCAL_BROWSER_PATH_REQUIRED");
        if (existing && (File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new InvalidDataException("LOCAL_BROWSER_PATH_REQUIRED");
    }
    public static void WritePackage(string path, string json)
    {
        CheckPath(path, ".browser.json", false);
        var bytes = Utf8.GetBytes(json);
        if (bytes.Length > ReviewJson.MaximumBytes) throw new InvalidDataException("BROWSER_PACKAGE_OVERSIZED");
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(bytes);
    }
    public static string ReadResponse(string path)
    {
        CheckPath(path, ".response.json", true);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[4097]; var count = 0;
        while (count < bytes.Length) { var n = input.Read(bytes, count, bytes.Length - count); if (n == 0) break; count += n; }
        if (count > 4096) throw new InvalidDataException("BROWSER_RESPONSE_OVERSIZED");
        return Utf8.GetString(bytes, 0, count);
    }
}
