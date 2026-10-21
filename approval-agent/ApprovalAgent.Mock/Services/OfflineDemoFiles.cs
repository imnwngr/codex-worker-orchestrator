using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
namespace ApprovalAgent.Mock.Services;
public static class OfflineDemoFiles
{
    public static byte[] Create(long now, string marker)
    {
        if (now <= 0 || now > 253402300499999 || marker.Length != 32 || !marker.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("DEMO_INPUT_INVALID");
        using var resource = typeof(OfflineDemoFiles).Assembly.GetManifestResourceStream("OfflineDemo.review.json")
            ?? throw new InvalidDataException("DEMO_TEMPLATE_MISSING");
        using var reader = new StreamReader(resource, new UTF8Encoding(false, true));
        var root = JsonNode.Parse(reader.ReadToEnd())!;
        var context = root["context"]!;
        context["createdAt"] = now; context["expiresAt"] = checked(now + 300000);
        context["requestId"] = "demo-" + marker; context["sessionId"] = "session-" + marker;
        using var doc = JsonDocument.Parse(context.ToJsonString());
        context["contextSha256"] = ReviewJson.Hash(ReviewJson.Canonical(doc.RootElement, "contextSha256"));
        using var result = JsonDocument.Parse(root.ToJsonString());
        var bytes = Encoding.UTF8.GetBytes(ReviewJson.Canonical(result.RootElement) + "\n");
        _ = OfflineReviewValidator.Validate(bytes, now);
        return bytes;
    }
    public static void WriteNew(string path, long now)
    {
        BrowserPreviewFiles.CheckPath(path, ".review.json", false);
        var bytes = Create(now, Guid.NewGuid().ToString("N"));
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(bytes); output.Flush(true);
    }
}
