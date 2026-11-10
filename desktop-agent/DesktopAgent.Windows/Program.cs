using System.IO;
using System.Security.Cryptography;
using System.Text;
using DesktopAgent.Core;

namespace DesktopAgent.Windows;

internal static class Program
{
    private static string? ReadFrame()
    {
        var buffer = new StringBuilder();
        while (true) {
            int next = Console.In.Read();
            if (next < 0) return buffer.Length == 0 ? null : throw new AgentException("TRUNCATED_FRAME");
            if (next == 10) return buffer.ToString();
            if (buffer.Length >= Protocol.MaximumFrame) throw new AgentException("FRAME_TOO_LARGE");
            buffer.Append((char)next);
        }
    }
    [STAThread]
    private static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.SequenceEqual(new[] { "--probe" })) {
            var backend = new WindowsBackend(new(false, 0, "Default", [], [], [], Path.GetTempPath(), true), null!);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(backend.Identity(), Protocol.Json));
            return 0;
        }
        if (!args.SequenceEqual(new[] { "--stdio" }) || !Console.IsInputRedirected || !Console.IsOutputRedirected) return 2;
        byte[]? key = null;
        EvidenceStore? evidence = null;
        try {
            var bootstrap = Protocol.Parse<Bootstrap>(Encoding.UTF8.GetBytes(ReadFrame() ?? throw new AgentException("BOOTSTRAP_REQUIRED")));
            key = Convert.FromBase64String(bootstrap.Key);
            if (bootstrap.Version != 1 || key.Length != 32 || bootstrap.Policy.Targets.Length > 8 ||
                bootstrap.Policy.AutomationIds.Length > 128) throw new AgentException("INVALID_BOOTSTRAP");
            string workerId = Guid.NewGuid().ToString("D");
            evidence = new EvidenceStore(bootstrap.Policy.EvidenceRoot, workerId);
            var backend = new WindowsBackend(bootstrap.Policy, evidence);
            var dispatcher = new Dispatcher(bootstrap.Policy, backend, evidence, workerId);
            Write(new { version = 1, workerId, status = "READY", session = backend.Identity() }, key);
            while (ReadFrame() is { } frame) {
                var envelope = Protocol.Parse<Envelope>(Encoding.UTF8.GetBytes(frame));
                var command = Protocol.Open<Command>(envelope, key);
                Write(dispatcher.Run(command, CancellationToken.None), key);
            }
            return 0;
        } catch {
            try {
                var empty = Guid.Empty.ToString("D");
                evidence?.Audit(new(1, empty, empty, empty, "invalid", 100), "DENIED", "CHANNEL_REJECTED", 0);
            } catch { }
            Console.Error.WriteLine("AGENT_CHANNEL_CLOSED"); return 3;
        }
        finally { if (key != null) CryptographicOperations.ZeroMemory(key); }
    }
    private static void Write<T>(T value, byte[] key)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(Protocol.Seal(value, key), Protocol.Json));
        Console.Out.Flush();
    }
}
