using System.Diagnostics;
using System.Text;

namespace DesktopAgent.Core;

public interface IDesktopBackend
{
    SessionIdentity Identity();
    ActionData Execute(Command command, CancellationToken cancellation);
}

public sealed class EvidenceStore
{
    public string Root { get; }
    private readonly object sync = new();
    private readonly string worker;
    private string previous = new('0', 64);
    public EvidenceStore(string root, string workerId)
    {
        Root = SafeRoot(root);
        worker = workerId;
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Path.Combine(Root, "claims"));
    }
    public static string SafeRoot(string root)
    {
        if (!Path.IsPathFullyQualified(root) || root.StartsWith(@"\\") ||
            root.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(p => p is "." or "..") ||
            root.Skip(2).Contains(':')) throw new AgentException("EVIDENCE_PATH_DENIED");
        var full = Path.GetFullPath(root);
        for (var dir = new DirectoryInfo(full); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new AgentException("REPARSE_DENIED");
        return full;
    }
    public void Claim(Command command)
    {
        SafeRoot(Path.Combine(Root, "claims"));
        try {
            using var file = new FileStream(Path.Combine(Root, "claims", command.Id + ".json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            file.Write(Protocol.Bytes(new { command.Id, command.TaskId, command.CorrelationId,
                command.Action, requestSha256 = Protocol.Hash(Protocol.Bytes(command)), status = "RESERVED" }));
            file.Flush(true);
        } catch (IOException) { throw new AgentException("DUPLICATE_OR_JOURNAL_UNAVAILABLE"); }
    }
    private static string? CleanId(string? id) => Guid.TryParseExact(id, "D", out _) ? id : null;
    public void Audit(Command command, string status, string code, long elapsed, Evidence? observation = null, Evidence? capture = null)
    {
        lock (sync) {
            SafeRoot(Root);
            var record = new { workerId = worker, Id = CleanId(command.Id), TaskId = CleanId(command.TaskId), CorrelationId = CleanId(command.CorrelationId),
                action = Protocol.Actions.Contains(command.Action ?? "") ? command.Action : "INVALID", status, code, elapsedMs = elapsed, retryCount = 0,
                timestamp = DateTimeOffset.UtcNow, previous, observation, capture, production = "DEFAULT_DENY" };
            var body = Protocol.Bytes(record);
            var hash = Protocol.Hash(body);
            var line = Protocol.Bytes(new { payload = Convert.ToBase64String(body), sha256 = hash });
            using var file = new FileStream(Path.Combine(Root, "audit-" + worker + ".ndjson"),
                FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
            file.Write(line); file.WriteByte(10); file.Flush(true); previous = hash;
        }
    }
    public Evidence Save(string id, byte[] bytes, string extension, string method)
    {
        if (!Guid.TryParseExact(id, "D", out _) || extension is not ("png" or "json"))
            throw new AgentException("EVIDENCE_PATH_DENIED");
        SafeRoot(Root);
        string name = id + "." + extension;
        using var file = new FileStream(Path.Combine(Root, name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(bytes); file.Flush(true);
        return new(name, Protocol.Hash(bytes), bytes.Length, method);
    }
}

public sealed class Dispatcher(AgentPolicy policy, IDesktopBackend backend, EvidenceStore store, string workerId)
{
    public Result Run(Command command, CancellationToken cancellation)
    {
        var watch = Stopwatch.StartNew();
        string status = "DENIED", code = "DEFAULT_DENY";
        ActionData? data = null;
        Evidence? observationEvidence = null;
        try {
            Protocol.Validate(command);
            if (!policy.Enabled || !policy.SyntheticOnly || !policy.Actions.Contains(command.Action) ||
                policy.Targets.Length == 0) throw new AgentException("DEFAULT_DENY");
            var identity = backend.Identity();
            if (identity.SessionId != policy.SessionId || policy.Desktop != "Default" ||
                identity.Desktop != policy.Desktop || identity.Station != "WinSta0" || !identity.InputDesktop)
                throw new AgentException("SESSION_OR_DESKTOP_DENIED");
            if (command.Element != null && !policy.AutomationIds.Contains(command.Element))
                throw new AgentException("ELEMENT_DENIED");
            store.Claim(command);
            store.Audit(command, "STARTED", "SCOPE_ALLOWED", 0);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(command.TimeoutMs);
            timeout.Token.ThrowIfCancellationRequested();
            data = backend.Execute(command, timeout.Token);
            timeout.Token.ThrowIfCancellationRequested();
            observationEvidence = store.Save(command.Id, Protocol.Bytes(data), "json", "UIA_OBSERVATION");
            status = "OBSERVED"; code = "OBSERVATION_REQUIRES_VERIFICATION";
        } catch (OperationCanceledException) {
            status = Protocol.IsMutation(command.Action) ? "UNKNOWN" : "CANCELLED";
            code = cancellation.IsCancellationRequested ? "CANCELLED" : "TIMEOUT";
        } catch (AgentException e) {
            code = e.Code;
            status = code is "INPUT_INCOMPLETE" or "UNKNOWN_OUTCOME" ? "UNKNOWN" : code is "STALE_TARGET" or "ELEMENT_UNAVAILABLE" or "SCREENSHOT_FAILED" ? "FAILED" : "DENIED";
        } catch {
            status = Protocol.IsMutation(command.Action) ? "UNKNOWN" : "FAILED"; code = "BACKEND_FAILURE";
        }
        try { store.Audit(command, status, code, watch.ElapsedMilliseconds, observationEvidence, data?.Evidence); }
        catch { status = "UNKNOWN"; code = "AUDIT_UNAVAILABLE"; data = null; }
        return new(1, workerId, command.Id, command.TaskId, command.CorrelationId, status, code,
            watch.ElapsedMilliseconds, 0, data, observationEvidence);
    }
}
