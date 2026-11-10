using DesktopAgent.Core;
using System.Text;
using System.Security.Cryptography;

var root = Path.Combine(Path.GetTempPath(), "phase15-core-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int passed = 0, failed = 0;
void Test(string name, Action test) {
    try { test(); passed++; Console.WriteLine("PASS " + name); }
    catch (Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.GetType().Name + " " + e.Message); }
}
void Assert(bool value) { if (!value) throw new Exception("assertion"); }
void Throws(Action action, string code) {
    try { action(); } catch (AgentException e) { Assert(e.Code == code); return; }
    throw new Exception("expected " + code);
}
Command Cmd(string action = "observe") => new(1, Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
    Guid.NewGuid().ToString("D"), action, 100);
AgentPolicy Policy() => new(true, 7, "Default", [new(123, "456", new string('a', 64))],
    ["observe", "heartbeat", "capture", "focus", "key", "click", "setFile"], ["Button"], root, true);
Result Run(Command c, AgentPolicy? p = null, FakeBackend? b = null, CancellationToken ct = default) {
    var worker = Guid.NewGuid().ToString("D");
    return new Dispatcher(p ?? Policy(), b ?? new(), new EvidenceStore(root, worker), worker).Run(c, ct);
}
Test("strict schema accepts valid command", () => Protocol.Validate(Cmd()));
Test("rejects unknown action", () => Throws(() => Protocol.Validate(Cmd("shell")), "INVALID_COMMAND"));
Test("rejects excess timeout", () => Throws(() => Protocol.Validate(Cmd() with { TimeoutMs = 10001 }), "INVALID_COMMAND"));
Test("rejects unknown JSON property", () => Throws(() => Protocol.Parse<Command>(Encoding.UTF8.GetBytes("{\"extra\":true}")), "MALFORMED"));
Test("rejects duplicate JSON property", () => Throws(() => Protocol.Parse<Command>(Encoding.UTF8.GetBytes("{\"id\":1,\"id\":2}")), "DUPLICATE_PROPERTY"));
Test("rejects oversized frame", () => Throws(() => Protocol.Parse<Command>(new byte[Protocol.MaximumFrame + 1]), "FRAME_TOO_LARGE"));
Test("rejects arbitrary keyboard shortcut", () => Throws(() => Protocol.Validate(Cmd("key") with { Window = Guid.NewGuid().ToString("D"), Key = "WinR" }), "KEY_DENIED"));
Test("rejects extra file parameter", () => Throws(() => Protocol.Validate(Cmd() with { File = "test.json" }), "UNEXPECTED_ARGUMENT"));
Test("HMAC roundtrip", () => { var key = RandomNumberGenerator.GetBytes(32); var c = Cmd(); Assert(Protocol.Open<Command>(Protocol.Seal(c, key), key) == c); });
Test("rejects forged MAC", () => { var key = RandomNumberGenerator.GetBytes(32); var e = Protocol.Seal(Cmd(), key); Throws(() => Protocol.Open<Command>(e with { Mac = new string('0', 64) }, key), "AUTHENTICATION_DENIED"); });
Test("rejects wrong key", () => { var e = Protocol.Seal(Cmd(), RandomNumberGenerator.GetBytes(32)); Throws(() => Protocol.Open<Command>(e, RandomNumberGenerator.GetBytes(32)), "AUTHENTICATION_DENIED"); });
Test("DEFAULT_DENY no execution", () => { var b = new FakeBackend(); var r = Run(Cmd(), Policy() with { Enabled = false }, b); Assert(r.Code == "DEFAULT_DENY" && b.Calls == 0); });
Test("non-synthetic scope denied", () => Assert(Run(Cmd(), Policy() with { SyntheticOnly = false }).Code == "DEFAULT_DENY"));
Test("empty target list denied", () => Assert(Run(Cmd(), Policy() with { Targets = [] }).Code == "DEFAULT_DENY"));
Test("session mismatch denied", () => Assert(Run(Cmd(), Policy() with { SessionId = 8 }).Code == "SESSION_OR_DESKTOP_DENIED"));
Test("sandbox desktop denied", () => Assert(Run(Cmd(), b: new() { Session = new(7, "WinSta0", "CodexSandboxDesktop-test", false) }).Code == "SESSION_OR_DESKTOP_DENIED"));
Test("non-input desktop denied", () => Assert(Run(Cmd(), b: new() { Session = new(7, "WinSta0", "Default", false) }).Code == "SESSION_OR_DESKTOP_DENIED"));
Test("station mismatch denied", () => Assert(Run(Cmd(), b: new() { Session = new(7, "Service", "Default", true) }).Code == "SESSION_OR_DESKTOP_DENIED"));
Test("unsupported action scope denied", () => Assert(Run(Cmd(), Policy() with { Actions = ["heartbeat"] }).Code == "DEFAULT_DENY"));
Test("unknown control denied", () => Assert(Run(Cmd("focus") with { Window = Guid.NewGuid().ToString("D"), Element = "Other" }).Code == "ELEMENT_DENIED"));
Test("observations are not task success", () => { var r = Run(Cmd()); Assert(r.Status == "OBSERVED" && !r.Authorized && r.Production == "DEFAULT_DENY"); });
Test("durable duplicate execution prevention across dispatchers", () => { var c = Cmd(); Assert(Run(c).Status == "OBSERVED"); Assert(Run(c).Code == "DUPLICATE_OR_JOURNAL_UNAVAILABLE"); });
Test("cancel before action", () => { using var ct = new CancellationTokenSource(); ct.Cancel(); var b = new FakeBackend(); Assert(Run(Cmd(), b: b, ct: ct.Token).Status == "CANCELLED" && b.Calls == 0); });
Test("timeout classification", () => Assert(Run(Cmd(), b: new() { Delay = 150 }).Code == "TIMEOUT"));
Test("mutation timeout unknown", () => Assert(Run(Cmd("focus") with { Window = Guid.NewGuid().ToString("D"), Element = "Button" }, b: new() { Delay = 150 }).Status == "UNKNOWN"));
Test("stale target classified", () => Assert(Run(Cmd(), b: new() { Error = "STALE_TARGET" }).Status == "FAILED"));
Test("screenshot failure classified", () => Assert(Run(Cmd("capture") with { Window = Guid.NewGuid().ToString("D") }, b: new() { Error = "SCREENSHOT_FAILED" }).Status == "FAILED"));
Test("backend failure contains no raw message", () => Assert(Run(Cmd(), b: new() { Crash = true }).Code == "BACKEND_FAILURE"));
Test("evidence checksum matches bytes", () => { var s = new EvidenceStore(root, Guid.NewGuid().ToString("D")); var e = s.Save(Guid.NewGuid().ToString("D"), [1, 2, 3], "json", "synthetic"); Assert(e.Sha256 == Protocol.Hash(File.ReadAllBytes(Path.Combine(root, e.Path))) && e.Bytes == 3); });
Test("evidence cannot overwrite", () => { var s = new EvidenceStore(root, Guid.NewGuid().ToString("D")); var id = Guid.NewGuid().ToString("D"); s.Save(id, [1], "json", "test"); try { s.Save(id, [2], "json", "test"); } catch (IOException) { return; } throw new Exception("overwrite"); });
Test("evidence traversal denied", () => Throws(() => new EvidenceStore(root, Guid.NewGuid().ToString("D")).Save("../x", [1], "json", "test"), "EVIDENCE_PATH_DENIED"));
Test("audit records no input text", () => { var c = Cmd(); Run(c); var lines = Directory.GetFiles(root, "audit-*.ndjson").SelectMany(File.ReadAllLines).Select(l => Encoding.UTF8.GetString(Convert.FromBase64String(System.Text.Json.JsonDocument.Parse(l).RootElement.GetProperty("payload").GetString()!))).ToArray(); Assert(lines.Any(l => l.Contains(c.Id)) && lines.All(l => !l.Contains("executableSha256"))); });
Test("rejects invalid window token", () => Throws(() => Protocol.Validate(Cmd("capture") with { Window = "stale" }), "TARGET_REQUIRED"));
Test("rejects reserved filename", () => Throws(() => Protocol.Validate(Cmd("setFile") with { Window = Guid.NewGuid().ToString("D"), Element = "Button", File = "NUL.json" }), "FILE_PATH_DENIED"));
Test("capture does not accept ignored element arguments", () => Throws(() => Protocol.Validate(Cmd("capture") with { Window = Guid.NewGuid().ToString("D"), Element = "Button" }), "UNEXPECTED_ARGUMENT"));
Test("nonblank chrome cannot validate blank WPF client", () => {
    var pixels = new byte[20 * 20 * 4];
    for (int x = 0; x < 20; x++) pixels[x * 4] = 255;
    Assert(!CaptureValidation.HasClientContent(pixels, 20, 20, 2, 2, 18, 18));
});
Test("synthetic varied client pixels satisfy only nonblank heuristic", () => {
    var pixels = new byte[20 * 20 * 4];
    for (int y = 5; y < 10; y++) for (int x = 5; x < 10; x++) pixels[(y * 20 + x) * 4] = 255;
    Assert(CaptureValidation.HasClientContent(pixels, 20, 20, 2, 2, 18, 18));
    Assert(!CaptureValidation.HasClientContent(pixels, 20, 20, -1, 0, 20, 20));
});
Test("incomplete native input remains unknown", () => Assert(Run(Cmd("click") with { Window = Guid.NewGuid().ToString("D"), Element = "Button" }, b: new() { Error = "INPUT_INCOMPLETE" }).Status == "UNKNOWN"));
Test("post-action observation failure remains unknown", () => Assert(Run(Cmd("click") with { Window = Guid.NewGuid().ToString("D"), Element = "Button" }, b: new() { Error = "UNKNOWN_OUTCOME" }).Status == "UNKNOWN"));
Console.WriteLine($"RESULT {passed} passed; {failed} failed; synthetic backend only");
return failed == 0 ? 0 : 1;

sealed class FakeBackend : IDesktopBackend
{
    public SessionIdentity Session { get; init; } = new(7, "WinSta0", "Default", true);
    public int Calls { get; private set; }
    public int Delay { get; init; }
    public string? Error { get; init; }
    public bool Crash { get; init; }
    public SessionIdentity Identity() => Session;
    public ActionData Execute(Command command, CancellationToken ct) {
        Calls++;
        if (Delay > 0) { ct.WaitHandle.WaitOne(Delay); ct.ThrowIfCancellationRequested(); }
        if (Error != null) throw new AgentException(Error);
        if (Crash) throw new InvalidOperationException("sensitive raw diagnostic");
        return new(new(Session, [], new string('0', 64)));
    }
}
