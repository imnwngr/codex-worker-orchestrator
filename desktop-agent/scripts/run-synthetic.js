"use strict";
const fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { verifyPackage } = require("./provenance");
const { DesktopBridge, required } = require("../../broker/desktop/bridge");
const { ControlledDesktopBroker, ExecutionEngine } = require("../../broker/desktop/controller");
const { command } = require("../../broker/desktop/protocol");
const { auditWriter, readEvidence, hash } = require("../../broker/desktop/evidence");
async function run(root, pin, authorization) {
  if (authorization !== "--authorized-synthetic-desktop") throw new Error("EXPLICIT_DESKTOP_SCOPE_REQUIRED");
  const manifest = verifyPackage(path.resolve(root), pin);
  const directory = path.resolve(root, "payload/agent");
  const pins = Object.fromEntries(required.map(n => [n, manifest.artifacts.find(f => f.path === "agent/" + n)?.sha256]));
  const probe = spawnSync(path.join(directory, "DesktopAgent.Windows.exe"), ["--probe"], { encoding: "utf8", windowsHide: true });
  if (probe.error || probe.status !== 0) throw new Error("DESKTOP_PROBE_UNAVAILABLE");
  const session = JSON.parse(probe.stdout);
  if (session.desktop !== "Default" || session.station !== "WinSta0" || !session.inputDesktop)
    return { status: "BLOCKED", code: "AUTHORIZED_INPUT_DESKTOP_REQUIRED" };
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-real-synthetic-"));
  const fixture = spawn(path.resolve(root, "payload/fixture/DesktopAgent.Fixture.exe"), ["--synthetic"],
    { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  const target = await new Promise((resolve, reject) => {
    let bytes = "";
    const timer = setTimeout(() => reject(new Error("FIXTURE_TIMEOUT")), 5000);
    fixture.once("error", () => { clearTimeout(timer); reject(new Error("FIXTURE_FAILED")); });
    fixture.stdout.on("data", chunk => {
      bytes += chunk;
      if (bytes.length > 4096) { clearTimeout(timer); reject(new Error("FIXTURE_INVALID")); }
      else if (bytes.includes("\n")) { clearTimeout(timer); try { resolve(JSON.parse(bytes.trim())); } catch { reject(new Error("FIXTURE_INVALID")); } }
    });
  }).catch(error => { fixture.kill(); throw error; });
  const policy = { enabled: true, syntheticOnly: true, sessionId: session.sessionId, desktop: "Default",
    targets: [target], actions: ["heartbeat", "observe", "capture", "focus", "key", "click"],
    automationIds: ["Increment", "OpenDialog", "CloseDialog"], evidenceRoot };
  const audit = auditWriter(path.join(evidenceRoot, "controller.ndjson"));
  const bridge = new DesktopBridge({ directory, pins, policy });
  const taskId = crypto.randomUUID();
  const controller = new ControlledDesktopBroker({ bridge, evidenceRoot, audit: e => audit.write(e),
    authorize: c => c.taskId === taskId && policy.actions.includes(c.action) });
  try {
    const title = "Phase15 Synthetic Fixture";
    const focused = element => ({ kind: "focused", windowTitle: title, element });
    const name = value => ({ kind: "name", windowTitle: title, element: "Counter", value });
    const engine = new ExecutionEngine({ controller, historyPath: path.join(evidenceRoot, "history.ndjson") });
    const result = await engine.run({ taskId, steps: [
      { windowTitle: title, action: "focus", element: "Increment", expect: focused("Increment") },
      { windowTitle: title, action: "key", element: "Increment", key: "Enter", expect: name("Count: 1") },
      { windowTitle: title, action: "key", element: "Increment", key: "Tab", expect: focused("OpenDialog") },
      { windowTitle: title, action: "key", element: "OpenDialog", key: "ShiftTab", expect: focused("Increment") },
      { windowTitle: title, action: "click", element: "Increment", expect: name("Count: 2") },
      { windowTitle: title, action: "capture", expect: name("Count: 2") }
    ] });
    if (result.status === "VERIFIED") {
      const observations = fs.readdirSync(evidenceRoot).filter(n => /^[a-f0-9-]{36}\.json$/.test(n))
        .map(n => JSON.parse(fs.readFileSync(path.join(evidenceRoot, n))));
      const captures = observations.filter(d => d.evidence).map(d => d.evidence);
      if (!captures.length) throw new Error("SCREENSHOT_REQUIRED");
      captures.forEach(e => readEvidence(evidenceRoot, e));
      result.screenshots = captures;
    }
    result.scope = "REAL_SYNTHETIC_FIXTURE_ONLY_NOT_PHASE14_ACCEPTANCE";
    fs.writeFileSync(path.join(evidenceRoot, "report.json"), JSON.stringify(result, null, 2), { flag: "wx" });
    console.log(JSON.stringify({ ...result, evidenceRoot }, null, 2));
    return result;
  } finally { await bridge.close(); fixture.kill(); audit.close(); }
}
if (require.main === module) run(...process.argv.slice(2)).then(r => { if (r.status !== "VERIFIED") { console.log(JSON.stringify(r)); process.exitCode = 2; } })
  .catch(error => { console.error(/^[A-Z_]+$/.test(error.message) ? error.message : "SYNTHETIC_RUN_FAILED"); process.exitCode = 1; });
module.exports = { run };
