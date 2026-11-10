"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), crypto = require("node:crypto");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { command } = require("../desktop/protocol");
const { hash, readEvidence, verifyAudit } = require("../desktop/evidence");
const { ControlledDesktopBroker, ExecutionEngine } = require("../desktop/controller");
const { inventory, verifyPackage } = require("../../desktop-agent/scripts/provenance");
const { RealBrowser } = require("../../desktop-agent/acceptance/webdriver");
const { GuiSession, configurationDependent } = require("../../desktop-agent/acceptance/cases");
const { HeartbeatMonitor } = require("../desktop/heartbeat");
const root = () => fs.mkdtempSync(path.join(os.tmpdir(), "phase15-harden-"));
test("evidence rejects altered bytes, path traversal and wrong length", () => {
  const dir = root(), name = crypto.randomUUID() + ".json", bytes = Buffer.from("{}");
  fs.writeFileSync(path.join(dir, name), bytes);
  const reference = { path: name, bytes: 2, sha256: hash(bytes) };
  assert.deepEqual(readEvidence(dir, reference), bytes);
  assert.throws(() => readEvidence(dir, { ...reference, bytes: 1 }), /EVIDENCE_INTEGRITY_FAILED/);
  assert.throws(() => readEvidence(dir, { ...reference, path: "../x.json" }), /INVALID_EVIDENCE_REFERENCE/);
  fs.appendFileSync(path.join(dir, name), "x");
  assert.throws(() => readEvidence(dir, reference), /EVIDENCE_INTEGRITY_FAILED/);
});
test("audit hash chain rejects tamper and record reordering", () => {
  const dir = root(), file = path.join(dir, "audit.ndjson");
  let previous = "0".repeat(64);
  const rows = [1, 2].map(sequence => { const bytes = Buffer.from(JSON.stringify({ sequence, previous }));
    previous = hash(bytes); return JSON.stringify({ payload: bytes.toString("base64"), sha256: previous }); });
  fs.writeFileSync(file, rows.join("\n") + "\n");
  assert.equal(verifyAudit(file).records, 2);
  fs.writeFileSync(file, rows.reverse().join("\n"));
  assert.throws(() => verifyAudit(file), /AUDIT_INTEGRITY_FAILED/);
});
test("package verification checks independent manifest pin and exact payload inventory", () => {
  const dir = root(); fs.mkdirSync(path.join(dir, "payload")); fs.writeFileSync(path.join(dir, "payload", "a.dll"), "fixture");
  const manifest = { version: 1, authorized: false, production: "DEFAULT_DENY", artifacts: inventory(path.join(dir, "payload")) };
  const bytes = Buffer.from(JSON.stringify(manifest)); fs.writeFileSync(path.join(dir, "manifest.json"), bytes);
  assert.equal(verifyPackage(dir, hash(bytes)).version, 1);
  assert.throws(() => verifyPackage(dir, "0".repeat(64)), /MANIFEST_PIN_MISMATCH/);
  fs.writeFileSync(path.join(dir, "payload", "unexpected.exe"), "x");
  assert.throws(() => verifyPackage(dir, hash(bytes)), /PACKAGE_INTEGRITY_FAILED/);
});
test("controller binds observed response to persisted evidence", async () => {
  const dir = root(), data = { observation: { windows: [] } }, bytes = Buffer.from(JSON.stringify(data));
  const name = crypto.randomUUID() + ".json"; fs.writeFileSync(path.join(dir, name), bytes);
  const result = { status: "OBSERVED", data, observationEvidence: { path: name, sha256: hash(bytes), bytes: bytes.length } };
  const controller = new ControlledDesktopBroker({ evidenceRoot: dir, authorize: () => true, audit() {},
    bridge: { async execute() { return result; } } });
  assert.equal((await controller.execute(command("observe", crypto.randomUUID()))).status, "OBSERVED");
  result.data = { observation: { windows: ["tampered"] } };
  await assert.rejects(controller.execute(command("observe", crypto.randomUUID())), /EVIDENCE_BINDING_FAILED/);
});
test("authorization cannot race input mutation", async () => {
  const input = command("observe", crypto.randomUUID()); let dispatched;
  const controller = new ControlledDesktopBroker({ authorize: async () => { input.action = "click"; return true; }, audit() {},
    bridge: { async execute(c) { dispatched = c; return { status: "DENIED" }; } } });
  await controller.execute(input);
  assert.equal(dispatched.action, "observe"); assert.equal(Object.isFrozen(dispatched), true);
});

test("controller verifies capture bytes and preserves uncertainty after input evidence loss", async () => {
  const dir = root(), data = { observation: { windows: [] } }, name = crypto.randomUUID() + ".json";
  const bytes = Buffer.from(JSON.stringify(data)); fs.writeFileSync(path.join(dir, name), bytes);
  const result = { status: "OBSERVED", data, observationEvidence: { path: name, sha256: hash(bytes), bytes: bytes.length } };
  const controller = new ControlledDesktopBroker({ evidenceRoot: dir, authorize: () => true, audit() {},
    bridge: { async execute() { return result; } } });
  await assert.rejects(controller.execute(command("capture", crypto.randomUUID(), { window: crypto.randomUUID() })), /CAPTURE_EVIDENCE_REQUIRED/);
  fs.appendFileSync(path.join(dir, name), "tampered");
  await assert.rejects(controller.execute(command("click", crypto.randomUUID(), { window: crypto.randomUUID(), element: "Button" })), /UNKNOWN_EVIDENCE_INVALID/);
});
test("read recovery reconnects within bounded attempts and reacquires a fresh target", async () => {
  let calls = 0, reconnects = 0;
  const controller = { bridge: { stop() {} }, async reconnect() { reconnects++; return { stop() {} }; },
    async execute() {
      if (++calls === 1) throw new Error("AGENT_DISCONNECTED");
      return { status: "OBSERVED", data: { observation: { windows: [{ title: "Synthetic",
        token: crypto.randomUUID(), elements: [{ id: "Counter", name: "done", offscreen: false }] }] } } };
    } };
  const engine = new ExecutionEngine({ controller, historyPath: path.join(root(), "history"), maxObservations: 2 });
  const result = await engine.run({ taskId: crypto.randomUUID(), steps: [{ windowTitle: "Synthetic", action: "capture",
    expect: { kind: "name", element: "Counter", value: "done" } }] });
  assert.equal(result.status, "VERIFIED"); assert.equal(reconnects, 1); assert.equal(calls, 3);
});
test("retry exhaustion terminates; invalid verification plan performs no action", async () => {
  let calls = 0;
  const controller = { async execute() { calls++; throw new Error("AGENT_DISCONNECTED"); } };
  const engine = new ExecutionEngine({ controller, historyPath: path.join(root(), "history"), maxObservations: 2 });
  const plan = { taskId: crypto.randomUUID(), steps: [{ windowTitle: "Synthetic", action: "capture",
    expect: { kind: "windowPresent" } }] };
  assert.equal((await engine.run(plan)).code, "OBSERVATION_RETRY_EXHAUSTED");
  assert.equal(calls, 2);
  await assert.rejects(engine.run({ ...plan, steps: [{ ...plan.steps[0], expect: { kind: "exitCode" } }] }), /INVALID_PLAN/);
  assert.equal(calls, 2);
});
test("browser driver requires exact reviewed executable; configuration tests remain blocked", () => {
  assert.throws(() => new RealBrowser({ kind: "chrome", driver: "cmd.exe" }), /DRIVER_PIN_REQUIRED/);
  assert.ok(configurationDependent.every(c => c.status === "BLOCKED" && c.modifiesPersonalSettings === false));
});

test("GUI acceptance never converts uncertain input to a definite failure", async () => {
  const gui = new GuiSession({ async execute(c) {
    return c.action === "observe" ? { status: "OBSERVED", data: { observation: { windows: [{ title: "Synthetic", token: crypto.randomUUID() }] } } }
      : { status: "UNKNOWN", code: "INPUT_INCOMPLETE" };
  } }, root(), crypto.randomUUID());
  await assert.rejects(gui.act("Synthetic", "click", { element: "Button" }), /UNKNOWN_ACTION/);
});
test("heartbeat monitors loss without infinite reconnect", async () => {
  const states = [];
  const monitor = new HeartbeatMonitor({ async execute() { throw new Error("AGENT_DISCONNECTED"); } }, crypto.randomUUID(),
    { intervalMs: 250, onState: state => states.push(state.state) });
  monitor.start(); await new Promise(resolve => setTimeout(resolve, 350)); monitor.stop();
  assert.deepEqual(states, ["DISCONNECTED"]);
});
