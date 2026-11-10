"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { validate, command, seal, open } = require("../desktop/protocol");
const { DesktopBridge, required, verifyBundle } = require("../desktop/bridge");
const { ControlledDesktopBroker, ExecutionEngine, verify } = require("../desktop/controller");
const taskId = () => crypto.randomUUID();
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-node-"));
  const pins = {};
  for (const name of required) {
    fs.writeFileSync(path.join(root, name), name);
    pins[name] = crypto.createHash("sha256").update(name).digest("hex");
  }
  return { directory: root, pins };
}
function fakeSpawn(mode = "normal") {
  return () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
    child.kill = () => { setImmediate(() => child.emit("exit", 1)); return true; };
    child.stdin.on("finish", () => setImmediate(() => child.emit("exit", 0)));
    let key, workerId = taskId();
    child.stdin.on("data", bytes => {
      const frame = bytes.toString();
      if (!key) {
        key = Buffer.from(JSON.parse(frame).key, "base64");
        setImmediate(() => child.stdout.write(seal({ version: 1, status: "READY", workerId }, key)));
      } else if (mode === "disconnect") setImmediate(() => child.emit("exit", 1));
      else if (mode !== "hang") {
        const c = open(frame.trim(), key);
        const result = { version: 1, workerId, id: c.id, taskId: c.taskId, correlationId: c.correlationId,
          status: "OBSERVED", authorized: false, production: "DEFAULT_DENY" };
        if (mode === "wrong-id") result.id = taskId();
        if (mode === "forged") key = crypto.randomBytes(32);
        setImmediate(() => child.stdout.write(seal(result, key)));
      }
    });
    return child;
  };
}
test("desktop protocol allowlist rejects arbitrary commands and excess properties", () => {
  assert.throws(() => validate({ ...command("observe", taskId()), shell: "cmd" }), /INVALID_COMMAND/);
  assert.throws(() => command("exec", taskId()), /INVALID_COMMAND/);
  assert.throws(() => command("key", taskId(), { window: taskId(), key: "WinR" }), /KEY_DENIED/);
  assert.throws(() => command("setFile", taskId(), { window: taskId(), element: "File", file: "../x.json" }), /FILE_PATH_DENIED/);
});
test("HMAC rejects tampering and wrong keys", () => {
  const key = crypto.randomBytes(32), c = command("observe", taskId()), frame = seal(c, key);
  assert.deepEqual(open(frame, key), c);
  assert.throws(() => open(frame, crypto.randomBytes(32)), /AUTHENTICATION_DENIED/);
  const bad = JSON.parse(frame); bad.payload = Buffer.from("{}").toString("base64");
  assert.throws(() => open(JSON.stringify(bad), key), /AUTHENTICATION_DENIED/);
});
test("bundle verification rejects missing pins and modified dependency", () => {
  const f = fixture();
  assert.throws(() => verifyBundle(f.directory, {}), /BUILD_PINS_REQUIRED/);
  fs.appendFileSync(path.join(f.directory, "DesktopAgent.Core.dll"), "tamper");
  assert.throws(() => verifyBundle(f.directory, f.pins), /BUILD_INTEGRITY_FAILED/);
});
test("authenticated handshake, response binding and heartbeat", async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn() });
  const result = await bridge.execute(command("heartbeat", taskId()));
  assert.equal(result.status, "OBSERVED"); assert.ok(bridge.lastHeartbeat);
  await bridge.close();
});
for (const mode of ["wrong-id", "forged", "disconnect"]) test("bridge fails closed: " + mode, async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn(mode) });
  await assert.rejects(bridge.execute(command("observe", taskId())), /CHANNEL_AUTHENTICATION_FAILED|AGENT_DISCONNECTED/);
  assert.equal(bridge.closed, true);
});
test("bounded timeout terminates agent and mutation remains unknown", async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn("hang") });
  await assert.rejects(bridge.execute(command("click", taskId(), { window: taskId(), element: "Button", timeoutMs: 100 })), /UNKNOWN_TIMEOUT/);
  assert.equal(bridge.closed, true);
});

for (const mode of ["wrong-id", "forged", "disconnect"]) test("input channel failure remains unknown: " + mode, async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn(mode) });
  await assert.rejects(bridge.execute(command("click", taskId(), { window: taskId(), element: "Button" })), /UNKNOWN_CHANNEL_FAILURE/);
  assert.equal(bridge.closed, true);
});

test("cancellation after input dispatch remains unknown", async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn("hang") });
  await bridge.ready; const abort = new AbortController();
  const pending = bridge.execute(command("key", taskId(), { window: taskId(), element: "Button", key: "Enter" }), { signal: abort.signal });
  setImmediate(() => abort.abort());
  await assert.rejects(pending, /UNKNOWN_CANCELLED/);
});
test("cancellation terminates in-flight read and disconnect prevents reuse", async () => {
  const bridge = new DesktopBridge({ ...fixture(), policy: {}, spawnAgent: fakeSpawn("hang") });
  await bridge.ready; const abort = new AbortController();
  const pending = bridge.execute(command("observe", taskId()), { signal: abort.signal });
  setImmediate(() => abort.abort());
  await assert.rejects(pending, /CANCELLED/);
  await assert.rejects(bridge.execute(command("observe", taskId())), /AGENT_DISCONNECTED/);
});
test("controller default deny and audit failure prevent execution", async () => {
  let calls = 0; const bridge = { execute() { calls++; } };
  await assert.rejects(new ControlledDesktopBroker({ bridge, audit() {} }).execute(command("observe", taskId())), /DEFAULT_DENY/);
  await assert.rejects(new ControlledDesktopBroker({ bridge, authorize: () => true }).execute(command("observe", taskId())), /AUDIT_REQUIRED/);
  assert.equal(calls, 0);
});
function observation(focused = false) {
  return { windows: [{ title: "Synthetic", token: taskId(), elements: [{ id: "Button", focused, offscreen: false, name: "ready" }] }] };
}
test("verification requires observed exact unique state", () => {
  assert.equal(verify(observation(false), { kind: "focused", element: "Button" }), false);
  assert.equal(verify(observation(true), { kind: "focused", element: "Button" }), true);
  assert.equal(verify(observation(true), { kind: "exitCodeZero" }), false);
  assert.equal(verify({ windows: [...observation(true).windows, ...observation(true).windows] }, { kind: "focused", element: "Button" }), false);
});
function plan() { return { taskId: taskId(), steps: [{ windowTitle: "Synthetic", action: "focus", element: "Button",
  expect: { kind: "focused", windowTitle: "Synthetic", element: "Button" } }] }; }
test("engine verifies, persists and refuses duplicate task on restart", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-engine-")), historyPath = path.join(dir, "history.ndjson");
  let count = 0;
  const controller = { async execute() { return { status: "OBSERVED", data: { observation: observation(++count > 1) } }; } };
  const engine = new ExecutionEngine({ controller, historyPath }), p = plan();
  assert.equal((await engine.run(p)).status, "VERIFIED");
  await assert.rejects(new ExecutionEngine({ controller, historyPath }).run(p), /EEXIST/);
  assert.match(fs.readFileSync(historyPath, "utf8"), /STEP_VERIFIED/);
});
test("recovery is bounded observation only; never replay input", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-engine-")), calls = [];
  const controller = { async execute(c) { calls.push(c); return { status: "OBSERVED", data: { observation: observation(false) } }; } };
  const result = await new ExecutionEngine({ controller, historyPath: path.join(dir, "history.ndjson"), maxObservations: 2 }).run(plan());
  assert.equal(result.code, "POSTCONDITION_FAILED");
  assert.equal(calls.filter(c => c.action === "focus").length, 1);
  assert.equal(calls.length, 4);
});
test("disconnect after action is unknown, no replay", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-engine-")); let calls = 0;
  const controller = { async execute() { if (++calls > 1) throw new Error("AGENT_DISCONNECTED");
    return { status: "OBSERVED", data: { observation: observation(false) } }; } };
  assert.equal((await new ExecutionEngine({ controller, historyPath: path.join(dir, "h") }).run(plan())).status, "UNKNOWN");
  assert.equal(calls, 2);
});
