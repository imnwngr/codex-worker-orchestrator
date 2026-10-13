"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const { createBrokerServer } = require("../broker");
const { validateConfig } = require("../providers/config");
const { ProviderRegistry } = require("../providers/registry");
const { BatchGate, validateBatch, limits } = require("../providers/batch-security");

const TOKEN = "test-only-token-long-enough-0123456789";
const config = validateConfig({
  version: 1, defaultProvider: "antigravity",
  providers: [
    { id: "antigravity", kind: "cli", enabled: true, timeoutSeconds: 600 },
    { id: "api", kind: "api", enabled: true, baseUrl: "https://api.example.test/v1",
      timeoutSeconds: 30, models: ["m1", "m2"], defaultModel: "m1", credentialEnv: "TEST_API_KEY" }
  ]
});
const api = (id, task = "review") => ({ id, provider: "api", model: "m1", task });

async function setup(t, options = {}) {
  const calls = [];
  const adapters = [
    { id: "antigravity", kind: "cli", async analyze(request) {
      calls.push(["antigravity", request]); return { response: "cli advice" };
    } },
    { id: "api", kind: "api", async analyze(request) {
      calls.push(["api", request]);
      if (request.task === "fail") throw new Error("private upstream secret");
      return { response: `${request.model} advice` };
    } }
  ];
  const registry = new ProviderRegistry(config, adapters);
  const server = createBrokerServer({
    config, registry, adapters, env: options.env ?? { BROKER_BATCH_AUTH_TOKEN: TOKEN },
    authorizeTarget: options.authorizeTarget,
    batchGate: options.gate,
    logger: { log() {}, error() {} }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}`, calls, registry };
}

function post(base, value, headers = {}) {
  return fetch(`${base}/v1/analyze/batch`, {
    method: "POST", headers: {
      authorization: `Bearer ${TOKEN}`, "content-type": "application/json", ...headers
    }, body: JSON.stringify(value)
  });
}

test("fails closed without authentication configuration", async t => {
  const { base, calls } = await setup(t, { env: {}, authorizeTarget: () => true });
  assert.equal((await post(base, { targets: [api("a")] })).status, 503);
  assert.deepEqual(calls, []);
});

test("rejects invalid and missing authentication", async t => {
  const { base, calls } = await setup(t, { authorizeTarget: () => true });
  assert.equal((await post(base, { targets: [api("a")] }, { authorization: "Bearer wrong" })).status, 401);
  assert.equal((await post(base, { targets: [api("a")] }, { authorization: "" })).status, 401);
  assert.deepEqual(calls, []);
});

test("authentication alone never establishes approval", async t => {
  const { base, calls } = await setup(t);
  const response = await post(base, { targets: [api("a")] });
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "authorization_required");
  assert.deepEqual(calls, []);
});

test("explicit internal test approval enables ordered advisory data", async t => {
  const approvals = [];
  const { base, calls } = await setup(t, {
    authorizeTarget: info => { approvals.push(info); return info.provider === "api" && info.model === "m1"; }
  });
  const response = await post(base, { targets: [api("second", "later"), api("first", "earlier")] });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.deepEqual(data.results.map(x => x.id), ["second", "first"]);
  assert.deepEqual(data.results.map(x => x.status), ["success", "success"]);
  assert.equal(calls.length, 2);
  assert.match(approvals[0].taskSha256, /^[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(approvals[0], "task"), false);
});

test("invalid requests and unauthorized models start no workers", async t => {
  const { base, calls } = await setup(t, { authorizeTarget: () => true });
  const bad = [
    { targets: [] },
    { targets: [api("dup"), api("dup")] },
    { targets: [{ ...api("x"), model: "nope" }] },
    { targets: [{ ...api("x"), endpoint: "https://evil.test" }] },
    { targets: [{ ...api("x"), apiKey: "stolen" }] },
    { targets: [{ ...api("x"), timeout_seconds: 31 }] },
    { targets: [{ ...api("x"), effort: "invalid" }] },
    { targets: [api("x", " ")] },
    { targets: Array.from({ length: 9 }, (_, i) => api(`x${i}`)) },
    { targets: [api("x")], config: {} }
  ];
  for (const value of bad) assert.equal((await post(base, value)).status, 400);
  assert.equal((await post(base, { targets: [api("x")] }, { "content-type": "text/plain" })).status, 415);
  assert.deepEqual(calls, []);
});

test("partial failure is sanitized, preserving other results", async t => {
  const { base } = await setup(t, { authorizeTarget: () => true });
  const response = await post(base, { targets: [api("bad", "fail"), api("good")] });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.results.map(x => x.status), ["failure", "success"]);
  assert.doesNotMatch(JSON.stringify(body), /private upstream secret/);
});

test("gate limits active and queued jobs and removes cancelled queue items", async () => {
  const gate = new BatchGate();
  const releases = await Promise.all([gate.acquire(), gate.acquire()]);
  assert.equal(gate.active, limits.activeBatches);
  const signals = Array.from({ length: 4 }, () => new AbortController());
  const waiting = signals.map(controller => gate.acquire(controller.signal));
  await assert.rejects(gate.acquire(), /busy/);
  signals[0].abort();
  await assert.rejects(waiting[0], /cancelled/);
  releases[0]();
  const releaseNext = await waiting[1];
  assert.equal(gate.active, 2);
  releases[1]();
  const releaseThird = await waiting[2];
  releaseNext();
  const releaseFourth = await waiting[3];
  releaseThird(); releaseFourth();
  assert.equal(gate.active, 0);
  assert.equal(gate.queue.length, 0);
});

test("pre-aborted queue requests never occupy slots", async () => {
  const gate = new BatchGate();
  const controller = new AbortController(); controller.abort();
  await assert.rejects(gate.acquire(controller.signal), /cancelled/);
  assert.equal(gate.active, 0);
});

test("rejects oversized declared payload without dispatch", async t => {
  const { base, calls } = await setup(t, { authorizeTarget: () => true });
  const response = await post(base, { targets: [api("x", "z".repeat(280000))] });
  assert.equal(response.status, 413);
  assert.deepEqual(calls, []);
});

test("legacy endpoints remain compatible", async t => {
  const { base } = await setup(t);
  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).provider, "antigravity");
  const legacy = await fetch(`${base}/v1/analyze`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ task: "review" })
  });
  assert.equal(legacy.status, 200);
  assert.equal((await legacy.json()).provider, "antigravity");
});
