"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const { createBrokerServer } = require("../broker");

async function withServer(t, options) {
  const server = createBrokerServer(options);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${address.port}`;
}

function responseAdapter(result = {
  response: "advisory text",
  conversation_id: "conv-test",
  usage: { total: 2 }
}) {
  const calls = [];
  return {
    calls,
    adapter: {
      id: "antigravity",
      kind: "cli",
      async analyze(request) {
        calls.push(request);
        return result;
      }
    }
  };
}

test("GET /health preserves status and response structure on loopback", async t => {
  const { adapter } = responseAdapter();
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });
  const response = await fetch(`${base}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: "codex-worker-broker",
    provider: "antigravity"
  });
  assert.equal(new URL(base).hostname, "127.0.0.1");
});

test("valid POST /v1/analyze preserves response fields and dispatch values", async t => {
  const { adapter, calls } = responseAdapter();
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });
  const response = await fetch(`${base}/v1/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      task: "  review this  ",
      effort: "medium",
      timeout_seconds: 30
    })
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.match(body.request_id, /^[0-9a-f-]{36}$/i);
  assert.equal(body.provider, "antigravity");
  assert.equal(body.response, "advisory text");
  assert.equal(body.conversation_id, "conv-test");
  assert.deepEqual(body.usage, { total: 2 });
  assert.deepEqual(calls[0], {
    task: "review this",
    effort: "medium",
    timeoutSeconds: 30,
    signal: calls[0].signal
  });
  assert.equal(calls[0].signal instanceof AbortSignal, true);
});

test("rejects request-controlled provider settings", async t => {
  const { adapter, calls } = responseAdapter();
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });
  const response = await fetch(`${base}/v1/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      task: "review",
      provider: "other",
      baseUrl: "https://example.test",
      credential: "secret"
    })
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { ok: false, error: "invalid_request" });
  assert.equal(calls.length, 0);
});

test("returns generic worker failures without exposing subprocess errors", async t => {
  const { adapter } = responseAdapter();
  adapter.analyze = async () => {
    throw new Error("sensitive stderr and secret details");
  };
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });
  const response = await fetch(`${base}/v1/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ task: "review" })
  });
  assert.equal(response.status, 502);
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.equal(body.provider, "antigravity");
  assert.equal(body.error, "worker_failed");
  assert.equal(body.message, "Worker request failed");
  assert.doesNotMatch(JSON.stringify(body), /sensitive|secret/);
});

test("invalid JSON and task preserve client error behavior", async t => {
  const { adapter } = responseAdapter();
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });

  const invalidJson = await fetch(`${base}/v1/analyze`, {
    method: "POST",
    body: "{"
  });
  assert.equal(invalidJson.status, 400);
  assert.deepEqual(await invalidJson.json(), { ok: false, error: "invalid_json" });

  const invalidTask = await fetch(`${base}/v1/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ task: " " })
  });
  assert.equal(invalidTask.status, 400);
  assert.deepEqual(await invalidTask.json(), { ok: false, error: "invalid_task" });
});

test("unknown route remains a 404", async t => {
  const { adapter } = responseAdapter();
  const base = await withServer(t, { adapter, logger: { log() {}, error() {} } });
  const response = await fetch(`${base}/not-a-route`);
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { ok: false, error: "not_found" });
});
