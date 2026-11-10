"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createBrokerServer } = require("../broker");
const { command } = require("../desktop/protocol");
async function server(options, work) {
  const app = createBrokerServer(options);
  await new Promise(resolve => app.listen(0, "127.0.0.1", resolve));
  try { await work("http://127.0.0.1:" + app.address().port); }
  finally { await new Promise(resolve => app.close(resolve)); }
}
test("production desktop endpoint stays DEFAULT_DENY", async () => server({}, async base => {
  const response = await fetch(base + "/v1/desktop/execute", { method: "POST", body: "{}" });
  assert.equal(response.status, 403); assert.equal((await response.json()).code, "DEFAULT_DENY");
}));
test("authenticated endpoint cannot bypass absent controller", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  await server({ desktopAuthToken: token }, async base => {
    const response = await fetch(base + "/v1/desktop/execute", { method: "POST", headers: { authorization: "Bearer " + token }, body: "{}" });
    assert.equal(response.status, 403);
  });
});
test("test-only injected scoped controller requires token and rejects browser Origin", async () => {
  const token = crypto.randomBytes(32).toString("hex"); let calls = 0;
  await server({ desktopAuthToken: token, desktopController: { async execute(c) { calls++; return { id: c.id, status: "OBSERVED" }; } } }, async base => {
    const c = command("observe", crypto.randomUUID());
    for (const headers of [{}, { authorization: "Bearer wrong" },
      { authorization: "Bearer " + token, "content-type": "application/json", origin: "http://evil.invalid" }]) {
      assert.notEqual((await fetch(base + "/v1/desktop/execute", { method: "POST", headers, body: JSON.stringify(c) })).status, 200);
    }
    const response = await fetch(base + "/v1/desktop/execute", { method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify(c) });
    assert.equal(response.status, 200); assert.equal((await response.json()).id, c.id); assert.equal(calls, 1);
  });
});

test("ambiguous JSON is rejected before the controller", async () => {
  const token = crypto.randomBytes(32).toString("hex"); let calls = 0;
  await server({ desktopAuthToken: token, desktopController: { async execute() { calls++; } } }, async base => {
    const c = command("observe", crypto.randomUUID());
    const body = JSON.stringify(c).replace('"action":"observe"', '"action":"click","action":"observe"');
    const response = await fetch(base + "/v1/desktop/execute", { method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body });
    assert.equal(response.status, 403); assert.equal((await response.json()).code, "NONCANONICAL_REQUEST");
    assert.equal(calls, 0);
  });
});
test("HTTP reports uncertain input outcomes instead of definite denial", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  await server({ desktopAuthToken: token, desktopController: { async execute() { throw new Error("AGENT_DISCONNECTED"); } } }, async base => {
    const c = command("click", crypto.randomUUID(), { window: crypto.randomUUID(), element: "Button" });
    const response = await fetch(base + "/v1/desktop/execute", { method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify(c) });
    assert.equal(response.status, 409); assert.equal((await response.json()).status, "UNKNOWN");
  });
});

test("HTTP preserves unknown channel and evidence failures", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  for (const code of ["UNKNOWN_CHANNEL_FAILURE", "UNKNOWN_EVIDENCE_INVALID"]) {
    await server({ desktopAuthToken: token, desktopController: { async execute() { throw new Error(code); } } }, async base => {
      const c = command("click", crypto.randomUUID(), { window: crypto.randomUUID(), element: "Button" });
      const response = await fetch(base + "/v1/desktop/execute", { method: "POST",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify(c) });
      assert.equal(response.status, 409); assert.equal((await response.json()).status, "UNKNOWN");
    });
  }
});
