"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateConfig } = require("../providers/config");
const { createRuntimeAdapters } = require("../providers/runtime");

function config(providers) {
  return validateConfig({
    version: 1,
    defaultProvider: "antigravity",
    providers: [{
      id: "antigravity",
      kind: "cli",
      enabled: true,
      timeoutSeconds: 30
    }, ...providers]
  });
}

test("constructs enabled runtime adapters separately from serializable config", () => {
  const validated = config([{
    id: "api-one",
    kind: "api",
    enabled: true,
    baseUrl: "https://api.example.test/v1",
    timeoutSeconds: 30,
    models: ["one", "two"],
    defaultModel: "one",
    credentialEnv: "API_ONE_KEY"
  }]);
  const adapters = createRuntimeAdapters(validated, {
    antigravity: { spawnProcess() { throw new Error("must not spawn in this test"); } },
    api: { env: {}, fetch: async () => { throw new Error("must not fetch in this test"); } }
  });
  assert.deepEqual(adapters.map(adapter => [adapter.id, adapter.kind]), [
    ["antigravity", "cli"],
    ["api-one", "api"]
  ]);
  assert.equal(Object.hasOwn(validated.providers[1], "credential"), false);
  assert.equal(Object.hasOwn(adapters[1], "credential"), false);
});

test("does not construct adapters or read credentials for disabled providers", () => {
  let reads = 0;
  const env = new Proxy({}, {
    get() { reads++; return "should-not-be-read"; }
  });
  const adapters = createRuntimeAdapters(config([{
    id: "api-off",
    kind: "api",
    enabled: false,
    baseUrl: "https://api.example.test/v1",
    timeoutSeconds: 30,
    models: ["one"],
    defaultModel: "one",
    credentialEnv: "API_OFF_KEY"
  }]), { api: { env } });
  assert.deepEqual(adapters.map(adapter => adapter.id), ["antigravity"]);
  assert.equal(reads, 0);
});

test("rejects unsupported enabled CLI providers", () => {
  const invalidRuntime = Object.freeze({
    defaultProvider: "other-cli",
    providers: Object.freeze([Object.freeze({
      id: "other-cli",
      kind: "cli",
      enabled: true,
      timeoutSeconds: 30
    })])
  });
  assert.throws(() => createRuntimeAdapters(invalidRuntime), /unsupported enabled CLI/);
});
