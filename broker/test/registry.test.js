"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { ProviderRegistry } = require("../providers/registry");
const { validateConfig } = require("../providers/config");

function makeConfig(overrides = {}) {
  return validateConfig({
    version: 1,
    defaultProvider: "api",
    providers: [
      {
        id: "api",
        kind: "api",
        enabled: true,
        baseUrl: "https://api.example.test/v1",
        credentialEnv: "TEST_API_KEY",
        timeoutSeconds: 1,
        models: ["m1", "m2"],
        defaultModel: "m1"
      },
      {
        id: "cli",
        kind: "cli",
        enabled: true,
        timeoutSeconds: 1
      },
      {
        id: "disabled",
        kind: "api",
        enabled: false,
        credentialEnv: "DISABLED_API_KEY",
        baseUrl: "https://disabled.example.test/v1",
        timeoutSeconds: 1,
        models: ["m1"],
        defaultModel: "m1"
      }
    ],
    ...overrides
  });
}

function adapters(overrides = {}) {
  return [
    {
      id: "api",
      kind: "api",
      async analyze(request) {
        return { response: `advice from ${request.model}` };
      },
      ...overrides.api
    },
    {
      id: "cli",
      kind: "cli",
      async analyze() {
        return { response: "cli advice" };
      },
      ...overrides.cli
    }
  ];
}

test("registers and dispatches an advisory result with the configured default model", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  const result = await registry.dispatch(undefined, { task: "review" });
  assert.deepEqual(result, {
    provider: "api",
    response: "advice from m1",
    conversation_id: null,
    usage: null
  });
  assert.equal(Object.isFrozen(result), true);
});

test("allows configured API models and rejects unlisted model IDs", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  assert.equal((await registry.dispatch("api", { task: "review", model: "m2" })).response,
    "advice from m2");
  await assert.rejects(
    registry.dispatch("api", { task: "review", model: "other" }),
    /unknown model/
  );
});

test("rejects model overrides for CLI providers", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  await assert.rejects(registry.dispatch("cli", { task: "review", model: "m1" }),
    /not supported for CLI/);
});

test("rejects adapter identity and kind mismatches", () => {
  assert.throws(() => new ProviderRegistry(makeConfig(), [
    { id: "wrong-id", kind: "api", async analyze() {} },
    ...adapters().slice(1)
  ]), /no configuration entry/);

  assert.throws(() => new ProviderRegistry(makeConfig(), [
    { id: "api", kind: "cli", async analyze() {} },
    ...adapters().slice(1)
  ]), /kind does not match/);
});

test("rejects unknown and disabled providers", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  await assert.rejects(registry.dispatch("missing", { task: "x" }), /unknown or disabled/);
  await assert.rejects(registry.dispatch("disabled", { task: "x" }), /unknown or disabled/);
});

test("rejects malformed requests and request-controlled configuration", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  for (const request of [
    null,
    [],
    {},
    { task: "x", endpoint: "https://example.test" },
    { task: "x", baseUrl: "https://example.test" },
    { task: "x", credential: "secret" },
    { task: "x", apiKey: "secret" },
    { task: "x", providerConfig: {} }
  ]) {
    await assert.rejects(registry.dispatch("api", request));
  }
});

test("rejects a result that arrives after the configured timeout", async () => {
  let finished = false;
  const config = makeConfig();
  const runtime = adapters({
    api: {
      async analyze() {
        await new Promise(resolve => setTimeout(resolve, 1100));
        finished = true;
        return { response: "late advice" };
      }
    }
  });
  const registry = new ProviderRegistry(config, runtime);
  await assert.rejects(registry.dispatch("api", { task: "slow" }), /timed out/);

  // Timeout rejects the dispatch promise; it does not cancel a provider that
  // ignores the supplied AbortSignal.
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal(finished, true);
});

test("signals cancellation when dispatch times out", async () => {
  let observedAbort = false;
  const config = makeConfig();
  const runtime = adapters({
    api: {
      async analyze(request) {
        await new Promise(resolve => {
          request.signal.addEventListener("abort", () => {
            observedAbort = true;
            resolve();
          }, { once: true });
        });
        return { response: "cancelled advice" };
      }
    }
  });
  const registry = new ProviderRegistry(config, runtime);
  await assert.rejects(registry.dispatch("api", { task: "cancel" }), /timed out/);
  assert.equal(observedAbort, true);
});

test("does not claim or implement parallel dispatch in this phase", () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  assert.equal("dispatchMany" in registry, false);
});
