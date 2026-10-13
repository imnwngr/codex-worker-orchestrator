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

test("supports explicit bounded batch dispatch", () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  assert.equal(typeof registry.dispatchMany, "function");
});


test("dispatchMany mixes providers/models and preserves input order", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze(request) {
      await new Promise(resolve => setTimeout(resolve, request.model === "m1" ? 25 : 5));
      return { response: request.model, injected_control: "ignore" };
    }}
  }));
  const result = await registry.dispatchMany([
    { id: "a", provider: "api", model: "m1", task: "a" },
    { id: "b", provider: "cli", task: "b" },
    { id: "c", provider: "api", model: "m2", task: "c" }
  ], { maxParallel: 3 });
  assert.deepEqual(result.map(x => x.id), ["a", "b", "c"]);
  assert.deepEqual(result.map(x => x.status), ["success", "success", "success"]);
  assert.deepEqual(result.map(x => x.model), ["m1", null, "m2"]);
  assert.equal(result[0].output.response, "m1");
  assert.equal("injected_control" in result[0].output, false);
});

test("dispatchMany bounds concurrency", async () => {
  let active = 0;
  let peak = 0;
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze(request) {
      peak = Math.max(peak, ++active);
      await new Promise(resolve => setTimeout(resolve, 12));
      --active;
      return { response: request.model };
    }}
  }));
  const targets = Array.from({ length: 8 }, (_, i) => ({
    id: `task-${i}`, provider: "api", model: i % 2 ? "m1" : "m2", task: "x"
  }));
  const result = await registry.dispatchMany(targets, { maxParallel: 2 });
  assert.equal(peak, 2);
  assert.equal(result.length, 8);
  assert.ok(result.every(x => x.status === "success"));
});

test("dispatchMany isolates failure and redacts errors", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze() { throw new Error("API_KEY=private raw stderr"); }}
  }));
  const result = await registry.dispatchMany([
    { id: "bad", provider: "api", task: "x" },
    { id: "good", provider: "cli", task: "x" }
  ]);
  assert.deepEqual(result.map(x => x.status), ["failure", "success"]);
  assert.equal(result[0].error, "worker_failed");
  assert.doesNotMatch(JSON.stringify(result), /private|stderr/);
});

test("dispatchMany validates every target before starting anything", async () => {
  let calls = 0;
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze() { calls++; return { response: "x" }; }}
  }));
  const good = { id: "ok", provider: "api", model: "m1", task: "x" };
  for (const bad of [
    { id: "bad", provider: "api", model: "unknown", task: "x" },
    { id: "ok", provider: "cli", task: "x" },
    { id: "bad", provider: "api", task: "x", apiKey: "secret" },
    { id: "bad", provider: "missing", task: "x" },
    { id: "bad", provider: "api", task: "" }
  ]) {
    await assert.rejects(registry.dispatchMany([good, bad]));
  }
  assert.equal(calls, 0);
});

test("dispatchMany checks concurrency options", async () => {
  const registry = new ProviderRegistry(makeConfig(), adapters());
  for (const maxParallel of [0, -1, 17, 1.5, "2"]) {
    await assert.rejects(registry.dispatchMany([], { maxParallel }), /maxParallel/);
  }
  await assert.rejects(registry.dispatchMany([], { endpoint: "https://bad.test" }), /unknown/);
});

test("dispatchMany cancels active and queued work promptly", async () => {
  let started = 0;
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze(request) {
      started++;
      await new Promise((resolve, reject) => {
        if (request.signal.aborted) return reject(new Error("cancelled"));
        request.signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true });
      });
      return { response: "impossible" };
    }}
  }));
  const controller = new AbortController();
  const pending = registry.dispatchMany([
    { id: "one", provider: "api", task: "x" },
    { id: "two", provider: "api", task: "x" },
    { id: "three", provider: "api", task: "x" }
  ], { maxParallel: 2, signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  const result = await pending;
  assert.equal(started, 2);
  assert.deepEqual(result.map(x => x.error), ["cancelled", "cancelled", "cancelled"]);
});

test("dispatchMany handles pre-aborted signal without invoking providers", async () => {
  let called = false;
  const registry = new ProviderRegistry(makeConfig(), adapters({
    api: { async analyze() { called = true; return { response: "x" }; }}
  }));
  const controller = new AbortController();
  controller.abort();
  const result = await registry.dispatchMany([{ id: "one", provider: "api", task: "x" }], {
    signal: controller.signal
  });
  assert.equal(called, false);
  assert.equal(result[0].error, "cancelled");
});
