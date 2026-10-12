"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateConfig } = require("../providers/config");
const { createOpenAICompatibleProvider, MAX_RESPONSE_BYTES } =
  require("../providers/openai-compatible");

function apiConfig(overrides = {}) {
  const config = validateConfig({
    version: 1,
    defaultProvider: "api-one",
    providers: [{
      id: "api-one",
      kind: "api",
      enabled: true,
      baseUrl: "https://api.example.test/v1",
      timeoutSeconds: 5,
      models: ["model-a", "model-b"],
      defaultModel: "model-a",
      credentialEnv: "TEST_API_KEY"
    }]
  });
  return { ...config.providers[0], ...overrides };
}

function mockResponse(body, options = {}) {
  const bytes = Buffer.from(body);
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    headers: {
      get(name) {
        return name.toLowerCase() === "content-length" && options.contentLength
          ? String(options.contentLength)
          : null;
      }
    },
    body: new ReadableStream({
      start(controller) {
        if (options.chunks) {
          for (const chunk of options.chunks) controller.enqueue(Buffer.from(chunk));
        } else {
          controller.enqueue(bytes);
        }
        controller.close();
      }
    })
  };
}

test("sends allowlisted model and task with runtime-only bearer credential", async () => {
  const calls = [];
  const env = { TEST_API_KEY: "test-secret" };
  const provider = createOpenAICompatibleProvider(apiConfig(), {
    env,
    fetch: async (...args) => {
      calls.push(args);
      return mockResponse(JSON.stringify({
        id: "completion-id",
        choices: [{ message: { content: "  advisory answer  " } }],
        usage: { total_tokens: 7 }
      }));
    }
  });

  const result = await provider.analyze({ task: "review", model: "model-b" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "https://api.example.test/v1/chat/completions");
  assert.equal(calls[0][1].method, "POST");
  assert.equal(calls[0][1].headers.authorization, "Bearer test-secret");
  assert.deepEqual(JSON.parse(calls[0][1].body), {
    model: "model-b",
    messages: [{ role: "user", content: "review" }]
  });
  assert.deepEqual(result, {
    response: "advisory answer",
    conversation_id: "completion-id",
    usage: { total_tokens: 7 }
  });
  assert.equal(Object.hasOwn(provider, "credential"), false);
});

test("uses configured default model and rejects unconfigured overrides", async () => {
  let called = false;
  const provider = createOpenAICompatibleProvider(apiConfig(), {
    env: { TEST_API_KEY: "key" },
    fetch: async (_url, options) => {
      called = true;
      assert.equal(JSON.parse(options.body).model, "model-a");
      return mockResponse(JSON.stringify({
        choices: [{ message: { content: "answer" } }]
      }));
    }
  });

  await provider.analyze({ task: "review" });
  assert.equal(called, true);
  await assert.rejects(provider.analyze({ task: "review", model: "other" }), /not configured/);
});

test("requires runtime credential and does not expose it in error messages", async () => {
  let calls = 0;
  const provider = createOpenAICompatibleProvider(apiConfig(), {
    env: {},
    fetch: async () => { calls += 1; }
  });
  await assert.rejects(provider.analyze({ task: "review" }), /credential is unavailable/);
  assert.equal(calls, 0);
});

test("hides provider response details and request credentials on HTTP failures", async () => {
  const secret = "top-secret-value";
  const provider = createOpenAICompatibleProvider(apiConfig(), {
    env: { TEST_API_KEY: secret },
    fetch: async () => mockResponse(secret, { ok: false, status: 401 })
  });
  await assert.rejects(provider.analyze({ task: "review" }), error => {
    assert.match(error.message, /request failed/);
    assert.doesNotMatch(error.message, new RegExp(secret));
    return true;
  });
});

test("rejects an oversized declared or streamed response", async () => {
  const env = { TEST_API_KEY: "key" };
  const declared = createOpenAICompatibleProvider(apiConfig(), {
    env,
    maxResponseBytes: 8,
    fetch: async () => mockResponse("{}", { contentLength: 9 })
  });
  await assert.rejects(declared.analyze({ task: "x" }), /size limit/);

  const streamed = createOpenAICompatibleProvider(apiConfig(), {
    env,
    maxResponseBytes: 8,
    fetch: async () => mockResponse("", { chunks: ["12345", "67890"] })
  });
  await assert.rejects(streamed.analyze({ task: "x" }), /size limit/);
  assert.equal(MAX_RESPONSE_BYTES, 1024 * 1024);
});

test("rejects malformed provider responses without leaking body contents", async () => {
  const provider = createOpenAICompatibleProvider(apiConfig(), {
    env: { TEST_API_KEY: "key" },
    fetch: async () => mockResponse("private-provider-error")
  });
  await assert.rejects(provider.analyze({ task: "x" }), error => {
    assert.match(error.message, /invalid JSON/);
    assert.doesNotMatch(error.message, /private-provider-error/);
    return true;
  });

  const noContent = createOpenAICompatibleProvider(apiConfig(), {
    env: { TEST_API_KEY: "key" },
    fetch: async () => mockResponse(JSON.stringify({ choices: [] }))
  });
  await assert.rejects(noContent.analyze({ task: "x" }), /no usable response/);
});

test("aborts the HTTP request on timeout and caller cancellation", async t => {
  await t.test("timeout", async () => {
    let receivedSignal;
    const provider = createOpenAICompatibleProvider(apiConfig({ timeoutSeconds: 1 }), {
      env: { TEST_API_KEY: "key" },
      fetch: async (_url, options) => {
        receivedSignal = options.signal;
        return new Promise((resolve, reject) => {
          options.signal.addEventListener("abort", () => reject(new Error("network detail")), { once: true });
        });
      }
    });
    await assert.rejects(provider.analyze({ task: "slow" }), /timed out/);
    assert.equal(receivedSignal.aborted, true);
  });

  await t.test("caller signal", async () => {
    const controller = new AbortController();
    let receivedSignal;
    const provider = createOpenAICompatibleProvider(apiConfig(), {
      env: { TEST_API_KEY: "key" },
      fetch: async (_url, options) => {
        receivedSignal = options.signal;
        return new Promise((resolve, reject) => {
          options.signal.addEventListener("abort", () => reject(new Error("network detail")), { once: true });
        });
      }
    });
    const pending = provider.analyze({ task: "cancel", signal: controller.signal });
    controller.abort();
    await assert.rejects(pending, /cancelled/);
    assert.equal(receivedSignal.aborted, true);
  });
});

test("validates adapter config and never calls a real network", async () => {
  assert.throws(() => createOpenAICompatibleProvider({ kind: "cli" }), /validated API/);
  const config = apiConfig({ baseUrl: "http://insecure.example" });
  let called = false;
  assert.throws(() => createOpenAICompatibleProvider(config, {
    env: { TEST_API_KEY: "key" },
    fetch: async () => { called = true; }
  }), /HTTPS/);
  assert.equal(called, false);
});
