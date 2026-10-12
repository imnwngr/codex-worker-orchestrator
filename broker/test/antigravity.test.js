"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { createAntigravityProvider } = require("../providers/antigravity");

function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    return true;
  };
  return child;
}

function fakeTimer() {
  let callback;
  return {
    setTimeout(fn, delay) {
      callback = fn;
      return { callback: fn, delay };
    },
    clearTimeout() {},
    fire() {
      callback();
    }
  };
}

test("uses the expected AGY arguments and returns parsed advisory data", async () => {
  const child = fakeChild();
  const timers = fakeTimer();
  let invocation;
  const provider = createAntigravityProvider({
    spawnProcess(...args) {
      invocation = args;
      return child;
    },
    env: { TEST_ENV: "yes" },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  });

  const pending = provider.analyze({ task: "inspect this", effort: "medium", timeoutSeconds: 23 });
  assert.equal(invocation[0], "agy");
  assert.deepEqual(invocation[1].slice(0, 8), [
    "--mode", "plan", "--sandbox", "--effort", "medium",
    "--output-format", "json", "--print-timeout"
  ]);
  assert.equal(invocation[1][8], "23s");
  assert.match(invocation[1][9], /^--print=/);
  assert.match(invocation[1][9], /Codex is the sole coordinating AI agent/);
  assert.match(invocation[1][9], /Do not modify, create, rename, or delete/);
  assert.match(invocation[1][9], /Do not delegate tasks/);
  assert.equal(invocation[2].windowsHide, true);
  assert.equal(invocation[2].shell, false);
  assert.deepEqual(invocation[2].env, { TEST_ENV: "yes" });

  child.stdout.end(JSON.stringify({
    status: "SUCCESS",
    response: "  advisory response  ",
    conversation_id: "conv-1",
    usage: { total: 3 }
  }));
  child.emit("close", 0);
  assert.deepEqual(await pending, {
    response: "advisory response",
    conversation_id: "conv-1",
    usage: { total: 3 }
  });
});

test("rejects invalid output, unsuccessful status, denied actions and process errors", async t => {
  const cases = [
    ["invalid JSON", "not-json", 0, /invalid JSON/],
    ["bad status", JSON.stringify({ status: "FAILED" }), 0, /unsuccessful status/],
    ["denied actions", JSON.stringify({
      status: "SUCCESS",
      response: "text",
      denied_actions: [{ action: "write" }]
    }), 0, /denied actions/],
    ["empty response", JSON.stringify({ status: "SUCCESS", response: " " }), 0, /no usable response/],
    ["nonzero exit", "", 2, /unsuccessfully/]
  ];

  for (const [name, stdout, code, expected] of cases) {
    await t.test(name, async () => {
      const child = fakeChild();
      const provider = createAntigravityProvider({
        spawnProcess: () => child,
        setTimeout: () => 1,
        clearTimeout() {}
      });
      const pending = provider.analyze({ task: "task", effort: "high", timeoutSeconds: 10 });
      child.stdout.end(stdout);
      child.stderr.end("sensitive stderr should not escape");
      child.emit("close", code);
      await assert.rejects(pending, expected);
    });
  }

  await t.test("spawn error hides underlying details", async () => {
    const child = fakeChild();
    const provider = createAntigravityProvider({
      spawnProcess: () => child,
      setTimeout: () => 1,
      clearTimeout() {}
    });
    const pending = provider.analyze({ task: "task", effort: "high", timeoutSeconds: 10 });
    child.emit("error", new Error("secret-bearing low-level detail"));
    await assert.rejects(pending, /process failed/);
    await assert.rejects(pending, error => !/secret-bearing/.test(error.message));
  });
});

test("timeout kills the mocked child and reports a generic timeout", async () => {
  const child = fakeChild();
  const timers = fakeTimer();
  const provider = createAntigravityProvider({
    spawnProcess: () => child,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  });
  const pending = provider.analyze({ task: "task", effort: "high", timeoutSeconds: 10 });
  timers.fire();
  await assert.rejects(pending, /Antigravity broker timeout/);
  assert.equal(child.killed, true);
});

test("AbortSignal cancels an in-flight mocked AGY process", async () => {
  const child = fakeChild();
  const controller = new AbortController();
  const provider = createAntigravityProvider({
    spawnProcess: () => child,
    setTimeout: () => 1,
    clearTimeout() {}
  });
  const pending = provider.analyze({ task: "task", effort: "high", timeoutSeconds: 10, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  assert.equal(child.killed, true);
});
