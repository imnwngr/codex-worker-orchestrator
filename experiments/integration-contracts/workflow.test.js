"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fixture = require("./fixtures/consistent-scenario.json");
const { canonicalJson, sha256Text, configurationFingerprint } = require("../../broker/providers/approval-core");
const { batchSha256 } = require("../../broker/providers/webauthn-approval");
const { prepareRequest } = require("./prepare-request");
const { renderPreview, createReview } = require("./review-preview");
const { FakeTransport, runPrepared, runRequest } = require("./fake-workflow");

function setup() {
  const request = structuredClone(fixture.request); const config = structuredClone(fixture.configuration);
  let time = request.createdAt + 2000;
  const now = () => time;
  return { request, config, now, setTime: t => { time = t; }, prepare: () => prepareRequest(request, config, { now: time, expiresAt: request.createdAt + 300000 }) };
}
function deferred() { let resolve; let reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
function scheduler() {
  let callback; let delay; let cleared = false;
  return { schedule(fn, ms) { callback = fn; delay = ms; return 1; }, unschedule() { cleared = true; }, fire() { callback(); }, get delay() { return delay; }, get cleared() { return cleared; } };
}
const flush = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };
function safe(result, status) {
  assert.equal(result.status, status); assert.equal(result.authorized, false);
  assert.equal(result.productionAuthorization, "DEFAULT_DENY");
  assert.equal(result.designation, "SYNTHETIC_DESIGN_ONLY");
}
function flow(s, transport, action = "APPROVE_MOCK", options = {}) {
  return runPrepared(s.prepare(), { now: s.now, transport, onReview: r => r.decide(action), ...options });
}

test("4B preparation reuses canonical hashes and snapshots effective wire action", () => {
  const s = setup(); const context = s.prepare();
  assert.equal(context.targets[0].task, s.request.targets[0].task.trim());
  assert.equal(context.targets[0].taskSha256, sha256Text(context.targets[0].task));
  assert.notEqual(context.targets[0].taskSha256, sha256Text(s.request.targets[0].task));
  assert.equal(context.batchSha256, batchSha256(context.targets.map(t => ({ providerId: t.providerId, modelId: t.modelId, task: t.task }))));
  const { contextSha256, ...payload } = context;
  assert.equal(contextSha256, sha256Text(canonicalJson(payload)));
  const targets = context.targets.map(t => ({ id: t.id, providerId: t.providerId, modelId: t.modelId, destination: t.destination, effort: t.metadata.requestedEffort, timeoutSeconds: t.parameters.effectiveTimeoutSeconds }));
  assert.equal(context.configurationFingerprint, configurationFingerprint({ configuration: context.configurationSnapshot, targets }));
  assert.deepEqual(context.targets[0].wire, { model: "model-alpha", messages: [{ role: "user", content: context.targets[0].task }] });
  assert.equal(context.targets[0].metadata.effortTransmission, "NOT_SENT_BY_API_ADAPTER");
  assert.equal(context.targets[0].parameters.effectiveTimeoutSeconds, 30);
  assert.equal(context.targets[0].parameters.adapterTimeoutSeconds, 120);
});

test("4B prepared action is deeply immutable after original request configuration and order mutation", () => {
  const s = setup(); const context = s.prepare(); const before = canonicalJson(context);
  s.request.targets.reverse(); s.request.targets[0].task = "substitution";
  s.config.providers[0].baseUrl = "https://changed.example.invalid/v1"; s.config.providers[0].models[0] = "changed";
  assert.equal(canonicalJson(context), before);
  assert.throws(() => { context.targets[0].task = "changed"; }, TypeError);
  assert.throws(() => context.targets.reverse(), TypeError);
  assert.throws(() => context.configurationSnapshot.providers[0].models.push("changed"), TypeError);
  assert.throws(() => { context.targets[0].wire.messages[0].content = "changed"; }, TypeError);
});

test("4B reordering destination config parameters and session changes yield distinct context identities", () => {
  const original = setup().prepare();
  for (const mutate of [s => s.request.targets.reverse(), s => { s.config.providers[0].baseUrl = "https://other.example.invalid/v1"; },
    s => { s.request.targets[0].timeoutSeconds = 15; }, s => { s.request.targets[0].effort = "low"; },
    s => { s.config.providers[0].timeoutSeconds = 100; }, s => { s.request.sessionId = "new-session"; }]) {
    const s = setup(); mutate(s); assert.notEqual(s.prepare().contextSha256, original.contextSha256);
  }
  const s = setup(); s.request.targets.reverse(); assert.notEqual(s.prepare().batchSha256, original.batchSha256);
});

test("4B preview uses identical prepared target objects and safely reversible task rendering", () => {
  const s = setup(); s.request.targets[0].task = "  Synthetic\n\u001b[31mspoof\r\n café  ";
  const context = s.prepare(); const preview = renderPreview(context);
  assert.equal(preview.targets, context.targets); assert.equal(preview.contextSha256, context.contextSha256);
  const taskLine = preview.text.split("\n").find(line => line.startsWith("Task (exact JSON string"));
  assert.equal(JSON.parse(taskLine.slice(taskLine.indexOf(": ") + 2)), context.targets[0].task);
  assert.doesNotMatch(preview.text, /\u001b/); assert.match(preview.text, /SYNTHETIC \/ NO DISPATCH/);
  assert.throws(() => renderPreview(JSON.parse(JSON.stringify(context))), /preparation rejected/);
});

test("4B unsupported fields versions identifiers models CLI and disabled targets fail closed", () => {
  for (const change of [s => { s.request.schemaVersion = 2; }, s => { s.request.targets[0].destination = "https://attacker.invalid"; },
    s => { s.request.targets[0].model = "vendor/model"; }, s => { s.request.targets[0].model = null; },
    s => { s.request.targets[0].id = "../target"; }, s => { s.request.targets[1].id = s.request.targets[0].id; },
    s => { s.request.targets[0].timeoutSeconds = 121; }, s => { s.request.targets[0].task = " \n "; },
    s => { s.request.targets[0].task = "\ud800"; }]) {
    const s = setup(); change(s); assert.throws(() => s.prepare());
  }
  const cli = setup(); cli.config.providers = [{ id: "fixture-api", kind: "cli", enabled: true, timeoutSeconds: 120 }];
  assert.throws(() => cli.prepare(), { code: "CLI_CONTEXT_UNSUPPORTED" });
  const disabled = setup(); disabled.config.providers.push({ ...structuredClone(disabled.config.providers[0]), id: "disabled", enabled: false });
  disabled.request.targets[0].provider = "disabled";
  assert.throws(() => disabled.prepare(), { code: "TARGET_NOT_CONFIGURED" });
});

test("4B destination normalization rejects non-idempotent base URLs and config secrets", () => {
  const s = setup(); s.config.providers[0].baseUrl += "//";
  assert.throws(() => s.prepare(), { code: "DESTINATION_NORMALIZATION_UNSUPPORTED" });
  const secret = setup(); secret.config.providers[0].apiKey = "DO_NOT_ECHO";
  assert.throws(() => secret.prepare(), error => error.code === "INVALID_CONFIGURATION" && !error.message.includes("DO_NOT_ECHO"));
  const lifetime = setup(); assert.throws(() => prepareRequest(lifetime.request, lifetime.config, { now: lifetime.now(), expiresAt: lifetime.request.createdAt + 300001 }), { code: "INVALID_LIFETIME" });
});

test("4B prepared wire body and endpoint match the existing API adapter with injected fake fetch", async () => {
  const s = setup(); const context = s.prepare(); const target = context.targets[0]; let observed;
  const { createOpenAICompatibleProvider } = require("../../broker/providers/openai-compatible");
  const adapter = createOpenAICompatibleProvider(context.configurationSnapshot.providers[0], {
    env: { SYNTHETIC_UNUSED_KEY: "SYNTHETIC_TEST_ONLY" },
    fetch: async (url, options) => {
      observed = { url, body: JSON.parse(options.body) };
      return { ok: true, headers: { get: () => null }, body: new ReadableStream({ start(c) { c.enqueue(Buffer.from('{"choices":[{"message":{"content":"fake"}}]}')); c.close(); } }) };
    }
  });
  await adapter.analyze({ task: target.task, model: target.modelId, effort: target.metadata.requestedEffort, timeoutSeconds: target.parameters.effectiveTimeoutSeconds });
  assert.equal(observed.url, target.destination); assert.deepEqual(observed.body, target.wire);
  assert.equal(Object.hasOwn(observed.body, "effort"), false);
});

test("4B client preparation preview explicit mock approval and fake completion work together", async () => {
  const s = setup(); const transport = new FakeTransport({ now: s.now }); let preview;
  const result = await runRequest(s.request, s.config, { now: s.now, expiresAt: s.request.createdAt + 300000, transport,
    onReview: r => { preview = r.preview; return r.decide("APPROVE_MOCK"); } });
  safe(result, "MOCK_COMPLETED"); assert.equal(result.contextSha256, preview.contextSha256);
  assert.deepEqual(result.history, ["PREPARED", "SUBMITTED", "MOCK_COMPLETED"]);
  assert.deepEqual(result.results.map(r => r.id), s.request.targets.map(t => t.id));
  assert.equal(transport.deliveryCount, 1);
  assert.equal(Object.hasOwn(result, "signature"), false);
});

test("4B explicit rejection prevents fake processing even when processing gate never resolves", async () => {
  const s = setup(); const transport = new FakeTransport({ now: s.now, processingGate: deferred().promise });
  const result = await flow(s, transport, "REJECT"); safe(result, "REJECTED");
  assert.equal(result.operationState, "NOT_STARTED"); assert.deepEqual(result.results, []);
});

test("4B cancellation before submission never delivers a context", async () => {
  const s = setup(); const controller = new AbortController(); controller.abort(); const transport = new FakeTransport({ now: s.now });
  safe(await flow(s, transport, "APPROVE_MOCK", { signal: controller.signal }), "NOT_SUBMITTED");
  assert.equal(transport.deliveryCount, 0);
});

test("4B cancellation during review closes preview and prevents late mock approval", async () => {
  const s = setup(); const controller = new AbortController(); const pending = deferred(); let review;
  const transport = new FakeTransport({ now: s.now });
  const resultPromise = flow(s, transport, "APPROVE_MOCK", { signal: controller.signal, onReview: r => { review = r; return pending.promise; } });
  controller.abort(); const result = await resultPromise; safe(result, "CANCELLED");
  assert.equal(review.view().canDecide, false); assert.equal(review.decide("APPROVE_MOCK").state, "Cancelled");
  pending.resolve(review.decide("APPROVE_MOCK")); await flush();
  safe(result, "CANCELLED");
});

test("4B cancellation after potential fake processing is unknown and cannot replay", async () => {
  const s = setup(); const gate = deferred(); const controller = new AbortController(); const transport = new FakeTransport({ now: s.now, processingGate: gate.promise });
  const resultPromise = flow(s, transport, "APPROVE_MOCK", { signal: controller.signal }); await flush(); controller.abort();
  const result = await resultPromise; safe(result, "OUTCOME_UNKNOWN"); assert.equal(result.operationState, "MAY_HAVE_STARTED");
  gate.resolve(); await flush(); safe(result, "OUTCOME_UNKNOWN");
  const replay = await flow(s, transport); safe(replay, "NOT_SUBMITTED"); assert.equal(replay.reason, "DUPLICATE_REQUEST");
});

test("4B expiry before submission and pending review cannot be revived", async () => {
  const s = setup(); const context = s.prepare(); const transport = new FakeTransport({ now: s.now });
  s.setTime(context.expiresAt); safe(await runPrepared(context, { now: s.now, transport, onReview: r => r.decide("APPROVE_MOCK") }), "EXPIRED");
  assert.equal(transport.deliveryCount, 0);
  const r = createReview(context, s.now); assert.equal(r.decide("APPROVE_MOCK").state, "Expired");
  const pending = setup(); const timer = scheduler(); const wait = deferred(); let review;
  const prepared = pending.prepare();
  const promise = runPrepared(prepared, { now: pending.now, transport: new FakeTransport({ now: pending.now }),
    onReview: value => { review = value; return wait.promise; }, timeoutMs: 300000, schedule: timer.schedule, unschedule: timer.unschedule });
  pending.setTime(prepared.expiresAt); timer.fire(); safe(await promise, "EXPIRED");
  assert.equal(review.decide("APPROVE_MOCK").state, "Expired");
  wait.resolve(review.decide("APPROVE_MOCK")); await flush();
});

test("4B expiry during fake processing locks the client outcome against delayed response", async () => {
  const s = setup(); const gate = deferred(); const timer = scheduler(); const context = s.prepare(); const transport = new FakeTransport({ now: s.now, processingGate: gate.promise });
  const promise = runPrepared(context, { now: s.now, transport, onReview: r => r.decide("APPROVE_MOCK"), timeoutMs: 300000, schedule: timer.schedule, unschedule: timer.unschedule });
  await flush(); assert.equal(timer.delay, context.expiresAt - s.now()); s.setTime(context.expiresAt); timer.fire();
  const result = await promise; safe(result, "EXPIRED"); assert.equal(result.operationState, "MAY_HAVE_STARTED");
  gate.resolve(); await flush(); safe(result, "EXPIRED"); assert.equal(timer.cleared, true);
});

test("4B timeout distinguishes pending review from potential processing", async () => {
  for (const processing of [false, true]) {
    const s = setup(); const gate = deferred(); const timer = scheduler(); const transport = new FakeTransport({ now: s.now, processingGate: gate.promise });
    const promise = flow(s, transport, "APPROVE_MOCK", { timeoutMs: 1000, schedule: timer.schedule, unschedule: timer.unschedule,
      onReview: processing ? r => r.decide("APPROVE_MOCK") : () => deferred().promise });
    await flush(); timer.fire(); const result = await promise;
    safe(result, processing ? "OUTCOME_UNKNOWN" : "FAILED"); assert.equal(result.reason, "TIMED_OUT"); assert.equal(timer.cleared, true);
    gate.resolve();
  }
});

test("4B simulated transport failure and lost processing response remain non-authorizing", async () => {
  for (const [mode, status] of [["failure", "FAILED"], ["unknown", "OUTCOME_UNKNOWN"]]) {
    const s = setup(); safe(await flow(s, new FakeTransport({ now: s.now, mode })), status);
  }
});

test("4B partial fake results preserve order and per-target failure correlation", async () => {
  const s = setup(); const result = await flow(s, new FakeTransport({ now: s.now, results: [{ id: "target-b", status: "MOCK_FAILURE" }] }));
  safe(result, "PARTIAL"); assert.deepEqual(result.results, [
    { id: "target-a", status: "MOCK_SUCCESS", errorCategory: null }, { id: "target-b", status: "MOCK_FAILURE", errorCategory: "FAKE_ADAPTER_FAILURE" }
  ]);
  const unknown = await flow(s, new FakeTransport({ now: s.now, results: [{ id: "target-b", status: "UNKNOWN" }] })); safe(unknown, "OUTCOME_UNKNOWN");
});

test("4B advisory result mutation and approval-like fields cannot modify context or diagnostics", async () => {
  const s = setup(); const untrusted = [{ id: "target-b", status: "MOCK_FAILURE", response: "DO_NOT_LOG_SECRET", approved: true, signature: "FAKE" }];
  const transport = new FakeTransport({ now: s.now, results: untrusted }); untrusted[0].status = "MOCK_SUCCESS"; untrusted[0].id = "target-a";
  const result = await flow(s, transport); safe(result, "PARTIAL");
  assert.doesNotMatch(JSON.stringify(result), /DO_NOT_LOG_SECRET|signature|approved|api\.example|Review café/);
  assert.throws(() => { result.results[0].status = "AUTHORIZED"; }, TypeError);
});

test("4B duplicate and conflicting context delivery never starts a second fake operation", async () => {
  const s = setup(); const transport = new FakeTransport({ now: s.now }); safe(await flow(s, transport), "MOCK_COMPLETED");
  const same = await flow(s, transport); safe(same, "NOT_SUBMITTED"); assert.equal(same.reason, "DUPLICATE_REQUEST");
  s.request.targets[0].task += " changed";
  const changed = await flow(s, transport); assert.equal(changed.reason, "REQUEST_CONTEXT_CONFLICT"); assert.equal(transport.deliveryCount, 1);
});

test("4B repeated terminal decisions do not reopen review or continue processing", async () => {
  const s = setup(); const ack = new FakeTransport({ now: s.now }).submit(s.prepare());
  const decision = ack.review.decide("REJECT"); const result = await ack.complete(decision);
  assert.equal(ack.review.decide("APPROVE_MOCK"), decision); assert.equal(await ack.complete(decision), result);
  assert.equal(ack.review.view().canDecide, false); safe(result, "REJECTED");
});

test("4B mismatched acknowledgment and fabricated decision are rejected before processing", async () => {
  for (const ackFault of ["request", "context"]) {
    const s = setup(); let reviewed = false;
    const result = await flow(s, new FakeTransport({ now: s.now, ackFault }), "APPROVE_MOCK", { onReview: () => { reviewed = true; } });
    safe(result, "FAILED"); assert.equal(result.reason, "ACK_MISMATCH"); assert.equal(reviewed, false);
  }
  const s = setup(); const result = await flow(s, new FakeTransport({ now: s.now }), "APPROVE_MOCK", {
    onReview: r => ({ ...r.decide("APPROVE_MOCK"), contextSha256: "0".repeat(64) })
  }); safe(result, "FAILED"); assert.equal(result.reason, "DECISION_MISMATCH");
});

test("4B preparation and callback failures return fixed diagnostics without secret input", async () => {
  const s = setup(); s.request.targets[0].task = null;
  const failed = await runRequest(s.request, s.config, { now: s.now, expiresAt: s.request.createdAt + 300000 }); safe(failed, "NOT_SUBMITTED"); assert.equal(failed.reason, "PREPARATION_REJECTED");
  const valid = setup(); const result = await flow(valid, new FakeTransport({ now: valid.now }), "APPROVE_MOCK", { onReview: () => { throw new Error("SECRET_CONFIGURATION_VALUE"); } });
  safe(result, "FAILED"); assert.doesNotMatch(JSON.stringify(result), /SECRET_CONFIGURATION_VALUE/);
});

test("4B fake workflow cannot invoke fetch or construct production approval proofs", async t => {
  t.mock.method(globalThis, "fetch", () => { throw new Error("live fetch forbidden"); });
  const net = require("node:net"); const child = require("node:child_process");
  t.mock.method(net, "connect", () => { throw new Error("socket forbidden"); });
  t.mock.method(child, "spawn", () => { throw new Error("provider process forbidden"); });
  const s = setup(); const context = s.prepare(); const result = await flow(s, new FakeTransport({ now: s.now }));
  safe(result, "MOCK_COMPLETED"); assert.equal(fetch.mock.callCount(), 0);
  assert.equal(net.connect.mock.callCount(), 0); assert.equal(child.spawn.mock.callCount(), 0);
  for (const key of ["signature", "assertion", "approvalData", "credentialId", "nonce"]) assert.equal(Object.hasOwn(context, key), false);
});

test("4B bounded fake delivery registry retains duplicates without eviction and result IDs must match", async () => {
  const s = setup(); const transport = new FakeTransport({ now: s.now });
  for (let i = 0; i < 32; i++) {
    s.request.requestId = `bounded-${i}`;
    safe(await flow(s, transport, "REJECT"), "REJECTED");
  }
  s.request.requestId = "overflow";
  const overflow = await flow(s, transport); assert.equal(overflow.reason, "FAKE_CAPACITY_REACHED"); assert.equal(transport.deliveryCount, 32);
  s.request.requestId = "bounded-0"; assert.equal((await flow(s, transport)).reason, "DUPLICATE_REQUEST");
  const mismatched = await flow(setup(), new FakeTransport({ now: s.now, results: [{ id: "not-a-target", status: "MOCK_SUCCESS" }] }));
  safe(mismatched, "NOT_SUBMITTED"); assert.equal(mismatched.reason, "RESULT_ID_MISMATCH");
});

test("4B clock and interruption diagnostics fail safely without echoing arbitrary reasons", async () => {
  const s = setup(); const ack = new FakeTransport({ now: s.now }).submit(s.prepare());
  const result = ack.interrupt("SECRET_INPUT"); safe(result, "FAILED"); assert.equal(result.reason, "CLIENT_FAILURE");
  assert.doesNotMatch(JSON.stringify(result), /SECRET_INPUT/);
  const badClock = setup(); const wait = deferred(); const controller = new AbortController();
  const promise = flow(badClock, new FakeTransport({ now: badClock.now }), "APPROVE_MOCK", {
    signal: controller.signal, onReview: () => wait.promise
  });
  badClock.setTime(NaN); controller.abort(); const failed = await promise;
  safe(failed, "FAILED"); assert.equal(failed.reason, "INVALID_CLOCK");
  wait.resolve(null);
});
