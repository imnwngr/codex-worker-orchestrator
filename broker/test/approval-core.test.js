"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  ApprovalVerifier,
  canonicalJson,
  configurationFingerprint,
  sha256Text
} = require("../providers/approval-core");

// Ephemeral signatures in this test file are fixtures for verifier behavior.
// They do not represent production user approval or an installed issuer.
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const NOW = 1_800_000_000_000;
const SESSION = "broker-session-test";
const BATCH = "batch-test";
const CONFIG = Object.freeze({
  version: 1,
  providers: Object.freeze([Object.freeze({
    id: "provider-a", kind: "api", baseUrl: "https://api.example.test/v1",
    models: Object.freeze(["model-a", "model-b"])
  })])
});
const FINGERPRINT = configurationFingerprint(CONFIG);
const target = (overrides = {}) => ({
  providerId: "provider-a",
  modelId: "model-a",
  task: "exact task content",
  ...overrides
});

function fixture(overrides = {}) {
  const data = {
    version: 1,
    approvalId: "approval-a",
    providerId: "provider-a",
    modelId: "model-a",
    taskSha256: sha256Text("exact task content"),
    configFingerprint: FINGERPRINT,
    batchId: BATCH,
    nonce: crypto.randomBytes(32).toString("base64url"),
    sessionId: SESSION,
    expiresAt: NOW + 60_000,
    ...overrides
  };
  const signature = crypto.sign(
    null, Buffer.from(canonicalJson(data), "utf8"), privateKey
  ).toString("base64url");
  return { ...data, signature };
}

function verifier(options = {}) {
  return new ApprovalVerifier({
    trustedPublicKey: publicKey,
    sessionId: SESSION,
    now: () => NOW,
    ...options
  });
}

function consume(instance, grants = [fixture()], targets = [target()], context = {}) {
  return instance.verifyAndConsumeBatch(grants, targets, {
    batchId: BATCH,
    configFingerprint: FINGERPRINT,
    ...context
  });
}

test("canonical JSON sorts object keys recursively and hashes exact task text", () => {
  assert.equal(
    canonicalJson({ z: 1, a: { y: true, x: "v" } }),
    '{"a":{"x":"v","y":true},"z":1}'
  );
  assert.equal(configurationFingerprint({ b: 2, a: 1 }),
    configurationFingerprint({ a: 1, b: 2 }));
  assert.notEqual(sha256Text("task"), sha256Text(" task"));
  assert.throws(() => canonicalJson({ value: undefined }), /canonical JSON/);
});

test("requires an explicit Ed25519 public key and broker session", () => {
  assert.throws(() => new ApprovalVerifier({ sessionId: SESSION }), /options/);
  assert.throws(() => new ApprovalVerifier({
    trustedPublicKey: crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey,
    sessionId: SESSION
  }), /Ed25519/);
});

test("accepts a valid signed grant and emits a sanitized audit event", () => {
  const events = [];
  const instance = verifier({ audit: event => events.push(event) });
  const result = consume(instance);
  assert.equal(result.length, 1);
  assert.equal(result[0].providerId, "provider-a");
  assert.equal(events[0].event, "approval_consumed");
  assert.equal(Object.hasOwn(events[0], "task"), false);
  assert.doesNotMatch(JSON.stringify(events), /signature|privateKey|exact task content/);
});

test("rejects forged signatures and altered signed data", () => {
  const forged = fixture();
  forged.signature = crypto.randomBytes(64).toString("base64url");
  assert.throws(() => consume(verifier(), [forged]), /approval grant rejected/);

  const altered = fixture();
  altered.modelId = "model-b";
  assert.throws(() => consume(verifier(), [altered]), /approval grant rejected/);
});

test("rejects expired grants and grants from another broker session", () => {
  assert.throws(() => consume(verifier(), [fixture({ expiresAt: NOW })]),
    /approval grant rejected/);

  const otherSessionGrant = fixture({ sessionId: "another-session" });
  assert.throws(() => consume(verifier(), [otherSessionGrant]),
    /approval grant rejected/);
  assert.throws(() => consume(verifier({ sessionId: "new-broker-session" })),
    /approval grant rejected/);
});

test("rejects target, batch, and configuration fingerprint mismatches", () => {
  assert.throws(() => consume(verifier(), [fixture()], [
    target({ task: "changed task" })
  ]), /approval grant rejected/);
  assert.throws(() => consume(verifier(), [fixture()], [target()], {
    batchId: "other-batch"
  }), /approval grant rejected/);
  assert.throws(() => consume(verifier(), [fixture()], [target()], {
    configFingerprint: "0".repeat(64)
  }), /approval grant rejected/);
  assert.throws(() => consume(verifier(), [fixture()], [
    target({ providerId: "provider-b" })
  ]), /approval grant rejected/);
  assert.throws(() => consume(verifier(), [fixture()], [
    target({ modelId: "model-b" })
  ]), /approval grant rejected/);
});

test("rejects unknown fields, malformed hashes, and non-canonical signatures", () => {
  const extra = { ...fixture(), task: "secret task must not be accepted" };
  assert.throws(() => consume(verifier(), [extra]), /approval grant rejected/);
  const badHash = fixture({ taskSha256: "bad" });
  assert.throws(() => consume(verifier(), [badHash]), /approval grant rejected/);
  const badSignature = fixture();
  badSignature.signature += "=";
  assert.throws(() => consume(verifier(), [badSignature]), /approval grant rejected/);
});

test("consumes a grant once and rejects sequential and concurrent replay", async () => {
  const instance = verifier();
  const grant = fixture();
  consume(instance, [grant]);
  assert.throws(() => consume(instance, [grant]), /approval grant rejected/);

  const another = fixture({
    approvalId: "approval-concurrent",
    nonce: crypto.randomBytes(32).toString("base64url")
  });
  const results = await Promise.allSettled([
    Promise.resolve().then(() => consume(instance, [another])),
    Promise.resolve().then(() => consume(instance, [another]))
  ]);
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(results.filter(result => result.status === "rejected").length, 1);
});

test("multi-target consumption is all-or-none", () => {
  const instance = verifier();
  const first = fixture();
  const second = fixture({
    approvalId: "approval-b",
    nonce: crypto.randomBytes(32).toString("base64url"),
    taskSha256: sha256Text("second task")
  });
  const targets = [target(), target({ task: "second task" })];
  const invalidSecond = { ...second, signature: crypto.randomBytes(64).toString("base64url") };
  assert.throws(() => consume(instance, [first, invalidSecond], targets),
    /approval grant rejected/);
  // Failure of the second grant must not consume the first.
  assert.doesNotThrow(() => consume(instance, [first], [targets[0]]));
});

test("rejects duplicate nonce or approval IDs inside one batch", () => {
  const first = fixture();
  const duplicateNonce = fixture({
    approvalId: "approval-b",
    nonce: first.nonce,
    taskSha256: sha256Text("second task")
  });
  assert.throws(() => consume(verifier(), [first, duplicateNonce], [
    target(), target({ task: "second task" })
  ]), /approval grant rejected/);
});

test("audit callback failure cannot approve or leak grant data", () => {
  const instance = verifier({ audit() { throw new Error("sensitive audit failure"); } });
  assert.doesNotThrow(() => consume(instance));
  assert.throws(() => consume(instance), /approval grant rejected/);
});
