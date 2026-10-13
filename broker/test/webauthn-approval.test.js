"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  OfflineWebAuthnApprovalVerifier: Verifier, challengeFor, batchSha256
} = require("../providers/webauthn-approval");
const { sha256Text, configurationFingerprint, ApprovalVerifier, canonicalJson } = require("../providers/approval-core");

// Synthetic credentials: NOT enrolled Windows Hello keys or user authorization.
const es = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const rs = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ed = crypto.generateKeyPairSync("ed25519");
const esId = crypto.randomBytes(32).toString("base64url");
const rsId = crypto.randomBytes(32).toString("base64url");
const origin = "https://approval.example.test";
const rpId = "example.test";
const now = 1800000000000;
const sessionId = "session-fixture";
const configFingerprint = configurationFingerprint({
  providerId: "api-a", modelId: "m1", resolvedEndpoint: "https://api.example.test/v1"
});
const target = (overrides = {}) => ({ providerId: "api-a", modelId: "m1", task: "review this text", ...overrides });
const credentials = [
  { id: esId, algorithm: -7, publicKey: es.publicKey },
  { id: rsId, algorithm: -257, publicKey: rs.publicKey }
];
const makeVerifier = (overrides = {}) => new Verifier({
  origin, rpId, sessionId, configFingerprint, credentials, now: () => now, ...overrides
});
const baseData = (targets, i = 0, overrides = {}) => ({
  version: 1,
  approvalId: `approved-${i}`,
  providerId: targets[i].providerId,
  modelId: targets[i].modelId,
  taskSha256: sha256Text(targets[i].task),
  configFingerprint,
  batchId: "batch-fixture",
  batchSha256: batchSha256(targets),
  nonce: crypto.randomBytes(32).toString("base64url"),
  sessionId,
  expiresAt: now + 30000,
  ...overrides
});

function assertion(data, overrides = {}) {
  const algorithm = overrides.algorithm ?? -7;
  const keypair = algorithm === -257 ? rs : es;
  const credentialId = overrides.credentialId ?? (algorithm === -257 ? rsId : esId);
  const client = {
    type: "webauthn.get",
    challenge: challengeFor(data),
    origin,
    ...(overrides.client || {})
  };
  const clientDataJSON = Buffer.from(JSON.stringify(client));
  const auth = Buffer.alloc(37);
  crypto.createHash("sha256").update(rpId).digest().copy(auth, 0);
  auth[32] = overrides.flags ?? 0x05;
  auth.writeUInt32BE(overrides.signCount ?? 0, 33);
  if (overrides.rpHash) Buffer.from(overrides.rpHash).copy(auth, 0);
  const message = Buffer.concat([auth, crypto.createHash("sha256").update(clientDataJSON).digest()]);
  const signature = crypto.sign("sha256", message, keypair.privateKey);
  return {
    credentialId,
    credentialAlgorithm: algorithm,
    clientDataJSON: clientDataJSON.toString("base64url"),
    authenticatorData: auth.toString("base64url"),
    signature: signature.toString("base64url")
  };
}
function proof(targets = [target()], i = 0, dataOverrides = {}, assertionOverrides = {}) {
  const approvalData = baseData(targets, i, dataOverrides);
  return { version: 1, approvalData, assertion: assertion(approvalData, assertionOverrides) };
}
const consume = (verifier, envelopes, targets = [target()]) =>
  verifier.verifyAndConsumeBatch(envelopes, targets, { batchId: "batch-fixture" });

function rejects(envelope, targets = [target()], verifier = makeVerifier()) {
  assert.throws(() => consume(verifier, [envelope], targets), /WebAuthn approval rejected/);
}

test("domain-separated challenges bind every approval field", () => {
  const initial = baseData([target()]);
  assert.match(challengeFor(initial), /^[A-Za-z0-9_-]{43}$/);
  for (const [key, value] of Object.entries({
    approvalId: "changed", providerId: "other-provider", modelId: "other-model",
    taskSha256: "0".repeat(64), configFingerprint: "0".repeat(64),
    batchId: "another-batch", batchSha256: "0".repeat(64),
    nonce: crypto.randomBytes(32).toString("base64url"),
    sessionId: "new-session", expiresAt: initial.expiresAt + 1
  })) {
    assert.notEqual(challengeFor({ ...initial, [key]: value }), challengeFor(initial), key);
  }
});

test("accepts synthetic ES256 and RS256 assertions from pinned trusted keys", () => {
  const t = [target()];
  assert.equal(consume(makeVerifier(), [proof(t)]).length, 1);
  assert.equal(consume(makeVerifier(), [proof(t, 0, {}, { algorithm: -257 })]).length, 1);
});

test("rejects modified assertions, signatures and unsupported algorithms", () => {
  const t = [target()];
  const broken = proof(t);
  broken.assertion.signature = crypto.randomBytes(71).toString("base64url");
  rejects(broken);
  const altered = proof(t);
  altered.approvalData.taskSha256 = "0".repeat(64);
  rejects(altered);
  const unknown = proof(t);
  unknown.assertion.credentialAlgorithm = -8;
  rejects(unknown);
});

test("rejects wrong origin, challenge, wrong WebAuthn type and cross-origin assertions", () => {
  const t = [target()];
  for (const client of [
    { origin: "https://attacker.example.test" },
    { challenge: crypto.randomBytes(32).toString("base64url") },
    { type: "webauthn.create" },
    { crossOrigin: true }
  ]) rejects(proof(t, 0, {}, { client }));
});

test("rejects wrong RP ID hash, missing UP, missing UV and unexpected extension bits", () => {
  const t = [target()];
  rejects(proof(t, 0, {}, { rpHash: crypto.randomBytes(32) }));
  for (const flags of [0, 0x01, 0x04, 0x45, 0x85]) {
    rejects(proof(t, 0, {}, { flags }));
  }
});

test("rejects unregistered credential ID, incorrect algorithm and attacker-supplied keys", () => {
  const t = [target()];
  rejects(proof(t, 0, {}, { credentialId: crypto.randomBytes(32).toString("base64url") }));
  const swapped = proof(t);
  swapped.assertion.credentialAlgorithm = -257;
  rejects(swapped);
  const injected = proof(t);
  injected.assertion.publicKey = es.publicKey.export({ type: "spki", format: "pem" });
  rejects(injected);
});

test("rejects task, provider, model, destination/config, batch, session and expiry changes", () => {
  const t = [target()];
  rejects(proof(t), [target({ task: "modified" })]);
  rejects(proof(t), [target({ providerId: "api-b" })]);
  rejects(proof(t), [target({ modelId: "m2" })]);
  rejects(proof(t), t, makeVerifier({ configFingerprint: "0".repeat(64) }));
  rejects(proof(t), t, makeVerifier({ sessionId: "new-session" }));
  rejects(proof(t, 0, { expiresAt: now }));
  rejects(proof(t, 0, { expiresAt: now + 300001 }));
  rejects(proof(t, 0, { batchId: "other-batch" }));
});

test("batch digest binds exact ordered target set and denies altered composition", () => {
  const t = [target(), target({ task: "second" })];
  assert.notEqual(batchSha256(t), batchSha256([...t].reverse()));
  assert.notEqual(batchSha256(t), batchSha256([t[0]]));
  assert.notEqual(batchSha256(t), batchSha256([t[0], target({ task: "third" })]));
  rejects(proof(t), [t[0]]);
});

test("one-time consumption rejects sequential and concurrently scheduled replay", async () => {
  const t = [target()];
  const signed = proof(t);
  const verifier = makeVerifier();
  consume(verifier, [signed]);
  rejects(signed, t, verifier);
  const fresh = proof(t, 0, { approvalId: "approved-concurrent" });
  const concurrent = await Promise.allSettled([
    Promise.resolve().then(() => consume(verifier, [fresh])),
    Promise.resolve().then(() => consume(verifier, [fresh]))
  ]);
  assert.equal(concurrent.filter(x => x.status === "fulfilled").length, 1);
  assert.equal(concurrent.filter(x => x.status === "rejected").length, 1);
});

test("batch validation is atomic; a bad second proof does not consume the first", () => {
  const targets = [target(), target({ task: "second" })];
  const first = proof(targets);
  const second = proof(targets, 1);
  second.assertion.signature = crypto.randomBytes(70).toString("base64url");
  const verifier = makeVerifier();
  assert.throws(() => consume(verifier, [first, second], targets), /rejected/);
  const retry = proof(targets, 1);
  assert.equal(consume(verifier, [first, retry], targets).length, 2);
});

test("rejects duplicate approval ID or nonce within one batch", () => {
  const targets = [target(), target({ task: "second" })];
  const first = proof(targets);
  rejectsBatch(first, proof(targets, 1, { nonce: first.approvalData.nonce }), targets);
  rejectsBatch(first, proof(targets, 1, { approvalId: first.approvalData.approvalId }), targets);
});
function rejectsBatch(first, second, targets) {
  assert.throws(() => consume(makeVerifier(), [first, second], targets), /rejected/);
}

test("monotonic signature counters reject reuse when nonzero and remain atomic", () => {
  const t = [target()];
  const v = makeVerifier();
  consume(v, [proof(t, 0, { approvalId: "counter-1" }, { signCount: 3 })]);
  rejects(proof(t, 0, { approvalId: "counter-2" }, { signCount: 3 }), t, v);
  rejects(proof(t, 0, { approvalId: "counter-3" }, { signCount: 0 }), t, v);
  assert.equal(consume(v, [proof(t, 0, { approvalId: "counter-4" }, { signCount: 4 })]).length, 1);
});

test("audit events exclude task text, keys and proof content", () => {
  const seen = [];
  const v = makeVerifier({ audit: e => seen.push(e) });
  const t = [target()];
  consume(v, [proof(t)]);
  assert.equal(seen[0].event, "webauthn_approval_consumed");
  assert.doesNotMatch(JSON.stringify(seen), /review this text|signature|privateKey|credentialId|clientDataJSON/);
});

test("audit failures cannot undo consumption or authorize replay", () => {
  const v = makeVerifier({ audit: () => { throw new Error("secret audit exception"); } });
  const t = [target()];
  const signed = proof(t);
  assert.equal(consume(v, [signed]).length, 1);
  rejects(signed, t, v);
});

test("trust anchors must be configured explicitly and only allowed public key types", () => {
  assert.throws(() => new Verifier({}), /configuration/);
  assert.throws(() => makeVerifier({ origin: "http://approval.example.test" }), /HTTPS/);
  assert.throws(() => makeVerifier({ credentials: [{ id: esId, algorithm: -7, publicKey: rs.publicKey }] }), /P-256/);
  assert.throws(() => makeVerifier({ credentials: [{ id: esId, algorithm: -257, publicKey: es.publicKey }] }), /RSA/);
  assert.throws(() => makeVerifier({ credentials: [{ id: esId, algorithm: -7, publicKey: es.privateKey }] }), /public key/);
});

test("legacy Ed25519 approval verifier still accepts its original grant format", () => {
  const data = {
    version: 1, approvalId: "legacy", providerId: "api-a", modelId: "m1",
    taskSha256: sha256Text("review this text"), configFingerprint,
    batchId: "batch-fixture", nonce: crypto.randomBytes(32).toString("base64url"),
    sessionId, expiresAt: now + 30000
  };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(data)), ed.privateKey).toString("base64url");
  const verifier = new ApprovalVerifier({ trustedPublicKey: ed.publicKey, sessionId, now: () => now });
  assert.equal(verifier.verifyAndConsumeBatch([{ ...data, signature }], [target()],
    { batchId: "batch-fixture", configFingerprint }).length, 1);
});
