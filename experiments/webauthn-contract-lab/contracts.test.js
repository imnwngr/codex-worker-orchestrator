"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  OfflineWebAuthnApprovalVerifier,
  batchSha256,
  challengeFor
} = require("../../broker/providers/webauthn-approval");
const { validateBatch } = require("../../broker/providers/batch-security");
const {
  decodeCborStrict,
  parseCredentialId,
  parseRegistration
} = require("./contracts");

const ORIGIN = "https://approval.example.test";
const RP_ID = "example.test";
const SESSION = "synthetic-session";
const CONFIG = "a".repeat(64);
const NOW = 1800000000000;
const CREDENTIAL_ID = Buffer.from("synthetic-credential-1", "utf8");
// Ephemeral synthetic keys generated for tests only; never persisted.
const RSA_KEY_PAIR = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function head(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  if (length <= 0xffff) return Buffer.from([(major << 5) | 25, length >> 8, length & 255]);
  throw new Error("fixture length out of range");
}
function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Number.isInteger(value)) {
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (value instanceof Map) {
    const parts = [];
    for (const [key, child] of value) parts.push(cbor(key), cbor(child));
    return Buffer.concat([head(5, value.size), ...parts]);
  }
  throw new Error("unsupported fixture value");
}
function coseFor(algorithm) {
  if (algorithm === -7) {
    const ecdh = crypto.createECDH("prime256v1");
    const d = Buffer.alloc(32, 1);
    ecdh.setPrivateKey(d);
    const point = ecdh.getPublicKey(undefined, "uncompressed");
    return {
      privateKey: crypto.createPrivateKey({
        key: {
          kty: "EC", crv: "P-256",
          x: point.subarray(1, 33).toString("base64url"),
          y: point.subarray(33, 65).toString("base64url"),
          d: d.toString("base64url")
        },
        format: "jwk"
      }),
      cose: new Map([
        [1, 2], [3, -7], [-1, 1],
        [-2, point.subarray(1, 33)], [-3, point.subarray(33, 65)]
      ])
    };
  }
  const privateKey = RSA_KEY_PAIR.privateKey;
  const jwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  return {
    privateKey,
    cose: new Map([
      [1, 3], [3, -257], [-1, Buffer.from(jwk.n, "base64url")],
      [-2, Buffer.from(jwk.e, "base64url")]
    ])
  };
}
function registration(algorithm, options = {}) {
  const keys = coseFor(algorithm);
  const challenge = Buffer.alloc(32, 7).toString("base64url");
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge, origin: ORIGIN
  }), "utf8");
  const rpHash = options.rpHash ??
    crypto.createHash("sha256").update(RP_ID).digest();
  const flags = options.flags ?? 0x45;
  const id = options.credentialId ?? CREDENTIAL_ID;
  const authData = Buffer.concat([
    rpHash, Buffer.from([flags, 0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([id.length >> 8, id.length & 255]), id, cbor(keys.cose)
  ]);
  const attestationObject = cbor(new Map([
    ["fmt", options.format ?? "none"],
    ["attStmt", options.statement ?? new Map()],
    ["authData", authData]
  ]));
  const parsed = parseRegistration(
    { clientDataJSON, attestationObject },
    { challenge, origin: ORIGIN, rpId: RP_ID }
  );
  return { ...parsed, privateKey: keys.privateKey, challenge };
}

function approvalData(task, suffix = "one") {
  const target = { providerId: "mock-provider", modelId: "mock-model", task };
  return {
    target,
    data: {
      version: 1, approvalId: `approval-${suffix}`,
      providerId: target.providerId, modelId: target.modelId,
      taskSha256: crypto.createHash("sha256").update(task, "utf8").digest("hex"),
      configFingerprint: CONFIG, batchId: "batch-lab",
      batchSha256: batchSha256([target]),
      nonce: Buffer.alloc(32, suffix === "one" ? 1 : 2).toString("base64url"),
      sessionId: SESSION, expiresAt: NOW + 30000
    }
  };
}

function assertion(registrationKey, data, algorithm, options = {}) {
  const clientObject = {
    type: "webauthn.get",
    challenge: options.challenge ?? challengeFor(data),
    origin: options.origin ?? ORIGIN
  };
  const clientDataJSON = options.clientDataJSON ??
    Buffer.from(JSON.stringify(clientObject), "utf8");
  const rpHash = options.rpHash ??
    crypto.createHash("sha256").update(RP_ID).digest();
  const flags = options.flags ?? 0x05;
  const auth = Buffer.concat([rpHash, Buffer.from([flags, 0, 0, 0, 1])]);
  const signedBytes = Buffer.concat([
    auth, crypto.createHash("sha256").update(clientDataJSON).digest()
  ]);
  const signature = crypto.sign("sha256", signedBytes, registrationKey.privateKey);
  return {
    version: 1, approvalData: data,
    assertion: {
      credentialId: options.credentialId ??
        Buffer.from(CREDENTIAL_ID).toString("base64url"),
      credentialAlgorithm: options.credentialAlgorithm ?? algorithm,
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: auth.toString("base64url"),
      signature: (options.signature ?? signature).toString("base64url")
    }
  };
}

function expectVerifierReject(action, code) {
  assert.throws(action, error =>
    error instanceof Error &&
    error.message === "WebAuthn approval rejected" &&
    error.code === code,
  `Expected sanitized rejection with code ${code}`);
}

function verifier(registrationKey) {
  return new OfflineWebAuthnApprovalVerifier({
    origin: ORIGIN, rpId: RP_ID, sessionId: SESSION,
    configFingerprint: CONFIG, now: () => NOW,
    credentials: [{
      id: Buffer.from(CREDENTIAL_ID).toString("base64url"),
      algorithm: registrationKey.algorithm,
      publicKey: registrationKey.publicKey
    }]
  });
}

for (const algorithm of [-7, -257]) {
  test(`synthetic registration and assertion interoperate for ${algorithm}`, () => {
    const key = registration(algorithm);
    const { target, data } = approvalData("effective text", `alg${Math.abs(algorithm)}`);
    const envelope = assertion(key, data, algorithm);
    assert.equal(key.algorithm, algorithm);
    assert.equal(verifier(key).verifyAndConsumeBatch(
      [envelope], [target], { batchId: data.batchId }).length, 1);
  });
}

test("registration parser rejects unsupported algorithms, curves, and key sizes", () => {
  const unsupported = coseFor(-7).cose;
  unsupported.set(3, -8);
  assert.throws(() => parseRegistrationFixture(unsupported), /unsupported_cose/);

  const wrongCurve = coseFor(-7).cose;
  wrongCurve.set(-1, 2);
  assert.throws(() => parseRegistrationFixture(wrongCurve), /invalid_es256_curve/);

  const smallRsa = new Map([
    [1, 3], [3, -257], [-1, Buffer.alloc(128, 0x80)], [-2, Buffer.from([1, 0, 1])]
  ]);
  assert.throws(() => parseRegistrationFixture(smallRsa), /invalid_rs256_key_size/);
});

function parseRegistrationFixture(cose, options = {}) {
  const challenge = Buffer.alloc(32, 7).toString("base64url");
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge, origin: ORIGIN,
    ...(options.client ?? {})
  }));
  const authData = Buffer.concat([
    options.rpHash ?? crypto.createHash("sha256").update(RP_ID).digest(),
    Buffer.from([options.flags ?? 0x45, 0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([0, CREDENTIAL_ID.length]), CREDENTIAL_ID, cbor(cose)
  ]);
  const attestationObject = cbor(new Map([
    ["fmt", options.format ?? "none"],
    ["attStmt", options.statement ?? new Map()], ["authData", authData]
  ]));
  return parseRegistration(
    { clientDataJSON, attestationObject },
    { challenge, origin: ORIGIN, rpId: RP_ID }
  );
}

test("CBOR rejects truncation, indefinite lengths, duplicate keys and trailing bytes", () => {
  assert.throws(() => decodeCborStrict(Buffer.from([0x58])), /truncated_cbor/);
  assert.throws(() => decodeCborStrict(Buffer.from([0x9f, 0xff])),
    /indefinite_or_reserved/);
  assert.throws(() => decodeCborStrict(Buffer.from([0xa2, 0x01, 0x00, 0x01, 0x01])),
    /duplicate_cbor_map_key/);
  assert.throws(() => decodeCborStrict(Buffer.from([0x00, 0x00])),
    /trailing_cbor_bytes/);
  assert.throws(() => decodeCborStrict(Buffer.alloc(16385)),
    /cbor_input_length/);
});

test("credential IDs are bounded and canonical base64url", () => {
  assert.throws(() => parseCredentialId(Buffer.alloc(15).toString("base64url")),
    /invalid_base64url/);
  assert.throws(() => parseCredentialId(Buffer.alloc(513).toString("base64url")),
    /invalid_base64url/);
  assert.throws(() => parseCredentialId("not+base64"),
    /invalid_base64url/);
  assert.equal(parseCredentialId(CREDENTIAL_ID.toString("base64url")).length,
    CREDENTIAL_ID.length);
});

test("registration rejects RP hash, UP/UV, attestation format and client data mismatches", () => {
  const wrongRpHash = Buffer.alloc(32);
  assert.throws(() => parseRegistrationFixture(coseFor(-7).cose, { rpHash: wrongRpHash }),
    /registration_rp_id_hash_mismatch/);
  assert.throws(() => parseRegistrationFixture(coseFor(-7).cose, { flags: 0x41 }),
    /registration_flags/);
  assert.throws(() => parseRegistrationFixture(coseFor(-7).cose, { format: "packed" }),
    /unsupported_attestation_format/);
});

test("registration client data requires exact synthetic origin and challenge", () => {
  const key = coseFor(-7).cose;
  for (const client of [
    { challenge: "changed" },
    { origin: "https://attacker.example.test" },
    { type: "webauthn.get" },
    { crossOrigin: true },
    { unexpected: "extra" }
  ]) {
    assert.throws(() => parseRegistrationFixture(key, { client }),
      /registration_client_data_mismatch/);
  }
});

test("CBOR rejects invalid UTF-8 and non-minimal numeric encodings", () => {
  assert.throws(() => decodeCborStrict(Buffer.from([0x61, 0xff])),
    /invalid_cbor_utf8/);
  assert.throws(() => decodeCborStrict(Buffer.from([0x18, 0x01])),
    /non_minimal_cbor_integer/);
  assert.throws(() => decodeCborStrict(Buffer.from([0x5f])),
    /indefinite_or_reserved_cbor_length/);
});

test("COSE registration rejects unexpected key fields and malformed points", () => {
  const extra = coseFor(-7).cose;
  extra.set(4, Buffer.from([1]));
  assert.throws(() => parseRegistrationFixture(extra), /invalid_es256_cose_key/);

  const invalidPoint = coseFor(-7).cose;
  invalidPoint.set(-2, Buffer.alloc(32));
  invalidPoint.set(-3, Buffer.alloc(32));
  assert.throws(() => parseRegistrationFixture(invalidPoint), /invalid_es256_point/);
});

test("assertion verifier rejects altered raw clientDataJSON bytes", () => {
  const key = registration(-7);
  const { target, data } = approvalData("exact bytes", "rawbytes");
  const valid = assertion(key, data, -7);
  const changed = Buffer.from(valid.assertion.clientDataJSON, "base64url");
  const withWhitespace = Buffer.concat([changed, Buffer.from(" ")]);
  const invalid = {
    ...valid,
    assertion: { ...valid.assertion, clientDataJSON: withWhitespace.toString("base64url") }
  };
  expectVerifierReject(() => verifier(key).verifyAndConsumeBatch(
    [invalid], [target], { batchId: data.batchId }), "bad_signature");
});

test("assertion verifier rejects wrong challenge, origin, RP hash, flags, ID, algorithm, and signature", () => {
  const key = registration(-7);
  const { target, data } = approvalData("bound task", "negative");
  const cases = [
    [assertion(key, data, -7, { challenge: "wrong" }), "client_mismatch"],
    [assertion(key, data, -7, { origin: "https://wrong.example.test" }), "client_mismatch"],
    [assertion(key, data, -7, { rpHash: Buffer.alloc(32) }), "rp_mismatch"],
    [assertion(key, data, -7, { flags: 0x01 }), "invalid_flags"],
    [assertion(key, data, -7, { flags: 0x04 }), "invalid_flags"],
    [assertion(key, data, -7, { credentialId: Buffer.alloc(16, 3).toString("base64url") }), "unknown_credential"],
    [assertion(key, data, -7, { credentialAlgorithm: -257 }), "unknown_credential"]
  ];
  for (const [envelope, error] of cases) {
    expectVerifierReject(() => verifier(key).verifyAndConsumeBatch(
      [envelope], [target], { batchId: data.batchId }), error);
  }
  const badSignature = Buffer.alloc(64);
  expectVerifierReject(() => verifier(key).verifyAndConsumeBatch(
    [assertion(key, data, -7, { signature: badSignature })],
    [target], { batchId: data.batchId }), "bad_signature");
});

test("normalized batch task bytes are the bytes that approval hashing must bind", () => {
  const registry = {
    configured: new Map([["mock-provider", {
      enabled: true, kind: "api", models: ["mock-model"], timeoutSeconds: 30
    }]]),
    adapters: new Map([["mock-provider", {}]])
  };
  const [effective] = validateBatch({
    targets: [{
      id: "target-1", provider: "mock-provider", model: "mock-model",
      task: " \n exact transmitted task \t "
    }]
  }, registry);
  assert.equal(effective.task, "exact transmitted task");
  const raw = " \n exact transmitted task \t ";
  assert.notEqual(
    crypto.createHash("sha256").update(raw, "utf8").digest("hex"),
    crypto.createHash("sha256").update(effective.task, "utf8").digest("hex")
  );

  const key = registration(-7);
  const { target, data } = approvalData(effective.task, "normalized");
  const signed = assertion(key, data, -7);
  assert.equal(verifier(key).verifyAndConsumeBatch(
    [signed], [target], { batchId: data.batchId }).length, 1);

  const rawTarget = { ...target, task: raw };
  expectVerifierReject(() => verifier(key).verifyAndConsumeBatch(
    [assertion(key, data, -7)], [rawTarget], { batchId: data.batchId }),
    "binding_mismatch");
});

test("the existing verifier consumes a synthetic approval once, including concurrent calls", async () => {
  const key = registration(-7);
  const { target, data } = approvalData("one use", "replay");
  const envelope = assertion(key, data, -7);
  const instance = verifier(key);
  const results = await Promise.allSettled([
    Promise.resolve().then(() =>
      instance.verifyAndConsumeBatch([envelope], [target], { batchId: data.batchId })),
    Promise.resolve().then(() =>
      instance.verifyAndConsumeBatch([envelope], [target], { batchId: data.batchId }))
  ]);
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(results.filter(result => result.status === "rejected").length, 1);
  expectVerifierReject(() => instance.verifyAndConsumeBatch(
    [envelope], [target], { batchId: data.batchId }), "replay");
});
