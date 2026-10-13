"use strict";

// OFFLINE PROTOTYPE ONLY. Verification of a signed assertion is not evidence
// that a trusted Windows approval UI displayed the task to the USER.
// This module MUST NOT be used as an HTTP authorizer or production issuer.
const crypto = require("node:crypto");
const { canonicalJson, sha256Text } = require("./approval-core");

const DOMAIN = Buffer.from("orchestrator-approval-webauthn-v1\0", "utf8");
const BATCH_DOMAIN = Buffer.from("orchestrator-approval-batch-v1\0", "utf8");
const DATA_KEYS = [
  "version", "approvalId", "providerId", "modelId", "taskSha256",
  "configFingerprint", "batchId", "batchSha256", "nonce", "sessionId", "expiresAt"
];
const ASSERTION_KEYS = [
  "credentialId", "credentialAlgorithm", "clientDataJSON", "authenticatorData", "signature"
];
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const MAX_LIFETIME_MS = 5 * 60 * 1000;
const MAX_TARGETS = 8;
const ES256 = -7;
const RS256 = -257;

function deny(code) {
  const err = new Error("WebAuthn approval rejected");
  err.code = code;
  throw err;
}

function plain(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value, required, optional = []) {
  if (!plain(value)) return false;
  const keys = Object.keys(value);
  return required.every(key => Object.hasOwn(value, key)) &&
    keys.every(key => required.includes(key) || optional.includes(key));
}
function stringId(value) { return typeof value === "string" && ID_RE.test(value); }
function hash(value) { return typeof value === "string" && HASH_RE.test(value); }

function decode64(value, min, max) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > Math.ceil(max * 4 / 3) + 2 ||
      !/^[A-Za-z0-9_-]+$/.test(value)) deny("invalid_encoding");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < min || bytes.length > max || bytes.toString("base64url") !== value) {
    deny("invalid_encoding");
  }
  return bytes;
}

function validateData(data) {
  if (!exactKeys(data, DATA_KEYS) || data.version !== 1 ||
      !stringId(data.approvalId) || !stringId(data.providerId) ||
      !stringId(data.modelId) || !stringId(data.batchId) ||
      !stringId(data.sessionId) || !hash(data.taskSha256) ||
      !hash(data.batchSha256) || !hash(data.configFingerprint) ||
      !Number.isSafeInteger(data.expiresAt) || data.expiresAt <= 0) deny("invalid_data");
  if (decode64(data.nonce, 32, 32).length !== 32) deny("invalid_nonce");
  return data;
}

function challengeFor(data) {
  validateData(data);
  return crypto.createHash("sha256")
    .update(DOMAIN).update(canonicalJson(data), "utf8").digest("base64url");
}

function batchSha256(targets) {
  if (!Array.isArray(targets) || targets.length < 1 || targets.length > MAX_TARGETS) {
    deny("invalid_targets");
  }
  const digestItems = targets.map(target => {
    if (!exactKeys(target, ["providerId", "modelId", "task"]) ||
        !stringId(target.providerId) || !stringId(target.modelId) ||
        typeof target.task !== "string" || !target.task.trim() || target.task.length > 50000) {
      deny("invalid_target");
    }
    return {
      providerId: target.providerId,
      modelId: target.modelId,
      taskSha256: sha256Text(target.task)
    };
  });
  return crypto.createHash("sha256")
    .update(BATCH_DOMAIN).update(canonicalJson(digestItems), "utf8").digest("hex");
}

function parseClientData(bytes) {
  let data;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    data = JSON.parse(json);
  } catch { deny("invalid_client_data"); }
  if (!exactKeys(data, ["type", "challenge", "origin"], ["crossOrigin"]) ||
      data.type !== "webauthn.get" || typeof data.challenge !== "string" ||
      typeof data.origin !== "string" ||
      (Object.hasOwn(data, "crossOrigin") && data.crossOrigin !== false)) {
    deny("invalid_client_data");
  }
  return data;
}

function publicKeyOf(value) {
  if (value instanceof crypto.KeyObject && value.type === "public") return value;
  if (typeof value !== "string" || !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(value)) {
    throw new TypeError("trusted credential must provide a public key");
  }
  return crypto.createPublicKey(value);
}

class OfflineWebAuthnApprovalVerifier {
  #origin;
  #rpId;
  #sessionId;
  #configFingerprint;
  #credentials;
  #clock;
  #audit;
  #usedIds = new Set();
  #usedNonces = new Set();
  #signCounts = new Map();

  constructor(options) {
    if (!exactKeys(options, ["origin", "rpId", "sessionId", "configFingerprint", "credentials"], ["now", "audit"]) ||
        typeof options.origin !== "string" || typeof options.rpId !== "string" ||
        !stringId(options.sessionId) || !hash(options.configFingerprint) ||
        !Array.isArray(options.credentials) || options.credentials.length < 1 ||
        options.credentials.length > 32) {
      throw new TypeError("trusted WebAuthn verifier configuration required");
    }
    let url;
    try { url = new URL(options.origin); } catch { throw new TypeError("invalid trusted origin"); }
    if (url.protocol !== "https:" || url.origin !== options.origin ||
        url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
        !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(options.rpId) ||
        !(url.hostname === options.rpId || url.hostname.endsWith(`.${options.rpId}`))) {
      throw new TypeError("trusted HTTPS origin and RP ID must match");
    }
    const now = options.now ?? Date.now;
    const audit = options.audit ?? (() => {});
    if (typeof now !== "function" || typeof audit !== "function") {
      throw new TypeError("invalid trusted callbacks");
    }
    const credentials = new Map();
    for (const entry of options.credentials) {
      if (!exactKeys(entry, ["id", "algorithm", "publicKey"]) ||
          ![ES256, RS256].includes(entry.algorithm)) {
        throw new TypeError("invalid trusted credential");
      }
      decode64(entry.id, 16, 512);
      if (credentials.has(entry.id)) throw new TypeError("duplicate trusted credential");
      const publicKey = publicKeyOf(entry.publicKey);
      if (entry.algorithm === ES256 &&
          !(publicKey.asymmetricKeyType === "ec" &&
            publicKey.asymmetricKeyDetails?.namedCurve === "prime256v1")) {
        throw new TypeError("ES256 requires a P-256 public key");
      }
      if (entry.algorithm === RS256 &&
          !(publicKey.asymmetricKeyType === "rsa" &&
            publicKey.asymmetricKeyDetails?.modulusLength >= 2048)) {
        throw new TypeError("RS256 requires an RSA key of at least 2048 bits");
      }
      credentials.set(entry.id, { algorithm: entry.algorithm, publicKey });
      this.#signCounts.set(entry.id, 0);
    }
    this.#origin = options.origin;
    this.#rpId = options.rpId;
    this.#sessionId = options.sessionId;
    this.#configFingerprint = options.configFingerprint;
    this.#credentials = credentials;
    this.#clock = now;
    this.#audit = audit;
  }

  #record(event) {
    try { this.#audit(Object.freeze({ ...event })); } catch { /* No approval from audit. */ }
  }

  // Synchronous verify+consume. Only one verifier instance / process is covered.
  verifyAndConsumeBatch(envelopes, targets, context) {
    try {
      if (!Array.isArray(envelopes) || !Array.isArray(targets) ||
          !exactKeys(context, ["batchId"]) || !stringId(context.batchId) ||
          envelopes.length !== targets.length) deny("invalid_batch");
      const expectedBatchSha = batchSha256(targets);
      const now = this.#clock();
      if (!Number.isSafeInteger(now) || now < 0) deny("invalid_clock");
      const freshIds = new Set();
      const freshNonces = new Set();
      const localCounts = new Map(this.#signCounts);
      const accepted = [];
      const rpHash = crypto.createHash("sha256").update(this.#rpId, "utf8").digest();

      for (let index = 0; index < envelopes.length; index++) {
        const envelope = envelopes[index];
        if (!exactKeys(envelope, ["version", "approvalData", "assertion"]) || envelope.version !== 1) {
          deny("invalid_envelope");
        }
        const data = validateData(envelope.approvalData);
        const proof = envelope.assertion;
        if (!exactKeys(proof, ASSERTION_KEYS)) deny("invalid_assertion");
        const target = targets[index];
        if (data.providerId !== target.providerId || data.modelId !== target.modelId ||
            data.taskSha256 !== sha256Text(target.task) ||
            data.batchId !== context.batchId || data.batchSha256 !== expectedBatchSha ||
            data.sessionId !== this.#sessionId ||
            data.configFingerprint !== this.#configFingerprint) deny("binding_mismatch");
        if (data.expiresAt <= now || data.expiresAt > now + MAX_LIFETIME_MS) deny("expired");
        if (this.#usedIds.has(data.approvalId) || this.#usedNonces.has(data.nonce) ||
            freshIds.has(data.approvalId) || freshNonces.has(data.nonce)) deny("replay");
        freshIds.add(data.approvalId);
        freshNonces.add(data.nonce);

        const credentialBytes = decode64(proof.credentialId, 16, 512);
        const credentialId = credentialBytes.toString("base64url");
        const credential = this.#credentials.get(credentialId);
        if (!credential || proof.credentialAlgorithm !== credential.algorithm) deny("unknown_credential");
        const clientBytes = decode64(proof.clientDataJSON, 2, 8192);
        const client = parseClientData(clientBytes);
        if (client.origin !== this.#origin ||
            client.challenge !== challengeFor(data)) deny("client_mismatch");
        const auth = decode64(proof.authenticatorData, 37, 37);
        if (!crypto.timingSafeEqual(auth.subarray(0, 32), rpHash)) deny("rp_mismatch");
        const flags = auth[32];
        if ((flags & 0x05) !== 0x05 || (flags & 0xc0) !== 0) deny("invalid_flags");
        const counter = auth.readUInt32BE(33);
        const prev = localCounts.get(credentialId) ?? 0;
        // Zero counters are allowed only while the authenticator has never
        // advertised nonzero counters; nonzero counts must be increasing.
        if (prev !== 0 && counter <= prev) {
          deny("sign_count_replay");
        }
        const message = Buffer.concat([
          auth, crypto.createHash("sha256").update(clientBytes).digest()
        ]);
        const signature = decode64(proof.signature, 64, 1024);
        const keyOptions = credential.algorithm === RS256
          ? { key: credential.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }
          : { key: credential.publicKey, dsaEncoding: "der" };
        let valid = false;
        try { valid = crypto.verify("sha256", message, keyOptions, signature); }
        catch { deny("bad_signature"); }
        if (!valid) deny("bad_signature");
        if (counter > 0) localCounts.set(credentialId, counter);
        accepted.push(data);
      }
      // All proof validations have succeeded. Commit state before callbacks.
      for (const data of accepted) {
        this.#usedIds.add(data.approvalId);
        this.#usedNonces.add(data.nonce);
      }
      this.#signCounts = localCounts;
      for (const data of accepted) {
        this.#record({ event: "webauthn_approval_consumed", approvalId: data.approvalId,
          batchId: data.batchId, providerId: data.providerId, modelId: data.modelId });
      }
      return Object.freeze(accepted.map(data => Object.freeze({
        approvalId: data.approvalId, providerId: data.providerId,
        modelId: data.modelId, batchId: data.batchId
      })));
    } catch (error) {
      const reason = typeof error?.code === "string" &&
        /^[a-z_]+$/.test(error.code) ? error.code : "verification_failed";
      this.#record({ event: "webauthn_approval_rejected", reason });
      deny(reason);
    }
  }
}

module.exports = {
  OfflineWebAuthnApprovalVerifier,
  challengeFor,
  batchSha256
};
