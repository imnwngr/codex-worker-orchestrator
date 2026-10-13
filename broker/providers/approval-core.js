"use strict";

const crypto = require("node:crypto");

const DATA_KEYS = Object.freeze([
  "version",
  "approvalId",
  "providerId",
  "modelId",
  "taskSha256",
  "configFingerprint",
  "batchId",
  "nonce",
  "sessionId",
  "expiresAt"
]);
const GRANT_KEYS = new Set([...DATA_KEYS, "signature"]);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH_RE = /^[a-f0-9]{64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{43}$/;
const MAX_GRANT_LIFETIME_MS = 5 * 60 * 1000;

function approvalError(code) {
  const error = new Error("approval grant rejected");
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Deterministic JSON serialization for JSON-compatible data. Object keys are
 * sorted recursively. Undefined, non-finite numbers, cycles, and non-plain
 * objects are rejected rather than silently normalized.
 */
function canonicalJson(value) {
  const ancestors = new Set();
  function encode(item) {
    if (item === null || typeof item === "string" || typeof item === "boolean") {
      return JSON.stringify(item);
    }
    if (typeof item === "number" && Number.isFinite(item)) {
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) {
      if (ancestors.has(item)) throw new TypeError("value is not canonical JSON");
      ancestors.add(item);
      const result = `[${item.map(encode).join(",")}]`;
      ancestors.delete(item);
      return result;
    }
    if (isPlainObject(item)) {
      if (ancestors.has(item)) throw new TypeError("value is not canonical JSON");
      ancestors.add(item);
      const keys = Object.keys(item).sort();
      const result = `{${keys.map(key =>
        `${JSON.stringify(key)}:${encode(item[key])}`
      ).join(",")}}`;
      ancestors.delete(item);
      return result;
    }
    throw new TypeError("value is not canonical JSON");
  }
  return encode(value);
}

function sha256Text(text) {
  if (typeof text !== "string") throw new TypeError("task must be a string");
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function configurationFingerprint(configuration) {
  return sha256Text(canonicalJson(configuration));
}

function validateGrantData(data) {
  if (!isPlainObject(data)) throw approvalError("invalid_schema");
  const keys = Object.keys(data);
  if (keys.length !== DATA_KEYS.length ||
      keys.some(key => !DATA_KEYS.includes(key))) {
    throw approvalError("invalid_schema");
  }
  if (data.version !== 1 ||
      typeof data.approvalId !== "string" || !ID_RE.test(data.approvalId) ||
      typeof data.providerId !== "string" || !ID_RE.test(data.providerId) ||
      typeof data.modelId !== "string" || !ID_RE.test(data.modelId) ||
      typeof data.batchId !== "string" || !ID_RE.test(data.batchId) ||
      typeof data.sessionId !== "string" || !ID_RE.test(data.sessionId) ||
      typeof data.taskSha256 !== "string" || !HASH_RE.test(data.taskSha256) ||
      typeof data.configFingerprint !== "string" || !HASH_RE.test(data.configFingerprint) ||
      typeof data.nonce !== "string" || !NONCE_RE.test(data.nonce) ||
      !Number.isSafeInteger(data.expiresAt) || data.expiresAt < 1) {
    throw approvalError("invalid_schema");
  }
  return Object.freeze(Object.fromEntries(DATA_KEYS.map(key => [key, data[key]])));
}

function grantPayload(grant) {
  if (!isPlainObject(grant)) throw approvalError("invalid_schema");
  const keys = Object.keys(grant);
  if (keys.length !== GRANT_KEYS.size ||
      keys.some(key => !GRANT_KEYS.has(key)) ||
      typeof grant.signature !== "string") {
    throw approvalError("invalid_schema");
  }
  const data = validateGrantData(Object.fromEntries(
    DATA_KEYS.map(key => [key, grant[key]])
  ));
  if (!/^[A-Za-z0-9_-]{86}$/.test(grant.signature)) {
    throw approvalError("invalid_schema");
  }
  const signature = Buffer.from(grant.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== grant.signature) {
    throw approvalError("invalid_schema");
  }
  return { data, signature };
}

class ApprovalVerifier {
  /**
   * The trusted public key and session ID must be supplied by trusted startup
   * code. This class has no issuer, HTTP, worker, or provider credential API.
   */
  constructor(options) {
    if (!isPlainObject(options) ||
        !options.trustedPublicKey ||
        typeof options.sessionId !== "string" ||
        !ID_RE.test(options.sessionId)) {
      throw new TypeError("trusted approval verifier options are required");
    }
    try {
      this.trustedPublicKey = options.trustedPublicKey instanceof crypto.KeyObject
        && options.trustedPublicKey.type === "public"
        ? options.trustedPublicKey
        : crypto.createPublicKey(options.trustedPublicKey);
    } catch {
      throw new TypeError("trusted approval public key is invalid");
    }
    if (this.trustedPublicKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("trusted approval key must be Ed25519");
    }
    this.sessionId = options.sessionId;
    this.now = options.now || Date.now;
    if (typeof this.now !== "function") throw new TypeError("clock must be a function");
    this.audit = options.audit || (() => {});
    if (typeof this.audit !== "function") throw new TypeError("audit must be a function");
    this.consumedApprovalIds = new Set();
    this.consumedNonces = new Set();
  }

  record(event) {
    // Only fixed, non-secret event fields are accepted by this private method.
    try { this.audit(Object.freeze({ ...event })); } catch { /* Audit sink failure cannot approve. */ }
  }

  reject(reason) {
    this.record({ event: "approval_rejected", reason });
    throw approvalError(reason);
  }

  /**
   * Verify every grant against its exact target and consume the entire batch
   * synchronously. No await occurs between validation and marking consumed,
   * making the operation atomic with respect to concurrent calls in this
   * process. This is not durable or cross-process replay protection.
   */
  verifyAndConsumeBatch(grants, targets, context) {
    try {
      if (!Array.isArray(grants) || !Array.isArray(targets) ||
          grants.length === 0 || grants.length !== targets.length ||
          !isPlainObject(context) ||
          typeof context.batchId !== "string" || !ID_RE.test(context.batchId) ||
          typeof context.configFingerprint !== "string" ||
          !HASH_RE.test(context.configFingerprint)) {
        throw approvalError("invalid_batch");
      }

      const now = this.now();
      if (!Number.isSafeInteger(now) || now < 0) throw approvalError("invalid_clock");
      const seenIds = new Set();
      const seenNonces = new Set();
      const verified = [];

      for (let index = 0; index < grants.length; index++) {
        const { data, signature } = grantPayload(grants[index]);
        const target = targets[index];
        if (!isPlainObject(target) ||
            typeof target.providerId !== "string" ||
            typeof target.modelId !== "string" ||
            typeof target.task !== "string") {
          throw approvalError("invalid_target");
        }

        if (!crypto.verify(
          null,
          Buffer.from(canonicalJson(data), "utf8"),
          this.trustedPublicKey,
          signature
        )) throw approvalError("bad_signature");

        if (data.sessionId !== this.sessionId) throw approvalError("session_mismatch");
        if (data.batchId !== context.batchId) throw approvalError("batch_mismatch");
        if (data.providerId !== target.providerId ||
            data.modelId !== target.modelId ||
            data.taskSha256 !== sha256Text(target.task)) {
          throw approvalError("target_mismatch");
        }
        if (data.configFingerprint !== context.configFingerprint) {
          throw approvalError("configuration_mismatch");
        }
        if (data.expiresAt <= now ||
            data.expiresAt > now + MAX_GRANT_LIFETIME_MS) {
          throw approvalError("expired_or_too_long");
        }
        if (this.consumedApprovalIds.has(data.approvalId) ||
            this.consumedNonces.has(data.nonce) ||
            seenIds.has(data.approvalId) ||
            seenNonces.has(data.nonce)) {
          throw approvalError("replay");
        }
        seenIds.add(data.approvalId);
        seenNonces.add(data.nonce);
        verified.push(data);
      }

      // This mutation is deliberately synchronous and happens only after all
      // targets validate, so a bad member never partially consumes a batch.
      for (const data of verified) {
        this.consumedApprovalIds.add(data.approvalId);
        this.consumedNonces.add(data.nonce);
        this.record({
          event: "approval_consumed",
          approvalId: data.approvalId,
          batchId: data.batchId,
          providerId: data.providerId,
          modelId: data.modelId,
          expiresAt: data.expiresAt
        });
      }
      return Object.freeze(verified.map(data => Object.freeze({
        approvalId: data.approvalId,
        providerId: data.providerId,
        modelId: data.modelId,
        batchId: data.batchId,
        expiresAt: data.expiresAt
      })));
    } catch (error) {
      if (error?.code) this.reject(error.code);
      this.reject("verification_failed");
    }
  }
}

module.exports = {
  ApprovalVerifier,
  canonicalJson,
  configurationFingerprint,
  sha256Text
};
