"use strict";

const crypto = require("node:crypto");

const AUTH_ENV = "BROKER_BATCH_AUTH_TOKEN";
const MAX_BODY_BYTES = 256 * 1024;
const MAX_TARGETS = 8;
const MAX_TASK_LENGTH = 50000;
const MAX_ACTIVE_BATCHES = 2;
const MAX_QUEUED_BATCHES = 4;
const MAX_PARALLEL_TARGETS = 2;
const EFFORTS = new Set(["low", "medium", "high", "xhigh", "max"]);
const TARGET_KEYS = new Set(["id", "provider", "model", "task", "effort", "timeout_seconds"]);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = crypto.createHash("sha256").update(left).digest();
  const b = crypto.createHash("sha256").update(right).digest();
  return crypto.timingSafeEqual(a, b);
}

function send(res, status, value) {
  if (res.destroyed || res.writableEnded) return;
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store"
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    let ended = false;
    const finish = (err, data) => {
      if (ended) return;
      ended = true;
      if (err) reject(err); else resolve(data);
    };
    req.on("data", chunk => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        // Drain remaining bytes without buffering them, preserving the 413 response.
        finish(new Error("too_large"));
        return;
      }
      if (!ended) chunks.push(chunk);
    });
    req.on("aborted", () => finish(new Error("invalid")));
    req.on("error", () => finish(new Error("invalid")));
    req.on("end", () => {
      if (ended) return;
      try { finish(null, JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { finish(new Error("invalid")); }
    });
  });
}

function validateBatch(body, registry) {
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      Object.keys(body).length !== 1 || !Object.hasOwn(body, "targets") ||
      !Array.isArray(body.targets) || body.targets.length < 1 ||
      body.targets.length > MAX_TARGETS) throw new TypeError("invalid batch");
  const ids = new Set();
  return body.targets.map(target => {
    if (!target || typeof target !== "object" || Array.isArray(target) ||
        Object.keys(target).some(key => !TARGET_KEYS.has(key)) ||
        typeof target.id !== "string" || !ID_RE.test(target.id) || ids.has(target.id) ||
        typeof target.provider !== "string" || !ID_RE.test(target.provider) ||
        typeof target.task !== "string" || !target.task.trim() ||
        target.task.length > MAX_TASK_LENGTH ||
        (target.effort !== undefined && !EFFORTS.has(target.effort))) {
      throw new TypeError("invalid target");
    }
    ids.add(target.id);
    const entry = registry.configured.get(target.provider);
    if (!entry || !entry.enabled || !registry.adapters.has(target.provider)) {
      throw new TypeError("invalid provider");
    }
    if (entry.kind === "api") {
      if (typeof target.model !== "string" || !entry.models.includes(target.model)) {
        throw new TypeError("invalid model");
      }
    } else if (target.model !== undefined) throw new TypeError("invalid model");
    if (target.timeout_seconds !== undefined &&
        (!Number.isInteger(target.timeout_seconds) || target.timeout_seconds < 1 ||
         target.timeout_seconds > entry.timeoutSeconds)) throw new TypeError("invalid timeout");
    return Object.freeze({
      id: target.id, provider: target.provider, task: target.task.trim(),
      ...(target.model !== undefined ? { model: target.model } : {}),
      ...(target.effort !== undefined ? { effort: target.effort } : {}),
      ...(target.timeout_seconds !== undefined ? { timeoutSeconds: target.timeout_seconds } : {})
    });
  });
}

class BatchGate {
  constructor() {
    this.active = 0;
    this.queue = [];
  }
  acquire(signal) {
    if (signal?.aborted) return Promise.reject(new Error("cancelled"));
    if (this.active < MAX_ACTIVE_BATCHES && this.queue.length === 0) {
      this.active++;
      return Promise.resolve(() => this.release());
    }
    if (this.queue.length >= MAX_QUEUED_BATCHES) return Promise.reject(new Error("busy"));
    return new Promise((resolve, reject) => {
      const item = { resolve, reject, signal, onAbort: null };
      item.onAbort = () => {
        this.queue = this.queue.filter(x => x !== item);
        reject(new Error("cancelled"));
      };
      signal?.addEventListener("abort", item.onAbort, { once: true });
      this.queue.push(item);
      if (signal?.aborted) item.onAbort();
    });
  }
  release() {
    for (;;) {
      const next = this.queue.shift();
      if (!next) { this.active--; return; }
      next.signal?.removeEventListener("abort", next.onAbort);
      if (next.signal?.aborted) { next.reject(new Error("cancelled")); continue; }
      next.resolve(() => this.release());
      return;
    }
  }
}

async function handleBatch(req, res, options) {
  const env = options.env === undefined ? process.env : options.env;
  const expected = env[AUTH_ENV];
  if (typeof expected !== "string" || expected.length < 32) {
    return send(res, 503, { ok: false, error: "batch_unavailable" });
  }
  const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || "");
  if (!safeEqual(match?.[1], expected)) {
    return send(res, 401, { ok: false, error: "unauthorized" });
  }
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"] || "")) {
    return send(res, 415, { ok: false, error: "unsupported_media_type" });
  }
  if (Number(req.headers["content-length"]) > MAX_BODY_BYTES) {
    return send(res, 413, { ok: false, error: "request_too_large" });
  }
  let body;
  try { body = await readJson(req); }
  catch (error) {
    return send(res, error.message === "too_large" ? 413 : 400, {
      ok: false, error: error.message === "too_large" ? "request_too_large" : "invalid_json"
    });
  }
  let targets;
  try { targets = validateBatch(body, options.registry); }
  catch { return send(res, 400, { ok: false, error: "invalid_request" }); }

  const controller = new AbortController();
  const abort = () => controller.abort();
  res.once("close", abort);
  req.once("aborted", abort);
  let release;
  try {
    // Reserve a bounded slot before performing any potentially asynchronous approvals.
    release = await options.gate.acquire(controller.signal);
    // Production default is deny-all. Injection is reserved for a separately
    // audited, independently user-controlled authorizer (or mocked tests).
    const authorize = options.authorizeTarget || (() => false);
    for (const target of targets) {
      if (controller.signal.aborted) throw new Error("cancelled");
      let approved = false;
      try {
        approved = await authorize(Object.freeze({
          provider: target.provider,
          model: target.model ?? null,
          taskSha256: crypto.createHash("sha256").update(target.task).digest("hex")
        }));
      } catch { /* Fail closed. */ }
      if (approved !== true) {
        return send(res, 403, { ok: false, error: "authorization_required" });
      }
    }
    if (controller.signal.aborted) throw new Error("cancelled");
    const results = await options.registry.dispatchMany(targets, {
      maxParallel: MAX_PARALLEL_TARGETS,
      signal: controller.signal
    });
    send(res, 200, { ok: true, results });
  } catch (error) {
    if (!res.destroyed) send(res, error?.message === "busy" ? 503 : 503, {
      ok: false, error: error?.message === "busy" ? "batch_busy" : "batch_unavailable"
    });
  } finally {
    res.removeListener("close", abort);
    req.removeListener("aborted", abort);
    release?.();
  }
}

module.exports = {
  AUTH_ENV, BatchGate, handleBatch, validateBatch,
  limits: Object.freeze({
    bodyBytes: MAX_BODY_BYTES, targets: MAX_TARGETS, taskLength: MAX_TASK_LENGTH,
    activeBatches: MAX_ACTIVE_BATCHES, queuedBatches: MAX_QUEUED_BATCHES,
    parallelTargets: MAX_PARALLEL_TARGETS
  })
};
