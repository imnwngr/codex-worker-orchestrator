"use strict";

const http = require("http");
const crypto = require("crypto");
const { loadConfig } = require("./providers/config-loader");
const { ProviderRegistry } = require("./providers/registry");
const { createRuntimeAdapters } = require("./providers/runtime");
const { BatchGate, handleBatch } = require("./providers/batch-security");

const HOST = "127.0.0.1";
const PORT = 8765;

const MAX_BODY = 256 * 1024;
const DEFAULT_TIMEOUT = 300;
const MAX_TIMEOUT = 600;

function send(res, status, obj) {
  const body = JSON.stringify(obj);

  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store"
  });

  res.end(body);
}

function createBrokerServer(options = {}) {
  // Load and validate the complete file synchronously before returning a
  // server, so invalid configuration cannot leave a partially started host.
  const config = options.config || loadConfig(options.configPath);
  const adapters = options.adapters || (options.adapter
    ? [options.adapter]
    : createRuntimeAdapters(config, {
        antigravity: {
          spawnProcess: options.spawnProcess,
          env: options.env,
          setTimeout: options.setTimeout,
          clearTimeout: options.clearTimeout
        },
        api: {
          env: options.env,
          fetch: options.fetch,
          setTimeout: options.setTimeout,
          clearTimeout: options.clearTimeout
        }
      }));
  const registry = options.registry || new ProviderRegistry(config, adapters);
  // The legacy HTTP route deliberately remains pinned to Antigravity.
  registry.get("antigravity");
  const batchOptions = { ...options, registry, gate: options.batchGate || new BatchGate() };
  const logger = options.logger || console;

  return http.createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/v1/analyze/batch") {
      return handleBatch(req, res, batchOptions);
    }
  if (req.method === "GET" && req.url === "/health") {
    return send(res, 200, {
      ok: true,
      service: "codex-worker-broker",
      provider: "antigravity"
    });
  }

  if (req.method !== "POST" || req.url !== "/v1/analyze") {
    return send(res, 404, {
      ok: false,
      error: "not_found"
    });
  }

  let raw = "";
  let tooLarge = false;

  req.on("data", chunk => {
    if (tooLarge) return;

    raw += chunk.toString();

    if (Buffer.byteLength(raw) > MAX_BODY) {
      tooLarge = true;
      send(res, 413, {
        ok: false,
        error: "request_too_large"
      });
      // The request is discarded after the size limit is exceeded.
      req.destroy();
    }
  });

  req.on("end", async () => {
    if (tooLarge) return;

    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      return send(res, 400, {
        ok: false,
        error: "invalid_json"
      });
    }

    if (
      body === null ||
      typeof body.task !== "string" ||
      !body.task.trim() ||
      body.task.length > 50000
    ) {
      return send(res, 400, {
        ok: false,
        error: "invalid_task"
      });
    }
    const allowedRequestKeys = new Set(["task", "effort", "timeout_seconds"]);
    if (Object.keys(body).some(key => !allowedRequestKeys.has(key))) {
      return send(res, 400, {
        ok: false,
        error: "invalid_request"
      });
    }

    const allowedEffort = new Set([
      "low",
      "medium",
      "high",
      "xhigh",
      "max"
    ]);

    const effort = allowedEffort.has(body.effort)
      ? body.effort
      : "high";

    const requestedTimeout = Number(body.timeout_seconds);

    const timeoutSeconds =
      Number.isFinite(requestedTimeout)
        ? Math.max(
            10,
            Math.min(MAX_TIMEOUT, Math.floor(requestedTimeout))
          )
        : DEFAULT_TIMEOUT;

    const requestId = crypto.randomUUID();

    logger.log(
      `[${new Date().toISOString()}] ${requestId} antigravity request`
    );

    try {
      const result = await registry.dispatch("antigravity", {
        task: body.task.trim(),
        effort,
        timeoutSeconds
      });

      logger.log(
        `[${new Date().toISOString()}] ${requestId} success`
      );

      return send(res, 200, {
        ok: true,
        request_id: requestId,
        provider: result.provider,
        response: result.response,
        conversation_id: result.conversation_id,
        usage: result.usage
      });
    } catch (err) {
      // Do not send subprocess stderr, exception messages, or secret-bearing
      // process details to the HTTP caller.
      logger.error(
        `[${new Date().toISOString()}] ${requestId} failed:`,
        "worker_failed"
      );

      return send(res, 502, {
        ok: false,
        request_id: requestId,
        provider: "antigravity",
        error: "worker_failed",
        message: "Worker request failed"
      });
    }
  });
  });
}

if (require.main === module) {
  try {
    const server = createBrokerServer();
    server.listen(PORT, HOST, () => {
      console.log(`Codex Worker Broker listening on http://${HOST}:${PORT}`);
      console.log("Provider: antigravity");
      console.log("Mode: analysis-only");
    });
  } catch {
    console.error("Codex Worker Broker could not start: invalid provider configuration");
    process.exitCode = 1;
  }
}

module.exports = { createBrokerServer };
