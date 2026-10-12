"use strict";

const MAX_RESPONSE_BYTES = 1024 * 1024;

function validateBaseUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("API provider base URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new TypeError("API provider base URL must be HTTPS without credentials, query, or fragment");
  }
  return url.toString().replace(/\/$/, "");
}

async function readBoundedBody(response, maxBytes) {
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength && Number(declaredLength) > maxBytes) {
    throw new Error("API provider response exceeded size limit");
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    throw new Error("API provider returned an invalid response");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("API provider response exceeded size limit");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

function createOpenAICompatibleProvider(config, options = {}) {
  if (!config || config.kind !== "api") {
    throw new TypeError("validated API provider configuration is required");
  }
  const baseUrl = validateBaseUrl(config.baseUrl);
  const fetchImpl = options.fetch || globalThis.fetch;
  const env = options.env || process.env;
  const scheduleTimer = options.setTimeout || setTimeout;
  const cancelTimer = options.clearTimeout || clearTimeout;
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;

  if (typeof fetchImpl !== "function") {
    throw new TypeError("a fetch implementation is required");
  }
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new TypeError("maxResponseBytes must be a positive integer");
  }

  return Object.freeze({
    id: config.id,
    kind: "api",

    async analyze(request) {
      const model = request.model ?? config.defaultModel;
      if (typeof model !== "string" || !config.models.includes(model)) {
        throw new Error("API model is not configured for this provider");
      }
      if (typeof request.task !== "string" || !request.task.trim()) {
        throw new TypeError("API request task must be a non-empty string");
      }
      if (!Number.isInteger(config.timeoutSeconds) || config.timeoutSeconds < 1) {
        throw new TypeError("API provider timeout configuration is invalid");
      }

      // Read the credential only at invocation time. Never retain it on the
      // adapter, include it in an error, or log it.
      const credential = env[config.credentialEnv];
      if (typeof credential !== "string" || !credential.trim()) {
        throw new Error("API provider credential is unavailable");
      }

      const controller = new AbortController();
      const onAbort = () => controller.abort();
      if (request.signal?.aborted) controller.abort();
      else request.signal?.addEventListener("abort", onAbort, { once: true });

      let timer;
      const timeout = new Promise((resolve, reject) => {
        timer = scheduleTimer(() => {
          controller.abort();
          reject(new Error("API provider request timed out"));
        }, config.timeoutSeconds * 1000);
      });

      const operation = (async () => {
        try {
          const url = `${baseUrl}/chat/completions`;
          const response = await fetchImpl(url, {
            method: "POST",
            redirect: "error",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${credential}`
            },
            body: JSON.stringify({
              model,
              messages: [{ role: "user", content: request.task }]
            }),
            signal: controller.signal
          });

          if (!response || typeof response.ok !== "boolean") {
            throw new Error("API provider returned an invalid response");
          }
          if (!response.ok) {
            throw new Error("API provider request failed");
          }

          const text = await readBoundedBody(response, maxResponseBytes);
          let data;
          try {
            data = JSON.parse(text);
          } catch {
            throw new Error("API provider returned invalid JSON");
          }

          const content = data?.choices?.[0]?.message?.content;
          if (typeof content !== "string" || !content.trim()) {
            throw new Error("API provider returned no usable response");
          }
          const usage = data.usage && typeof data.usage === "object" &&
            !Array.isArray(data.usage) ? data.usage : null;

          return {
            response: content.trim(),
            conversation_id: typeof data.id === "string" ? data.id : null,
            usage
          };
        } catch (error) {
          if (error?.message === "API provider response exceeded size limit" ||
              error?.message === "API provider returned invalid JSON" ||
              error?.message === "API provider returned no usable response" ||
              error?.message === "API provider returned an invalid response" ||
              error?.message === "API provider request failed") {
            throw error;
          }
          if (controller.signal.aborted) {
            throw new Error(request.signal?.aborted
              ? "API provider request cancelled"
              : "API provider request timed out");
          }
          // Do not expose fetch errors, response bodies, headers, or credentials.
          throw new Error("API provider request failed");
        }
      })();

      try {
        return await Promise.race([operation, timeout]);
      } finally {
        cancelTimer(timer);
        request.signal?.removeEventListener("abort", onAbort);
      }
    }
  });
}

module.exports = { createOpenAICompatibleProvider, MAX_RESPONSE_BYTES };
