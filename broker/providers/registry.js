"use strict";

const { validateProvider, validateProviderResult } = require("./provider");

const REQUEST_KEYS = new Set(["task", "model", "effort", "timeoutSeconds"]);
const TARGET_KEYS = new Set(["id", "provider", ...REQUEST_KEYS]);
const DEFAULT_MAX_PARALLEL = 4;

class ProviderRegistry {
  /**
   * @param {object} config A validated, serializable config from config.js.
   * @param {Array<object>} adapters Runtime adapters kept separate from config.
   */
  constructor(config, adapters) {
    if (!config || !Array.isArray(config.providers)) {
      throw new TypeError("validated provider configuration is required");
    }
    if (!Array.isArray(adapters)) {
      throw new TypeError("runtime adapters must be supplied separately as an array");
    }

    this.defaultProvider = config.defaultProvider;
    this.configured = new Map(config.providers.map(entry => [entry.id, entry]));
    this.adapters = new Map();

    for (const rawAdapter of adapters) {
      const adapter = validateProvider(rawAdapter);
      if (this.adapters.has(adapter.id)) {
        throw new TypeError(`duplicate runtime adapter: ${adapter.id}`);
      }
      const entry = this.configured.get(adapter.id);
      if (!entry) {
        throw new TypeError(`runtime adapter has no configuration entry: ${adapter.id}`);
      }
      if (adapter.kind !== entry.kind) {
        throw new TypeError(`runtime adapter kind does not match configuration for ${adapter.id}`);
      }
      if (!entry.enabled) {
        throw new TypeError(`runtime adapter is configured as disabled: ${adapter.id}`);
      }
      this.adapters.set(adapter.id, adapter);
    }

    const defaultConfig = this.configured.get(this.defaultProvider);
    if (!defaultConfig || !defaultConfig.enabled || !this.adapters.has(this.defaultProvider)) {
      throw new TypeError("default provider is missing, disabled, or has no runtime adapter");
    }
  }

  get(id = this.defaultProvider) {
    const entry = this.configured.get(id);
    const adapter = this.adapters.get(id);
    if (!entry || !entry.enabled || !adapter) {
      throw new Error(`unknown or disabled provider: ${id}`);
    }
    return adapter;
  }

  validateRequest(entry, request) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      throw new TypeError("request must be an object");
    }
    for (const key of Object.keys(request)) {
      if (!REQUEST_KEYS.has(key)) {
        throw new TypeError(`unknown request field: ${key}`);
      }
    }
    if (typeof request.task !== "string" || !request.task.trim()) {
      throw new TypeError("request.task must be a non-empty string");
    }
    if (request.effort !== undefined &&
        !["low", "medium", "high", "xhigh", "max"].includes(request.effort)) {
      throw new TypeError("request.effort is invalid");
    }
    if (
      request.timeoutSeconds !== undefined &&
      (!Number.isInteger(request.timeoutSeconds) ||
        request.timeoutSeconds < 1 ||
        request.timeoutSeconds > entry.timeoutSeconds)
    ) {
      throw new TypeError("request.timeoutSeconds is invalid or exceeds provider timeout");
    }

    if (entry.kind === "api") {
      const model = request.model ?? entry.defaultModel;
      if (typeof model !== "string" || !entry.models.includes(model)) {
        throw new TypeError(`unknown model for provider ${entry.id}`);
      }
      return {
        task: request.task,
        model,
        ...(request.effort ? { effort: request.effort } : {}),
        ...(request.timeoutSeconds !== undefined
          ? { timeoutSeconds: request.timeoutSeconds }
          : {})
      };
    }

    if (request.model !== undefined) {
      throw new TypeError(`model selection is not supported for CLI provider ${entry.id}`);
    }
    return {
      task: request.task,
      ...(request.effort ? { effort: request.effort } : {}),
      ...(request.timeoutSeconds !== undefined
        ? { timeoutSeconds: request.timeoutSeconds }
        : {})
    };
  }

  /**
   * Dispatch enforces the configured timeout by rejecting the returned
   * promise. JavaScript promises do not cancel their underlying work: if an
   * adapter ignores the supplied AbortSignal, it may continue after timeout.
   * Adapters must opt in to cancellation by observing request.signal.
   */
  async dispatch(id, request, options = {}) {
    const providerId = id || this.defaultProvider;
    const entry = this.configured.get(providerId);
    const adapter = this.adapters.get(providerId);
    if (!entry || !entry.enabled || !adapter) {
      throw new Error(`unknown or disabled provider: ${providerId}`);
    }

    const safeRequest = this.validateRequest(entry, request);
    const externalSignal = options.signal;
    if (externalSignal !== undefined &&
        (typeof externalSignal?.aborted !== "boolean" ||
         typeof externalSignal.addEventListener !== "function" ||
         typeof externalSignal.removeEventListener !== "function")) {
      throw new TypeError("signal must be an AbortSignal");
    }
    if (externalSignal?.aborted) throw new Error(`provider ${providerId} cancelled`);

    const controller = new AbortController();
    const timeoutSeconds = safeRequest.timeoutSeconds ?? entry.timeoutSeconds;
    let timer;
    let onExternalAbort;
    const interruption = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error(`provider ${providerId} timed out`));
      }, timeoutSeconds * 1000);
      if (externalSignal) {
        onExternalAbort = () => {
          controller.abort();
          reject(new Error(`provider ${providerId} cancelled`));
        };
        externalSignal.addEventListener("abort", onExternalAbort, { once: true });
        if (externalSignal.aborted) onExternalAbort();
      }
    });
    const work = Promise.resolve().then(() => {
      if (controller.signal.aborted) throw new Error(`provider ${providerId} cancelled`);
      return adapter.analyze(Object.freeze({ ...safeRequest, signal: controller.signal }));
    });
    try {
      const result = await Promise.race([work, interruption]);
      if (controller.signal.aborted) throw new Error(`provider ${providerId} cancelled`);
      return validateProviderResult(result, providerId);
    } finally {
      clearTimeout(timer);
      if (onExternalAbort) externalSignal.removeEventListener("abort", onExternalAbort);
    }
  }

  /** Fully validate a batch before starting workers; return results in input order. */
  async dispatchMany(targets, options = {}) {
    if (!Array.isArray(targets)) throw new TypeError("targets must be an array");
    if (!options || typeof options !== "object" || Array.isArray(options)) {
      throw new TypeError("options must be an object");
    }
    for (const key of Object.keys(options)) {
      if (key !== "maxParallel" && key !== "signal") {
        throw new TypeError(`unknown dispatchMany option: ${key}`);
      }
    }
    const maxParallel = options.maxParallel ?? DEFAULT_MAX_PARALLEL;
    if (!Number.isInteger(maxParallel) || maxParallel < 1 || maxParallel > 16) {
      throw new TypeError("maxParallel must be an integer from 1 to 16");
    }
    const signal = options.signal;
    if (signal !== undefined &&
        (typeof signal?.aborted !== "boolean" ||
         typeof signal.addEventListener !== "function" ||
         typeof signal.removeEventListener !== "function")) {
      throw new TypeError("signal must be an AbortSignal");
    }
    const ids = new Set();
    const planned = targets.map((target, index) => {
      if (!target || typeof target !== "object" || Array.isArray(target)) {
        throw new TypeError(`target ${index} must be an object`);
      }
      for (const key of Object.keys(target)) {
        if (!TARGET_KEYS.has(key)) throw new TypeError(`unknown target field: ${key}`);
      }
      if (typeof target.id !== "string" || !target.id.trim()) {
        throw new TypeError(`target ${index} requires a non-empty id`);
      }
      if (ids.has(target.id)) throw new TypeError(`duplicate target id: ${target.id}`);
      ids.add(target.id);
      if (typeof target.provider !== "string" || !target.provider.trim()) {
        throw new TypeError(`target ${target.id} requires a provider ID`);
      }
      const entry = this.configured.get(target.provider);
      if (!entry || !entry.enabled || !this.adapters.has(target.provider)) {
        throw new Error(`target ${target.id} uses an unknown or disabled provider`);
      }
      const rawRequest = Object.fromEntries(
        ["task", "model", "effort", "timeoutSeconds"]
          .filter(key => Object.hasOwn(target, key))
          .map(key => [key, target[key]])
      );
      const request = this.validateRequest(entry, rawRequest);
      return Object.freeze({
        id: target.id,
        provider: target.provider,
        model: entry.kind === "api" ? request.model : null,
        request: Object.freeze(request)
      });
    });

    const results = new Array(planned.length);
    let nextIndex = 0;
    const runSlot = async () => {
      while (nextIndex < planned.length) {
        const index = nextIndex++;
        const target = planned[index];
        const base = { id: target.id, provider: target.provider, model: target.model };
        if (signal?.aborted) {
          results[index] = { ...base, status: "failure", error: "cancelled" };
          continue;
        }
        try {
          const output = await this.dispatch(target.provider, target.request, { signal });
          results[index] = {
            ...base, status: "success",
            output: { response: output.response, conversation_id: output.conversation_id, usage: output.usage }
          };
        } catch (error) {
          const errorCode = signal?.aborted || /cancelled/.test(error?.message || "")
            ? "cancelled"
            : /timed out/.test(error?.message || "") ? "timed_out" : "worker_failed";
          results[index] = { ...base, status: "failure", error: errorCode };
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(maxParallel, planned.length) }, runSlot));
    return results;
  }
}

module.exports = { ProviderRegistry };
