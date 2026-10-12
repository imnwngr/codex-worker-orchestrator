"use strict";

const { validateProvider, validateProviderResult } = require("./provider");

const REQUEST_KEYS = new Set(["task", "model", "effort", "timeoutSeconds"]);

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
  async dispatch(id, request) {
    const providerId = id || this.defaultProvider;
    const entry = this.configured.get(providerId);
    const adapter = this.adapters.get(providerId);
    if (!entry || !entry.enabled || !adapter) {
      throw new Error(`unknown or disabled provider: ${providerId}`);
    }

    const safeRequest = this.validateRequest(entry, request);
    const controller = new AbortController();
    let timeoutHandle;
    const timeoutSeconds = request.timeoutSeconds ?? entry.timeoutSeconds;
    const timeout = new Promise((resolve, reject) => {
      timeoutHandle = setTimeout(() => {
        controller.abort();
        reject(new Error(`provider ${providerId} timed out`));
      }, timeoutSeconds * 1000);
    });
    const work = Promise.resolve().then(() =>
      adapter.analyze(Object.freeze({ ...safeRequest, signal: controller.signal }))
    );

    try {
      const result = await Promise.race([work, timeout]);
      return validateProviderResult(result, providerId);
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

module.exports = { ProviderRegistry };
