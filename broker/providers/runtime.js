"use strict";

const { createAntigravityProvider } = require("./antigravity");
const { createOpenAICompatibleProvider } = require("./openai-compatible");

function createRuntimeAdapters(config, options = {}) {
  if (!config || !Array.isArray(config.providers)) {
    throw new TypeError("validated provider configuration is required");
  }

  const adapters = [];
  for (const entry of config.providers) {
    if (!entry.enabled) continue;

    if (entry.kind === "cli") {
      if (entry.id !== "antigravity") {
        throw new TypeError(`unsupported enabled CLI provider: ${entry.id}`);
      }
      adapters.push(createAntigravityProvider(options.antigravity));
      continue;
    }

    if (entry.kind === "api") {
      adapters.push(createOpenAICompatibleProvider(entry, options.api));
      continue;
    }

    // The validator rejects unknown kinds; retain a fail-closed guard here
    // in case this function is called with an unvalidated object.
    throw new TypeError(`unsupported provider kind for ${entry.id}`);
  }

  return Object.freeze(adapters);
}

module.exports = { createRuntimeAdapters };
