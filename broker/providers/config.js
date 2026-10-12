"use strict";

const TOP_KEYS = new Set(["version", "defaultProvider", "providers"]);
const BASE_PROVIDER_KEYS = new Set(["id", "kind", "enabled", "timeoutSeconds"]);
const API_KEYS = new Set([
  ...BASE_PROVIDER_KEYS,
  "models",
  "defaultModel",
  "credentialEnv"
]);
const CLI_KEYS = new Set([...BASE_PROVIDER_KEYS, "efforts"]);
const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function fail(path, message) {
  throw new TypeError(`${path}: ${message}`);
}

function assertObject(value, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(path, "must be an object");
  }
}

function assertOnlyKeys(value, allowed, path) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(path, `unknown field '${key}'`);
  }
}

function validateConfig(config) {
  assertObject(config, "config");
  assertOnlyKeys(config, TOP_KEYS, "config");
  if (config.version !== 1) fail("config.version", "must be 1");
  if (typeof config.defaultProvider !== "string" || !ID_PATTERN.test(config.defaultProvider)) {
    fail("config.defaultProvider", "must be a valid provider ID");
  }
  if (!Array.isArray(config.providers) || config.providers.length === 0) {
    fail("config.providers", "must be a non-empty array");
  }

  const ids = new Set();
  const providers = config.providers.map((provider, index) => {
    const path = `config.providers[${index}]`;
    assertObject(provider, path);
    if (typeof provider.kind !== "string" || !["cli", "api"].includes(provider.kind)) {
      fail(`${path}.kind`, "must be 'cli' or 'api'");
    }
    assertOnlyKeys(provider, provider.kind === "api" ? API_KEYS : CLI_KEYS, path);

    if (typeof provider.id !== "string" || !ID_PATTERN.test(provider.id)) {
      fail(`${path}.id`, "must be a valid provider ID");
    }
    if (ids.has(provider.id)) fail(`${path}.id`, "duplicate provider ID");
    ids.add(provider.id);

    if (typeof provider.enabled !== "boolean") fail(`${path}.enabled`, "must be boolean");
    if (
      !Number.isInteger(provider.timeoutSeconds) ||
      provider.timeoutSeconds < 1 ||
      provider.timeoutSeconds > 600
    ) {
      fail(`${path}.timeoutSeconds`, "must be an integer from 1 to 600");
    }

    if (provider.kind === "api") {
      if (!Array.isArray(provider.models) || provider.models.length === 0) {
        fail(`${path}.models`, "must be a non-empty array");
      }
      if (provider.models.some(model => typeof model !== "string" || !MODEL_PATTERN.test(model))) {
        fail(`${path}.models`, "must contain valid model identifiers");
      }
      if (new Set(provider.models).size !== provider.models.length) {
        fail(`${path}.models`, "must not contain duplicate models");
      }
      if (
        typeof provider.defaultModel !== "string" ||
        !provider.models.includes(provider.defaultModel)
      ) {
        fail(`${path}.defaultModel`, "must name a model in models");
      }
      if (
        provider.credentialEnv !== undefined &&
        (typeof provider.credentialEnv !== "string" ||
          !/^[A-Z][A-Z0-9_]{0,127}$/.test(provider.credentialEnv))
      ) {
        fail(`${path}.credentialEnv`, "must be an environment variable name");
      }
    } else if (
      provider.efforts !== undefined &&
      (!Array.isArray(provider.efforts) ||
        provider.efforts.length === 0 ||
        provider.efforts.some(value => !["low", "medium", "high", "xhigh", "max"].includes(value)))
    ) {
      fail(`${path}.efforts`, "contains an invalid effort");
    }

    return Object.freeze({
      ...provider,
      ...(provider.models ? { models: Object.freeze([...provider.models]) } : {}),
      ...(provider.efforts ? { efforts: Object.freeze([...provider.efforts]) } : {})
    });
  });

  const defaultEntry = providers.find(provider => provider.id === config.defaultProvider);
  if (!defaultEntry || !defaultEntry.enabled) {
    fail("config.defaultProvider", "provider is missing or disabled");
  }

  return Object.freeze({
    version: 1,
    defaultProvider: config.defaultProvider,
    providers: Object.freeze(providers)
  });
}

module.exports = { validateConfig };
