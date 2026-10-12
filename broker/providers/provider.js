"use strict";

const PROVIDER_KINDS = Object.freeze(["cli", "api"]);

/**
 * Runtime adapter contract:
 *   { id, kind, analyze(request) }
 *
 * Provider output is advisory data for Codex to evaluate. This module has no
 * network, subprocess, or filesystem capabilities.
 */
function validateProvider(provider) {
  if (!provider || typeof provider !== "object" || Array.isArray(provider)) {
    throw new TypeError("provider adapter must be an object");
  }
  if (typeof provider.id !== "string" || !provider.id.trim()) {
    throw new TypeError("provider adapter id must be a non-empty string");
  }
  if (!PROVIDER_KINDS.includes(provider.kind)) {
    throw new TypeError(`provider adapter ${provider.id} has an unknown kind`);
  }
  if (typeof provider.analyze !== "function") {
    throw new TypeError(`provider adapter ${provider.id} must implement analyze(request)`);
  }
  return provider;
}

function validateProviderResult(result, providerId) {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError(`provider ${providerId} returned an invalid result`);
  }
  if (typeof result.response !== "string" || !result.response.trim()) {
    throw new TypeError(`provider ${providerId} returned no usable response`);
  }
  if (
    result.conversation_id !== undefined &&
    result.conversation_id !== null &&
    typeof result.conversation_id !== "string"
  ) {
    throw new TypeError(`provider ${providerId} returned an invalid conversation_id`);
  }
  if (
    result.usage !== undefined &&
    result.usage !== null &&
    (typeof result.usage !== "object" || Array.isArray(result.usage))
  ) {
    throw new TypeError(`provider ${providerId} returned invalid usage metadata`);
  }

  // Only advisory result fields cross the registry boundary. Provider-added
  // fields cannot act as routing or execution instructions.
  return Object.freeze({
    provider: providerId,
    response: result.response.trim(),
    conversation_id: result.conversation_id ?? null,
    usage: result.usage ?? null
  });
}

module.exports = { PROVIDER_KINDS, validateProvider, validateProviderResult };
