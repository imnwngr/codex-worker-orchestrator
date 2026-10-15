"use strict";

const { canonicalJson, sha256Text, configurationFingerprint } = require("../../broker/providers/approval-core");
const { batchSha256 } = require("../../broker/providers/webauthn-approval");
const { validateConfig } = require("../../broker/providers/config");
const { ProviderRegistry } = require("../../broker/providers/registry");
const { checkRequest, snapshotJson } = require("./check-contracts");
const preparedObjects = new WeakSet();

class PreparationError extends Error {
  constructor(code) { super("Offline request preparation rejected"); this.code = code; }
}
function fail(code) { throw new PreparationError(code); }
function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function assertPrepared(context) { if (!preparedObjects.has(context)) fail("UNRECOGNIZED_PREPARED_CONTEXT"); }
function clockValue(now, context) {
  const value = now();
  if (!Number.isSafeInteger(value) || value < context.createdAt) fail("INVALID_CLOCK");
  return value;
}

function prepareRequest(request, operatorConfiguration, { now, expiresAt } = {}) {
  const checked = checkRequest(request);
  if (checked.contractStatus !== "CONSISTENT_NON_AUTHORIZING") fail(checked.errorCategory);
  if (!Number.isSafeInteger(now) || now < request.createdAt || !Number.isSafeInteger(expiresAt) || expiresAt > 8640000000000000 || expiresAt <= now || expiresAt - request.createdAt > 300000) fail("INVALID_LIFETIME");
  let configuration;
  try {
    configuration = validateConfig(snapshotJson(operatorConfiguration));
  } catch (error) { if (error instanceof PreparationError) throw error; fail("INVALID_CONFIGURATION"); }
  const ids = new Set();
  const targets = request.targets.map(target => {
    if (ids.has(target.id)) fail("DUPLICATE_TARGET_ID"); ids.add(target.id);
    const entry = configuration.providers.find(p => p.id === target.provider);
    if (!entry || !entry.enabled) fail("TARGET_NOT_CONFIGURED");
    if (entry.kind !== "api") fail("CLI_CONTEXT_UNSUPPORTED");
    // The adapter normalizes the already-normalized base URL again. Reject non-idempotent trailing slashes.
    if (entry.baseUrl.endsWith("/")) fail("DESTINATION_NORMALIZATION_UNSUPPORTED");
    let resolved;
    try {
      resolved = ProviderRegistry.prototype.validateRequest(entry, {
        task: target.task, model: target.model, effort: target.effort, timeoutSeconds: target.timeoutSeconds
      });
    } catch { fail("INVALID_TARGET_PARAMETERS"); }
    if (resolved.task.length > 50000) fail("TASK_OVERSIZED");
    // Exactly one effective normalization; preserve all interior Unicode and line endings.
    const task = resolved.task.trim();
    if (!task) fail("EMPTY_EFFECTIVE_TASK");
    return {
      id: target.id, providerId: entry.id, modelId: resolved.model,
      destination: `${entry.baseUrl}/chat/completions`, task, taskSha256: sha256Text(task),
      wire: { model: resolved.model, messages: [{ role: "user", content: task }] },
      parameters: { effectiveTimeoutSeconds: resolved.timeoutSeconds, adapterTimeoutSeconds: entry.timeoutSeconds },
      metadata: { requestedEffort: resolved.effort, effortTransmission: "NOT_SENT_BY_API_ADAPTER" }
    };
  });
  const routing = targets.map(t => ({ id: t.id, providerId: t.providerId, modelId: t.modelId, destination: t.destination, effort: t.metadata.requestedEffort, timeoutSeconds: t.parameters.effectiveTimeoutSeconds }));
  const payload = {
    schemaVersion: 1, designation: "SYNTHETIC_DESIGN_ONLY", requestId: request.requestId,
    batchId: request.batchId, sessionId: request.sessionId, createdAt: request.createdAt, expiresAt,
    applicationIdentity: "UNESTABLISHED", userIdentity: "UNESTABLISHED", authorized: false,
    productionAuthorization: "DEFAULT_DENY", normalization: "ECMASCRIPT_TRIM_UTF8_V1",
    orderedTargetIds: targets.map(t => t.id), targets, configurationSnapshot: configuration,
    configurationFingerprint: configurationFingerprint({ configuration, targets: routing }),
    batchSha256: batchSha256(targets.map(t => ({ providerId: t.providerId, modelId: t.modelId, task: t.task })))
  };
  const context = freeze({ ...payload, contextSha256: sha256Text(canonicalJson(payload)) });
  preparedObjects.add(context);
  return context;
}

module.exports = { prepareRequest, assertPrepared, clockValue, freeze, PreparationError };
