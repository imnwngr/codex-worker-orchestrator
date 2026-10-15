"use strict";

// OFFLINE DESIGN CHECK ONLY. Nothing here verifies approval, dispatches, or persists state.
const schema = require("./contracts.schema.json");
const { canonicalJson, sha256Text, configurationFingerprint } = require("../../broker/providers/approval-core");
const { batchSha256 } = require("../../broker/providers/webauthn-approval");
const { validateConfig } = require("../../broker/providers/config");

function reject(code) { const error = new Error("design contract rejected"); error.code = code; throw error; }
function same(a, b) { return canonicalJson(a) === canonicalJson(b); }
function boundedJson(value) {
  let nodes = 0; let bytes = 0;
  const seen = new Set();
  function visit(item, depth) {
    if (++nodes > 4096 || depth > 16) reject("INPUT_BOUND_EXCEEDED");
    if (typeof item === "string") {
      if (!item.isWellFormed()) reject("INVALID_TEXT_ENCODING");
      bytes += Buffer.byteLength(item, "utf8");
    } else if (item !== null && typeof item === "object") {
      if (seen.has(item)) reject("NON_JSON_INPUT");
      seen.add(item);
      if (!Array.isArray(item) && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) reject("NON_JSON_INPUT");
      if (Reflect.ownKeys(item).some(k => typeof k !== "string")) reject("NON_JSON_INPUT");
      const descriptors = Object.getOwnPropertyDescriptors(item);
      if (Array.isArray(item) && Object.keys(item).length !== item.length) reject("NON_JSON_INPUT");
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (Array.isArray(item) && key === "length") continue;
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) reject("NON_JSON_INPUT");
        bytes += Buffer.byteLength(key, "utf8");
        visit(descriptor.value, depth + 1);
      }
    } else if (item !== null && typeof item !== "boolean" && !(typeof item === "number" && Number.isSafeInteger(item))) reject("NON_JSON_INPUT");
    if (bytes > 262144) reject("INPUT_BOUND_EXCEEDED");
  }
  visit(value, 0);
  if (Buffer.byteLength(canonicalJson(value), "utf8") > 262144) reject("INPUT_BOUND_EXCEEDED");
}

// Only the finite JSON Schema subset used by the checked-in schema is supported.
// No remote refs, coercion, defaults, format inference, or general schema framework.
const keywords = new Set(["$ref", "$schema", "$id", "$defs", "title", "description", "type", "const", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern", "minItems", "maxItems", "items", "properties", "required", "additionalProperties"]);
function shape(value, rule, key = "") {
  if (Object.keys(rule).some(k => !keywords.has(k))) reject("UNSUPPORTED_SCHEMA_KEYWORD");
  if (rule.$ref) {
    if (!/^#\/\$defs\/[A-Za-z]+$/.test(rule.$ref)) reject("UNSUPPORTED_SCHEMA_REFERENCE");
    const target = schema.$defs[rule.$ref.split("/").pop()];
    if (!target) reject("UNSUPPORTED_SCHEMA_REFERENCE");
    return shape(value, target, key);
  }
  if (Object.hasOwn(rule, "const") && value !== rule.const) reject(key === "schemaVersion" || key === "version" ? "UNSUPPORTED_VERSION" : "SCHEMA_INVALID");
  if (rule.enum && !rule.enum.includes(value)) reject("SCHEMA_INVALID");
  if (rule.type === "object") {
    if (!value || typeof value !== "object" || Array.isArray(value)) reject("SCHEMA_INVALID");
    if (rule.required?.some(k => !Object.hasOwn(value, k))) reject("REQUIRED_FIELD_MISSING");
    if (rule.additionalProperties === false && Object.keys(value).some(k => !Object.hasOwn(rule.properties, k))) reject("UNKNOWN_FIELD");
    for (const [name, child] of Object.entries(rule.properties || {})) if (Object.hasOwn(value, name)) shape(value[name], child, name);
  } else if (rule.type === "array") {
    if (!Array.isArray(value) || value.length < rule.minItems || value.length > rule.maxItems) reject("SCHEMA_INVALID");
    for (const item of value) shape(item, rule.items);
  } else if (rule.type === "string") {
    if (typeof value !== "string" || [...value].length < rule.minLength || [...value].length > rule.maxLength || (rule.pattern && new RegExp(rule.pattern, "u").exec(value)?.[0] !== value)) reject("SCHEMA_INVALID");
  } else if (rule.type === "integer") {
    if (!Number.isSafeInteger(value) || value < rule.minimum || value > rule.maximum) reject("SCHEMA_INVALID");
  }
}

function cancellation(value) {
  const expected = value.state === "OUTCOME_UNKNOWN"
    ? { operationState: "MAY_HAVE_STARTED", retryPolicy: "RECONCILE_FIRST" }
    : { operationState: "NOT_STARTED", retryPolicy: "NO_AUTOMATIC_RETRY" };
  if (value.operationState !== expected.operationState || value.retryPolicy !== expected.retryPolicy) reject("UNCERTAIN_OUTCOME_CONFLICT");
}

function scenario(value, now) {
  if (!Number.isSafeInteger(now) || now < 1) reject("INVALID_CLOCK");
  const config = validateConfig(value.configuration);
  // Fixed fixtures only: never imply a real destination or trusted application was validated.
  if (config.providers.some(p => p.kind === "api" && !new URL(p.baseUrl).hostname.endsWith(".invalid"))) reject("NON_SYNTHETIC_DESTINATION");
  const { request, approvalRequest: approval, decision } = value;
  if (request.createdAt > now || approval.createdAt !== request.createdAt || approval.expiresAt <= approval.createdAt || approval.expiresAt - approval.createdAt > 300000) reject("TIME_BINDING_INVALID");
  const ids = new Set();
  const displays = request.targets.map(target => {
    if (ids.has(target.id)) reject("DUPLICATE_TARGET_ID"); ids.add(target.id);
    const entry = config.providers.find(p => p.id === target.provider);
    if (!entry || !entry.enabled || entry.kind !== "api" || !entry.models.includes(target.model) || target.timeoutSeconds > entry.timeoutSeconds) reject("TARGET_NOT_CONFIGURED");
    if (target.task.length > 50000) reject("AMBIGUOUS_ACTION_IDENTITY"); // Existing runtime limit counts UTF-16 units.
    const task = target.task.trim();
    if (!task) reject("AMBIGUOUS_ACTION_IDENTITY");
    return { id: target.id, providerId: target.provider, modelId: target.model,
      destination: `${entry.baseUrl}/chat/completions`, task, taskSha256: sha256Text(task), effort: target.effort, timeoutSeconds: target.timeoutSeconds };
  });
  const identities = displays.map(t => ({ id: t.id, taskSha256: t.taskSha256, normalization: "ECMASCRIPT_TRIM_UTF8_V1" }));
  if (!same(identities, value.taskIdentities)) reject("TASK_IDENTITY_MISMATCH");
  const digest = batchSha256(displays.map(t => ({ providerId: t.providerId, modelId: t.modelId, task: t.task })));
  if (!same(value.batchIdentity, { batchId: request.batchId, orderedTargetIds: displays.map(t => t.id), batchSha256: digest })) reject("BATCH_IDENTITY_MISMATCH");
  if (!same(displays, approval.displayTargets)) reject("DISPLAY_CONTEXT_MISMATCH");
  const effective = { configuration: config, targets: displays.map(({ task, taskSha256, ...routing }) => routing) };
  const fingerprint = configurationFingerprint(effective);
  const approvalIds = new Set(); const nonces = new Set();
  if (approval.approvalData.length !== displays.length) reject("APPROVAL_BINDING_MISMATCH");
  for (const [index, data] of approval.approvalData.entries()) {
    const target = displays[index];
    if (approvalIds.has(data.approvalId) || nonces.has(data.nonce)) reject("DUPLICATE_APPROVAL_IDENTITY");
    approvalIds.add(data.approvalId); nonces.add(data.nonce);
    const bytes = Buffer.from(data.nonce, "base64url");
    if (bytes.length !== 32 || bytes.toString("base64url") !== data.nonce) reject("INVALID_NONCE_ENCODING");
    if (data.providerId !== target.providerId || data.modelId !== target.modelId || data.taskSha256 !== target.taskSha256 || data.configFingerprint !== fingerprint || data.batchId !== request.batchId || data.batchSha256 !== digest || data.sessionId !== request.sessionId || data.expiresAt !== approval.expiresAt) reject("APPROVAL_BINDING_MISMATCH");
  }
  const context = sha256Text(canonicalJson(approval));
  for (const item of [approval, decision, value.proofEnvelope, value.brokerOutcome, value.audit, value.cancellation]) {
    if (item.requestId !== request.requestId) reject("REQUEST_ID_MISMATCH");
    if (Object.hasOwn(item, "contextSha256") && item.contextSha256 !== context) reject("CONTEXT_BINDING_MISMATCH");
  }
  const terminal = { APPROVE_MOCK: "ApprovedMock", REJECT: "Rejected", EXPIRED: "Expired", CANCELLED: "Cancelled" }[decision.decision];
  if (!same(decision.states, ["Pending", terminal])) reject("INVALID_STATE_TRANSITION");
  if (decision.decidedAt < approval.createdAt || decision.decidedAt > now) reject("TIME_BINDING_INVALID");
  if (decision.decision === "EXPIRED") {
    if (decision.decidedAt < approval.expiresAt) reject("TIME_BINDING_INVALID");
  } else if (decision.decidedAt >= approval.expiresAt || now >= approval.expiresAt) reject("EXPIRED_DECISION");
  if (value.audit.batchId !== request.batchId || value.audit.occurredAt < decision.decidedAt || value.audit.occurredAt > now) reject("AUDIT_BINDING_MISMATCH");
  cancellation(value.cancellation);
  // This scenario's broker denies before execution; an unknown prior operation must be separate evidence.
  if (value.cancellation.state === "OUTCOME_UNKNOWN" || (value.cancellation.state === "CANCELLED_BEFORE_START") !== (decision.decision === "CANCELLED")) reject("CONFLICTING_CONTRACT_STATUS");
}

function check(value, definition, now) {
  try {
    boundedJson(value);
    shape(value, schema.$defs[definition]);
    if (definition === "scenario") scenario(value, now);
    else if (definition === "scenarioCollection") {
      const ids = new Set();
      for (const item of value) {
        if (ids.has(item.request.requestId)) reject("DUPLICATE_REQUEST_ID");
        ids.add(item.request.requestId); scenario(item, now);
      }
    } else if (definition === "cancellation") cancellation(value);
    return Object.freeze({ schemaVersion: 1, contractStatus: "CONSISTENT_NON_AUTHORIZING", errorCategory: null, authorized: false, productionAuthorization: "DEFAULT_DENY" });
  } catch (error) {
    const allowed = new Set(["DUPLICATE_REQUEST_ID", "INPUT_BOUND_EXCEEDED", "INVALID_TEXT_ENCODING", "NON_JSON_INPUT", "UNSUPPORTED_SCHEMA_KEYWORD", "UNSUPPORTED_SCHEMA_REFERENCE", "UNSUPPORTED_VERSION", "SCHEMA_INVALID", "REQUIRED_FIELD_MISSING", "UNKNOWN_FIELD", "UNCERTAIN_OUTCOME_CONFLICT", "INVALID_CLOCK", "NON_SYNTHETIC_DESTINATION", "TIME_BINDING_INVALID", "DUPLICATE_TARGET_ID", "TARGET_NOT_CONFIGURED", "AMBIGUOUS_ACTION_IDENTITY", "TASK_IDENTITY_MISMATCH", "BATCH_IDENTITY_MISMATCH", "DISPLAY_CONTEXT_MISMATCH", "APPROVAL_BINDING_MISMATCH", "DUPLICATE_APPROVAL_IDENTITY", "INVALID_NONCE_ENCODING", "REQUEST_ID_MISMATCH", "CONTEXT_BINDING_MISMATCH", "INVALID_STATE_TRANSITION", "EXPIRED_DECISION", "AUDIT_BINDING_MISMATCH", "CONFLICTING_CONTRACT_STATUS"]);
    return Object.freeze({ schemaVersion: 1, contractStatus: "REJECTED", errorCategory: allowed.has(error.code) ? error.code : "CONFIGURATION_OR_INPUT_INVALID", authorized: false, productionAuthorization: "DEFAULT_DENY" });
  }
}

module.exports = {
  checkScenario: (value, now) => check(value, "scenario", now),
  checkScenarioCollection: (value, now) => check(value, "scenarioCollection", now),
  checkCancellation: value => check(value, "cancellation"),
  checkRequest: value => check(value, "request"),
  snapshotJson(value) { boundedJson(value); return JSON.parse(canonicalJson(value)); }
};
