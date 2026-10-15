"use strict";

const { assertPrepared, clockValue, freeze } = require("./prepare-request");
const WARNING = "SYNTHETIC / NO DISPATCH — mock decisions never authorize production.";

function renderPreview(context) {
  assertPrepared(context);
  // JSON-quoted values keep terminal control characters from impersonating UI warnings.
  const quoted = value => JSON.stringify(value).replace(/[\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/gu,
    c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  const lines = [WARNING, `Request: ${context.requestId}`, `Batch: ${context.batchId}`,
    `Context SHA-256: ${context.contextSha256}`, `Expires UTC: ${new Date(context.expiresAt).toISOString()}`,
    "Application/user identity: UNESTABLISHED; authorization: DEFAULT_DENY"];
  for (const [index, target] of context.targets.entries()) {
    lines.push(`Target ${index + 1}: ${quoted(target.id)} / ${quoted(target.providerId)} / ${quoted(target.modelId)}`,
      `Destination: ${quoted(target.destination)}`, `Task (exact JSON string; escapes represent task characters): ${quoted(target.task)}`,
      `Task SHA-256: ${target.taskSha256}`, `Wire body: ${quoted(target.wire)}`,
      `Effective timeout: ${target.parameters.effectiveTimeoutSeconds}s; adapter timer: ${target.parameters.adapterTimeoutSeconds}s`,
      `Requested effort metadata: ${quoted(target.metadata.requestedEffort)} — NOT SENT to API`);
  }
  return freeze({ requestId: context.requestId, contextSha256: context.contextSha256,
    targets: context.targets, expiresAt: context.expiresAt, warning: WARNING, text: lines.join("\n") });
}

function createReview(context, now) {
  const preview = renderPreview(context);
  let decision = null; let closed = false;
  function capture(state) {
    decision = freeze({ requestId: context.requestId, contextSha256: context.contextSha256,
      state, decidedAt: clockValue(now, context), provenance: "LOCAL_MOCK_NOT_USER_APPROVAL", authorized: false });
    return decision;
  }
  function refresh() {
    if (!decision && clockValue(now, context) >= context.expiresAt) capture("Expired");
  }
  return Object.freeze({
    preview,
    view() { refresh(); return freeze({ preview, state: decision?.state ?? "Pending", canDecide: !closed && !decision }); },
    decide(action) {
      refresh();
      if (decision) return decision;
      if (closed) throw new Error("review closed");
      const state = { APPROVE_MOCK: "ApprovedMock", REJECT: "Rejected", CANCEL: "Cancelled" }[action];
      if (!state) throw new Error("invalid mock decision");
      return capture(state);
    },
    matches(value) { return decision !== null && value === decision; },
    close(reason) {
      try {
        refresh();
        if (!decision) capture(reason === "EXPIRED" ? "Expired" : "Cancelled");
      } finally { closed = true; }
    }
  });
}

module.exports = { renderPreview, createReview };
