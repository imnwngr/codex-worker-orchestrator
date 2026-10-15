"use strict";

// In-memory fake behavior only: no adapter construction, fetch, socket, process or persistence.
const { assertPrepared, clockValue, freeze, prepareRequest } = require("./prepare-request");
const { createReview } = require("./review-preview");

function outcome(context, status, reason, started = false, results = []) {
  return freeze({ schemaVersion: 1, designation: "SYNTHETIC_DESIGN_ONLY",
    requestId: context?.requestId ?? null, contextSha256: context?.contextSha256 ?? null,
    status, reason, operationState: started ? "MAY_HAVE_STARTED" : "NOT_STARTED",
    authorized: false, productionAuthorization: "DEFAULT_DENY", results });
}

class FakeTransport {
  #deliveries = new Map(); #now; #mode; #gate; #results; #ackFault;
  constructor({ now = Date.now, mode = "complete", processingGate = Promise.resolve(), results = [], ackFault = "none" } = {}) {
    if (typeof now !== "function" || !["complete", "failure", "unknown"].includes(mode) ||
        !["none", "request", "context"].includes(ackFault) || !Array.isArray(results) || results.length > 8 || !(processingGate instanceof Promise)) throw new Error("invalid fake transport options");
    this.#now = now; this.#mode = mode; this.#gate = processingGate; this.#ackFault = ackFault;
    // Advisory response text, usage, approval flags and extra fields are never diagnostics or instructions.
    this.#results = results.map(result => {
      const d = result && typeof result === "object" ? Object.getOwnPropertyDescriptors(result) : {};
      const id = d.id?.value; const status = d.status?.value;
      if (typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) throw new Error("invalid fake result identity");
      return Object.freeze({ id, status: ["MOCK_SUCCESS", "MOCK_FAILURE", "UNKNOWN"].includes(status) ? status : "MOCK_FAILURE" });
    });
    if (new Set(this.#results.map(r => r.id)).size !== this.#results.length) throw new Error("duplicate fake result identity");
  }
  get deliveryCount() { return this.#deliveries.size; }
  submit(context) {
    assertPrepared(context);
    const old = this.#deliveries.get(context.requestId);
    if (old) throw Object.assign(new Error("duplicate fake delivery"), { code: old.contextSha256 === context.contextSha256 ? "DUPLICATE_REQUEST" : "REQUEST_CONTEXT_CONFLICT" });
    if (this.#deliveries.size >= 32) throw Object.assign(new Error("fake capacity reached"), { code: "FAKE_CAPACITY_REACHED" });
    if (clockValue(this.#now, context) >= context.expiresAt) throw Object.assign(new Error("expired"), { code: "EXPIRED" });
    if (this.#results.some(r => !context.orderedTargetIds.includes(r.id))) throw Object.assign(new Error("fake result mismatch"), { code: "RESULT_ID_MISMATCH" });
    const review = createReview(context, this.#now);
    let terminal = null; let started = false; let completing = false;
    const finish = (status, reason, results = []) => {
      if (!terminal) {
        terminal = outcome(context, status, reason, started, results);
        try { review.close(status === "EXPIRED" ? "EXPIRED" : reason); } catch { /* Terminal outcome stays fail-closed on clock failure. */ }
      }
      return terminal;
    };
    const interrupt = reason => {
      if (!["EXPIRED", "CANCELLED", "ACK_MISMATCH", "REPEATED_COMPLETION", "SIMULATED_TRANSPORT_FAILURE", "TIMED_OUT", "REVIEW_OR_TRANSPORT_FAILURE", "CLIENT_FAILURE"].includes(reason)) reason = "CLIENT_FAILURE";
      if (terminal) return terminal;
      let expired;
      try { expired = clockValue(this.#now, context) >= context.expiresAt; }
      catch { return finish(started ? "OUTCOME_UNKNOWN" : "FAILED", "INVALID_CLOCK"); }
      if (reason === "EXPIRED" || expired) return finish("EXPIRED", "EXPIRED");
      return finish(started ? "OUTCOME_UNKNOWN" : reason === "CANCELLED" ? "CANCELLED" : "FAILED", reason);
    };
    this.#deliveries.set(context.requestId, { contextSha256: context.contextSha256 });
    return Object.freeze({
      context, review, requestId: this.#ackFault === "request" ? "mismatched-request" : context.requestId,
      contextSha256: this.#ackFault === "context" ? "0".repeat(64) : context.contextSha256,
      interrupt,
      complete: async decision => {
        if (terminal) return terminal;
        if (completing) return interrupt("REPEATED_COMPLETION");
        if (!review.matches(decision) || decision.requestId !== context.requestId || decision.contextSha256 !== context.contextSha256) return finish("FAILED", "DECISION_MISMATCH");
        if (clockValue(this.#now, context) >= context.expiresAt || decision.state === "Expired") return finish("EXPIRED", "EXPIRED");
        if (decision.state === "Rejected") return finish("REJECTED", "MOCK_REJECTION");
        if (decision.state === "Cancelled") return finish("CANCELLED", "MOCK_CANCELLATION");
        if (decision.state !== "ApprovedMock") return finish("FAILED", "DECISION_MISMATCH");
        if (this.#mode === "failure") return finish("FAILED", "SIMULATED_TRANSPORT_FAILURE");
        completing = true; started = true;
        try { await this.#gate; }
        catch { return interrupt("SIMULATED_TRANSPORT_FAILURE"); }
        if (terminal) return terminal;
        if (clockValue(this.#now, context) >= context.expiresAt) return finish("EXPIRED", "EXPIRED");
        if (this.#mode === "unknown") return finish("OUTCOME_UNKNOWN", "SIMULATED_RESPONSE_LOSS");
        const results = context.targets.map(target => {
          const status = this.#results.find(r => r.id === target.id)?.status ?? "MOCK_SUCCESS";
          return { id: target.id, status, errorCategory: status === "MOCK_FAILURE" ? "FAKE_ADAPTER_FAILURE" : status === "UNKNOWN" ? "RECONCILIATION_REQUIRED" : null };
        });
        const status = results.some(r => r.status === "UNKNOWN") ? "OUTCOME_UNKNOWN" :
          results.every(r => r.status === "MOCK_SUCCESS") ? "MOCK_COMPLETED" :
          results.some(r => r.status === "MOCK_SUCCESS") ? "PARTIAL" : "FAILED";
        return finish(status, status === "MOCK_COMPLETED" ? "FAKE_ONLY_NO_DISPATCH" : "FAKE_TARGET_OUTCOMES", results);
      }
    });
  }
}

async function runPrepared(context, { transport, now = Date.now, onReview, signal, timeoutMs = 30000,
  schedule = setTimeout, unschedule = clearTimeout } = {}) {
  const history = [];
  const observe = value => freeze({ ...value, history: [...history, value.status] });
  let ack; let timer; let abort;
  try {
    assertPrepared(context);
    history.push("PREPARED");
    if (typeof onReview !== "function" || !(transport instanceof FakeTransport) || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) return observe(outcome(context, "NOT_SUBMITTED", "INVALID_CLIENT_OPTIONS"));
    if (signal?.aborted) return observe(outcome(context, "NOT_SUBMITTED", "CANCELLED"));
    if (clockValue(now, context) >= context.expiresAt) return observe(outcome(context, "EXPIRED", "EXPIRED"));
    ack = transport.submit(context); history.push("SUBMITTED");
    if (ack.context !== context || ack.requestId !== context.requestId || ack.contextSha256 !== context.contextSha256) return observe(ack.interrupt("ACK_MISMATCH"));
    const interruption = new Promise(resolve => {
      abort = () => resolve(ack.interrupt("CANCELLED"));
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      const untilExpiry = context.expiresAt - clockValue(now, context);
      timer = schedule(() => resolve(ack.interrupt(untilExpiry <= timeoutMs ? "EXPIRED" : "TIMED_OUT")), Math.min(timeoutMs, untilExpiry));
    });
    const interaction = (async () => {
      try {
        const decision = await onReview(ack.review);
        if (signal?.aborted) return ack.interrupt("CANCELLED");
        if (clockValue(now, context) >= context.expiresAt) return ack.interrupt("EXPIRED");
        return await ack.complete(decision);
      } catch { return ack.interrupt("REVIEW_OR_TRANSPORT_FAILURE"); }
    })();
    return observe(await Promise.race([interaction, interruption]));
  } catch (error) {
    const reason = ["DUPLICATE_REQUEST", "REQUEST_CONTEXT_CONFLICT", "FAKE_CAPACITY_REACHED", "EXPIRED", "RESULT_ID_MISMATCH"].includes(error?.code) ? error.code : "CLIENT_FAILURE";
    return observe(ack ? ack.interrupt(reason) : outcome(null, "NOT_SUBMITTED", reason));
  } finally {
    if (timer !== undefined) unschedule(timer);
    if (abort) signal?.removeEventListener("abort", abort);
  }
}

async function runRequest(request, configuration, options) {
  let context;
  try { context = prepareRequest(request, configuration, { now: options.now(), expiresAt: options.expiresAt }); }
  catch (error) {
    const categories = new Set(["INVALID_LIFETIME", "INVALID_CONFIGURATION", "DUPLICATE_TARGET_ID", "TARGET_NOT_CONFIGURED", "CLI_CONTEXT_UNSUPPORTED", "DESTINATION_NORMALIZATION_UNSUPPORTED", "INVALID_TARGET_PARAMETERS", "TASK_OVERSIZED", "EMPTY_EFFECTIVE_TASK", "INPUT_BOUND_EXCEEDED", "INVALID_TEXT_ENCODING", "NON_JSON_INPUT", "UNSUPPORTED_VERSION", "SCHEMA_INVALID", "REQUIRED_FIELD_MISSING", "UNKNOWN_FIELD"]);
    return freeze({ ...outcome(null, "NOT_SUBMITTED", "PREPARATION_REJECTED"),
      errorCategory: categories.has(error?.code) ? error.code : "PREPARATION_REJECTED", history: ["NOT_SUBMITTED"] });
  }
  return runPrepared(context, options);
}

module.exports = { FakeTransport, runPrepared, runRequest };
