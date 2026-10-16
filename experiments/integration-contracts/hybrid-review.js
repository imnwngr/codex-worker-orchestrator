"use strict";

// Local mock coordination only. No transport, provider, proof or persistence dependencies.
const { assertPrepared, clockValue, freeze } = require("./prepare-request");
const { HybridSimulation } = require("./hybrid-simulation");
const { createReview } = require("./review-preview");

const METHODS = freeze([
  { id: "LOCAL_DESKTOP", displayName: "A — Local Desktop", description: "Existing WPF offline review",
    availability: "OFFLINE_FUNCTIONAL", prerequisites: "Explicit valid local review file", actions: ["APPROVE_MOCK", "REJECT", "CANCEL"],
    assurance: "UNESTABLISHED_NON_AUTHORIZING", simulated: false, transportEstablished: false, identityEstablished: false },
  { id: "PROTECTED_WINDOWS", displayName: "B — Protected Windows (simulation)", description: "No protected component or authenticated IPC",
    availability: "SIMULATED", prerequisites: "Reviewed installation, component identity and privileges", actions: ["APPROVE_MOCK", "REJECT", "CANCEL"],
    assurance: "UNESTABLISHED_NON_AUTHORIZING", simulated: true, transportEstablished: false, identityEstablished: false },
  { id: "REMOTE_BROWSER", displayName: "C — Remote / Browser (simulation)", description: "No device or browser communication",
    availability: "SIMULATED", prerequisites: "Device registration, browser origin and authenticated channels", actions: ["APPROVE_MOCK", "REJECT", "CANCEL"],
    assurance: "UNESTABLISHED_NON_AUTHORIZING", simulated: true, transportEstablished: false, identityEstablished: false }
]);
const method = id => METHODS.find(m => m.id === id);
function metadataValid(value) { return METHODS.includes(value); } // Caller metadata never supplies capabilities.
function policyOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options) || Object.keys(options).some(k => !["allowedMethods", "requirement"].includes(k))) throw new Error("HYBRID_POLICY_INVALID");
  const allowed = options.allowedMethods ?? METHODS.map(m => m.id);
  const requirement = options.requirement ?? "OFFLINE_PREVIEW";
  if (!Array.isArray(allowed) || allowed.length > 3 || new Set(allowed).size !== allowed.length || allowed.some(id => !method(id)) ||
      !["OFFLINE_PREVIEW", "PROTECTED_IDENTITY", "REMOTE_IDENTITY"].includes(requirement)) throw new Error("HYBRID_POLICY_INVALID");
  return freeze({ allowedMethods: [...allowed], requirement });
}
function checkPolicy(metadata, policy) {
  if (!metadataValid(metadata)) return "HYBRID_METADATA_INVALID";
  if (!policy.allowedMethods.includes(metadata.id)) return "HYBRID_METHOD_NOT_ALLOWED";
  if (policy.requirement !== "OFFLINE_PREVIEW") return "HYBRID_ASSURANCE_UNAVAILABLE";
  return "OFFLINE_ONLY";
}

class HybridCoordinator {
  #instanceId = require("node:crypto").randomUUID();
  #simulation = new HybridSimulation();
  #clock; #policy; #preferred; #context = null; #selected = null; #generation = 0; #review = null; #state = "NO_REQUEST"; #reason = "NO_REQUEST";
  constructor({ now = Date.now, preferredMethod = null, policy = {} } = {}) {
    if (typeof now !== "function" || (preferredMethod !== null && !method(preferredMethod))) throw new Error("HYBRID_OPTIONS_INVALID");
    let last = -Infinity; this.#clock = () => { const value = now(); if (!Number.isSafeInteger(value) || value < last) throw Error("INVALID_CLOCK"); last = value; return value; }; this.#preferred = preferredMethod; this.#policy = policyOptions(policy);
  }
  setPreference(id) {
    if (id !== null && !method(id)) return false;
    this.#preferred = id; return true; // Future begin only; cannot mutate policy/current selection.
  }
  begin(context) {
    assertPrepared(context);
    let time;
    try { time = clockValue(this.#clock, context); } catch { throw new Error("HYBRID_CLOCK_INVALID"); }
    if (time >= context.expiresAt) throw new Error("HYBRID_CONTEXT_EXPIRED");
    const review = createReview(context, this.#clock);
    if (!Number.isSafeInteger(this.#generation + 1)) throw new Error("HYBRID_GENERATION_EXHAUSTED");
    this.#context = context; this.#review = review; this.#generation++;
    this.#selected = this.#preferred ?? "LOCAL_DESKTOP"; this.#state = "Pending"; this.#reason = this.#check(this.#selected);
    this.#resetSimulation();
    return this.view();
  }
  #check(id) { return checkPolicy(method(id), this.#policy); }
  #refresh() {
    if (this.#state !== "Pending") return;
    try { if (this.#review.view().state === "Expired") { this.#state = "Expired"; this.#reason = "EXPIRED"; this.#simulation.end("Expired"); } }
    catch { this.#state = "Expired"; this.#reason = "INVALID_CLOCK"; this.#simulation.end("Expired"); }
  }
  #matches(token) {
    return token && typeof token === "object" && !Array.isArray(token) && Object.keys(token).length === 6 && token.instanceId === this.#instanceId && token.requestId === this.#context?.requestId && token.sessionId === this.#context?.sessionId &&
      token.contextSha256 === this.#context?.contextSha256 && token.generation === this.#generation && token.methodId === this.#selected;
  }
  view() {
    this.#refresh();
    return freeze({ simulation: this.#simulation.view(), designation: "SYNTHETIC_DESIGN_ONLY", preferredMethod: this.#preferred, selectedMethod: this.#selected,
      state: this.#state, reason: this.#reason, generation: this.#generation,
      correlation: this.#context ? { requestId: this.#context.requestId, sessionId: this.#context.sessionId,
        instanceId: this.#instanceId, contextSha256: this.#context.contextSha256, generation: this.#generation, methodId: this.#selected } : null,
      preview: this.#review?.preview ?? null, expiresAt: this.#context?.expiresAt ?? null,
      canSwitch: this.#state === "Pending", canDecide: this.#state === "Pending" && this.#check(this.#selected) === "OFFLINE_ONLY",
      authorized: false, productionAuthorization: "DEFAULT_DENY" });
  }
  switchMethod(id, token, { setAsDefault = false } = {}) {
    this.#refresh();
    if (this.#state !== "Pending" || !this.#matches(token)) return false;
    if (typeof setAsDefault !== "boolean") return false;
    const reason = this.#check(id);
    if (reason !== "OFFLINE_ONLY") { this.#reason = reason; return false; }
    if (id !== this.#selected) {
      if (!Number.isSafeInteger(this.#generation + 1)) { this.#state = "Cancelled"; this.#reason = "HYBRID_GENERATION_EXHAUSTED"; this.#simulation.end("Cancelled"); return false; }
      // Validate the candidate generation before replacing the current review. A clock can
      // advance between opening and applying a picker; expiry must not be revived.
      let candidate;
      try {
        candidate = createReview(this.#context, this.#clock);
        if (candidate.view().state === "Expired") { this.#state = "Expired"; this.#reason = "EXPIRED"; this.#simulation.end("Expired"); return false; }
      } catch { this.#state = "Expired"; this.#reason = "INVALID_CLOCK"; this.#simulation.end("Expired"); return false; }
      this.#review = candidate;
      this.#selected = id; this.#generation++; this.#resetSimulation();
    }
    if (setAsDefault) this.#preferred = id;
    this.#reason = "OFFLINE_ONLY"; return true;
  }
  #resetSimulation() {
    this.#simulation.reset(this.view().correlation, this.#state === "Pending" && this.#selected !== "LOCAL_DESKTOP" && this.#check(this.#selected) === "OFFLINE_ONLY");
  }
  simulate(action, token, fixtureId) {
    this.#refresh();
    if (this.#state !== "Pending" || this.#selected === "LOCAL_DESKTOP" || !this.#matches(token) || this.#check(this.#selected) !== "OFFLINE_ONLY" || !this.#simulation.apply(action, token, fixtureId)) return false;
    const state = this.#simulation.view().state;
    const decision = { SimulatedComplete: "APPROVE_MOCK", Rejected: "REJECT", Cancelled: "CANCEL" }[state];
    return decision ? this.decide(decision, token) : true;
  }
  decide(action, token) {
    this.#refresh();
    if (this.#state !== "Pending" || !this.#matches(token) || (action !== "CANCEL" && this.#check(this.#selected) !== "OFFLINE_ONLY") || !["APPROVE_MOCK", "REJECT", "CANCEL"].includes(action)) return false;
    try {
      const decision = this.#review.decide(action);
      // The nested canonical check/capture may reach the original expiry after refresh.
      if (decision.state === "Expired" || decision.decidedAt >= this.#context.expiresAt) {
        this.#state = "Expired"; this.#reason = "EXPIRED"; this.#simulation.end("Expired"); return false;
      }
      this.#state = decision.state; this.#reason = "LOCAL_MOCK_ONLY_NO_DISPATCH"; this.#simulation.end(this.#state === "ApprovedMock" ? "SimulatedComplete" : this.#state); return true; }
    catch { this.#state = "Expired"; this.#reason = "INVALID_CLOCK"; this.#simulation.end("Expired"); return false; }
  }
}
module.exports = { METHODS, metadataValid, HybridCoordinator };
