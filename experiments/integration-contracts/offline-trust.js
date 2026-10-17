"use strict";

// Phase 5/6 offline protocol fixtures. These values are never identity evidence.
const { canonicalJson } = require("../../broker/providers/approval-core");
const { assertPrepared, freeze } = require("./prepare-request");
const { METHODS } = require("./hybrid-review");
const VERSION = 1;
const FIELDS = ["version", "kind", "methodId", "requestId", "sessionId", "contextSha256", "batchSha256", "instanceId", "generation", "expiresAt", "challenge", "nonce", "requesterClaim", "actorClaim", "accountClaim", "deviceClaim", "originClaim", "peerRole", "trustStatus", "outcome", "consentStatement", "endpointTrust", "channelTrust", "authorized", "productionAuthorization"];
const KINDS = ["CONSENT_REQUEST", "CONSENT_RESPONSE", "HELLO", "REGISTRATION", "REVOCATION"];
const OUTCOMES = ["NONE", "GRANT", "DENY", "CANCEL", "UNKNOWN"];
const ROLES = ["FAKE_LOCAL_UI", "FAKE_PROTECTED_COMPONENT", "FAKE_REMOTE_DEVICE"];
const ID = /^[A-Za-z0-9_.:-]{1,96}$/u;
const HEX = /^[0-9a-f]{64}$/u;
function valid(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== FIELDS.length || keys.some(key => typeof key !== "string" || !FIELDS.includes(key))) return false;
  const d = Object.getOwnPropertyDescriptors(value);
  if (keys.some(key => !d[key].enumerable || !Object.hasOwn(d[key], "value"))) return false;
  return value.version === VERSION && KINDS.includes(value.kind) && METHODS.some(m => m.id === value.methodId) &&
    ["requestId", "sessionId", "instanceId", "challenge", "nonce", "requesterClaim", "actorClaim", "accountClaim", "deviceClaim"].every(k => typeof value[k] === "string" && ID.test(value[k])) &&
    HEX.test(value.contextSha256) && HEX.test(value.batchSha256) && Number.isSafeInteger(value.generation) && value.generation > 0 &&
    Number.isSafeInteger(value.expiresAt) && value.expiresAt > 0 &&
    value.originClaim === "UNVERIFIED: https://simulation.invalid" && ROLES.includes(value.peerRole) &&
    value.peerRole === ({ LOCAL_DESKTOP: ROLES[0], PROTECTED_WINDOWS: ROLES[1], REMOTE_BROWSER: ROLES[2] })[value.methodId] &&
    value.trustStatus === "UNVERIFIED_SIMULATION_ONLY" && OUTCOMES.includes(value.outcome) &&
    (value.kind === "CONSENT_RESPONSE" ? value.outcome !== "NONE" : value.outcome === "NONE") &&
    value.consentStatement === `SIMULATION ONLY: action context ${value.contextSha256} expires at ${value.expiresAt}; no production authorization.` &&
    value.endpointTrust === "UNESTABLISHED" && value.channelTrust === "FAKE_IN_PROCESS" &&
    value.authorized === false && value.productionAuthorization === "DEFAULT_DENY";
}
function encode(value) {
  if (!valid(value)) throw Error("OFFLINE_PROTOCOL_INVALID");
  const data = canonicalJson(value);
  if (Buffer.byteLength(data, "utf8") > 4096) throw Error("OFFLINE_PROTOCOL_OVERSIZED");
  return data;
}
function decode(data) {
  if (typeof data !== "string" || Buffer.byteLength(data, "utf8") > 4096 || Buffer.byteLength(data, "utf8") === 0) throw Error("OFFLINE_PROTOCOL_INVALID");
  let value;
  try { value = JSON.parse(data); } catch { throw Error("OFFLINE_PROTOCOL_INVALID"); }
  // Canonical-only input rejects duplicate JSON names, ambiguous encodings and non-canonical framing.
  if (!valid(value) || canonicalJson(value) !== data) throw Error("OFFLINE_PROTOCOL_INVALID");
  return freeze(value);
}
function message(correlation, context, kind, outcome = "NONE", challenge = "fake-challenge-v1", nonce = "fake-nonce-v1") {
  assertPrepared(context);
  const role = { LOCAL_DESKTOP: ROLES[0], PROTECTED_WINDOWS: ROLES[1], REMOTE_BROWSER: ROLES[2] }[correlation?.methodId];
  const result = {
    version: VERSION, kind, methodId: correlation?.methodId, requestId: context.requestId, sessionId: context.sessionId,
    contextSha256: context.contextSha256, batchSha256: context.batchSha256, instanceId: correlation?.instanceId,
    generation: correlation?.generation, expiresAt: context.expiresAt, challenge, nonce,
    requesterClaim: "fake-requester", actorClaim: "fake-approver", accountClaim: "fake-account", deviceClaim: "fake-device",
    originClaim: "UNVERIFIED: https://simulation.invalid", peerRole: role, trustStatus: "UNVERIFIED_SIMULATION_ONLY",
    outcome, consentStatement: `SIMULATION ONLY: action context ${context.contextSha256} expires at ${context.expiresAt}; no production authorization.`,
    endpointTrust: "UNESTABLISHED", channelTrust: "FAKE_IN_PROCESS", authorized: false, productionAuthorization: "DEFAULT_DENY"
  };
  return decode(encode(result));
}
class OfflineTrustSession {
  #coordinator; #context; #binding; #clock; #last; #state = "Ready"; #seen = false; #registered = false; #challenge; #nonce;
  constructor(coordinator, context, now, { challenge = "fake-challenge-v1", nonce = "fake-nonce-v1" } = {}) {
    assertPrepared(context);
    if (typeof now !== "function" || !ID.test(challenge) || !ID.test(nonce)) throw Error("OFFLINE_PROTOCOL_INVALID");
    const v = coordinator.view();
    if (v.state !== "Pending" || !v.canDecide || v.preview.contextSha256 !== context.contextSha256 || v.expiresAt !== context.expiresAt || !v.correlation) throw Error("OFFLINE_BINDING_INVALID");
    this.#coordinator = coordinator; this.#context = context; this.#binding = freeze({ ...v.correlation });
    this.#clock = now; this.#challenge = challenge; this.#nonce = nonce;
    this.#last = context.createdAt;
  }
  view() { return freeze({ state: this.#state, registered: this.#registered, authorized: false, productionAuthorization: "DEFAULT_DENY", identity: "UNVERIFIED_SIMULATION_ONLY", expiresAt: this.#context.expiresAt }); }
  fixture(kind, outcome = "NONE") { return message(this.#binding, this.#context, kind, outcome, this.#challenge, this.#nonce); }
  #active() {
    if (["Expired", "ApprovedMock", "Rejected", "Cancelled", "Abandoned"].includes(this.#state)) return false;
    let time;
    try { time = this.#clock(); } catch { this.#state = "Expired"; return false; }
    if (!Number.isSafeInteger(time) || time < this.#last || time < this.#context.createdAt || time >= this.#context.expiresAt) { this.#state = "Expired"; return false; }
    this.#last = time;
    const v = this.#coordinator.view();
    if (v.state !== "Pending" || !v.canDecide || Object.keys(this.#binding).some(k => v.correlation?.[k] !== this.#binding[k])) {
      this.#state = v.state === "Expired" ? "Expired" : "Abandoned"; return false;
    }
    return true;
  }
  #check(value, kind) {
    if (!valid(value) || value.kind !== kind) return false;
    const expected = this.fixture(kind, value.outcome);
    return FIELDS.every(k => value[k] === expected[k]);
  }
  negotiate(value) {
    if (!this.#active() || this.#state !== "Ready" || this.#binding.methodId !== "PROTECTED_WINDOWS" || !this.#check(value, "HELLO")) return false;
    this.#state = "Negotiated"; return true;
  }
  register(value) {
    if (!this.#active() || this.#state !== "Ready" || this.#binding.methodId !== "REMOTE_BROWSER" || !this.#check(value, "REGISTRATION")) return false;
    this.#registered = true; this.#state = "Registered"; return true; // Non-secret simulation metadata only.
  }
  revoke(value) {
    if (!this.#active() || this.#binding.methodId !== "REMOTE_BROWSER" || !this.#registered || !this.#check(value, "REVOCATION")) return false;
    this.#registered = false; this.#state = "Unknown"; return true;
  }
  start(value) {
    if (!this.#active() || !this.#check(value, "CONSENT_REQUEST")) return false;
    const method = this.#binding.methodId;
    if (this.#state !== (method === "PROTECTED_WINDOWS" ? "Negotiated" : method === "REMOTE_BROWSER" ? "Registered" : "Ready")) return false;
    if (method !== "LOCAL_DESKTOP" && !this.#coordinator.simulate("START", this.#binding, this.#coordinator.view().simulation.fixtureId)) return false;
    if (method === "REMOTE_BROWSER" && !this.#coordinator.simulate("DELIVER", this.#binding, this.#coordinator.view().simulation.fixtureId)) return false;
    this.#state = "Pending"; return true;
  }
  receive(value) {
    if (!this.#active() || this.#state !== "Pending" || this.#seen || !this.#check(value, "CONSENT_RESPONSE")) return false;
    this.#seen = true; // A received synthetic message can be consumed at most once.
    if (value.outcome === "UNKNOWN") { this.#state = "Unknown"; return true; }
    const operation = { GRANT: "APPROVE_MOCK", DENY: "REJECT", CANCEL: "CANCEL" }[value.outcome];
    const simOp = { GRANT: "COMPLETE", DENY: "REJECT", CANCEL: "CANCEL" }[value.outcome];
    const ok = this.#binding.methodId === "LOCAL_DESKTOP" ? this.#coordinator.decide(operation, this.#binding) : this.#coordinator.simulate(simOp, this.#binding, this.#coordinator.view().simulation.fixtureId);
    this.#state = ok ? ({ GRANT: "ApprovedMock", DENY: "Rejected", CANCEL: "Cancelled" })[value.outcome] : this.#coordinator.view().state === "Expired" ? "Expired" : "Abandoned";
    return ok;
  }
  crash() { if (!this.#active() || this.#state !== "Pending") return false; this.#state = "Unknown"; return true; }
  recover() {
    if (!this.#active() || this.#state !== "Unknown") return false;
    const accepted = this.#coordinator.decide("CANCEL", this.#binding);
    this.#state = accepted ? "Abandoned" : this.#coordinator.view().state === "Expired" ? "Expired" : "Abandoned";
    return accepted;
  }
}
class OfflineTrustFakeTransport {
  #frames = []; #online = true;
  get online() { return this.#online; }
  get pending() { return this.#frames.length; }
  disconnect() { this.#online = false; }
  reconnect() { this.#online = true; }
  clear() { this.#frames.length = 0; }
  send(frame) {
    if (!this.#online || this.#frames.length >= 4) return false;
    let value;
    try { value = decode(frame); } catch { return false; }
    if (value.kind !== "CONSENT_RESPONSE") return false;
    this.#frames.push(frame);
    return true;
  }
  deliver(session) {
    if (!this.#online || this.#frames.length === 0) return false;
    // A fake delivery consumes the frame even on failed canonical correlation.
    return session.receive(decode(this.#frames.shift()));
  }
}
module.exports = { VERSION, FIELDS, valid, encode, decode, message, OfflineTrustSession, OfflineTrustFakeTransport };
