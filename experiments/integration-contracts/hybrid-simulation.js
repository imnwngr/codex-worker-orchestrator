"use strict";
const { freeze } = require("./prepare-request");
// One bounded in-process fixture per current canonical generation. No network or proofs.
class HybridSimulation {
  #binding = null; #state = "Unavailable"; #registered = false;
  reset(binding, eligible) { this.#binding = binding; this.#registered = eligible; this.#state = eligible ? "ReadyForSimulation" : "Unavailable"; }
  end(state) { this.#binding = null; this.#registered = false; this.#state = state; }
  view() { return freeze({ state: this.#state, registered: this.#registered, identity: "UNVERIFIED_SIMULATION_FIXTURE",
    fixtureId: this.#binding?.methodId === "PROTECTED_WINDOWS" ? "fake-component-v1" : "fake-device-v1",
    prerequisites: "FAKE_FIXTURE_ID_MATCH_ONLY; INSTALLATION_SIGNATURE_ENDPOINT_TRUST_NOT_ESTABLISHED", origin: "UNVERIFIED: https://simulation.invalid", channel: "IN_PROCESS_FAKE_ONLY", authorized: false, productionAuthorization: "DEFAULT_DENY" }); }
  apply(action, token, fixtureId) {
    if (!this.#registered || !token || !this.#binding ||
      Object.keys(this.#binding).some(k => token[k] !== this.#binding[k]) || fixtureId !== this.view().fixtureId) return false;
    const s = this.#state; let next;
    if (s === "ReadyForSimulation" && action === "UNAVAILABLE") next = "Unavailable";
    if (s === "ReadyForSimulation" && action === "START") next = "Pending";
    if (s === "Pending" && action === "DELIVER" && token.methodId === "REMOTE_BROWSER") next = "AwaitingResponse";
    if ((s === "AwaitingResponse" || s === "Pending" && token.methodId === "PROTECTED_WINDOWS") && action === "COMPLETE") next = "SimulatedComplete";
    if (["Pending", "AwaitingResponse"].includes(s) && action === "REJECT") next = "Rejected";
    if (["ReadyForSimulation", "Pending", "AwaitingResponse", "Unknown"].includes(s) && ["CANCEL", "REVOKE"].includes(action)) next = "Cancelled";
    if (["Pending", "AwaitingResponse"].includes(s) && action === "FAIL") next = "Failed";
    if (s === "AwaitingResponse" && action === "UNKNOWN") next = "Unknown";
    if (s === "Unknown" && action === "RECOVER") next = "Cancelled";
    if (!next) return false;
    if (["REVOKE", "UNAVAILABLE"].includes(action)) this.#registered = false;
    this.#state = next; return true;
  }
}
module.exports = { HybridSimulation };
