"use strict";
(function (root) {
  const fields = "version kind methodId requestId sessionId contextSha256 batchSha256 instanceId generation expiresAt challenge nonce requesterClaim actorClaim accountClaim deviceClaim originClaim peerRole trustStatus outcome consentStatement endpointTrust channelTrust authorized productionAuthorization".split(" ");
  const id = /^[A-Za-z0-9_.:-]{1,96}$/u, hex = /^[0-9a-f]{64}$/u;
  function fail() { throw Error("INVALID_OFFLINE_BROWSER_PACKAGE"); }
  function canonical(value, depth = 0) {
    if (depth > 16) fail();
    if (value === null || typeof value !== "object") {
      if (typeof value === "number" && !Number.isSafeInteger(value)) fail();
      if (typeof value === "string" && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) fail();
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return "[" + value.map(v => canonical(v, depth + 1)).join(",") + "]";
    return "{" + Object.keys(value).sort().map(k => canonical(k, depth + 1) + ":" + canonical(value[k], depth + 1)).join(",") + "}";
  }
  function keys(value, expected) {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== expected.length || expected.some(k => !Object.hasOwn(value, k))) fail();
  }
  function parse(text) {
    if (typeof text !== "string" || new TextEncoder().encode(text).length > 262144 || text.length === 0) fail();
    let value; try { value = JSON.parse(text); } catch { fail(); }
    if (canonical(value) !== text) fail();
    keys(value, ["schemaVersion", "designation", "request", "responseTemplate"]);
    if (value.schemaVersion !== 1 || value.designation !== "OFFLINE_BROWSER_PREVIEW_ONLY") fail();
    const r = value.request, m = value.responseTemplate;
    keys(r, ["requestId", "sessionId", "contextSha256", "batchSha256", "createdAt", "expiresAt", "targets"]);
    keys(m, fields);
    for (const k of ["requestId", "sessionId"]) if (typeof r[k] !== "string" || !id.test(r[k]) || m[k] !== r[k]) fail();
    for (const k of ["contextSha256", "batchSha256"]) if (typeof r[k] !== "string" || !hex.test(r[k]) || m[k] !== r[k]) fail();
    if (!Number.isSafeInteger(r.createdAt) || r.createdAt <= 0 || !Number.isSafeInteger(r.expiresAt) || r.expiresAt <= r.createdAt || r.expiresAt - r.createdAt > 300000 || m.expiresAt !== r.expiresAt) fail();
    if (!Array.isArray(r.targets) || r.targets.length < 1 || r.targets.length > 8) fail();
    const seen = new Set();
    for (const t of r.targets) {
      keys(t, ["id", "providerId", "modelId", "destination", "task", "taskSha256"]);
      if (["id", "providerId", "modelId"].some(k => typeof t[k] !== "string" || !id.test(t[k])) || seen.has(t.id)) fail();
      seen.add(t.id);
      if (typeof t.task !== "string" || t.task.length < 1 || t.task.length > 50000 || typeof t.destination !== "string" || t.destination.length > 2048 || !/^https:\/\//u.test(t.destination) || typeof t.taskSha256 !== "string" || !hex.test(t.taskSha256)) fail();
    }
    if (new TextEncoder().encode(canonical(m)).length > 4096 || m.version !== 1 || m.kind !== "CONSENT_RESPONSE" || m.methodId !== "REMOTE_BROWSER" || m.outcome !== "GRANT" || !Number.isSafeInteger(m.generation) || m.generation <= 0) fail();
    for (const k of ["instanceId", "challenge", "nonce", "requesterClaim", "actorClaim", "accountClaim", "deviceClaim"]) if (typeof m[k] !== "string" || !id.test(m[k])) fail();
    if (m.originClaim !== "UNVERIFIED: https://simulation.invalid" || m.peerRole !== "FAKE_REMOTE_DEVICE" || m.trustStatus !== "UNVERIFIED_SIMULATION_ONLY" || m.endpointTrust !== "UNESTABLISHED" || m.channelTrust !== "FAKE_IN_PROCESS" || m.authorized !== false || m.productionAuthorization !== "DEFAULT_DENY" || m.consentStatement !== `SIMULATION ONLY: action context ${r.contextSha256} expires at ${r.expiresAt}; no production authorization.`) fail();
    return value;
  }
  class Preview {
    #package; #last; #state = "Empty";
    get state() { return this.#state; }
    get request() { return this.#package ? JSON.parse(canonical(this.#package.request)) : null; }
    load(text, now) {
      const candidate = parse(text);
      if (!Number.isSafeInteger(now) || now < candidate.request.createdAt || now >= candidate.request.expiresAt) fail();
      this.#package = candidate; this.#last = now; this.#state = "Pending";
      return this.request;
    }
    tick(now) {
      if (this.#state !== "Pending") return this.#state;
      if (!Number.isSafeInteger(now) || now < this.#last || now >= this.#package.request.expiresAt) this.#state = "Expired";
      else this.#last = now;
      return this.#state;
    }
    respond(outcome, now) {
      if (this.tick(now) !== "Pending" || !["GRANT", "DENY", "CANCEL", "UNKNOWN"].includes(outcome)) throw Error("OFFLINE_RESPONSE_DENIED");
      const result = canonical({ ...this.#package.responseTemplate, outcome });
      this.#state = outcome === "UNKNOWN" ? "Unknown" : "Exported";
      return result;
    }
  }
  const api = { canonical, parse, Preview };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.OfflineBrowserPreview = api;
})(globalThis);
