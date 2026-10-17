"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { Preview, parse, canonical } = require("./preview");
const { pending } = require("./vector-cli");
const { decode } = require("../integration-contracts/offline-trust");
for (const outcome of ["GRANT", "DENY", "CANCEL", "UNKNOWN"]) test(`browser ${outcome} returns exact canonical Node session response`, () => {
  const f = pending(), p = new Preview(); p.load(f.package, f.now);
  const text = p.respond(outcome, f.now);
  assert.equal(text, canonical(f.session.fixture("CONSENT_RESPONSE", outcome)));
  assert.equal(f.session.receive(decode(text)), true);
  assert.equal(f.session.receive(decode(text)), false);
  assert.throws(() => p.respond(outcome, f.now));
  assert.equal(f.coordinator.view().authorized, false);
  assert.equal(f.coordinator.view().productionAuthorization, "DEFAULT_DENY");
  if (outcome === "UNKNOWN") { assert.equal(f.session.recover(), true); assert.equal(f.coordinator.view().state, "Cancelled"); }
  else assert.equal(f.coordinator.view().state, { GRANT: "ApprovedMock", DENY: "Rejected", CANCEL: "Cancelled" }[outcome]);
});
test("browser strict framing and malformed replacement preserve pending review", () => {
  const f = pending(), p = new Preview(); p.load(f.package, f.now);
  for (const bad of ["{}", f.package + " ", f.package.replace("{", '{"schemaVersion":1,'), "x".repeat(262145)]) assert.throws(() => p.load(bad, f.now));
  assert.equal(p.state, "Pending"); assert.equal(p.respond("GRANT", f.now), canonical(f.session.fixture("CONSENT_RESPONSE", "GRANT")));
});
test("browser exact deadline and rollback deny export", () => {
  for (const time of [f => f.context.expiresAt, f => f.now - 1]) {
    const f = pending(), p = new Preview(); p.load(f.package, f.now);
    assert.throws(() => p.respond("GRANT", time(f))); assert.equal(p.state, "Expired");
  }
});
test("browser tampered claims, authority and extra fields fail closed", () => {
  const f = pending();
  for (const change of [m => m.authorized = true, m => m.originClaim = "https://trusted.example", m => m.methodId = "LOCAL_DESKTOP", m => m.generation = 0, m => m.expiresAt++, m => m.deviceClaim = "bad space", m => m.extra = 1, m => m.contextSha256 = "a".repeat(64)]) {
    const value = JSON.parse(f.package); change(value.responseTemplate); assert.throws(() => parse(canonical(value)));
  }
});
test("browser mutable display copy cannot alter exported canonical response", () => {
  const f = pending(), p = new Preview(); p.load(f.package, f.now); p.request.targets[0].task = "forged";
  assert.equal(p.respond("GRANT", f.now), canonical(f.session.fixture("CONSENT_RESPONSE", "GRANT")));
});
test("browser old generation, different instance and cancelled session reject", () => {
  const f = pending(), p = new Preview(); p.load(f.package, f.now); const frame = decode(p.respond("GRANT", f.now));
  assert.equal(f.coordinator.switchMethod("LOCAL_DESKTOP", f.coordinator.view().correlation), true);
  assert.equal(f.session.receive(frame), false);
  const other = pending(); assert.equal(other.session.receive(frame), false);
  const third = pending(); assert.equal(third.coordinator.decide("CANCEL", third.coordinator.view().correlation), true);
  assert.equal(third.session.receive(third.session.fixture("CONSENT_RESPONSE", "GRANT")), false);
});
test("browser UTF-16 and oversized task rejection", () => {
  let nested = null; for (let i = 0; i < 18; i++) nested = [nested]; assert.throws(() => canonical(nested));
  const f = pending();
  for (const task of ["x".repeat(50001), "\ud800"]) { const v = JSON.parse(f.package); v.request.targets[0].task = task; assert.throws(() => parse(canonical(v))); }
});
test("browser download response tampering is independently rejected by Node", () => {
  const f = pending(), p = new Preview(); p.load(f.package, f.now); const frame = JSON.parse(p.respond("GRANT", f.now));
  frame.contextSha256 = "a".repeat(64); frame.consentStatement = `SIMULATION ONLY: action context ${frame.contextSha256} expires at ${frame.expiresAt}; no production authorization.`; assert.equal(f.session.receive(decode(canonical(frame))), false);
  frame.contextSha256 = f.context.contextSha256; frame.consentStatement = f.session.fixture("CONSENT_RESPONSE", "GRANT").consentStatement; assert.equal(f.session.receive(decode(canonical(frame))), true);
});
test("browser UI has local assets, text-only rendering and network prohibition", () => {
  const fs = require("node:fs"), path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8"), ui = fs.readFileSync(path.join(__dirname, "ui.js"), "utf8");
  assert.match(html, /connect-src 'none'/); assert.match(html, /role="status"/);
  assert.doesNotMatch(html, /(?:src|href)="https?:/); assert.doesNotMatch(ui, /innerHTML|fetch\(|XMLHttpRequest/); assert.match(ui, /textContent/);
});


test("browser golden request and response remain deterministic across Node contract", () => {
  const fs = require("node:fs"), path = require("node:path");
  const { fixtureContext } = require("../integration-contracts/export-review-cli");
  const { message, encode } = require("../integration-contracts/offline-trust");
  const { packageFor } = require("./vector-cli");
  const { context, now } = fixtureContext(true);
  const response = message({ methodId: "REMOTE_BROWSER", instanceId: "golden-browser-v1", generation: 7 }, context, "CONSENT_RESPONSE", "GRANT");
  const input = fs.readFileSync(path.join(__dirname, "fixtures/golden.browser.json"), "utf8");
  const expected = fs.readFileSync(path.join(__dirname, "fixtures/golden.response.json"), "utf8");
  assert.equal(input, packageFor(context, response)); assert.equal(expected, encode(response));
  const p = new Preview(); p.load(input, now); assert.equal(p.respond("GRANT", now), expected);
});
