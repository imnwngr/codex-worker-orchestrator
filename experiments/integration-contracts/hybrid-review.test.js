"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { METHODS, metadataValid, HybridCoordinator } = require("./hybrid-review");
const { fixtureContext } = require("./export-review-cli");
const { serializeReview } = require("./export-review");
const { FakeTransport, runPrepared } = require("./fake-workflow");
const [A, B, C] = METHODS.map(m => m.id);
function setup(options = {}) {
  const { context, now } = fixtureContext(true); let time = now;
  const coordinator = new HybridCoordinator({ now: () => time, ...options });
  return { context, coordinator, begin: () => coordinator.begin(context), setTime: value => { time = value; } };
}
test("4D method metadata distinguishes simulation from identity and is immutable", () => {
  assert.deepEqual(METHODS.map(m => m.id), ["LOCAL_DESKTOP", "PROTECTED_WINDOWS", "REMOTE_BROWSER"]);
  assert.equal(METHODS[0].simulated, false); assert.ok(METHODS.slice(1).every(m => m.simulated));
  assert.ok(METHODS.every(m => !m.identityEstablished && !m.transportEstablished && Object.isFrozen(m)));
  assert.equal(metadataValid({ ...METHODS[1], identityEstablished: true }), false);
  assert.equal(metadataValid({ ...METHODS[1], availability: "OFFLINE_FUNCTIONAL" }), false);
  assert.throws(() => { METHODS[1].identityEstablished = true; }, TypeError);
});
test("4D actual preparation preview A B C A switches retain bytes task order digest and expiry", () => {
  const s = setup(); const first = s.begin(); const bytes = serializeReview(s.context, s.context.createdAt + 2000);
  let generation = first.generation;
  for (const id of [B, C, A]) {
    assert.equal(s.coordinator.switchMethod(id, s.coordinator.view().correlation), true);
    const v = s.coordinator.view(); assert.equal(v.selectedMethod, id); assert.equal(v.generation, ++generation);
    assert.equal(v.state, "Pending"); assert.equal(v.preview.targets, s.context.targets);
    assert.equal(v.preview.contextSha256, s.context.contextSha256); assert.equal(v.expiresAt, s.context.expiresAt);
    assert.ok(v.preview.text.includes("NO DISPATCH")); assert.equal(v.authorized, false); assert.equal(v.productionAuthorization, "DEFAULT_DENY");
    assert.deepEqual(serializeReview(s.context, s.context.createdAt + 2000), bytes);
  }
});
test("4D preference changes only future explicit begin and optional default is opt-in", () => {
  const s = setup(); s.begin(); const old = s.coordinator.view();
  assert.equal(s.coordinator.setPreference(C), true); assert.equal(s.coordinator.view().selectedMethod, A);
  assert.equal(s.coordinator.view().generation, old.generation);
  assert.equal(s.coordinator.switchMethod(B, old.correlation), true); assert.equal(s.coordinator.view().preferredMethod, C);
  s.begin(); assert.equal(s.coordinator.view().selectedMethod, C);
  assert.equal(s.coordinator.switchMethod(A, s.coordinator.view().correlation, { setAsDefault: true }), true);
  assert.equal(s.coordinator.view().preferredMethod, A);
  assert.equal(s.coordinator.setPreference("BAD"), false); assert.equal(s.coordinator.setPreference(null), true);
});
test("4D same method selection no-op invalid method and options retain generation", () => {
  const s = setup(); const v = s.begin();
  assert.equal(s.coordinator.switchMethod(A, v.correlation), true);
  assert.equal(s.coordinator.view().generation, v.generation);
  assert.equal(s.coordinator.switchMethod("BAD", v.correlation), false);
  assert.equal(s.coordinator.switchMethod(B, v.correlation, { setAsDefault: "true" }), false);
  assert.equal(s.coordinator.view().generation, v.generation);
});
test("4D cannot switch absent review or reopen a terminal mock outcome", () => {
  const absent = setup(); assert.equal(absent.coordinator.switchMethod(B, null), false);
  for (const action of ["APPROVE_MOCK", "REJECT", "CANCEL"]) {
    const s = setup(); const v = s.begin(); assert.equal(s.coordinator.decide(action, v.correlation), true);
    const terminal = s.coordinator.view();
    assert.equal(s.coordinator.switchMethod(B, v.correlation, { setAsDefault: true }), false);
    assert.equal(s.coordinator.decide("APPROVE_MOCK", v.correlation), false);
    assert.equal(s.coordinator.view().state, terminal.state); assert.equal(s.coordinator.view().preferredMethod, null);
  }
});
test("4D pending switch keeps deadline and expiry prevents delayed method response", () => {
  const s = setup(); s.begin(); s.setTime(s.context.expiresAt - 1);
  assert.equal(s.coordinator.switchMethod(B, s.coordinator.view().correlation), true);
  const token = s.coordinator.view().correlation; s.setTime(s.context.expiresAt);
  assert.equal(s.coordinator.switchMethod(C, token), false); assert.equal(s.coordinator.decide("APPROVE_MOCK", token), false);
  assert.equal(s.coordinator.view().state, "Expired"); assert.equal(s.coordinator.view().expiresAt, s.context.expiresAt);
  assert.throws(() => s.begin(), /HYBRID_CONTEXT_EXPIRED/);
  let calls = 0; let race = false;
  const { context, now } = fixtureContext(true);
  const coordinator = new HybridCoordinator({ now: () => race && ++calls > 1 ? context.expiresAt : now });
  const first = coordinator.begin(context); race = true;
  assert.equal(coordinator.switchMethod(B, first.correlation, { setAsDefault: true }), false);
  assert.equal(coordinator.view().state, "Expired"); assert.equal(coordinator.view().preferredMethod, null);
});
test("4D old method generation reload or substituted identity cannot decide", () => {
  const s = setup(); const first = s.begin(); assert.equal(s.coordinator.switchMethod(B, first.correlation), true);
  assert.equal(s.coordinator.decide("APPROVE_MOCK", first.correlation), false);
  const current = s.coordinator.view();
  for (const [key, value] of [["methodId", A], ["requestId", "wrong"], ["sessionId", "wrong"], ["contextSha256", "0".repeat(64)]]) {
    assert.equal(s.coordinator.decide("APPROVE_MOCK", { ...current.correlation, [key]: value }), false);
    assert.equal(s.coordinator.switchMethod(C, { ...current.correlation, [key]: value }), false);
  }
  s.begin(); assert.equal(s.coordinator.decide("APPROVE_MOCK", current.correlation), false);
  assert.throws(() => s.coordinator.begin(structuredClone(s.context)));
  assert.equal(s.coordinator.view().preview.contextSha256, s.context.contextSha256);
});
test("4D unavailable preferred method has no silent fallback and policy is snapshotted", () => {
  const allowed = [A]; const s = setup({ preferredMethod: C, policy: { allowedMethods: allowed } });
  allowed.push(B, C); const v = s.begin();
  assert.equal(v.selectedMethod, C); assert.equal(v.canDecide, false); assert.equal(v.reason, "HYBRID_METHOD_NOT_ALLOWED");
  assert.equal(s.coordinator.decide("APPROVE_MOCK", v.correlation), false);
  assert.equal(s.coordinator.switchMethod(B, v.correlation), false);
  assert.equal(s.coordinator.switchMethod(A, v.correlation), true); assert.equal(s.coordinator.view().canDecide, true);
});
test("4D protected remote policy cannot be met by any simulated or local selection", () => {
  for (const requirement of ["PROTECTED_IDENTITY", "REMOTE_IDENTITY"]) {
    const s = setup({ policy: { requirement } }); const v = s.begin();
    for (const id of [A, B, C]) {
      assert.equal(s.coordinator.setPreference(id), true);
      assert.equal(s.coordinator.switchMethod(id, v.correlation), false);
      assert.equal(s.coordinator.decide("APPROVE_MOCK", v.correlation), false);
    }
    assert.equal(s.coordinator.view().selectedMethod, A); assert.equal(s.coordinator.view().authorized, false);
  }
  for (const policy of [{ requirement: "BAD" }, { allowedMethods: [A, A] }, { allowedMethods: ["BAD"] }, { authorized: true }])
    assert.throws(() => setup({ policy }), /HYBRID_POLICY_INVALID/);
});
test("4D clock failure fails closed without manufacturing a valid selection", () => {
  const { context, now } = fixtureContext(true); let broken = false;
  const c = new HybridCoordinator({ now: () => { if (broken) throw Error("DO_NOT_ECHO_SECRET"); return now; } });
  const v = c.begin(context); broken = true;
  assert.equal(c.switchMethod(B, v.correlation), false); assert.equal(c.view().state, "Expired");
  assert.equal(c.view().reason, "INVALID_CLOCK"); assert.ok(!JSON.stringify(c.view()).includes("DO_NOT_ECHO_SECRET"));
});
test("4D each method mock decision stays non-authorizing beside existing fake workflow", async () => {
  for (const id of [A, B, C]) {
    const s = setup({ preferredMethod: id }); const v = s.begin();
    assert.equal(s.coordinator.decide("APPROVE_MOCK", v.correlation), true);
    assert.equal(s.coordinator.view().state, "ApprovedMock"); assert.equal(s.coordinator.view().authorized, false);
    // Explicit, independent existing fake client; hybrid results are never approval proofs.
    const outcome = await runPrepared(s.context, { now: () => s.context.createdAt + 2000,
      transport: new FakeTransport({ now: () => s.context.createdAt + 2000 }), onReview: r => r.decide("REJECT") });
    assert.equal(outcome.status, "REJECTED"); assert.equal(outcome.authorized, false); assert.equal(outcome.productionAuthorization, "DEFAULT_DENY");
  }
});
