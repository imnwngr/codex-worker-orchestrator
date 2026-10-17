"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { fixtureContext } = require("./export-review-cli");
const { HybridCoordinator } = require("./hybrid-review");
const { OfflineTrustSession, OfflineTrustFakeTransport, encode, decode } = require("./offline-trust");
const METHODS = ["LOCAL_DESKTOP", "PROTECTED_WINDOWS", "REMOTE_BROWSER"];
function setup(method = METHODS[0], policy = {}) {
  const { context, now } = fixtureContext(true); let time = now;
  const coordinator = new HybridCoordinator({ preferredMethod: method, now: () => time, policy });
  coordinator.begin(context);
  const session = new OfflineTrustSession(coordinator, context, () => time);
  return { context, coordinator, session, setTime: n => { time = n; } };
}
function ready(s, method) {
  if (method === METHODS[1]) assert.equal(s.session.negotiate(s.session.fixture("HELLO")), true);
  if (method === METHODS[2]) assert.equal(s.session.register(s.session.fixture("REGISTRATION")), true);
  assert.equal(s.session.start(s.session.fixture("CONSENT_REQUEST")), true);
}
for (const method of METHODS) for (const outcome of ["GRANT", "DENY", "CANCEL", "UNKNOWN"]) {
  test(`5/6 ${method} ${outcome} synthetic lifecycle and single consumption`, () => {
    const s = setup(method); ready(s, method);
    const response = s.session.fixture("CONSENT_RESPONSE", outcome);
    assert.equal(s.session.receive(decode(encode(response))), true);
    assert.equal(s.session.receive(response), false);
    assert.equal(s.session.view().authorized, false);
    assert.equal(s.session.view().productionAuthorization, "DEFAULT_DENY");
    const expected = { GRANT: "ApprovedMock", DENY: "Rejected", CANCEL: "Cancelled", UNKNOWN: "Unknown" }[outcome];
    assert.equal(s.session.view().state, expected);
    if (outcome === "UNKNOWN") {
      assert.equal(s.session.recover(), true);
      assert.equal(s.session.view().state, "Abandoned");
      assert.equal(s.coordinator.view().state, "Cancelled");
    } else assert.equal(s.coordinator.view().state, expected);
    assert.equal(s.coordinator.view().authorized, false);
  });
}
test("5/6 strict canonical framing rejects duplicate fields, oversized or malicious JSON", () => {
  const s = setup(); const good = encode(s.session.fixture("CONSENT_REQUEST"));
  for (const payload of [good + " ", good.replace('{', '{"version":1,'), good.replace('"authorized":false', '"authorized":true'), good.replace('"version":1', '"version":2'),
    good.replace('"trustStatus":"UNVERIFIED_SIMULATION_ONLY"', '"trustStatus":"AUTHENTICATED"'), 'X'.repeat(5000), '{}', '[1]', '{"__proto__":{}}']) assert.throws(() => decode(payload));
  assert.equal(s.session.start({ ...s.session.fixture("CONSENT_REQUEST"), authorized: true }), false);
  assert.equal(s.session.start({ ...s.session.fixture("CONSENT_REQUEST"), newField: "bad" }), false);
  assert.equal(s.session.start({ ...s.session.fixture("CONSENT_REQUEST"), instanceId: "attacker" }), false);
});
test("5/6 implicit protocol downgrade, role spoof, message confusion all denied", () => {
  const s = setup(METHODS[1]); const hello = s.session.fixture("HELLO");
  for (const bad of [{...hello,version:0}, {...hello,peerRole:"FAKE_REMOTE_DEVICE"}, {...hello,trustStatus:"VERIFIED"}, {...hello,challenge:"different"}, {...hello,nonce:"other"}]) assert.equal(s.session.negotiate(bad),false);
  assert.equal(s.session.start(s.session.fixture("CONSENT_REQUEST")),false);
  assert.equal(s.session.negotiate(hello),true);
  assert.equal(s.session.negotiate(hello),false);
});
test("5/6 remote revocation, offline unknown and recovery fail closed", () => {
  const s=setup(METHODS[2]);
  assert.equal(s.session.register(s.session.fixture("REGISTRATION")),true);
  assert.equal(s.session.revoke(s.session.fixture("REVOCATION")),true);
  assert.equal(s.session.start(s.session.fixture("CONSENT_REQUEST")),false);
  assert.equal(s.session.recover(),true);
  assert.equal(s.session.view().state,"Abandoned");
});
test("5/6 crash recovery abandons local consent without implicit grant", () => {
  const s=setup(); ready(s,METHODS[0]);
  assert.equal(s.session.crash(),true);
  assert.equal(s.session.receive(s.session.fixture("CONSENT_RESPONSE","GRANT")),false);
  assert.equal(s.session.recover(),true);
  assert.equal(s.coordinator.view().state,"Cancelled");
});
test("5/6 stale generation, method switch and concurrent session isolation", () => {
  const a=setup(METHODS[1]); ready(a,METHODS[1]);
  const token=a.coordinator.view().correlation;
  assert.equal(a.coordinator.switchMethod(METHODS[0],token),true);
  assert.equal(a.session.receive(a.session.fixture("CONSENT_RESPONSE","GRANT")),false);
  const b=setup(METHODS[1]); ready(b,METHODS[1]);
  assert.equal(b.session.receive(a.session.fixture("CONSENT_RESPONSE","GRANT")),false);
  assert.equal(b.session.receive(b.session.fixture("CONSENT_RESPONSE","GRANT")),true);
});
test("5/6 original deadline and rollback reject all response methods", () => {
  for (const method of METHODS) for (const timeShift of [-1, 0]) {
    const s=setup(method); ready(s,method);
    s.setTime(timeShift===0 ? s.context.expiresAt : s.context.createdAt-1);
    assert.equal(s.session.receive(s.session.fixture("CONSENT_RESPONSE","GRANT")),false);
    assert.equal(s.session.view().state,"Expired");
    assert.equal(s.session.view().expiresAt,s.context.expiresAt);
  }
});
test("5/6 code-owned policy denies constructing an offline trust session", () => {
  const {context,now}=fixtureContext(true);
  const coord=new HybridCoordinator({now:()=>now,preferredMethod:METHODS[2],policy:{allowedMethods:[METHODS[0]]}});coord.begin(context);
  assert.throws(()=>new OfflineTrustSession(coord,context,()=>now),/OFFLINE_BINDING_INVALID/);
});
test("5/6 failed response at nested canonical expiry is denied", () => {
  const {context,now}=fixtureContext(true); let armed=false,reads=0;
  const coord=new HybridCoordinator({now:()=>armed ? (++reads===1 ? context.expiresAt-1 : context.expiresAt) : now});coord.begin(context);
  const s=new OfflineTrustSession(coord,context,()=>now);
  assert.equal(s.start(s.fixture("CONSENT_REQUEST")),true);armed=true;
  assert.equal(s.receive(s.fixture("CONSENT_RESPONSE","GRANT")),false);
  assert.equal(coord.view().state,"Expired"); assert.equal(s.view().authorized,false);
});
test("6A exact canonical consent and endpoint properties reject forged trust", () => {
  const s=setup();
  const msg=s.session.fixture("CONSENT_REQUEST");
  assert.match(msg.consentStatement,/SIMULATION ONLY: action context/);
  for (const item of [
    {...msg,endpointTrust:"TRUSTED"}, {...msg,channelTrust:"AUTHENTICATED_IPC"},
    {...msg,consentStatement:msg.consentStatement+" override"},
    {...msg,deviceClaim:"authenticated"}, {...msg,originClaim:"https://trusted.example"}
  ]) assert.equal(s.session.start(item),false);
  assert.equal(s.session.start(msg),true);
});
test("6B in-process fake transport is bounded and never treats duplication as approval proof", () => {
  const s=setup(METHODS[1]);ready(s,METHODS[1]);
  const t=new OfflineTrustFakeTransport();const wire=encode(s.session.fixture("CONSENT_RESPONSE","GRANT"));
  assert.equal(t.send("[]"),false);
  for(let i=0;i<4;i++) assert.equal(t.send(wire),true);
  assert.equal(t.send(wire),false);
  t.disconnect();assert.equal(t.deliver(s.session),false);
  assert.equal(t.send(wire),false);
  t.reconnect();assert.equal(t.deliver(s.session),true);
  assert.equal(t.deliver(s.session),false);
  t.clear();assert.equal(t.pending,0);assert.equal(s.session.view().authorized,false);
});
test("6C fake remote offline delivery and unknown outcome require explicit abandonment", () => {
  const s=setup(METHODS[2]);ready(s,METHODS[2]);
  const t=new OfflineTrustFakeTransport();
  assert.equal(t.send(encode(s.session.fixture("CONSENT_RESPONSE","GRANT"))),true);
  t.disconnect();assert.equal(t.deliver(s.session),false);
  assert.equal(s.session.crash(),true);
  t.reconnect();assert.equal(t.deliver(s.session),false);
  assert.equal(s.session.recover(),true);
  assert.equal(s.coordinator.view().state,"Cancelled");
});
test("6D concurrent queued responses cannot produce multiple accepted decisions", async () => {
  const s=setup();ready(s,METHODS[0]);
  const results=await Promise.all(Array.from({length:24},()=>Promise.resolve().then(()=>s.session.receive(s.session.fixture("CONSENT_RESPONSE","GRANT")))));
  assert.equal(results.filter(Boolean).length,1);
  assert.equal(s.coordinator.view().state,"ApprovedMock");
  assert.equal(s.coordinator.view().authorized,false);
});
