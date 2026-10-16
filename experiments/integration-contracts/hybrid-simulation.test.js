"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { HybridCoordinator, METHODS } = require("./hybrid-review");
const { fixtureContext } = require("./export-review-cli");
const [A,B,C] = METHODS.map(m => m.id);
function setup(id = B, options = {}) {
  const {context, now} = fixtureContext(true); let time = now;
  const c = new HybridCoordinator({now: () => time, preferredMethod:id, ...options}); c.begin(context);
  return {c, context, setTime: v => time=v, token: () => c.view().correlation,
    send: action => c.simulate(action, c.view().correlation, c.view().simulation.fixtureId)};
}
for (const id of [B,C]) {
  test(`4F-H ${id} positive scripted completion and duplicate denial`, () => {
    const s=setup(id); assert.equal(s.c.view().simulation.state,"ReadyForSimulation");
    assert.equal(s.send("COMPLETE"),false); assert.equal(s.send("START"),true); assert.equal(s.send("START"),false);
    if(id===C) { assert.equal(s.send("COMPLETE"),false); assert.equal(s.send("DELIVER"),true); assert.equal(s.send("DELIVER"),false); }
    assert.equal(s.send("COMPLETE"),true); assert.equal(s.c.view().state,"ApprovedMock");
    assert.equal(s.c.view().simulation.state,"SimulatedComplete"); assert.equal(s.send("REJECT"),false);
    assert.equal(s.c.view().authorized,false); assert.equal(s.c.view().productionAuthorization,"DEFAULT_DENY");
  });
  test(`4F-H ${id} exact fixture and five correlation dimensions`, () => {
    const s=setup(id); const token=s.token();
    assert.equal(s.c.simulate("START", token,"pretend-authenticated"),false);
    for(const key of Object.keys(token)) assert.equal(s.c.simulate("START",{...token,[key]:"wrong"},s.c.view().simulation.fixtureId),false);
    for(const action of [null,{},"BAD","RECOVER","DELIVER","REVOKE_AUTHORITY"]) assert.equal(s.send(action),false);
    assert.equal(s.send("START"),true);
  });
  test(`4F-H ${id} failure requires explicit switch away for fresh simulation`, () => {
    const s=setup(id); assert.equal(s.send("START"),true); assert.equal(s.send("FAIL"),true);
    assert.equal(s.c.view().simulation.state,"Failed"); assert.equal(s.send("COMPLETE"),false); assert.equal(s.send("START"),false);
    assert.equal(s.c.switchMethod(A,s.token()),true); assert.equal(s.c.view().simulation.state,"Unavailable");
    assert.equal(s.c.switchMethod(id,s.token()),true); assert.equal(s.send("START"),true);
  });
  for(const action of ["CANCEL","REJECT","REVOKE"]) test(`4F-H ${id} ${action} terminal and late completion denied`,()=>{
    const s=setup(id); s.send("START"); assert.equal(s.send(action),true);
    assert.equal(s.c.view().state,action==="REJECT"?"Rejected":"Cancelled"); assert.equal(s.send("COMPLETE"),false);
  });
}
test("4G unknown response recovery abandons locally without delivery retry",()=>{
  const s=setup(C); s.send("START"); s.send("DELIVER"); assert.equal(s.send("UNKNOWN"),true);
  assert.equal(s.send("COMPLETE"),false); assert.equal(s.send("DELIVER"),false); assert.equal(s.send("RECOVER"),true);
  assert.equal(s.c.view().state,"Cancelled"); assert.equal(s.c.view().expiresAt,s.context.expiresAt);
});
test("4H A B C A cleanup and pending-picker response races",()=>{
  const s=setup(A); const original=s.token();
  for(const id of [B,C,A]) {
    const old=s.token(); assert.equal(s.c.switchMethod(id,old),true);
    assert.equal(s.c.simulate("COMPLETE",old,"fake-device-v1"),false);
    assert.equal(s.c.switchMethod(B,old),false);
    assert.equal(s.c.view().expiresAt,s.context.expiresAt);
    if(id!==A) assert.equal(s.send("START"),true);
  }
  assert.equal(s.c.view().simulation.state,"Unavailable"); assert.equal(s.c.decide("APPROVE_MOCK",original),false);
});
test("4H expiry and clock anomaly consume no synthetic response",()=>{
  for(const time of ["expiry","backwards",NaN]) {
    const s=setup(C); s.send("START"); s.send("DELIVER");
    s.setTime(time==="expiry"?s.context.expiresAt:time==="backwards"?s.context.createdAt-1:time);
    assert.equal(s.send("COMPLETE"),false); assert.equal(s.c.view().state,"Expired"); assert.equal(s.c.view().simulation.state,"Expired");
  }
});
test("4H concurrent coordinators cannot substitute sessions and preferences are future only",()=>{
  const s=setup(C), other=setup(B); s.send("START"); other.send("START");
  assert.equal(s.c.simulate("COMPLETE",other.token(),"fake-component-v1"),false);
  assert.equal(s.c.setPreference(A),true); assert.equal(s.c.view().selectedMethod,C);
  assert.equal(s.send("DELIVER"),true); assert.equal(s.send("COMPLETE"),true);
  assert.equal(other.c.view().state,"Pending");
});
test("4H unavailable policy does not become ready from fixture metadata",()=>{
  const s=setup(C,{policy:{allowedMethods:[A]}}); assert.equal(s.c.view().simulation.state,"Unavailable");
  assert.equal(s.send("START"),false); assert.equal(s.c.view().selectedMethod,C);
  assert.equal(s.c.switchMethod(A,s.token()),true); assert.equal(s.c.view().canDecide,true);
});
test("4H identical fixture sessions cannot exchange instance-bound responses",()=>{
  const s=setup(C), other=setup(C); s.send("START"); s.send("DELIVER"); other.send("START"); other.send("DELIVER");
  assert.equal(s.c.simulate("COMPLETE",other.token(),"fake-device-v1"),false); assert.equal(s.send("COMPLETE"),true);
});
test("4E clock rollback within original lifetime fails closed",()=>{
  const s=setup(B); s.setTime(s.context.createdAt+3000); s.send("START"); s.setTime(s.context.createdAt+2500);
  assert.equal(s.send("COMPLETE"),false); assert.equal(s.c.view().state,"Expired");
});
test("4F-G fake prerequisite unavailable requires explicit recovery without fallback",()=>{
  for(const id of [B,C]) { const s=setup(id); assert.equal(s.send("UNAVAILABLE"),true);
    assert.equal(s.c.view().simulation.state,"Unavailable"); assert.equal(s.send("START"),false); assert.equal(s.c.view().selectedMethod,id);
    assert.equal(s.c.switchMethod(A,s.token()),true); assert.equal(s.c.switchMethod(id,s.token()),true); assert.equal(s.send("START"),true);
  }
});
test("4H unexpected correlation fields cannot imply authority",()=>{
  const s=setup(B); assert.equal(s.c.simulate("START",{...s.token(),authorized:true},"fake-component-v1"),false); assert.equal(s.send("START"),true);
});
test("4H terminal simulation rejects expiry at each nested decision clock check",()=>{
  for(const id of [B,C]) for(const expiryCheck of [2,3,4]) {
    const {context,now}=fixtureContext(true); let armed=false,checks=0;
    const c=new HybridCoordinator({preferredMethod:id,now:()=>armed?(++checks<expiryCheck?context.expiresAt-1:context.expiresAt):now});
    c.begin(context); const token=c.view().correlation, fixture=c.view().simulation.fixtureId;
    assert.equal(c.simulate("START",token,fixture),true);
    if(id===C) assert.equal(c.simulate("DELIVER",token,fixture),true);
    const before=c.view(); armed=true;
    assert.equal(c.simulate("COMPLETE",token,fixture),false);
    const after=c.view(); assert.equal(after.state,"Expired"); assert.equal(after.simulation.state,"Expired");
    assert.equal(after.simulation.registered,false); assert.deepEqual(after.correlation,token);
    assert.equal(after.expiresAt,before.expiresAt); assert.equal(after.preview,before.preview);
    assert.equal(after.authorized,false); assert.equal(after.productionAuthorization,"DEFAULT_DENY");
    assert.equal(c.simulate("COMPLETE",token,fixture),false);
  }
});
