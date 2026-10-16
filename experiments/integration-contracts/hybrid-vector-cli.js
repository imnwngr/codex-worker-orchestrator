"use strict";
// Deterministic cross-runtime semantic vector; no file input, dispatch or provider access.
const { HybridCoordinator } = require("./hybrid-review");
const { fixtureContext } = require("./export-review-cli");
const {context,now}=fixtureContext(true);
const result=[];
for(const id of ["PROTECTED_WINDOWS","REMOTE_BROWSER"]) {
  const c=new HybridCoordinator({now:()=>now,preferredMethod:id}); c.begin(context);
  const actions=id==="REMOTE_BROWSER"?["COMPLETE","START","DELIVER","UNKNOWN","COMPLETE","RECOVER","COMPLETE"]:["COMPLETE","START","START","COMPLETE","COMPLETE"];
  for(const action of actions) {
    const v=c.view(); const accepted=c.simulate(action,v.correlation,v.simulation.fixtureId); const after=c.view();
    result.push({method:id,action,accepted,state:after.state,simulation:after.simulation.state,digest:after.preview.contextSha256,expiresAt:after.expiresAt,authorized:after.authorized,productionAuthorization:after.productionAuthorization});
  }
}
for(const id of ["PROTECTED_WINDOWS","REMOTE_BROWSER"]) {
  let armed=false,checks=0;
  const c=new HybridCoordinator({preferredMethod:id,now:()=>armed?(++checks===1?context.expiresAt-1:context.expiresAt):now});
  c.begin(context); const token=c.view().correlation,fixture=c.view().simulation.fixtureId;
  c.simulate("START",token,fixture); if(id==="REMOTE_BROWSER") c.simulate("DELIVER",token,fixture);
  armed=true;
  const accepted=c.simulate("COMPLETE",token,fixture),after=c.view();
  result.push({expiryBoundary:true,method:id,action:"COMPLETE",accepted,state:after.state,simulation:after.simulation.state,digest:after.preview.contextSha256,expiresAt:after.expiresAt,authorized:after.authorized,productionAuthorization:after.productionAuthorization});
}
process.stdout.write(JSON.stringify(result));
