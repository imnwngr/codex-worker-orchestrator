"use strict";
const { fixtureContext } = require("./export-review-cli");
const { HybridCoordinator } = require("./hybrid-review");
const { OfflineTrustSession, encode } = require("./offline-trust");
const {context,now}=fixtureContext(true);
const vectors=[];
for(const method of ["LOCAL_DESKTOP","PROTECTED_WINDOWS","REMOTE_BROWSER"]) for(const outcome of ["GRANT","DENY","CANCEL","UNKNOWN"]) {
  const coordinator = new HybridCoordinator({preferredMethod:method,now:()=>now}); coordinator.begin(context);
  const session = new OfflineTrustSession(coordinator,context,()=>now);
  const handshake = method === "PROTECTED_WINDOWS" ? "HELLO" : method === "REMOTE_BROWSER" ? "REGISTRATION" : null;
  if(handshake) (handshake === "HELLO" ? session.negotiate(session.fixture(handshake)) : session.register(session.fixture(handshake)));
  session.start(session.fixture("CONSENT_REQUEST"));
  const response = session.fixture("CONSENT_RESPONSE",outcome);
  const accepted = session.receive(response);
  if(outcome === "UNKNOWN") session.recover();
  vectors.push({method,outcome,handshake,request:encode(session.fixture("CONSENT_REQUEST")),response:encode(response),accepted,
    state:session.view().state,canonicalState:coordinator.view().state,digest:context.contextSha256,expiresAt:context.expiresAt,
    authorized:session.view().authorized,productionAuthorization:session.view().productionAuthorization});
}
process.stdout.write(JSON.stringify(vectors));
