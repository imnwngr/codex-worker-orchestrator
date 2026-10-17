"use strict";
const { canonical, Preview } = require("./preview");
const { encode, decode, OfflineTrustSession } = require("../integration-contracts/offline-trust");
const { fixtureContext } = require("../integration-contracts/export-review-cli");
const { HybridCoordinator } = require("../integration-contracts/hybrid-review");
function packageFor(context, responseTemplate) {
  return canonical({ schemaVersion: 1, designation: "OFFLINE_BROWSER_PREVIEW_ONLY", request: {
    requestId: context.requestId, sessionId: context.sessionId, contextSha256: context.contextSha256,
    batchSha256: context.batchSha256, createdAt: context.createdAt, expiresAt: context.expiresAt,
    targets: context.targets.map(({ id, providerId, modelId, destination, task, taskSha256 }) => ({ id, providerId, modelId, destination, task, taskSha256 }))
  }, responseTemplate });
}
function pending(clock) {
  const { context, now } = fixtureContext(true);
  const coordinator = new HybridCoordinator({ now: clock || (() => now), preferredMethod: "REMOTE_BROWSER" });
  coordinator.begin(context);
  const session = new OfflineTrustSession(coordinator, context, clock || (() => now));
  if (!session.register(session.fixture("REGISTRATION")) || !session.start(session.fixture("CONSENT_REQUEST"))) throw Error("fixture setup failed");
  return { context, now, coordinator, session, package: packageFor(context, session.fixture("CONSENT_RESPONSE", "GRANT")) };
}
if (require.main === module) {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => { input += chunk; if (input.length > 262144) process.exit(2); });
  process.stdin.on("end", () => {
    try {
      const p = new Preview(); const parsed = JSON.parse(input);
      p.load(input, parsed.request.createdAt + 2000);
      const response = p.respond(process.argv[2] || "GRANT", parsed.request.createdAt + 2000);
      if (encode(decode(response)) !== response) throw Error("canonical mismatch");
      process.stdout.write(response);
    } catch { process.exitCode = 2; }
  });
}
module.exports = { packageFor, pending };
