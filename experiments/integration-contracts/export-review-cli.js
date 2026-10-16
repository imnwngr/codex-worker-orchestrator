"use strict";
const { prepareRequest } = require("./prepare-request");
const { exportReview } = require("./export-review");
const fixture = require("./fixtures/consistent-scenario.json");

function fixtureContext(fixed = false) {
  const request = structuredClone(fixture.request);
  if (!fixed) request.createdAt = Date.now();
  // Golden interoperability vector deliberately exercises JSON string escaping and supplementary Unicode.
  if (fixed) request.targets[0].task += '\nUnicode: 😀 e\u0301 café \u2028\u2029 "quote" \\ slash \b\t\u0001';
  const now = request.createdAt + (fixed ? 2000 : 0);
  return { context: prepareRequest(request, fixture.configuration, { now, expiresAt: request.createdAt + 300000 }), now };
}
function main(args) {
  if (!(args.length === 2 || args.length === 3) || args[0] !== "--output" || (args.length === 3 && args[2] !== "--fixture")) {
    process.stderr.write("usage: export-review-cli.js --output <absolute-new-file.review.json> [--fixture]\n"); return 64;
  }
  const { context, now } = fixtureContext(args[2] === "--fixture");
  process.stdout.write(JSON.stringify(exportReview(context, args[1], now)) + "\n");
  return 0;
}
if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch { process.stderr.write("REVIEW_EXPORT_FAILED; no handoff or authorization\n"); process.exitCode = 2; }
}
module.exports = { fixtureContext, main };
