"use strict";

const readline = require("node:readline/promises");
const fixture = require("./fixtures/consistent-scenario.json");
const { prepareRequest } = require("./prepare-request");
const { FakeTransport, runPrepared } = require("./fake-workflow");

async function main(args) {
  if (args.some(arg => !["--reject", "--cancel", "--approve-mock", "--partial"].includes(arg)) || args.filter(a => a !== "--partial").length > 1) {
    process.stderr.write("usage: preview-cli.js [--reject|--cancel|--approve-mock] [--partial]\n"); return 64;
  }
  // Only the checked-in synthetic request/config fixture is used; no file/URL/proof input or live transport.
  const request = structuredClone(fixture.request);
  request.createdAt = Date.now();
  const context = prepareRequest(request, fixture.configuration, { now: request.createdAt, expiresAt: request.createdAt + 60000 });
  const transport = new FakeTransport({ results: args.includes("--partial") ? [{ id: request.targets[1].id, status: "MOCK_FAILURE" }] : [] });
  const cancellation = new AbortController();
  let terminal;
  try {
    const result = await runPrepared(context, { transport, timeoutMs: 60000, signal: cancellation.signal,
      onReview: async review => {
        process.stdout.write(review.preview.text + "\n\n");
        let action = args.includes("--approve-mock") ? "a" : args.includes("--cancel") ? "c" : args.includes("--reject") ? "r" : null;
        if (action === null) {
          terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
          terminal.once("SIGINT", () => cancellation.abort());
          terminal.once("close", () => cancellation.abort());
          action = await terminal.question("[r] Reject mock / [c] Cancel / [a] Approve MOCK only (60s expiry): ");
        }
        return review.decide(action.trim().toLowerCase() === "a" ? "APPROVE_MOCK" : action.trim().toLowerCase() === "c" ? "CANCEL" : "REJECT");
      }
    });
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    return 0;
  } finally { terminal?.close(); }
}

if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(() => {
  process.stderr.write("Offline preview failed; no dispatch or authorization occurred.\n"); process.exitCode = 1;
});

module.exports = { main };
