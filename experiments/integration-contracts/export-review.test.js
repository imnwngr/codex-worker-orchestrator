"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fixtureContext } = require("./export-review-cli");
const { serializeReview, exportReview, MAXIMUM_BYTES } = require("./export-review");
const { prepareRequest } = require("./prepare-request");
const fixture = require("./fixtures/consistent-scenario.json");

function temporary(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phase4c-export-"));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    fs.rmSync(root, { recursive: true });
  }); return root;
}

test("4C actual preparation serializes deterministically to the cross-language golden vector", () => {
  const { context, now } = fixtureContext(true);
  const first = serializeReview(context, now); const second = serializeReview(context, now);
  assert.deepEqual(first, second);
  assert.deepEqual(first, fs.readFileSync(path.join(__dirname, "fixtures/golden.review.json")));
  const envelope = JSON.parse(first.toString("utf8"));
  assert.equal(envelope.context.contextSha256, context.contextSha256);
  assert.equal(envelope.context.authorized, false);
  assert.equal(envelope.producerAuthentication, "NONE");
});

test("4C export creates only an explicit new local review file and refuses overwrite", t => {
  const root = temporary(t); const output = path.join(root, "chosen.review.json");
  const { context, now } = fixtureContext(true); const summary = exportReview(context, output, now);
  assert.equal(summary.authorized, false); assert.equal(summary.bytes, fs.statSync(output).size);
  const before = fs.readFileSync(output);
  assert.throws(() => exportReview(context, output, now), { code: "REVIEW_OUTPUT_CREATE_FAILED" });
  assert.deepEqual(fs.readFileSync(output), before); assert.deepEqual(fs.readdirSync(root), ["chosen.review.json"]);
});

test("4C export refuses copied contexts stale files and unsupported portable config", () => {
  const { context, now } = fixtureContext(true);
  assert.throws(() => serializeReview(structuredClone(context), now), { code: "UNRECOGNIZED_PREPARED_CONTEXT" });
  assert.throws(() => serializeReview(context, context.expiresAt), { code: "REVIEW_TIME_INVALID" });
  const request = structuredClone(fixture.request); const config = structuredClone(fixture.configuration);
  config.providers[0].baseUrl = "https://api.example.invalid/v1/%20";
  const unsupported = prepareRequest(request, config, { now, expiresAt: context.expiresAt });
  assert.throws(() => serializeReview(unsupported, now), { code: "REVIEW_CONFIG_UNSUPPORTED" });
});

test("4C unsafe paths unsupported output types and missing parents fail without file creation", t => {
  const root = temporary(t); const { context, now } = fixtureContext(true);
  for (const output of ["relative.review.json", path.join(root, "wrong.exe"), path.join(root, "CON.review.json"),
    path.join(root, "missing", "file.review.json"), root + path.sep + ".." + path.sep + "escape.review.json", "\\\\host\\share\\file.review.json"]) {
    assert.throws(() => exportReview(context, output, now), { code: "REVIEW_OUTPUT_PATH_INVALID" });
  }
  assert.deepEqual(fs.readdirSync(root), []);
});

test("4C review export enforces a byte bound after effective-context serialization", () => {
  const request = structuredClone(fixture.request); const config = structuredClone(fixture.configuration);
  // Raw request is bounded; quoting control characters expands the derived task and wire fields.
  request.targets = Array.from({length:8}, (_, i) => ({...request.targets[0], id: `bounded-${i}`, task: "x\u0001".repeat(4000)}));
  const context = prepareRequest(request, config, { now: request.createdAt, expiresAt: request.createdAt + 300000 });
  assert.throws(() => serializeReview(context, request.createdAt), { code: "REVIEW_FILE_OVERSIZED" });
  assert.equal(MAXIMUM_BYTES, 262144);
});

test("4C export never invokes network process dispatch or approval proof construction", t => {
  const root = temporary(t); const { context, now } = fixtureContext(true);
  t.mock.method(globalThis, "fetch", () => { throw new Error("forbidden network"); });
  const child = require("node:child_process"); const net = require("node:net");
  t.mock.method(child, "spawn", () => { throw new Error("forbidden process"); });
  t.mock.method(net, "connect", () => { throw new Error("forbidden socket"); });
  exportReview(context, path.join(root,"isolated.review.json"), now);
  assert.equal(fetch.mock.callCount(), 0); assert.equal(child.spawn.mock.callCount(), 0); assert.equal(net.connect.mock.callCount(), 0);
  for (const field of ["signature", "assertion", "credentialId", "approvalData", "nonce"]) assert.equal(Object.hasOwn(context, field), false);
});
