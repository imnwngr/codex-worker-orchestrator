"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const vm = require("node:vm"), fs = require("node:fs"), path = require("node:path");
const { pending } = require("./vector-cli");
const protocol = require("./preview");

function harness() {
  const fixture = pending(), handlers = {};
  const request = { files: [], focus() {}, addEventListener(type, callback) { handlers[type] = callback; } };
  const status = { textContent: "" }, details = { textContent: "" };
  const buttonHandlers = {};
  const button = { disabled: true, dataset: { outcome: "GRANT" }, focus() {}, addEventListener(type, callback) { buttonHandlers[type] = callback; } };
  const document = {
    getElementById(id) { return { request, status, details }[id]; },
    querySelectorAll() { return [button]; },
    createElement() { return { click() {} }; }
  };
  const env = {
    document, OfflineBrowserPreview: protocol, TextDecoder, Blob,
    Date: { now: () => fixture.now }, setInterval() {}, setTimeout() {},
    URL: { createObjectURL() { return "blob:test"; }, revokeObjectURL() {} }
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "ui.js"), "utf8"), env);
  const select = file => { request.files = file ? [file] : []; return handlers.change({ target: request }); };
  const file = text => ({ size: Buffer.byteLength(text), async arrayBuffer() { return new TextEncoder().encode(text); } });
  return { fixture, button, details, status, handlers, select, file, respond() { buttonHandlers.click(); } };
}
function deferred() {
  let resolve;
  const result = new Promise(done => { resolve = done; });
  return { file: { size: 100, arrayBuffer: () => result }, resolve(text) { resolve(new TextEncoder().encode(text)); } };
}

test("browser UI cancelled and empty selections invalidate pending reads", async () => {
  for (const cancel of [h => h.handlers.cancel(), h => h.select(null)]) {
    const h = harness(), d = deferred(), selection = h.select(d.file);
    cancel(h); d.resolve(h.fixture.package); await selection;
    assert.equal(h.button.disabled, true);
    assert.equal(h.details.textContent, "");
    assert.equal(h.status.textContent, "");
  }
});

test("browser UI superseded invalid read cannot disturb the active preview", async () => {
  const h = harness(); await h.select(h.file(h.fixture.package));
  const original = h.details.textContent, d = deferred();
  const stale = h.select(d.file);
  await h.select(h.file("{}"));
  const failure = h.status.textContent;
  d.resolve(h.fixture.package); await stale;
  assert.equal(h.details.textContent, original);
  assert.equal(h.status.textContent, failure);
  assert.equal(h.button.disabled, false);
});

test("browser UI active response invalidates unfinished file selection", async () => {
  const h = harness(); await h.select(h.file(h.fixture.package));
  const d = deferred(), stale = h.select(d.file);
  h.respond();
  assert.equal(h.button.disabled, true);
  const status = h.status.textContent;
  d.resolve(h.fixture.package); await stale;
  assert.equal(h.status.textContent, status);
  assert.equal(h.button.disabled, true);
});

test("browser UI malformed replacement keeps a valid interactive preview", async () => {
  const h = harness(); await h.select(h.file(h.fixture.package));
  const original = h.details.textContent;
  await h.select(h.file("{}"));
  assert.equal(h.details.textContent, original);
  assert.equal(h.button.disabled, false);
  h.respond(); assert.equal(h.button.disabled, true);
});