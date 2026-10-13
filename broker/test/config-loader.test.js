"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { DEFAULT_CONFIG_PATH, loadConfig } = require("../providers/config-loader");

const validJson = JSON.stringify({
  version: 1,
  defaultProvider: "antigravity",
  providers: [{
    id: "antigravity",
    kind: "cli",
    enabled: true,
    timeoutSeconds: 30
  }]
});

test("loads and validates a dedicated provider JSON config", () => {
  const config = loadConfig("mock.json", {
    readFileSync(filePath, encoding) {
      assert.equal(filePath, "mock.json");
      assert.equal(encoding, "utf8");
      return validJson;
    }
  });
  assert.equal(config.defaultProvider, "antigravity");
  assert.match(DEFAULT_CONFIG_PATH, /broker[\\/]config[\\/]providers\.json$/);
});

test("fails closed for missing, malformed, and invalid configuration", () => {
  assert.throws(() => loadConfig("missing.json", {
    readFileSync() { throw new Error("path detail"); }
  }), /could not be read/);
  assert.throws(() => loadConfig("bad.json", {
    readFileSync() { return "not-json"; }
  }), /not valid JSON/);
  assert.throws(() => loadConfig("invalid.json", {
    readFileSync() { return JSON.stringify({ ...JSON.parse(validJson), unknown: true }); }
  }), /unknown field/);
});
