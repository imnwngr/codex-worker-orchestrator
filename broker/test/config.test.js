"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateConfig } = require("../providers/config");

const valid = () => ({
  version: 1,
  defaultProvider: "agy",
  providers: [
    { id: "agy", kind: "cli", enabled: true, timeoutSeconds: 300 },
    {
      id: "api-one",
      kind: "api",
      enabled: false,
      baseUrl: "https://api.one.example/v1",
      timeoutSeconds: 120,
      models: ["a", "b"],
      defaultModel: "a",
      credentialEnv: "TEST_API_ONE_KEY"
    },
    {
      id: "api-two",
      kind: "api",
      enabled: false,
      baseUrl: "https://api.two.example/v1",
      timeoutSeconds: 90,
      models: ["c", "d"],
      defaultModel: "d",
      credentialEnv: "TEST_API_TWO_KEY"
    }
  ]
});

test("accepts multiple API providers and multiple models", () => {
  const config = validateConfig(valid());
  assert.equal(config.providers.length, 3);
  assert.deepEqual(config.providers[1].models, ["a", "b"]);
  assert.deepEqual(config.providers[2].models, ["c", "d"]);
});

test("rejects duplicate IDs, unknown kinds, and unknown fields", () => {
  let config = valid();
  config.providers[2].id = "api-one";
  assert.throws(() => validateConfig(config), /duplicate provider ID/);

  config = valid();
  config.providers[1].kind = "mystery";
  assert.throws(() => validateConfig(config), /must be 'cli' or 'api'/);

  config = valid();
  config.extra = true;
  assert.throws(() => validateConfig(config), /unknown field/);

  config = valid();
  config.providers[1].unknown = true;
  assert.throws(() => validateConfig(config), /unknown field/);
});
test("requires HTTPS API URLs without embedded credentials or query parts", () => {
  for (const baseUrl of [
    "http://api.example.test/v1",
    "https://user:pass@api.example.test/v1",
    "https://api.example.test/v1?key=secret",
    "https://api.example.test/v1#fragment",
    "not a URL"
  ]) {
    const config = valid();
    config.providers[1].baseUrl = baseUrl;
    assert.throws(() => validateConfig(config), /baseUrl/);
  }
  const config = validateConfig(valid());
  assert.equal(config.providers[1].baseUrl, "https://api.one.example/v1");
});

test("rejects loopback, local, internal, and IP literal API hosts", () => {
  for (const baseUrl of [
    "https://localhost/v1",
    "https://service.local/v1",
    "https://service.internal/v1",
    "https://127.0.0.1/v1",
    "https://[::1]/v1"
  ]) {
    const config = valid();
    config.providers[1].baseUrl = baseUrl;
    assert.throws(() => validateConfig(config), /public hostname/);
  }
});


test("rejects invalid timeouts", () => {
  for (const timeoutSeconds of [0, -1, 601, 1.5, "20"]) {
    const config = valid();
    config.providers[0].timeoutSeconds = timeoutSeconds;
    assert.throws(() => validateConfig(config), /timeoutSeconds/);
  }
});

test("rejects invalid model lists and defaults", () => {
  let config = valid();
  config.providers[1].models = [];
  assert.throws(() => validateConfig(config), /models/);

  config = valid();
  config.providers[1].models = ["a", "a"];
  assert.throws(() => validateConfig(config), /duplicate models/);

  config = valid();
  config.providers[1].models = ["bad model"];
  assert.throws(() => validateConfig(config), /valid model identifiers/);

  config = valid();
  config.providers[1].defaultModel = "missing";
  assert.throws(() => validateConfig(config), /defaultModel/);
});

test("rejects missing and disabled default providers", () => {
  let config = valid();
  config.defaultProvider = "missing";
  assert.throws(() => validateConfig(config), /missing or disabled/);

  config = valid();
  config.providers[0].enabled = false;
  assert.throws(() => validateConfig(config), /missing or disabled/);
});

test("rejects API credential values and malformed environment references", () => {
  let config = valid();
  config.providers[1].apiKey = "secret";
  assert.throws(() => validateConfig(config), /unknown field/);

  config = valid();
  config.providers[1].credentialEnv = "not-an-env-name";
  assert.throws(() => validateConfig(config), /environment variable name/);
});
