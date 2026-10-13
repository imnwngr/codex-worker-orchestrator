"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { validateConfig } = require("./config");

const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "config", "providers.json");

function loadConfig(filePath = DEFAULT_CONFIG_PATH, options = {}) {
  const readFile = options.readFileSync || fs.readFileSync;
  let raw;
  try {
    raw = readFile(filePath, "utf8");
  } catch {
    throw new Error("provider configuration could not be read");
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("provider configuration is not valid JSON");
  }

  return validateConfig(parsed);
}

module.exports = { DEFAULT_CONFIG_PATH, loadConfig };
