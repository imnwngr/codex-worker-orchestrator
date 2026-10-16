"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { assertPrepared } = require("./prepare-request");
const { canonicalJson, sha256Text } = require("../../broker/providers/approval-core");
const MAXIMUM_BYTES = 262144;
function reject(code) { throw Object.assign(new Error("Offline review export rejected"), { code }); }

// Deliberately portable subset of the existing validated API URL rules. No DNS/connection is performed.
function portableBaseUrl(value) {
  if (typeof value !== "string" || value.length > 2048 || !/^https:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?(?:\/[A-Za-z0-9._~-]+)*$/.test(value)) return false;
  let url; try { url = new URL(value); } catch { return false; }
  return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(url.hostname) &&
    url.toString().replace(/\/$/, "") === value && !url.pathname.split("/").some(p => p === "." || p === "..");
}

function serializeReview(context, now = Date.now()) {
  assertPrepared(context);
  if (!Number.isSafeInteger(now) || now < context.createdAt || now >= context.expiresAt || context.expiresAt > 253402300799999) reject("REVIEW_TIME_INVALID");
  const providers = context.configurationSnapshot.providers;
  if (providers.length > 16 || providers.some(p => p.kind !== "api" || p.models.length > 32 || !portableBaseUrl(p.baseUrl))) reject("REVIEW_CONFIG_UNSUPPORTED");
  const bytes = Buffer.from(canonicalJson({ reviewFileSchemaVersion: 1, designation: "SYNTHETIC_DESIGN_ONLY",
    producerAuthentication: "NONE", context }) + "\n", "utf8");
  if (bytes.length > MAXIMUM_BYTES) reject("REVIEW_FILE_OVERSIZED");
  return bytes;
}

function exportReview(context, outputFile, now = Date.now()) {
  const bytes = serializeReview(context, now); // Validate before creating any file.
  if (typeof outputFile !== "string" || !path.isAbsolute(outputFile) || /^[\\/]{2}/.test(outputFile) ||
      !outputFile.toLowerCase().endsWith(".review.json") || outputFile.split(/[\\/]/).some(p => p === ".." || p === ".") ||
      /[\x00-\x1f\x7f]/.test(outputFile) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(path.basename(outputFile)) ||
      (process.platform === "win32" && (outputFile.slice(2).includes(":") || !/^[A-Za-z]:[\\/]/.test(outputFile)))) reject("REVIEW_OUTPUT_PATH_INVALID");
  const selected = path.resolve(outputFile);
  try {
    for (let dir = path.dirname(selected); ; dir = path.dirname(dir)) {
      const info = fs.lstatSync(dir);
      if (!info.isDirectory() || info.isSymbolicLink()) reject("REVIEW_OUTPUT_PATH_INVALID");
      if (path.dirname(dir) === dir) break;
    }
  } catch { reject("REVIEW_OUTPUT_PATH_INVALID"); }
  let file;
  try { file = fs.openSync(selected, "wx", 0o600); fs.writeFileSync(file, bytes); }
  catch { reject("REVIEW_OUTPUT_CREATE_FAILED"); }
  finally { if (file !== undefined) fs.closeSync(file); }
  return Object.freeze({ designation: "SYNTHETIC_DESIGN_ONLY", bytes: bytes.length, sha256: sha256Text(bytes.toString("utf8")), producerAuthentication: "NONE", authorized: false });
}

module.exports = { serializeReview, exportReview, portableBaseUrl, MAXIMUM_BYTES };
