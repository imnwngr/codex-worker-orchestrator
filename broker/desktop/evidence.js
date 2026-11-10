"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
function hash(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function safeRoot(root) {
  if (!path.isAbsolute(root) || root.startsWith("\\\\") || root.slice(2).includes(":")) throw new Error("UNSAFE_EVIDENCE_ROOT");
  for (let current = path.resolve(root); ; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error("REPARSE_DENIED");
    if (path.dirname(current) === current) break;
  }
  return path.resolve(root);
}
function readEvidence(root, reference) {
  safeRoot(root);
  if (!reference || !/^[a-f0-9-]{36}\.(png|json)$/.test(reference.path) ||
      !/^[a-f0-9]{64}$/.test(reference.sha256)) throw new Error("INVALID_EVIDENCE_REFERENCE");
  const file = path.join(root, reference.path);
  if (fs.lstatSync(file).isSymbolicLink()) throw new Error("REPARSE_DENIED");
  const bytes = fs.readFileSync(file);
  if (bytes.length !== reference.bytes || hash(bytes) !== reference.sha256) throw new Error("EVIDENCE_INTEGRITY_FAILED");
  return bytes;
}
function verifyAudit(file) {
  const rows = fs.readFileSync(file, "utf8").trim().split("\n").map(JSON.parse);
  let previous = "0".repeat(64);
  for (const row of rows) {
    const bytes = Buffer.from(row.payload, "base64"), record = JSON.parse(bytes);
    if (hash(bytes) !== row.sha256 || record.previous !== previous) throw new Error("AUDIT_INTEGRITY_FAILED");
    previous = row.sha256;
  }
  return { records: rows.length, tailSha256: previous, status: "HASH_CHAIN_CONSISTENT_NOT_AUTHENTICATED" };
}
function auditWriter(file) {
  const fd = fs.openSync(file, "wx");
  return { write(record) { fs.writeSync(fd, JSON.stringify(record) + "\n"); fs.fsyncSync(fd); },
    close() { fs.closeSync(fd); } };
}
module.exports = { hash, safeRoot, readEvidence, verifyAudit, auditWriter };
