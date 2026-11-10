"use strict";
const crypto = require("node:crypto");
const actions = new Set(["heartbeat", "observe", "capture", "focus", "key", "click", "setFile"]);
const keys = new Set(["Tab", "ShiftTab", "Enter", "Escape", "Space", "Up", "Down", "Left", "Right", "Home", "End"]);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fields = new Set(["version", "id", "taskId", "correlationId", "action", "timeoutMs", "window", "element", "key", "file"]);
const mutation = action => ["focus", "key", "click", "setFile"].includes(action);
function validate(command) {
  if (!command || typeof command !== "object" || Array.isArray(command) ||
      Object.keys(command).some(k => !fields.has(k)) || command.version !== 1 ||
      !["id", "taskId", "correlationId"].every(k => typeof command[k] === "string" && uuid.test(command[k])) ||
      !actions.has(command.action) || !Number.isInteger(command.timeoutMs) || command.timeoutMs < 100 || command.timeoutMs > 10000)
    throw new Error("INVALID_COMMAND");
  const target = !["observe", "heartbeat"].includes(command.action);
  if (target && (typeof command.window !== "string" || !uuid.test(command.window))) throw new Error("TARGET_REQUIRED");
  if (!target && ["window", "element", "key", "file"].some(k => command[k] != null)) throw new Error("UNEXPECTED_ARGUMENT");
  if (command.action === "key" && !keys.has(command.key)) throw new Error("KEY_DENIED");
  if (command.action !== "key" && command.key != null || command.action !== "setFile" && command.file != null)
    throw new Error("UNEXPECTED_ARGUMENT");
  if (["click", "focus", "setFile"].includes(command.action) &&
      (typeof command.element !== "string" || !command.element.length)) throw new Error("ELEMENT_REQUIRED");
  if (command.element != null && (typeof command.element !== "string" || command.element.length > 128))
    throw new Error("INVALID_ELEMENT");
  if (command.action === "capture" && command.element != null) throw new Error("UNEXPECTED_ARGUMENT");
  if (command.action === "setFile" && (typeof command.file !== "string" ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,90}\.json$/.test(command.file) || /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\./i.test(command.file))) throw new Error("FILE_PATH_DENIED");
  return command;
}
function seal(value, key) {
  const payload = Buffer.from(JSON.stringify(value));
  return JSON.stringify({ payload: payload.toString("base64"), mac: crypto.createHmac("sha256", key).update(payload).digest("hex") }) + "\n";
}
function open(frame, key) {
  if (Buffer.byteLength(frame) > 1048576) throw new Error("FRAME_TOO_LARGE");
  const envelope = JSON.parse(frame);
  if (!envelope || Object.keys(envelope).sort().join() !== "mac,payload" ||
      typeof envelope.mac !== "string" || !/^[a-f0-9]{64}$/.test(envelope.mac) ||
      typeof envelope.payload !== "string") throw new Error("INVALID_ENVELOPE");
  const payload = Buffer.from(envelope.payload, "base64");
  if (payload.toString("base64") !== envelope.payload) throw new Error("INVALID_ENVELOPE");
  const expected = crypto.createHmac("sha256", key).update(payload).digest();
  if (!crypto.timingSafeEqual(Buffer.from(envelope.mac, "hex"), expected)) throw new Error("AUTHENTICATION_DENIED");
  return JSON.parse(payload.toString("utf8"));
}
function command(action, taskId, extra = {}) {
  return validate({ version: 1, id: crypto.randomUUID(), taskId, correlationId: crypto.randomUUID(), action, timeoutMs: 3000, ...extra });
}
module.exports = { validate, seal, open, command, mutation };
