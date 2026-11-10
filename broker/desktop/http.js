"use strict";
const crypto = require("node:crypto");
function reply(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}
async function handleDesktop(request, response, options = {}) {
  const token = options.desktopAuthToken;
  const provided = request.headers.authorization;
  if (typeof token !== "string" || token.length < 32 || typeof provided !== "string" ||
      !crypto.timingSafeEqual(crypto.createHash("sha256").update(provided).digest(),
        crypto.createHash("sha256").update("Bearer " + token).digest()))
    return reply(response, 403, { status: "DENIED", code: "DEFAULT_DENY" });
  if (!options.desktopController) return reply(response, 403, { status: "DENIED", code: "DEFAULT_DENY" });
  if (request.headers.origin || request.headers["content-type"] !== "application/json")
    return reply(response, 400, { status: "DENIED", code: "INVALID_REQUEST" });
  const abort = new AbortController();
  const timer = setTimeout(() => { abort.abort(); request.destroy(); }, 12000);
  response.once("close", () => { if (!response.writableEnded) abort.abort(); });
  let command;
  try {
    const chunks = []; let bytes = 0;
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > 8192) return reply(response, 413, { status: "DENIED", code: "REQUEST_TOO_LARGE" });
      chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    command = JSON.parse(text);
    if (JSON.stringify(command) !== text) throw new Error("NONCANONICAL_REQUEST");
    const result = await options.desktopController.execute(command, { signal: abort.signal });
    reply(response, 200, result);
  } catch (error) {
    const known = new Set(["DEFAULT_DENY", "INVALID_COMMAND", "NONCANONICAL_REQUEST", "TIMEOUT", "CANCELLED",
      "UNKNOWN_TIMEOUT", "UNKNOWN_CANCELLED", "UNKNOWN_CHANNEL_FAILURE", "UNKNOWN_EVIDENCE_INVALID",
      "AGENT_DISCONNECTED", "AGENT_BUSY", "EVIDENCE_INTEGRITY_FAILED", "EVIDENCE_BINDING_FAILED",
      "CAPTURE_EVIDENCE_REQUIRED", "CAPTURE_EVIDENCE_INVALID"]);
    const code = known.has(error.message) ? error.message : "COMMAND_DENIED";
    const unknown = code.startsWith("UNKNOWN_") || code === "AGENT_DISCONNECTED" &&
      ["focus", "click", "key", "setFile"].includes(command?.action);
    const status = unknown ? "UNKNOWN" : code === "CANCELLED" ? "CANCELLED" :
      ["TIMEOUT", "AGENT_DISCONNECTED", "AGENT_BUSY"].includes(code) ? "FAILED" : "DENIED";
    if (!response.destroyed) reply(response, unknown ? 409 : code === "TIMEOUT" ? 504 : 403, { status, code });
  } finally { clearTimeout(timer); }
}
module.exports = { handleDesktop };
