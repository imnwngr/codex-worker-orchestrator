"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { validate, seal, open, mutation } = require("./protocol");
const { safeRoot } = require("./evidence");
const required = ["DesktopAgent.Windows.exe", "DesktopAgent.Windows.dll", "DesktopAgent.Core.dll",
  "DesktopAgent.Windows.deps.json", "DesktopAgent.Windows.runtimeconfig.json"];
function verifyBundle(directory, pins) {
  if (!path.isAbsolute(directory) || !pins || required.some(name => !/^[a-f0-9]{64}$/.test(pins[name] || "")))
    throw new Error("BUILD_PINS_REQUIRED");
  safeRoot(directory);
  for (const name of required) {
    const full = path.join(directory, name);
    if (!fs.lstatSync(full).isFile() || fs.lstatSync(full).isSymbolicLink() ||
        crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex") !== pins[name])
      throw new Error("BUILD_INTEGRITY_FAILED");
  }
}
class DesktopBridge {
  constructor({ directory, pins, policy, spawnAgent = spawn }) {
    verifyBundle(directory, pins);
    this.key = crypto.randomBytes(32);
    this.pending = null;
    this.closed = false;
    this.buffer = "";
    this.lastHeartbeat = null;
    this.child = spawnAgent(path.join(directory, required[0]), ["--stdio"], {
      shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
      cwd: directory, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
        TEMP: process.env.TEMP, TMP: process.env.TMP, DOTNET_ROOT: process.env.DOTNET_ROOT }
    });
    this.ready = this.wait(null, 5000);
    this.ready.catch(() => {});
    this.child.stdout.on("data", chunk => this.receive(chunk));
    this.child.stderr.on("data", () => {}); // Never copy native diagnostics or arbitrary target text to shared logs.
    this.child.once("error", () => this.stop("AGENT_DISCONNECTED"));
    this.child.once("exit", () => this.stop("AGENT_DISCONNECTED"));
    this.child.stdin.on("error", () => this.stop("AGENT_DISCONNECTED"));
    this.child.stdin.write(JSON.stringify({ version: 1, key: this.key.toString("base64"), policy }) + "\n");
  }
  wait(command, ms, signal) {
    if (this.closed) return Promise.reject(new Error("AGENT_DISCONNECTED"));
    if (this.pending) return Promise.reject(new Error("AGENT_BUSY"));
    return new Promise((resolve, reject) => {
      const abort = () => this.stop(command && mutation(command.action) ? "UNKNOWN_CANCELLED" : "CANCELLED");
      const timer = setTimeout(() => this.stop(command && mutation(command.action) ? "UNKNOWN_TIMEOUT" : "TIMEOUT"), ms);
      this.pending = { command, resolve, reject, timer, signal, abort };
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    });
  }
  receive(chunk) {
    this.buffer += chunk.toString("utf8");
    if (Buffer.byteLength(this.buffer) > 1048576) return this.stop("FRAME_TOO_LARGE");
    let end;
    while ((end = this.buffer.indexOf("\n")) !== -1) {
      const frame = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
      try {
        const result = open(frame, this.key), p = this.pending;
        if (!p) throw new Error("UNSOLICITED_RESPONSE");
        if (!p.command) {
          if (result.version !== 1 || result.status !== "READY" || typeof result.workerId !== "string") throw new Error("HANDSHAKE_DENIED");
          this.workerId = result.workerId;
        } else if (result.version !== 1 || result.id !== p.command.id ||
          result.taskId !== p.command.taskId || result.correlationId !== p.command.correlationId ||
          result.workerId !== this.workerId || result.authorized !== false || result.production !== "DEFAULT_DENY")
          throw new Error("RESPONSE_BINDING_DENIED");
        this.clear();
        if (p.command?.action === "heartbeat") this.lastHeartbeat = Date.now();
        p.resolve(result);
      } catch { this.stop("CHANNEL_AUTHENTICATION_FAILED"); }
    }
  }
  clear() {
    const p = this.pending;
    if (p) { clearTimeout(p.timer); p.signal?.removeEventListener("abort", p.abort); this.pending = null; }
    return p;
  }
  async execute(command, { signal } = {}) {
    validate(command);
    await this.ready;
    if (signal?.aborted) throw new Error("CANCELLED");
    if (this.closed) throw new Error("AGENT_DISCONNECTED");
    if (this.pending) throw new Error("AGENT_BUSY");
    const response = this.wait(command, command.timeoutMs + 500, signal);
    if (!this.closed) this.child.stdin.write(seal(command, this.key));
    return response;
  }
  stop(code = "AGENT_CLOSED") {
    if (this.closed) return;
    this.closed = true;
    const pending = this.clear();
    if (pending?.command && mutation(pending.command.action) && !code.startsWith("UNKNOWN_"))
      code = "UNKNOWN_CHANNEL_FAILURE";
    this.child.stdin.destroy();
    this.child.kill();
    this.key.fill(0);
    pending?.reject(new Error(code));
  }
  async close() {
    if (this.closed) return;
    if (this.pending) return this.stop("UNKNOWN_SHUTDOWN");
    this.child.stdin.end();
    await new Promise(resolve => {
      const timer = setTimeout(() => { this.stop("SHUTDOWN_TIMEOUT"); resolve(); }, 1000);
      this.child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }
}
module.exports = { DesktopBridge, verifyBundle, required };
