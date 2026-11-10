"use strict";
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const { DesktopBridge, required } = require("../../broker/desktop/bridge");
const { command } = require("../../broker/desktop/protocol");
const { hash, verifyAudit } = require("../../broker/desktop/evidence");
const crypto = require("node:crypto");
(async () => {
  const directory = path.resolve(__dirname, "../DesktopAgent.Windows/bin/Release/net8.0-windows");
  const pins = Object.fromEntries(required.map(name => [name, hash(fs.readFileSync(path.join(directory, name)))]));
  const probe = spawnSync(path.join(directory, "DesktopAgent.Windows.exe"), ["--probe"], { encoding: "utf8", windowsHide: true });
  if (probe.error) throw new Error(probe.error.code);
  if (probe.status !== 0) throw new Error("PROBE_FAILED");
  const session = JSON.parse(probe.stdout);
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-channel-"));
  const policy = { enabled: false, sessionId: session.sessionId, desktop: "Default",
    targets: [{ processId: process.pid, startTicks: "0", executableSha256: "0".repeat(64) }],
    actions: ["observe"], automationIds: [], evidenceRoot, syntheticOnly: true };
  const bridge = new DesktopBridge({ directory, pins, policy });
  try {
    const result = await bridge.execute(command("observe", crypto.randomUUID()));
    assert.equal(result.status, "DENIED"); assert.equal(result.code, "DEFAULT_DENY");
  } finally { await bridge.close(); }
  const second = new DesktopBridge({ directory, pins, policy: { ...policy, enabled: true, sessionId: -1 } });
  try { assert.equal((await second.execute(command("observe", crypto.randomUUID()))).code, "SESSION_OR_DESKTOP_DENIED"); }
  finally { await second.close(); }
  const audits = fs.readdirSync(evidenceRoot).filter(n => n.endsWith(".ndjson")).map(n => verifyAudit(path.join(evidenceRoot, n)));
  const report = { status: "VERIFIED", scope: "REAL_AGENT_IPC_AND_DENIAL_ONLY", session,
    realGui: "BLOCKED_UNLESS_AUTHORIZED_INPUT_DESKTOP", checks: ["HMAC", "DEFAULT_DENY", "SESSION_MISMATCH", "GRACEFUL_SHUTDOWN", "AUDIT_HASHES"], audits };
  fs.writeFileSync(path.join(evidenceRoot, "report.json"), JSON.stringify(report, null, 2), { flag: "wx" });
  console.log(JSON.stringify(report, null, 2));
})().catch(error => { console.error("REAL_AGENT_CHANNEL_TEST_FAILED: " + (/^[A-Z_]+$/.test(error.message) ? error.message : "UNCLASSIFIED")); process.exitCode = 1; });
