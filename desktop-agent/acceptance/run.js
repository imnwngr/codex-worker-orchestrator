"use strict";
const fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { verifyPackage } = require("../scripts/provenance");
const { DesktopBridge, required } = require("../../broker/desktop/bridge");
const { ControlledDesktopBroker } = require("../../broker/desktop/controller");
const { auditWriter, hash } = require("../../broker/desktop/evidence");
const { GuiSession, a11y01, a11y05, selectors, configurationDependent } = require("./cases");
const { RealBrowser } = require("./webdriver");
async function run(config) {
  if (config.isolatedDesktop !== true || !["A11Y01", "A11Y05"].includes(config.case))
    throw new Error("ISOLATED_DESKTOP_AUTHORIZATION_REQUIRED");
  const root = path.resolve(config.packageRoot), manifest = verifyPackage(root, config.manifestSha256);
  const directory = path.join(root, "payload/agent");
  const pins = Object.fromEntries(required.map(n => [n, manifest.artifacts.find(f => f.path === "agent/" + n)?.sha256]));
  const probe = spawnSync(path.join(directory, "DesktopAgent.Windows.exe"), ["--probe"], { encoding: "utf8", windowsHide: true });
  if (probe.error || probe.status !== 0) throw new Error("DESKTOP_PROBE_UNAVAILABLE");
  const session = JSON.parse(probe.stdout);
  if (session.desktop !== "Default" || session.station !== "WinSta0" || !session.inputDesktop)
    return { status: "BLOCKED", code: "AUTHORIZED_INPUT_DESKTOP_REQUIRED" };
  if (fs.existsSync(path.join(process.env.LOCALAPPDATA, "ApprovalAgent.Mock", "approval-method.json")))
    throw new Error("CLEAN_TEST_ACCOUNT_REQUIRED");
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase15-phase14-"));
  const appPath = path.join(root, "payload/approval/ApprovalAgent.Mock.exe");
  const app = spawn(appPath, [], { shell: false, windowsHide: true, stdio: "ignore" });
  let appError = false; app.on("error", () => { appError = true; });
  await new Promise(resolve => setTimeout(resolve, 500));
  let bridge, audit, browser;
  try {
    if (appError || !Number.isInteger(app.pid)) throw new Error("WPF_START_FAILED");
    const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
    const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command",
      "(Get-Process -Id " + app.pid + ").StartTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)"],
      { windowsHide: true, encoding: "utf8", timeout: 5000 });
    if (result.status !== 0 || !/^[0-9]{16,20}$/.test(result.stdout.trim())) throw new Error("PROCESS_IDENTITY_FAILED");
    const target = { processId: app.pid, startTicks: result.stdout.trim(), executableSha256: hash(fs.readFileSync(appPath)) };
    const policy = { enabled: true, syntheticOnly: true, sessionId: session.sessionId, desktop: "Default",
      targets: [target], actions: ["observe", "capture", "focus", "key", "setFile"], automationIds: Object.values(selectors), evidenceRoot };
    bridge = new DesktopBridge({ directory, pins, policy });
    audit = auditWriter(path.join(evidenceRoot, "controller.ndjson"));
    const reports = [];
    for (const kind of config.case === "A11Y05" ? ["edge", "firefox"] : ["wpf"]) {
      const taskId = crypto.randomUUID();
      const controller = new ControlledDesktopBroker({ bridge, evidenceRoot, audit: e => audit.write(e),
        authorize: c => c.taskId === taskId && policy.actions.includes(c.action) });
      const gui = new GuiSession(controller, evidenceRoot, taskId);
      if (kind === "wpf") reports.push(await a11y01(gui));
      else {
        const driver = config.drivers?.[kind];
        if (!driver) throw new Error("PINNED_BROWSER_DRIVER_REQUIRED");
        browser = new RealBrowser({ kind, driver: driver.path, driverSha256: driver.sha256,
          root: path.join(evidenceRoot, kind + "-" + taskId),
          preview: path.join(root, "payload/browser/index.html") });
        try { const report = await a11y05(gui, browser, kind); report.browserEvidence = browser.evidence; reports.push(report); }
        finally { await browser.close(); browser = null; }
      }
    }
    if (reports.length === 2 && (reports[0].requestId === reports[1].requestId || reports[0].response.path === reports[1].response.path))
      throw new Error("BROWSER_IDENTITY_REUSE");
    const report = { status: reports.some(r => r.status === "PARTIAL") ? "PARTIAL" : "VERIFIED",
      reports, configurationDependent, session, production: "DEFAULT_DENY" };
    fs.writeFileSync(path.join(evidenceRoot, "report.json"), JSON.stringify(report, null, 2), { flag: "wx" });
    return { ...report, evidenceRoot };
  } catch (error) {
    const code = /^[A-Z_]+$/.test(error.message) ? error.message : "GUI_ACCEPTANCE_FAILED";
    fs.writeFileSync(path.join(evidenceRoot, "failure.json"), JSON.stringify({
      status: code.startsWith("UNKNOWN_") ? "UNKNOWN" : "FAILED", code, production: "DEFAULT_DENY"
    }), { flag: "wx" });
    throw error;
  } finally { if (browser) await browser.close(); if (bridge) await bridge.close(); audit?.close(); app.kill(); }
}
if (require.main === module) {
  Promise.resolve().then(() => run(JSON.parse(fs.readFileSync(process.argv[2], "utf8"))))
    .then(report => { console.log(JSON.stringify(report, null, 2)); if (report.status !== "VERIFIED") process.exitCode = 2; })
    .catch(error => { console.error(/^[A-Z_]+$/.test(error.message) ? error.message : "ACCEPTANCE_FAILED"); process.exitCode = 1; });
}
module.exports = { run };
