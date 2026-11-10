"use strict";
const fs = require("node:fs"), path = require("node:path"), net = require("node:net");
const { pathToFileURL } = require("node:url");
const { spawn } = require("node:child_process");
const { hash, safeRoot } = require("../../broker/desktop/evidence");
async function port() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const result = server.address().port;
  await new Promise(resolve => server.close(resolve)); return result;
}
class RealBrowser {
  constructor({ kind, driver, driverSha256, root, preview }) {
    if (!["edge", "firefox"].includes(kind) || !path.isAbsolute(driver) ||
        path.basename(driver).toLowerCase() !== (kind === "edge" ? "msedgedriver.exe" : "geckodriver.exe") ||
        !/^[a-f0-9]{64}$/.test(driverSha256) || hash(fs.readFileSync(driver)) !== driverSha256)
      throw new Error("DRIVER_PIN_REQUIRED");
    Object.assign(this, { kind, driver, root: safeRoot(root), preview: pathToFileURL(path.resolve(preview)).href });
    this.consumed = false;
    fs.mkdirSync(this.root);
    this.download = path.join(this.root, "downloads"); fs.mkdirSync(this.download);
    this.profile = path.join(this.root, "profile"); fs.mkdirSync(this.profile);
  }
  async request(method, route, body) {
    const response = await fetch(this.base + route, { method, headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10000), redirect: "error" });
    const text = await response.text();
    if (text.length > 16 * 1024 * 1024) throw new Error("WEBDRIVER_RESPONSE_LIMIT");
    const result = JSON.parse(text);
    if (!response.ok || result.value?.error) throw new Error("WEBDRIVER_COMMAND_FAILED");
    return result.value;
  }
  async start() {
    const number = await port(); this.base = "http://127.0.0.1:" + number;
    this.child = spawn(this.driver, this.kind === "edge" ? ["--port=" + number, "--allowed-ips=127.0.0.1"] :
      ["--host", "127.0.0.1", "--port", String(number)], { shell: false, windowsHide: true, stdio: "ignore" });
    this.child.on("error", () => { this.failed = true; });
    let ready = false;
    for (let retry = 0; retry < 20 && !this.failed; retry++) {
      if (this.child.exitCode !== null) break;
      try { await this.request("GET", "/status"); ready = true; break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    if (!ready) throw new Error("WEBDRIVER_UNAVAILABLE");
    const options = this.kind === "edge" ? { browserName: "MicrosoftEdge", "ms:edgeOptions": {
      args: ["--user-data-dir=" + this.profile, "--no-first-run", "--disable-sync", "--disable-extensions"],
      prefs: { "download.default_directory": this.download, "download.prompt_for_download": false }
    } } : { browserName: "firefox", "moz:firefoxOptions": {
      args: ["-no-remote", "-profile", this.profile],
      prefs: { "browser.download.folderList": 2, "browser.download.dir": this.download,
        "browser.download.useDownloadDir": true, "browser.helperApps.neverAsk.saveToDisk": "application/json",
        "browser.download.always_ask_before_handling_new_types": false, "datareporting.healthreport.uploadEnabled": false,
        "toolkit.telemetry.enabled": false, "browser.shell.checkDefaultBrowser": false }
    } };
    const session = await this.request("POST", "/session", { capabilities: { alwaysMatch: options } });
    if (!session.sessionId) throw new Error("WEBDRIVER_SESSION_FAILED");
    this.session = "/session/" + encodeURIComponent(session.sessionId);
    this.capabilities = session.capabilities;
    if (session.capabilities?.["moz:headless"] === true) throw new Error("HEADLESS_REJECTED");
  }
  async find(css) {
    const found = await this.request("POST", this.session + "/element", { using: "css selector", value: css });
    const id = found["element-6066-11e4-a52e-4f735466cecf"];
    if (!id) throw new Error("BROWSER_ELEMENT_MISSING");
    return this.session + "/element/" + encodeURIComponent(id);
  }
  async roundtrip(requestFile) {
    if (this.consumed) throw new Error("BROWSER_RESPONSE_ALREADY_CONSUMED");
    this.consumed = true;
    await this.start();
    await this.request("POST", this.session + "/url", { url: this.preview });
    if (await this.request("GET", this.session + "/url") !== this.preview) throw new Error("BROWSER_PAGE_MISMATCH");
    const input = await this.find("#request");
    await this.request("POST", input + "/value", { text: path.resolve(requestFile) });
    const status = await this.find("#status");
    let pending = false;
    for (let retry = 0; retry < 15; retry++) {
      const text = await this.request("GET", status + "/text");
      if (text.startsWith("Pending synthetic review.")) { pending = true; break; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!pending) throw new Error("BROWSER_IMPORT_NOT_OBSERVED");
    const button = await this.find('button[data-outcome="GRANT"]');
    await this.request("POST", button + "/click", {});
    if (!(await this.request("GET", status + "/text")).startsWith("Synthetic response exported."))
      throw new Error("BROWSER_EXPORT_NOT_OBSERVED");
    const screenshot = Buffer.from(await this.request("GET", this.session + "/screenshot"), "base64");
    if (screenshot.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") throw new Error("BROWSER_SCREENSHOT_FAILED");
    fs.writeFileSync(path.join(this.root, "browser.png"), screenshot, { flag: "wx" });
    const file = path.join(this.download, "synthetic.response.json");
    for (let retry = 0; retry < 30; retry++) {
      if (fs.existsSync(file) && fs.statSync(file).size > 0 && fs.statSync(file).size <= 4096) {
        const bytes = fs.readFileSync(file);
        try { JSON.parse(bytes); this.evidence = { screenshotSha256: hash(screenshot), responseSha256: hash(bytes),
          browserName: this.capabilities.browserName, browserVersion: this.capabilities.browserVersion, headless: false };
          return bytes;
        } catch {}
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error("BROWSER_DOWNLOAD_NOT_OBSERVED");
  }
  async close() {
    try { if (this.session) await this.request("DELETE", this.session); }
    finally { this.child?.kill(); }
  }
}
module.exports = { RealBrowser };
