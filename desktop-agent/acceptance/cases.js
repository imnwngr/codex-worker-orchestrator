"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs"), path = require("node:path");
const { command } = require("../../broker/desktop/protocol");
const { readEvidence, hash } = require("../../broker/desktop/evidence");
const { parse } = require("../../experiments/browser-preview/preview");
const titles = { main: "Approval Agent — Local Mock Review", review: "Approval Agent — Offline Review Preview",
  method: "Approval Method — Offline Hybrid Foundation" };
const selectors = {
  open: "name:Open separate offline synthetic review preview", create: "name:Create a fresh synthetic five-minute review",
  select: "SelectFileButton", change: "name:Change Method…", picker: "MethodPicker", apply: "ApplyButton",
  register: "name:Register and deliver fake request", export: "name:Export browser request…",
  import: "name:Import browser response…", file: "1001", accept: "1"
};
class GuiSession {
  constructor(controller, evidenceRoot, taskId) { Object.assign(this, { controller, evidenceRoot, taskId }); this.captures = []; }
  async observe() {
    const result = await this.controller.execute(command("observe", this.taskId));
    if (result.status !== "OBSERVED") throw new Error(result.code);
    return result.data.observation;
  }
  async wait(predicate) {
    for (let attempt = 0; attempt < 8; attempt++) {
      const observation = await this.observe();
      if (predicate(observation)) return observation;
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    throw new Error("GUI_POSTCONDITION_FAILED");
  }
  async act(title, action, extra = {}) {
    const observation = await this.observe();
    const matches = observation.windows.filter(w => w.title === title);
    if (matches.length !== 1) throw new Error("GUI_TARGET_AMBIGUOUS");
    const result = await this.controller.execute(command(action, this.taskId, { window: matches[0].token, ...extra }));
    if (result.status !== "OBSERVED") throw new Error(result.status === "UNKNOWN" ? "UNKNOWN_ACTION" : result.code);
    if (result.data.evidence) { readEvidence(this.evidenceRoot, result.data.evidence); this.captures.push(result.data.evidence); }
    return result.data.observation;
  }
  async press(title, element, key = "Enter") {
    await this.act(title, "focus", { element });
    return this.act(title, "key", { element, key });
  }
  async dialogFile(title, file) {
    await this.wait(o => o.windows.some(w => w.title === title && w.dialog));
    await this.act(title, "setFile", { element: selectors.file, file });
    await this.press(title, selectors.accept);
    await this.wait(o => !o.windows.some(w => w.title === title));
  }
  async fresh(prefix) {
    const initial = await this.observe();
    if (!initial.windows.some(w => w.title === titles.review)) await this.press(titles.main, selectors.open);
    await this.wait(o => o.windows.some(w => w.title === titles.review));
    const windows = (await this.observe()).windows;
    if (windows.some(w => w.title === titles.method)) await this.press(titles.method, selectors.picker, "Escape");
    const file = prefix + "-" + crypto.randomUUID() + ".review.json";
    await this.press(titles.review, selectors.create);
    await this.dialogFile("Create a new offline synthetic demo", file);
    await this.wait(pending);
    const review = JSON.parse(fs.readFileSync(path.join(this.evidenceRoot, file)));
    if (Date.now() >= review.context.expiresAt) throw new Error("FRESH_REVIEW_EXPIRED");
    return review;
  }
}
function pending(o) { return o.windows.some(w => w.title === titles.review && w.elements.some(e => e.name === "Pending")); }
function identityVisible(observation, context) {
  const names = observation.windows.filter(w => w.title === titles.review).flatMap(w => w.elements.map(e => e.name));
  return names.includes("Request: " + context.requestId) && names.includes("Context SHA-256: " + context.contextSha256);
}
function focused(o, title, id) { return o.windows.some(w => w.title === title && w.elements.some(e => e.id === id && e.focused)); }
async function a11y01(gui) {
  const review = await gui.fresh("a11y01");
  await gui.act(titles.review, "focus", { element: selectors.select });
  await gui.act(titles.review, "key", { element: selectors.select, key: "Tab" });
  await gui.wait(o => focused(o, titles.review, selectors.create));
  await gui.act(titles.review, "capture");
  await gui.act(titles.review, "key", { element: selectors.create, key: "ShiftTab" });
  await gui.wait(o => focused(o, titles.review, selectors.select));
  await gui.press(titles.review, selectors.change);
  await gui.wait(o => o.windows.some(w => w.title === titles.method && w.dialog));
  await gui.act(titles.method, "capture");
  await gui.press(titles.method, selectors.picker, "Escape");
  await gui.wait(o => !o.windows.some(w => w.title === titles.method) && focused(o, titles.review, selectors.select) && pending(o) && identityVisible(o, review.context));
  await gui.act(titles.review, "capture");
  return { case: "A11Y01", status: "PARTIAL", behaviors: "VERIFIED_REAL_GUI",
    visibleFocusIndicator: "REQUIRES_SCREENSHOT_REVIEW", requestId: review.context.requestId,
    contextSha256: review.context.contextSha256, evidence: gui.captures };
}
async function a11y05(gui, browser, browserKind) {
  const review = await gui.fresh("a11y05-" + browserKind);
  await gui.press(titles.review, selectors.change);
  for (const key of ["Home", "Down", "Down"]) await gui.press(titles.method, selectors.picker, key);
  await gui.press(titles.method, selectors.apply);
  await gui.wait(o => !o.windows.some(w => w.title === titles.method));
  await gui.press(titles.review, selectors.register);
  const requestName = browserKind + "-" + crypto.randomUUID() + ".browser.json";
  await gui.press(titles.review, selectors.export);
  await gui.dialogFile("Export untrusted offline browser preview", requestName);
  const text = fs.readFileSync(path.join(gui.evidenceRoot, requestName), "utf8"), exported = parse(text);
  if (exported.request.requestId !== review.context.requestId || exported.request.contextSha256 !== review.context.contextSha256)
    throw new Error("REQUEST_CONTEXT_MISMATCH");
  const responseBytes = await browser.roundtrip(path.join(gui.evidenceRoot, requestName));
  const response = JSON.parse(responseBytes);
  for (const name of ["requestId", "sessionId", "contextSha256", "batchSha256", "instanceId", "generation", "challenge", "nonce", "expiresAt"])
    if (response[name] !== exported.responseTemplate[name]) throw new Error("BROWSER_RESPONSE_BINDING_FAILED");
  if (response.authorized !== false || response.productionAuthorization !== "DEFAULT_DENY" || response.outcome !== "GRANT")
    throw new Error("BROWSER_AUTHORITY_DENIED");
  const responseName = browserKind + "-" + crypto.randomUUID() + ".response.json";
  fs.writeFileSync(path.join(gui.evidenceRoot, responseName), responseBytes, { flag: "wx" });
  await gui.press(titles.review, selectors.import);
  await gui.dialogFile("Import untrusted browser response", responseName);
  await gui.wait(o => o.windows.some(w => w.title === titles.review && w.elements.some(e => e.name === "ApprovedMock")) && identityVisible(o, review.context));
  await gui.act(titles.review, "capture");
  return { case: "A11Y05", browser: browserKind, status: "VERIFIED", scope: "REAL_BROWSER_AND_WPF_SYNTHETIC_ONLY",
    requestId: review.context.requestId, contextSha256: review.context.contextSha256,
    response: { path: responseName, sha256: hash(responseBytes) }, evidence: gui.captures, authorized: false };
}
const configurationDependent = ["GUI13", "A11Y02", "A11Y03", "A11Y04"].map(caseId => ({
  case: caseId, status: "BLOCKED", reason: "ISOLATED_AUTHORIZED_CONFIGURATION_REQUIRED", modifiesPersonalSettings: false
}));
module.exports = { GuiSession, a11y01, a11y05, selectors, titles, configurationDependent };
