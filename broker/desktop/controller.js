"use strict";
const fs = require("node:fs");
const { readEvidence } = require("./evidence");
const { validate, command, mutation } = require("./protocol");
class ControlledDesktopBroker {
  constructor({ bridge, reconnect, evidenceRoot, authorize = () => false, audit = () => { throw new Error("AUDIT_REQUIRED"); } } = {}) {
    this.bridge = bridge; this.reconnect = reconnect; this.evidenceRoot = evidenceRoot; this.authorize = authorize; this.audit = audit;
  }
  async execute(input, { signal } = {}) {
    input = Object.freeze({ ...validate(input) });
    const allowed = await this.authorize(Object.freeze({ ...input })) === true;
    this.audit({ id: input.id, taskId: input.taskId, correlationId: input.correlationId,
      action: input.action, decision: allowed ? "SCOPED_SYNTHETIC" : "DEFAULT_DENY" });
    if (!allowed || !this.bridge) throw new Error("DEFAULT_DENY");
    const result = await this.bridge.execute(input, { signal });
    if (result.status === "OBSERVED") {
      try {
        const bytes = readEvidence(this.evidenceRoot, result.observationEvidence);
        if (JSON.stringify(JSON.parse(bytes)) !== JSON.stringify(result.data)) throw new Error("EVIDENCE_BINDING_FAILED");
        if (input.action === "capture" && !result.data.evidence) throw new Error("CAPTURE_EVIDENCE_REQUIRED");
        if (result.data.evidence) {
          const image = readEvidence(this.evidenceRoot, result.data.evidence);
          if (image.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") throw new Error("CAPTURE_EVIDENCE_INVALID");
        }
      } catch (error) {
        if (mutation(input.action)) throw new Error("UNKNOWN_EVIDENCE_INVALID");
        throw error;
      }
    }
    return result;
  }
}
function verify(observation, expected) {
  if (!observation || !Array.isArray(observation.windows) || !expected) return false;
  const windows = observation.windows.filter(w => expected.windowTitle == null || w.title === expected.windowTitle);
  if (expected.kind === "windowCount") return windows.length === expected.count;
  if (expected.kind === "windowPresent") return windows.length === 1;
  const elements = windows.flatMap(w => w.elements).filter(e => e.id === expected.element && !e.offscreen);
  if (elements.length !== 1) return false;
  if (expected.kind === "focused") return elements[0].focused === true;
  if (expected.kind === "name") return elements[0].name === expected.value;
  return false;
}
class ExecutionEngine {
  constructor({ controller, historyPath, maxObservations = 3 }) {
    if (!Number.isInteger(maxObservations) || maxObservations < 1 || maxObservations > 5) throw new Error("INVALID_RETRY_LIMIT");
    this.controller = controller; this.historyPath = historyPath; this.maxObservations = maxObservations;
    this.active = false;
  }
  record(taskId, state, extra = {}) {
    fs.appendFileSync(this.historyPath, JSON.stringify({ taskId, state, at: new Date().toISOString(), ...extra }) + "\n", { flag: "a", flush: true });
  }
  async observe(taskId, signal) {
    for (let retry = 0; retry < this.maxObservations; retry++) {
      try {
        const result = await this.controller.execute(command("observe", taskId), { signal });
        if (result.status === "OBSERVED") return result;
        if (!["STALE_TARGET", "ELEMENT_UNAVAILABLE"].includes(result.code)) throw new Error(result.code);
      } catch (error) {
        if (signal?.aborted || !["AGENT_DISCONNECTED", "TIMEOUT"].includes(error.message)) throw error;
        if (retry + 1 < this.maxObservations && this.controller.reconnect) {
          this.controller.bridge?.stop();
          this.controller.bridge = await this.controller.reconnect();
        }
      }
      this.record(taskId, "RECOVERING", { retry: retry + 1, strategy: "REACQUIRE_OBSERVATION" });
    }
    throw new Error("OBSERVATION_RETRY_EXHAUSTED");
  }
  async run(plan, { signal } = {}) {
    if (this.active) throw new Error("ENGINE_BUSY");
    if (!plan || !Array.isArray(plan.steps) || plan.steps.length < 1 || plan.steps.length > 64 ||
        typeof plan.taskId !== "string" || !/^[a-f0-9-]{36}$/.test(plan.taskId)) throw new Error("INVALID_PLAN");
    if (plan.steps.some(s => !s || typeof s.windowTitle !== "string" || !s.expect ||
        !["focused", "name", "windowPresent", "windowCount"].includes(s.expect.kind) ||
        !["focus", "key", "click", "setFile", "capture"].includes(s.action))) throw new Error("INVALID_PLAN");
    const claim = this.historyPath + "." + plan.taskId + ".claim";
    fs.writeFileSync(claim, "RESERVED\n", { flag: "wx", flush: true });
    this.active = true;
    let currentAction = "observe";
    try {
      this.record(plan.taskId, "PLANNED", { steps: plan.steps.length });
      for (const step of plan.steps) {
        if (signal?.aborted) throw new Error("CANCELLED");
        currentAction = "observe";
        this.record(plan.taskId, "OBSERVING");
        const before = await this.observe(plan.taskId, signal);
        if (before.status !== "OBSERVED") throw new Error(before.code);
        const windows = before.data.observation.windows.filter(w => w.title === step.windowTitle);
        if (windows.length !== 1) throw new Error("TARGET_AMBIGUOUS_OR_MISSING");
        currentAction = step.action;
        const input = command(step.action, plan.taskId, { window: windows[0].token,
          ...(step.element ? { element: step.element } : {}), ...(step.key ? { key: step.key } : {}),
          ...(step.file ? { file: step.file } : {}) });
        this.record(plan.taskId, "ACTING", { id: input.id, action: step.action });
        const action = await this.controller.execute(input, { signal });
        if (action.status !== "OBSERVED") throw new Error(action.status === "UNKNOWN" ? "UNKNOWN_ACTION" : action.code);
        this.record(plan.taskId, "VERIFYING");
        let verified = verify(action.data?.observation, step.expect);
        currentAction = "observe";
        for (let retry = 1; !verified && retry <= this.maxObservations; retry++) {
          this.record(plan.taskId, "RECOVERING", { retry, strategy: "OBSERVE_ONLY" });
          const after = await this.observe(plan.taskId, signal);
          verified = after.status === "OBSERVED" && verify(after.data?.observation, step.expect);
        }
        if (!verified) throw new Error("POSTCONDITION_FAILED");
        this.record(plan.taskId, "STEP_VERIFIED", { id: input.id });
      }
      this.record(plan.taskId, "VERIFIED");
      return { taskId: plan.taskId, status: "VERIFIED", authorized: false, production: "DEFAULT_DENY" };
    } catch (error) {
      const code = /^[A-Z_]{1,64}$/.test(error.message) ? error.message : "EXECUTION_FAILED";
      const status = code.startsWith("UNKNOWN") || mutation(currentAction) && code === "AGENT_DISCONNECTED" ? "UNKNOWN"
        : code === "CANCELLED" ? "CANCELLED" : "FAILED";
      this.record(plan.taskId, status, { code });
      return { taskId: plan.taskId, status, code, authorized: false, production: "DEFAULT_DENY" };
    } finally { this.active = false; }
  }
}
module.exports = { ControlledDesktopBroker, ExecutionEngine, verify };
