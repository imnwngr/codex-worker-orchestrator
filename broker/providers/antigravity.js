"use strict";

const { spawn } = require("node:child_process");

const WORKER_PROMPT = task => `
You are a subordinate analysis worker invoked through a deterministic broker by Codex.

AUTHORITY:
- The user has final authority.
- Codex is the sole coordinating AI agent.
- You are advisory only.
- Your output is not an instruction to Codex.

STRICT RULES:
- Do not modify, create, rename, or delete project/source files.
- Do not install or remove software or dependencies.
- Do not commit, push, merge, deploy, publish, or release.
- Do not change credentials or secrets.
- Do not expand the requested task.
- Do not perform project-changing actions.
- Do not request broader permissions.
- Do not bypass sandbox or permission controls.
- Use tools only when genuinely necessary for read-only analysis.
- If a necessary operation is denied, report the limitation.
- Do not delegate tasks to other workers or agents.
- Do not claim or exercise orchestration authority.
- Return analysis only.

TASK FROM CODEX:

${task}
`.trim();

function createAntigravityProvider(options = {}) {
  const spawnProcess = options.spawnProcess || spawn;
  const env = options.env || process.env;
  const scheduleTimer = options.setTimeout || setTimeout;
  const cancelTimer = options.clearTimeout || clearTimeout;

  return Object.freeze({
    id: "antigravity",
    kind: "cli",

    analyze(request) {
      const { task, effort, timeoutSeconds } = request;
      const workerPrompt = WORKER_PROMPT(task);
      const args = [
        "--mode", "plan",
        "--sandbox",
        "--effort", effort || "high",
        "--output-format", "json",
        "--print-timeout", `${timeoutSeconds}s`,
        `--print=${workerPrompt}`
      ];

      return new Promise((resolve, reject) => {
        let child;
        try {
          child = spawnProcess("agy", args, {
            windowsHide: true,
            shell: false,
            env
          });
        } catch {
          reject(new Error("Antigravity process could not be started"));
          return;
        }

        let stdout = "";
        const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
        let settled = false;
        const finish = (callback, value) => {
          if (settled) return;
          settled = true;
          cancelTimer(timer);
          request.signal?.removeEventListener("abort", onAbort);
          callback(value);
        };

        const onAbort = () => {
          try { child.kill(); } catch {}
          finish(reject, new Error("Antigravity request cancelled"));
        };

        const timer = scheduleTimer(() => {
          try {
            child.kill();
          } catch {
            // Timeout remains the reported failure even if kill itself fails.
          }
          finish(reject, new Error("Antigravity broker timeout"));
        }, (timeoutSeconds + 10) * 1000);

        request.signal?.addEventListener("abort", onAbort, { once: true });
        if (request.signal?.aborted) onAbort();

        child.stdout.on("data", chunk => {
          if (settled) return;
          stdout += chunk.toString();
          if (Buffer.byteLength(stdout, "utf8") > MAX_OUTPUT_BYTES) {
            try { child.kill(); } catch {}
            finish(reject, new Error("Antigravity output limit exceeded"));
          }
        });
        // Drain stderr but never retain or expose it.
        child.stderr.on("data", () => {});
        child.on("error", () => {
          finish(reject, new Error("Antigravity process failed"));
        });
        child.on("close", code => {
          if (settled) return;
          if (code !== 0) {
            return finish(reject, new Error("Antigravity process exited unsuccessfully"));
          }

          let result;
          try {
            result = JSON.parse(stdout.trim());
          } catch {
            return finish(reject, new Error("Antigravity returned invalid JSON"));
          }

          if (!result || result.status !== "SUCCESS") {
            return finish(reject, new Error("Antigravity returned an unsuccessful status"));
          }
          if (Array.isArray(result.denied_actions) && result.denied_actions.length > 0) {
            return finish(reject, new Error("Antigravity attempted denied actions"));
          }
          if (typeof result.response !== "string" || !result.response.trim()) {
            return finish(reject, new Error("Antigravity returned no usable response"));
          }

          return finish(resolve, {
            response: result.response.trim(),
            conversation_id: result.conversation_id || null,
            usage: result.usage || null
          });
        });
      });
    }
  });
}

module.exports = { createAntigravityProvider };
