const http = require("http");
const { spawn } = require("child_process");
const crypto = require("crypto");

const HOST = "127.0.0.1";
const PORT = 8765;

const MAX_BODY = 256 * 1024;
const DEFAULT_TIMEOUT = 300;
const MAX_TIMEOUT = 600;

function send(res, status, obj) {
  const body = JSON.stringify(obj);

  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store"
  });

  res.end(body);
}

function runAntigravity(task, effort, timeoutSeconds) {
  return new Promise((resolve, reject) => {
    const workerPrompt = `
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
- Return analysis only.

TASK FROM CODEX:

${task}
`.trim();

    const args = [
      "--mode", "plan",
      "--sandbox",
      "--effort", effort,
      "--output-format", "json",
      "--print-timeout", `${timeoutSeconds}s`,
      `--print=${workerPrompt}`
    ];

    const child = spawn("agy", args, {
      windowsHide: true,
      shell: false,
      env: process.env
    });

    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("Antigravity broker timeout"));
    }, (timeoutSeconds + 10) * 1000);

    child.stdout.on("data", chunk => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", chunk => {
      stderr += chunk.toString();
    });

    child.on("error", err => {
      clearTimeout(timer);
      reject(err);
    });

    child.on("close", code => {
      clearTimeout(timer);

      if (code !== 0) {
        return reject(
          new Error(
            `Antigravity exited with code ${code}` +
            (stderr.trim() ? `: ${stderr.trim()}` : "")
          )
        );
      }

      let result;

      try {
        result = JSON.parse(stdout.trim());
      } catch {
        return reject(new Error("Antigravity returned invalid JSON"));
      }

      if (result.status !== "SUCCESS") {
        return reject(
          new Error(`Antigravity status: ${result.status}`)
        );
      }

      if (
        Array.isArray(result.denied_actions) &&
        result.denied_actions.length > 0
      ) {
        return reject(
          new Error(
            "Antigravity attempted denied actions: " +
            result.denied_actions
              .map(x => x.action || "unknown")
              .join(", ")
          )
        );
      }

      if (
        typeof result.response !== "string" ||
        !result.response.trim()
      ) {
        return reject(
          new Error("Antigravity returned no usable response")
        );
      }

      resolve({
        response: result.response.trim(),
        conversation_id: result.conversation_id || null,
        usage: result.usage || null
      });
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return send(res, 200, {
      ok: true,
      service: "codex-worker-broker",
      provider: "antigravity"
    });
  }

  if (req.method !== "POST" || req.url !== "/v1/analyze") {
    return send(res, 404, {
      ok: false,
      error: "not_found"
    });
  }

  let raw = "";
  let tooLarge = false;

  req.on("data", chunk => {
    if (tooLarge) return;

    raw += chunk.toString();

    if (Buffer.byteLength(raw) > MAX_BODY) {
      tooLarge = true;
      send(res, 413, {
        ok: false,
        error: "request_too_large"
      });
      req.destroy();
    }
  });

  req.on("end", async () => {
    if (tooLarge) return;

    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      return send(res, 400, {
        ok: false,
        error: "invalid_json"
      });
    }

    if (
      typeof body.task !== "string" ||
      !body.task.trim() ||
      body.task.length > 50000
    ) {
      return send(res, 400, {
        ok: false,
        error: "invalid_task"
      });
    }

    const allowedEffort = new Set([
      "low",
      "medium",
      "high",
      "xhigh",
      "max"
    ]);

    const effort = allowedEffort.has(body.effort)
      ? body.effort
      : "high";

    const requestedTimeout = Number(body.timeout_seconds);

    const timeoutSeconds =
      Number.isFinite(requestedTimeout)
        ? Math.max(
            10,
            Math.min(MAX_TIMEOUT, Math.floor(requestedTimeout))
          )
        : DEFAULT_TIMEOUT;

    const requestId = crypto.randomUUID();

    console.log(
      `[${new Date().toISOString()}] ${requestId} antigravity request`
    );

    try {
      const result = await runAntigravity(
        body.task.trim(),
        effort,
        timeoutSeconds
      );

      console.log(
        `[${new Date().toISOString()}] ${requestId} success`
      );

      return send(res, 200, {
        ok: true,
        request_id: requestId,
        provider: "antigravity",
        response: result.response,
        conversation_id: result.conversation_id,
        usage: result.usage
      });
    } catch (err) {
      console.error(
        `[${new Date().toISOString()}] ${requestId} failed:`,
        err.message
      );

      return send(res, 502, {
        ok: false,
        request_id: requestId,
        provider: "antigravity",
        error: "worker_failed",
        message: err.message
      });
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(
    `Codex Worker Broker listening on http://${HOST}:${PORT}`
  );
  console.log("Provider: antigravity");
  console.log("Mode: analysis-only");
});
