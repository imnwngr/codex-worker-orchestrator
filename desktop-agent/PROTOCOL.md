# Desktop protocol v1

## Transport and authentication

One agent process, one inherited anonymous stdin/stdout pipe pair, one random
32-byte key, one in-flight command. The controller verifies pinned agent EXE,
agent DLL, Core DLL, deps.json and runtimeconfig.json before spawn. It supplies a
bootstrap object containing version, base64 key and fixed local policy. Bootstrap
is trusted only because it travels on the inherited pipe from the launcher.
There is no public agent socket and no persisted authentication secret.

Subsequent newline frames are JSON objects with exactly payload and mac.
payload is base64 of UTF-8 JSON bytes; mac is lowercase hex HMAC-SHA256 of those
bytes. Maximum frame is 1 MiB; JSON depth is 16. The .NET parser rejects duplicate
properties, unknown fields and incorrect types. Invalid MAC/framing closes the
channel, writes a sanitized rejection if the audit store was initialized, and
never dispatches the command. An empty GUID on that record means no authenticated
request identity was available.

The Node bridge authenticates READY and every result. Request, task, correlation
and worker IDs must match. Its key is erased on close. There is no token in argv,
the process environment or a policy file. No external account is used.

## Command

Required fields: version=1; id, taskId and correlationId as UUID strings; action;
timeoutMs integer from 100 to 10000. Optional fields are permitted only for their
specific operation:

| Action | Required target parameters | Meaning |
| --- | --- | --- |
| heartbeat | none | Scoped observation and responsiveness |
| observe | none | Enumerate only policy-target processes on this desktop |
| capture | window token | Capture allowed window client/content |
| focus | window, element | Focus a unique enabled UIA control |
| key | window, key; optional element | Input only to the allowed currently focused control |
| click | window, element | Click center of a visible, unoccluded allowed control |
| setFile | window, element, file | Set a native file-dialog edit to a JSON file under evidence root |

Keys: Tab, ShiftTab, Enter, Escape, Space, Up, Down, Left, Right, Home and End.
There are no system combinations or general text input. An element is an exact
AutomationId; for controls without one, name:<exact accessible name> is supported.
The selector must also appear in the local policy. Duplicate visible matches fail.
Window tokens are opaque UUIDs acquired by observation and expire after 3 seconds.
PID, process start ticks (decimal string, never a JavaScript number), executable
SHA-256 and UIA runtime ID are rechecked.

The policy is not accepted from an HTTP command. It includes enabled,
syntheticOnly, exact session/desktop, process targets, actions, control selectors
and a private evidence directory. enabled=false, absent scope or non-synthetic
scope denies all operations. Only WinSta0/Default with inputDesktop=true is valid.

## Response and state

Result: version, workerId, id, taskId, correlationId, status, code, durationMs,
retryCount, data, observationEvidence, authorized=false, production=DEFAULT_DENY.
Data contains a bounded observation, stable state hash and optional PNG reference.
References contain relative path, SHA-256, byte length and capture method.

OBSERVED means the agent returned an observation. Only the execution engine may
emit VERIFIED after an explicit, unique observed postcondition. A process exit
code or screenshot hash alone cannot verify a task.

DENIED means scope/schema/target checks rejected the request. FAILED is a definite
non-successful observation. CANCELLED applies to cancelled read-only work.
UNKNOWN applies when input may already have occurred. A command that may have
acted is never retried. Reservations survive process interruption. The engine
stores PLANNED, OBSERVING, ACTING, VERIFYING, RECOVERING, STEP_VERIFIED and a
terminal state. Recovery is observation-only with bounded reconnect.

Cancellation uses AbortSignal in the bridge and terminates the child to bound
blocking native calls. Graceful shutdown closes stdin, then enforces a one-second
deadline. Each command also has an agent-side cancellation deadline and a parent
watchdog with 500 ms transport allowance. Cancelling after input may have been
sent remains UNKNOWN even if the process has exited.

## Existing broker adapter

POST /v1/desktop/execute is an optional local integration seam. It requires a
separate 32+ character bearer token and an injected ControlledDesktopBroker.
Authentication alone cannot authorize input. Absent configuration stays 403
DEFAULT_DENY. Origin-bearing browser requests are rejected. Content-Type must be
application/json, body <=8192 bytes, and its encoding must exactly match
JSON.stringify(parsedCommand), rejecting duplicate properties and ambiguous JSON.
The body never supplies a command interpreter, policy, target process list,
evidence directory, model, endpoint or executable.

The production entry point does not configure this adapter for execution.
Tests inject synthetic scopes only. Advisory provider configuration and external
dispatch approval are unchanged.
