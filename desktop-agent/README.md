# Windows desktop agent, Phase 15

This is an unsigned development implementation for explicitly scoped synthetic
desktop tests. Production remains DEFAULT_DENY / NO_GO. A successful command is
an observation, not a completed task.

## Components and trust

The Node ControlledDesktopBroker validates and authorizes commands, writes a
decision record, and invokes DesktopBridge. The bridge launches a pinned .NET
agent with inherited stdin/stdout pipes and a random 256-bit session key. Frames
carry HMAC-SHA256 and exact request/task/correlation/worker identities. The key
exists in process memory and the inherited pipe, not arguments, configuration
files, environment variables, screenshots, or logs.

DesktopAgent.Core owns schemas, policy checks, replay reservations and evidence.
DesktopAgent.Windows uses Win32 and UI Automation. DesktopAgent.Fixture is a
disposable WPF test application with a counter and dialog, no external effects,
and a three-minute lifetime. The existing Approval Agent remains unchanged.

The existing advisory ProviderRegistry still handles advisory workers. Desktop
execution is deliberately registered through a separate controlled controller,
not through an API model or Antigravity adapter. No AI worker receives authority.
The optional /v1/desktop/execute broker route is DENIED without both an independent
token and an explicitly injected scoped controller. Normal broker startup installs
neither. Existing external batch denial is unchanged.

## Local requirements

Windows x64; .NET 8 SDK including Windows Desktop targeting pack; .NET 8 Desktop
runtime; Node 22 or 24; PowerShell 7; Git. No NuGet or npm packages are added.
The development machine used SDK 8.0.425, Desktop runtime 8.0.31 and Node 24.19.0.

Build and non-GUI verification:

```powershell
dotnet build desktop-agent/DesktopAgent.Windows -c Release
dotnet build desktop-agent/DesktopAgent.Fixture -c Release
dotnet run --project desktop-agent/DesktopAgent.Tests -c Release
node --test
pwsh -NoProfile -File desktop-agent/scripts/Verify-Phase15.ps1 -OutputRoot C:\dev\temp\phase15-new-verification
```

The verification directory must not exist. The runner preserves all output and
hashes it. It does not run GUI cases, configure Windows, commit, or release.
Where the sandbox denies Node test subprocess creation, `node --test --test-isolation=none`
runs the same mock tests in the current process. This does not enable desktop access.
The IPC denial test starts the real agent only with disabled policy or an
intentionally wrong session. It never enumerates, captures or controls windows.

## Build provenance and package inspection

```powershell
node desktop-agent/scripts/provenance.js build C:\dev\temp\phase15-new-package
node desktop-agent/scripts/provenance.js verify C:\dev\temp\phase15-new-package REVIEWED_MANIFEST_SHA256
```

The builder creates two independent intermediate directories and publishes the
agent, fixture and existing WPF app twice. Four browser assets are also inventoried.
All 17 payload files must have equal length and SHA-256 across the two builds.
The manifest records SDK, OS, architecture, revision, HEAD tree, dirty status,
and a raw working-file inventory including untracked source. That source hash
does not assert that uncommitted changes belong to HEAD.

Review and retain the manifest hash independently before executing its payload.
Verification checks the exact payload inventory without executing anything.
A locally generated hash is integrity evidence, not publisher authentication.
This is a development directory package, not an installer or release ZIP.
Cross-host reproducibility and historical Phase 14 package equivalence remain
unverified. Legacy CommittedRelease is never invoked.

## Run the real synthetic proof of concept

Use an unlocked, authorized WinSta0/Default desktop in a disposable Windows
account or VM. Run the following locally in that session, after reviewing the
manifest. Do not use privilege escalation, a scheduled task, desktop switching,
UIAccess, or sandbox escape to make it run.

```powershell
node desktop-agent/scripts/run-synthetic.js C:\dev\temp\phase15-new-package REVIEWED_MANIFEST_SHA256 --authorized-synthetic-desktop
```

The runner verifies every package payload before launch, probes desktop identity,
launches only the packaged fixture, and pins its PID, exact process start ticks
and executable hash. It focuses the counter button, sends Enter, verifies Count:
1, exercises Tab/Shift+Tab, clicks once, verifies Count: 2, captures the window,
and checks artifact hashes. Result and evidence location are printed. Any failed
postcondition prevents VERIFIED. The fixture and agent are stopped afterward.

Do not type, click or change foreground windows during the test. A held mouse
button or Shift/Ctrl/Alt/Windows key causes denial. The agent does not release
user-held keys, change UAC, alter DPI settings, or attach to another desktop.
Its manifest uses asInvoker, uiAccess=false and process-only DPI awareness.

CodexSandboxDesktop, service stations, locked/non-input desktops and mismatched
sessions are rejected. The current Codex sandbox is not real-desktop acceptance.
Use the deployment procedure above only after the desktop is independently
authorized. Do not infer that an elevated tool run is permission for GUI access.

## Phase 14 acceptance

Read [acceptance setup](acceptance/README.md). A11Y01 and A11Y05 have reusable
drivers, strict postconditions and fresh identities. GUI13 and A11Y02-A11Y04 remain
BLOCKED without a separately isolated and authorized configuration. They never
change personal scaling, High Contrast, Narrator or Windows preferences.

## Evidence, privacy and recovery

Each authenticated command reserves its ID on disk with create-new semantics
before side effects. Reusing an ID is denied, including after restart. Engine
task IDs are also reserved durably. A crash leaves a reservation, never implicit
permission to repeat an action. Recovery requires inspection and a new scoped
task; do not delete reservations to replay an uncertain action.

Every result includes status, fixed error code, duration and correlation.
Successful observations are stored as JSON with a SHA-256 reference; screenshots
are PNG files with size/hash/method. Audits are append-only, flushed hash chains
with sanitized IDs, decisions, timings, and evidence references. Decode each
audit payload from base64 to inspect its JSON. The evidence verifier checks the
hash and chain, not signer identity. Keep a reviewed final tail hash outside the
evidence directory to detect rewriting/truncation.

UIA traversal is bounded. Password controls are redacted; native file dialogs
expose only explicitly allowed control IDs and redact their names. File-dialog
screenshots are refused. File selection is limited to simple JSON filenames
inside the run's evidence root. No arbitrary text input, shell, script, URL
navigation, registry write, credential API or filesystem-write command exists.

Window screenshots use PrintWindow and reject a blank client region; chrome
alone cannot satisfy that heuristic. This is not semantic image verification or
proof of a visible keyboard focus indicator. Review actual images before making
those claims. No full-desktop capture is performed because unrelated windows
may contain private data.

The engine reacquires targets before acting, checks unique postconditions and
uses at most five attempts per observation acquisition and five postcondition polls (at most 30 read attempts per step). It never retries mouse,
keyboard or file-setting input. After an uncertain input outcome, timeout,
cancellation or disconnect, it stops with UNKNOWN. The bridge terminates a hung
agent process; native UIA/PrintWindow calls are not assumed cooperatively
cancellable. Optional HeartbeatMonitor runs while idle and reports disconnection;
do not run it concurrently with a sequence requiring stable observed targets.
Channel authentication failure or invalid evidence after dispatched input also
remains UNKNOWN. A capture cannot be accepted without checking its PNG evidence.

## Known security limits

This is not a boundary against a malicious process with the same Windows user
rights, a compromised operator/controller, a replaced runtime, or an adversarial
UIA provider. Bootstrap policy comes from the trusted launching controller, not
independent user-presence proof. The inherited pipes plus HMAC authenticate this
local launch relationship. They do not prove informed human approval.

Process and path checks are repeated, but do not claim atomic resistance to
same-user file replacement, reparse races, HWND reuse or foreground changes
between validation and native input. Window tokens expire after three seconds.
Audit hashes can be recomputed by an attacker unless independently pinned.
Production use requires a separate consent and protected execution design.

## Troubleshooting

- DEFAULT_DENY: the caller lacks an explicit synthetic scope. Do not change
  production configuration to work around it.
- SESSION_OR_DESKTOP_DENIED: use the authorized session described above.
- TARGET_REQUIRED / STALE_TARGET: observe again; never reuse a stale window token.
- ELEMENT_UNAVAILABLE: UIA selector is absent, duplicated, disabled or offscreen.
  Inspect the new scoped observation; do not blindly click guessed coordinates.
- MODIFIER_HELD / FOREGROUND_DENIED / OCCLUDED_TARGET: remove interference in the
  isolated test session and begin a new reviewed task if no action is uncertain.
- UNKNOWN_OUTCOME / INPUT_INCOMPLETE / UNKNOWN_TIMEOUT: inspect resulting state;
  automatic input replay is prohibited.
- SCREENSHOT_FAILED: client render is absent/blank or capture is unsupported.
  Do not substitute an image from a different session.
- EPERM from Node spawn inside the Codex sandbox: a process restriction is
  blocking the harness. Leave GUI tests blocked; no desktop escape fallback exists.
- BUILD_INTEGRITY_FAILED / PACKAGE_INTEGRITY_FAILED: reject the package and
  rebuild in a new directory. Do not update pins just to accept unexpected files.

References: [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput),
[PrintWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-printwindow),
[UI Automation threading](https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/ui-automation-threading-issues).
