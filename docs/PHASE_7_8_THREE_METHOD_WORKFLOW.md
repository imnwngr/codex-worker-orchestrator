# Phase 7A–8D: Three-method interactive offline workflow

Baseline: `c3f5a9c32563f1f218d592dc2e74e961ecd373ad`.
All results remain `authorized:false`, `DEFAULT_DENY`. Live trust activation is
**NO-GO**. The USER remains final authority. No Broker/provider or CI changes.

## Implemented workflow

| Workstream | Implementation |
|---|---|
| 7A | Existing strict review loader and complete read-only action remain canonical; remaining-time presentation, method-specific actions, terminal controls and explicit file failure feedback |
| 7B | Interactive fake HELLO negotiation, prerequisites, pending consent, grant/deny/cancel, crash, unavailable/failure and explicit recovery |
| 7C | Ordinary `file://` browser client, canonical bounded package import, action display, synthetic response downloads and WPF import |
| 7D | Existing onboarding, Settings and optional future default reused; both switching orders exercised; focus returns after picker/settings |
| 8A | One canonical view model; lifecycle mutations serialized; old sessions/queued frames cleared on switches and terminal transitions |
| 8B | Existing Node preparation/export and .NET validation retained; executable .NET → browser JS → Node decoder → .NET round trips; golden bytes |
| 8C | Existing WPF resources retained, method sections and wrapped controls; browser semantic labels/status/focus/system colors; manual checks pending |
| 8D | Positive/negative regressions for correlation, tampering, expiry, rollback, race, stale generation, failure/recovery and false authority |

`OfflineReviewViewModel` owns the active request and selected method. Interactive
B/C operations use the existing `OfflineTrustSession` and bounded in-process
`OfflineTrustFakeTransport`; they do not create another approval engine. Session
initialization is synthetic version-1 negotiation/registration, not installation
or enrollment. The canonical decision is rechecked at consumption, including the
original absolute deadline. Locks serialize response, switch, load and terminal
operations. Preferences only affect future loads and never supply policy.

Failure/unavailable requires explicit switching away and back or cancellation.
Crash/UNKNOWN requires explicit local abandonment, which cancels the canonical
review. No retransmission or success inference occurs. Switching discards the
previous session and fake transport queue and increments the existing generation.
Original context objects and expiry are retained. Terminal controls cannot reopen
the session. Repeated synthetic responses are rejected.

## Demonstrate on Windows

Run these commands from the disposable patched repository. Use a fresh filename:

```powershell
node experiments/integration-contracts/export-review-cli.js --output "$env:TEMP\interactive-demo.review.json"
dotnet run -c Release --project approval-agent/ApprovalAgent.Mock
```

Open Offline Review Preview from the existing application navigation. First-run
method selection and Method Settings use existing preferences. Select the newly
exported review file; its lifetime is five minutes. Historical golden fixtures
are for injected-clock tests, not current-time manual demos.

A: select Local Desktop, inspect the complete effective task and wire body, then
Approve Mock, Reject or Cancel. Load a fresh request to demonstrate another terminal
outcome. Select malformed replacement data while Pending and verify the valid
review remains. Deadline and remaining time remain visible.

B: Change Method → Protected Windows. Initialize and negotiate the fake component.
Inspect the UNVERIFIED identity/prerequisites and Pending protocol state. Choose
synthetic Approve/Deny/Cancel or crash then abandon unknown/recover. To demonstrate
unavailable, select it before initialization. Failure is available while Pending;
recover by explicitly switching A → B. Nothing invokes Windows Hello or a service.

C: Change Method → Remote/Browser. Register and deliver the fake request. Export a
new `.browser.json` file. Open `experiments/browser-preview/index.html` directly in
an ordinary browser. Import the package, review its untrusted action projection,
and choose a synthetic outcome. Import the downloaded `.response.json` in the same
WPF review. A different instance, switched generation, duplicate or expired file
is rejected. UNKNOWN can only be abandoned locally. Local C buttons also allow
an entirely in-process demonstration. Browser communication is manual files only.

Exercise A → B → C → A and A → C → B → A while Pending. Export a C response, switch
away and back, then import it: reject the stale generation. Set a future default
while a request is active: current method and deadline do not change. Try switching
near expiry and after a terminal decision: terminal state must stay authoritative.

## Browser contract and trust boundary

Package schema version 1 has exactly `schemaVersion`, `designation`, `request`,
`responseTemplate`; designation is `OFFLINE_BROWSER_PREVIEW_ONLY`. Request fields
are request/session IDs, context/batch digests, createdAt/expiresAt and ordered
target projections (id/provider/model/destination/task/task digest). ResponseTemplate
is the existing canonical version-1 REMOTE_BROWSER CONSENT_RESPONSE/GRANT fixture.
Only its outcome changes on browser export. Supported outcomes: GRANT, DENY,
CANCEL and UNKNOWN. Exact exported response bytes are checked by Node and .NET.

Packages are limited to 262144 UTF-8 bytes; responses to 4096. Browser parsing
rejects duplicate names through canonical-only equality, unsafe numbers, invalid
Unicode, unknown fields, oversized arrays/tasks, inconsistent binding and authority
claims. Invalid replacement preserves the previous valid browser review. Async
imports discard older file reads after a newer selection. Response export closes
the browser's local review; the actual active WPF session separately consumes once.
Browser reload is not durable consumption and cannot renew the original deadline.

Every fake principal/origin/device/channel is UNVERIFIED. `channelTrust` retains
`FAKE_IN_PROCESS` as the preexisting simulation contract classification; file
transport does not establish a network channel. Displayed browser digests and task
text are untrusted claims. They do not replace the authoritative .NET validated
action. Browser files can be spoofed and are not consent evidence. The .NET session
checks exact canonical response against its immutable action/context and original
expiry. A file attacker can manufacture matching synthetic responses; none can
authorize production. No browser hash or client claim is used as trusted proof.

Browser file selection invalidates pending reads on cancellation, empty selection, newer selection, or response export. Late superseded reads cannot republish a preview; malformed replacement data retains the active valid review.
UI uses textContent for request-controlled content. No third-party assets or remote
libraries. CSP disallows connections, objects and form submission. Local file dialogs
use bounded strict UTF-8 I/O, reject UNC/reparse paths, and require Windows to classify the drive root as Fixed (mapped Network, unknown, unavailable and unsupported volume types fail closed). Exports use create-new and never overwrite existing files. Filesystem checks cannot prove physical locality: synced folders, virtualized fixed drives, mount behavior and same-user filesystem races between checks and open remain residual risks. No paths are trusted as a production boundary.
Filesystem race resistance against same-user attackers is not a trusted boundary.

Golden vectors in `experiments/browser-preview/fixtures` derive from the existing
Node prepared fixture with instance `golden-browser-v1` and generation 7. Browser,
Node encoder and .NET builder must produce identical canonical response bytes.
The executable round trip uses the live .NET instance and all four outcomes.

## Verification and adversarial coverage

Run full fail-fast checks in a disposable exact-baseline patched checkout:

```powershell
pwsh -File experiments/browser-preview/Verify-Workflow.ps1
```

The script builds all four projects, runs Mock (including executable interop), Fake
Lab, Offline Assurance, policy validation, standard Node TAP tests and two independently
created/audited synthetic content candidates with byte/hash comparison. If sandbox
subprocess execution is blocked, the separately labeled supplemental command is:

```powershell
pwsh -File experiments/browser-preview/Verify-Workflow.ps1 -SupplementalNode
```

This is not standard Node CI equivalence. Windows reproduction of the blocked command:

```powershell
node --test --test-reporter=tap
```

New tests cover valid B/C outcomes, explicit failure recovery, unknown abandonment,
both switching orders, nested expiry, clock rollback, canonical immutability,
concurrent switch/response and duplicate response races, mismatched request/device/
instance, stale generation after switching back, malformed/oversized/invalid UTF-8,
strict canonical equality, default-policy independence and DEFAULT_DENY. Existing
Phase 4–6 and production Broker regressions remain unchanged.

## Manual UX acceptance (pending observation)

On Windows at 100%, 150% and 200% DPI, check each method at minimum window size,
long Unicode tasks, text wrapping, scroll reachability and terminal controls. Use
keyboard only: Tab/Shift+Tab, access keys, Enter, Escape, file dialogs, picker focus
return and browser download focus. Verify Narrator announces method, warnings,
status, read-only action and control names without countdown chatter. Check Windows
contrast themes and browser forced colors, visible focus, disabled states, readable
errors and zoom to 200%. Verify browser file import/download on Edge/Chrome and a
second ordinary browser. Confirm no network requests. Automated checks cover markup,
contracts and view-model states; they do not establish rendered UI/DPI/Narrator or
high-contrast acceptance. No browser/WPF automation tool was available in this session.

## Security decisions and future policy

Real trusted consent, requester authentication, protected UI, component installation,
Windows Hello, authenticated IPC, remote enrollment/networking, durable trusted
consumption, production proof issuance and deployment remain **NO-GO** under the
Phase 5–6 decision register. No production authorization type accepts these objects.

There is exactly one active method. Future broadcasting would require a separately
approved policy defining quorum, conflicting outcomes, identity/assurance minimums,
per-method challenges, atomic consumption and timeout/revocation behavior. It is not
implemented. Current switching invalidates all prior method responses.
