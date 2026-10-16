# Phase 4E-4H integrated offline hybrid review

## Scope and authority

Baseline: `881bd3f580af47aa44dae3a6ba975461f80bcdd3` (Phase 4D).
USER remains the final authority. Workers are advisory and the production Broker
is unchanged. Every simulation and review result is `authorized:false` with
`DEFAULT_DENY`. No output is a consent proof, grant, credential or authenticated
identity. Production activation is NO-GO pending separate USER approval and a
reviewed trust design. No live provider, network, service, IPC or credential
operation was added. Existing five CI jobs are unchanged.

## Architecture and implemented behavior

Phase 4D's prepared immutable context, digest, policy and absolute deadline
remain authoritative. `OfflineReviewViewModel` and Node `HybridCoordinator`
attach a single bounded in-process `HybridSimulation` to the current generation.
There is no second request preparation, transport, response store or approval
pipeline. A simulation has one current state and one binding; no unbounded
history, sessions or fixture collection is retained.

Binding includes request ID, session ID, context SHA-256, method ID, generation
and a per-review-model/coordinator instance ID. Instance IDs are non-secret
isolation markers, never authentication. Node correlation objects reject extra
fields. .NET uses a typed immutable binding. The script's fake component/device
ID must match the code-owned current fixture; it never establishes actual
component, origin, endpoint or device identity. Unknown actions and unexpected
transitions return false without advancing state. Exceptions and time anomalies
cannot manufacture success. A clock rollback, including within the nominal
lifetime, expires the pending review. The original expiry is never renewed.

Successful explicit loading publishes a fully validated immutable snapshot.
Malformed replacement retains the previous snapshot, generation, method and
script state with a sanitized error. Existing validator limits, digest checks,
UTF-8/duplicate-field checks and preference handling remain in force. Defaults
apply to future explicit loads/begins only. A disallowed preference remains
visibly disallowed without fallback. Invalid selection leaves the current method
intact. Cancellation is possible even when the current method is policy-denied.

Switching A -> B -> C -> A drops the old script state and increments the existing
generation. Selecting the same method preserves state and generation; it is
not a retry. A stale picker, response, previous load or different instance cannot
advance the current script. Terminal canonical decisions cannot reopen the
request. An explicit new file load/begin remains the Phase 4D way to create a
new synthetic review; it cannot confer durable replay protection or real consent.

## Shared lifecycle semantics

| Current script state | Event | Next script state | Canonical review effect |
|---|---|---|---|
| Unavailable | Any | Denied | None; explicit method change/new review needed |
| ReadyForSimulation | UNAVAILABLE | Unavailable | None; fixture prerequisite failure only |
| ReadyForSimulation | START | Pending | Remains pending |
| Pending, Method C | DELIVER | AwaitingResponse | Remains pending; no delivery occurs |
| Pending, Method B | COMPLETE | SimulatedComplete | ApprovedMock, never authorized |
| AwaitingResponse | COMPLETE | SimulatedComplete | ApprovedMock, never authorized |
| Pending / AwaitingResponse | REJECT | Rejected | Rejected |
| Ready / Pending / AwaitingResponse / Unknown | CANCEL / REVOKE | Cancelled | Cancelled |
| Pending / AwaitingResponse | FAIL | Failed | Pending, script blocked |
| AwaitingResponse | UNKNOWN | Unknown | Pending, script blocked |
| Unknown | RECOVER | Cancelled | Local abandonment, never retry or inferred success |
| Any pending canonical review | Deadline or invalid clock | Expired | Expired |
| Any pending canonical review | Switch to different method | Fresh ready/unavailable | Original context/expiry retained |

REVOKE clears non-secret in-memory registration metadata. There is no enrollment
or durable revocation claim. All fixture claims explicitly read UNVERIFIED or
FAKE. `https://simulation.invalid` is a display-only placeholder, never contacted.
Failed/unavailable scripts recover by explicit switch away and back, or cancel.
Unknown outcomes recover by abandonment. Late and duplicate responses are
denied; no retry extends expiry. Terminal cleanup invalidates the script binding
and clears registration while retaining the final display state.

Existing direct Approve Mock / Reject / Cancel controls remain an independent
explicit local mock decision on the same canonical review. They are not evidence
that the B/C script completed or established trust. They may terminate a pending
script, always with DEFAULT_DENY. No synthetic-to-production promotion exists.

## Method A trust-boundary decision record

Status: offline review usable; production consent channel NO-GO.

| Decision area | Current evidence / boundary | USER decision required before production |
|---|---|---|
| Principals | USER, requester, local UI, Broker, worker and OS are distinct roles | Define whose consent authorizes which action and delegation limits |
| Requester identity | File IDs and digests establish consistency only | Authenticate requester and bind it to allowed action and destination |
| Application/UI ownership | Local WPF process displaying untrusted file data | Define trusted publisher, install root, executable integrity and UI ownership |
| Deployment | No protected deployment assumptions established | Choose supported deployment, update authority, rollback and recovery model |
| Same-user threat | Same-user process may replace files/preferences or spoof UI | Decide whether same-user compromise is inside the protection goal |
| Administrator threat | No defense against administrator compromise claimed | Define administrator/OS trust assumptions and residual risks |
| Consent provenance | Mock events remain only in memory; no consent receipt | Define authenticated interaction, action binding, freshness and audit provenance |
| Authorization prerequisites | No method has trusted identity or transport | Review proof verification, durable consumption, expiry and deterministic Broker gate |

Do not infer the USER accepted a trusted desktop, benign same-user processes,
a trusted administrator, or an authenticated requester. None is settled here.
Preferences are untrusted UX configuration independent of code-owned policy.

## Method B security readiness checklist

All items below are design requirements, not established capabilities. Production
component work is NO-GO pending separate USER approval.

- Installation: trusted publisher, package integrity, immutable endpoint ownership,
  install/repair/uninstall permissions, ownership verification and rollback policy.
- Signed updates: signer rotation, revocation, anti-rollback, interrupted updates
  and consistency between component and UI versions.
- Privilege separation: least privilege, requester isolation, service account,
  OS/admin threat scope and minimal exposed operations.
- Authenticated IPC: peer identity, endpoint squatting resistance, channel binding,
  strict bounded messages, replay resistance and exact context/generation binding.
- Protected UI ownership: trusted display/input provenance, anti-spoofing limits,
  desktop/session identity, consent visibility and accessibility.
- Recovery/lifecycle: crash, cancellation/success race, unknown outcomes, durable
  consumption, expiry, uninstall, update failures, diagnostics and revocation.

The current fake ID check establishes only fixture consistency. No actual
installation, signature, protected UI, endpoint trust or IPC exists.

## Method C trust design and decision register

| Topic | Offline behavior | Unresolved production decision / NO-GO prerequisite |
|---|---|---|
| Enrollment | One code-owned fake-device fixture | Authenticate enrollment and account ownership, explicit USER consent |
| Revocation | Clears ephemeral fake registration and cancels | Durable revocation propagation, lost-device and offline policies |
| Custody | No keys or secrets | Device key custody, export/backup, compromise and recovery policy |
| Browser origins | UNVERIFIED simulation.invalid label | Exact origin policy, phishing resistance and browser/UI trust boundaries |
| Transport | No network; DELIVER is an in-process event | Authenticated encrypted transport and both endpoint identities |
| Cross-device replay | Request/session/context/generation/instance checks in memory | Cryptographic binding, domain separation, challenge scope and freshness |
| Consumption | One terminal local mock state | Durable atomic one-use consumption across restarts and concurrent Brokers |
| Unknown outcome | Explicit local abandonment | Reconciliation authority, timeout, lost response and revocation races |

No fixture is an authenticated device. Local instance IDs are not cross-device
anti-replay protection. Production enrollment, pairing, QR authentication,
accounts, push delivery, remote issuance and credentials remain NO-GO.

## UX and manual Windows acceptance

Incremental Hallmark layout retains method picker, Settings, action preview,
minimum sizing, scrolling, wrapping and access keys. Script state and unverified
claims are visible with distinct canonical status feedback. Failed operations
produce sanitized denial feedback. Initial keyboard focus returns to file
selection after onboarding. Explicit abandonment is available for policy-denied
pending reviews. High-contrast mode at window creation uses native system colors
and controls; a running-window theme change is not implemented or claimed.

Manual acceptance remains pending. On Windows:

1. Launch the WPF mock and open Offline Review. Cancel onboarding, then use only
   Tab/Shift+Tab, access keys and Enter/Space to select a fixture and operate it.
2. Check focus visibility/order, picker cancellation, Settings, optional unchecked
   future-default choice, and preference write failure feedback.
3. Review long tasks, Unicode, wire JSON, hashes and all labels at minimum size,
   maximized size and 100/150/200% DPI; verify wrapping and scroll access.
4. Exercise A/B/C/A, start/deliver/complete, unknown/recover, terminal duplicates,
   failed replacement, cancellation and deadline expiry while a picker is open.
5. Open under Windows high contrast and inspect text, focus, hover, disabled
   controls and button sizes. Reopen after changing theme. Check Narrator names,
   read-only text access, status announcements and complete action readability.
6. Confirm no screen implies trusted identity, actual delivery or authorization.

No visual, DPI, Narrator or high-contrast manual acceptance is claimed.

## Verification and reproduction

New Node and .NET tests cover positive B/C completion and negative prerequisite,
identity, binding, ordering, duplication, generation, method-switch, unknown,
failure, cancellation, revocation, expiry and rollback controls. Existing
assertions remain unchanged. .NET launches `hybrid-vector-cli.js` and compares
actual Node transitions, decisions, digest, expiry and DEFAULT_DENY against the
.NET implementation. Existing actual Node file export validation also remains.
The vector CLI writes only deterministic synthetic JSON to stdout.

Run from a disposable checkout with the integrated patch:

```powershell
node --test --test-reporter=tap
dotnet build approval-agent/ApprovalAgent.Mock -c Release
dotnet build approval-agent/ApprovalAgent.MockTests -c Release
dotnet build experiments/webauthn-windows-lab -c Release
dotnet build experiments/webauthn-offline-assurance -c Release
dotnet run --no-build --no-restore -c Release --project approval-agent/ApprovalAgent.MockTests
dotnet run --no-build --no-restore -c Release --project experiments/webauthn-windows-lab
dotnet run --no-build --no-restore -c Release --project experiments/webauthn-offline-assurance -- --self-test experiments/webauthn-windows-lab/experimental-readiness.json experiments/webauthn-offline-assurance/invariant-registry.json experiments/webauthn-offline-assurance/fixtures .
$baseline='881bd3f580af47aa44dae3a6ba975461f80bcdd3'
$candidate=Join-Path $env:TEMP ('hybrid-candidate-'+[guid]::NewGuid().ToString('N'))
dotnet run --no-build --no-restore -c Release --project experiments/webauthn-offline-assurance -- --candidate-create . $baseline $candidate
dotnet run --no-build --no-restore -c Release --project experiments/webauthn-offline-assurance -- --candidate-audit . $baseline $candidate
```

If the standard Node runner reports spawn EPERM in the sandbox, record it as
blocked. Direct execution of each test file with `node --test-reporter=tap FILE`
is supplemental evidence only, not equivalence to standard isolated Node CI.
Do not disable test isolation or elevate. The delivery report records actual
counts, builds, patch hashes and independent apply/reverse/reapply evidence.
Synthetic candidate reproduction describes its existing policy/content members,
not a signed build or proof that the integrated patch passed remote CI.

## Independent review remediation (v2)

Terminal `OfflineReviewViewModel.Simulate` now returns the bool from the canonical
`Decide` using the validated event binding. If the first clock check is just
before expiry and the second reaches the original deadline, acceptance is false,
canonical state and script state are Expired, and registration/binding are cleared.
The immutable context, generation, method and absolute deadline remain unchanged.
Node rejects expiry reached during its own second or nested decision/capture
checks; no expired decision is reported accepted. Actual Node/.NET vectors now
include the between-check expiry boundary for B and C.

Generation-exhaustion switching in both implementations cancels the canonical
review and ends the simulation, clearing registration and its active binding.
The .NET regression uses test-only reflection to reach long.MaxValue, with no
production mutation seam. Node's private-counter exhaustion branch is source
reviewed; no claim is made of executing quadrillions of increments.

Before correction, the two new .NET regressions failed against v1 (87/89 passed),
and the new Node nested-clock regression failed (21/22 passed in that file).
After correction, positive completion controls remain retained alongside the new
negative boundary controls. Production authorization remains DEFAULT_DENY.
