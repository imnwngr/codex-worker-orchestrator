# Phase 5A–6D: Offline trust foundation

Baseline: 5ce1b3b9e5f84cadbf8d1fe7f7eb9197b5fbffc2. This is an offline, in-process and non-authorizing implementation. The USER remains final authority. Workers and the Codex coordinator are advisory. The production Broker independently enforces policy and is unchanged. Every new synthetic result has authorized:false and productionAuthorization:DEFAULT_DENY. Live trust and production activation: **NO-GO**.

## 5A: Principals, trust boundaries and evidence

Distinct principals: USER; unverified requester; coordinator; untrusted subordinate workers; WPF review process; hypothetical protected Windows component; hypothetical remote account/browser/device; OS user and administrator; deterministic production Broker. The user's trusted requester identity, trusted UI provenance, same-user attacker scope and administrator scope are **unresolved**.

Repository evidence: experiments/integration-contracts/prepare-request.js prepares immutable action/context digests and absolute expiry. hybrid-review.js and hybrid-simulation.js own Node method selection and synthetic lifecycle. ApprovalAgent.Mock/Services/ReviewJson.cs and OfflineReviewValidator.cs validate canonical local review files; OfflineReviewViewModel.cs owns the .NET canonical review and terminal decisions. HybridMethods.cs owns independent method policy. broker/ owns the production boundary. New OfflineTrustProtocol.cs and offline-trust.js reuse these contracts. Structural integrity and matching hashes do not establish who originated a request or who consented.

Threat matrix. All real trust activation entries remain NO-GO. "Offline checked" refers only to the automated fixture safeguards.

| ID | Prerequisite | Boundary | Exploit hypothesis | Impact | Required mitigation | Verification | Residual risk | Gate |
|---|---|---|---|---|---|---|---|---|
| T01 | Malicious worker/coordinator | Request to Broker | Forge authority or alter action | Unauthorized execution | Broker policy and authenticated requester/action proof | Existing Broker tests and source-diff gate | No trusted requester | NO-GO live |
| T02 | Compromised requester | Request to local review | Spoof session/app | Misleading consent | Identity and exact action binding | Canonical digest and mismatch tests | Requester unauthenticated | NO-GO live |
| T03 | Same-user attacker | File/UI | Replace review/preferences or spoof WPF | Fraudulent approval | Trusted UI ownership and signed installation | Existing malformed/replacement tests | Same-user defense unproven | NO-GO live |
| T04 | Malicious administrator | OS to component | Hijack protected consent | Host takeover | Explicit OS/admin trust policy | Scope decision record | No admin-resistant channel | NO-GO live |
| T05 | Compromised UI | Display to result | Show different action | Incorrect consent | Protected display/input attestation | Existing display/hash tests | WPF process untrusted | NO-GO live |
| T06 | Malicious preference | Preference to policy | Force disallowed method | Policy bypass | Code-owned policy, no fallback | Existing hybrid policy tests | UI can be confused | Offline checked |
| T07 | Malformed review JSON | File to context | Duplicate fields, digest spoof | Wrong request | Strict bounded canonical parser | Existing validator tests | File owner unknown | Offline checked |
| T08 | Fake protected peer | Message to session | Claim authenticated component | Trust forgery | Real mutual endpoint authentication | Fake role/status rejection | No real IPC | NO-GO live |
| T09 | Message replay attacker | Response to lifecycle | Delayed/duplicate grant | Reused consent | Challenge, expiry, durable one-use proof | Duplicate/concurrent cases | Consumption only in memory | NO-GO live |
| T10 | Competing method response | Hybrid switch | Reuse old generation | Cross-method grant | Exact method/generation/instance binding | Switch and cross-instance tests | No distributed replay store | Offline checked |
| T11 | Clock manipulation | Clock to decision | Rollback or late accept | Expired consent | Monotonic clock, final canonical recheck | Nested expiry/rollback tests | Trusted clock undecided | NO-GO live |
| T12 | Crash and restart | Session to recovery | Unknown result replay | Duplicate approval | Durable atomic consumption and recovery | Fake crash/unknown recovery | No persistence | NO-GO live |
| T13 | Device lost/compromised | Enrollment to remote | Revoked device responds | Forged remote consent | Trusted enrollment, revocation and custody | Fake revoke/offline tests | No enrolled devices | NO-GO live |
| T14 | Origin/network attacker | Browser to remote | MITM, origin confusion, downgrade | Remote forgery | Pinned origins, authenticated transport, replay defense | Fake origin/version/role tests | No browser/network channel | NO-GO live |
| T15 | Privileged provider caller | Broker to provider | Bypass authorization | Host access | Deterministic Broker verification and privilege isolation | Existing regression, unchanged Broker | Deployment model undecided | NO-GO live |

## 5B and 6A: Local trust design and offline consent contract

Method A is existing offline WPF review, not an authenticated production consent channel. Current canonical authority is an immutable prepared request, original expiration, immutable context and batch SHA-256, session ID, method generation and per-instance token. Direct mock approval is local-only. A future trusted requester identity, trusted local application binary, approver identity, session/desktop ownership, consent provenance, authenticated proof verifier and replay store must all be separately specified and approved.

The new version-1 canonical message contains exact fields: version; kind; methodId; requestId; sessionId; contextSha256; batchSha256; instanceId; generation; expiresAt; challenge; nonce; requesterClaim; actorClaim; accountClaim; deviceClaim; originClaim; peerRole; trustStatus; outcome; consentStatement; endpointTrust; channelTrust; authorized; productionAuthorization. Supported message kinds: HELLO, REGISTRATION, REVOCATION, CONSENT_REQUEST and CONSENT_RESPONSE. Outcomes are NONE for non-responses and GRANT, DENY, CANCEL or UNKNOWN for responses. Fake peers are FAKE_LOCAL_UI, FAKE_PROTECTED_COMPONENT and FAKE_REMOTE_DEVICE only.

The consent statement is exactly: SIMULATION ONLY: action context {contextSha256} expires at {expiresAt}; no production authorization. The endpointTrust is UNESTABLISHED, channelTrust is FAKE_IN_PROCESS and trustStatus is UNVERIFIED_SIMULATION_ONLY. No fixture can claim an authenticated identity. Grant means ApprovedMock, never production permission. Request preparation remains in the Phase 4 canonical implementation.

Envelope input is limited to 4096 UTF-8 bytes. Strict cross-runtime canonical JSON rejects duplicate, extra, missing or noncanonical fields; invalid Unicode, unsafe integer, malformed digest/ID, mismatched role or origin, changed consent text, spoofed trust and unsupported version. Challenge and nonce are fixture markers, never secrets or proofs. Offline verification establishes structural consistency only.

## 5B and 6B: Protected Windows design and simulation

Production readiness requires signed install and update authority, rollback resistance, component identity, least-privilege isolation, endpoint ownership, mutual authenticated IPC with channel binding, protected UI and input provenance, OS session model, crash/restart/reconnect recovery, trusted clock, audit/privacy policy and durable proof consumption. NO-GO on all real components and endpoints.

Offline HELLO negotiates version 1 with a fake protected-component role. Only a valid current method and generation can transition to negotiated and then pending. Role spoofing, downgrade, malformed request, unexpected state, duplicate response and expiry are refused. OfflineTrustFakeTransport implements a deterministic bounded in-process queue of four valid synthetic response frames. Disconnect blocks send/delivery; reconnect does not renew expiry or create identity evidence. All delivery goes through the canonical session and original deadline.

## 5C and 6C: Remote/browser design and simulation

USER decisions required before production: account and device principal authority, enrollment, credential custody/rotation, device loss/revocation propagation, origin allowlist and browser-session binding, authenticated transport, device/request correlation, cross-device replay domain, intermittent connectivity and pending/unknown outcome reconciliation, durable exactly-once consumption, audit privacy/retention and clock provenance.

Offline registration and revocation are fake non-secret metadata on a single in-memory session. Origin is labeled UNVERIFIED: https://simulation.invalid and never contacted. An in-process fake channel models offline delivery and duplicate/delayed frames; a revoked or unknown session requires explicit local abandonment. Remote identity is never authenticated. No browser pairing, network, enrollment, push, credential issuance or trusted proof exists.

## 5D and 6D: Assurance, state and recovery

Only existing Phase 4 request preparation, selected-method policy, canonical decision, immutable digest, instance/generation and original expiry govern the new session. Valid synthetic positive responses progress to ApprovedMock; negatives to Rejected/Cancelled; UNKNOWN and crash require explicit local cancellation/abandonment. Canonical expiration between session verification and final decision causes failure and Expired. A monotonic rollback rejects the session. A response consumed once cannot be replayed. All .NET session transitions share a session lock, including receipt, crash, revocation and recovery; synchronous Node receipts use the same single-consumption rule. This is not a durable or distributed atomic-consumption implementation.

Threat-to-test traceability:
- T01/T15: existing Broker DEFAULT_DENY regression and production diff checks.
- T02/T05/T07: existing canonical review digest, immutable display, duplicate-JSON tests.
- T03/T06: existing preference, replacement and code-owned policy regressions.
- T04: explicit NO-GO architecture gate; no administrator assurance claim.
- T08/T14: fake endpoint, identity/role, origin, version and consent rejection tests.
- T09/T10/T11: duplicate, cross-instance, method switch, clock/expiry and concurrent receipt tests.
- T12: unknown/crash recovery and one-shot fake delivery tests.
- T13: fake registration/revocation and offline-device tests.

Actual interoperability test: .NET launches the Node vector generator, validates 12 Node canonical frames and outcomes (3 methods x 4 responses), checks immutability and rejection across independent instance IDs, and compares terminal synthetic state, expiry, digest and DEFAULT_DENY. It establishes synthetic protocol compatibility, not trust in a remote peer.

## USER decisions and explicit NO-GO gates

Real trusted authorization remains blocked pending separate USER approval and independent architecture review of requester authentication, authorized action classes, same-user and administrator attack assumptions, signed deployment/updates, protected UI and endpoint identity, authenticated local and remote channels, device custody/enrollment/revocation, trusted clock, durable atomic consumption, evidence audit/privacy and an independent deterministic Broker verifier. The production Broker must not interpret offline-trust/v1 as an accepted proof.

## Windows manual UX/accessibility checks (pending)

Launch the WPF mock, select a real local fixture and inspect full task/digest, method, simulated trust labels, terminal-state controls and long Unicode text at **100%, 150% and 200% DPI**, minimum and maximized sizes. Check text wrapping, scrolling and focus visibility with Tab, Shift+Tab, Enter, Space, Escape and access keys. Verify picker cancellation and focus return, Settings and future default, A-to-B-to-C-to-A switching, policy denial, expiry with picker open, mock grant/reject/cancel, unknown/recovery and duplicate response refusal. Use Narrator for control names, read-only task and terminal state. Inspect contrast themes and Windows high contrast before and after reopening the window; inspect disabled states, status announcement and legibility. Confirm no screen implies authenticated device, actual protected component or remote delivery.

No manual WPF DPI, screen-reader, focus or contrast acceptance has been performed. Offline tests cannot settle live UI ownership or identity. All real privileged, Windows Hello, IPC, remote, enrollment, production Broker and deployment features remain NO-GO.

## Phase 7–8 interactive preview extension

The WPF preview now exposes in-process component negotiation, synthetic outcomes,
crash/unknown abandonment, and Method C browser package export/response import.
Browser files are untrusted projections of the existing validated action. Their
response is the existing version-1 simulation contract; the active offline session
independently verifies exact canonical equality, instance, method, generation and
original deadline. This grants no new trust. No production gate in this document
has changed: real requester/UI provenance, protected endpoints, remote enrollment,
authenticated transport, durable consumption and production authorization remain
**NO-GO**. File possession is not approver authentication. Browser action display
can be spoofed by a file attacker; its exported outcome is only synthetic input.
