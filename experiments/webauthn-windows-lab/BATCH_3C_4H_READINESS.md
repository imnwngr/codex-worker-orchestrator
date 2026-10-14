# Phase 3C.4H synthetic trust and recovery readiness

## Evidence boundary

All identity, integrity, process, user, authenticator, RP/origin, credential,
presence, verification, and approval evidence in this phase is fixture data.
The evaluator keeps those evidence types separate. Caller supplied process
IDs, executable paths, certificate text, HTTPS-looking origins, usernames, and
authenticator responses do not establish trusted application identity. Even a
complete consistent fixture returns only `SATISFIED_FOR_SYNTHETIC_TEST`; it
cannot issue a production grant. A successful authenticator prompt or valid
signature cannot prove executable identity or independent USER approval.

Windows native capability reporting remains a distinct read-only observation.
An API version gate only states whether the reported version reaches a mapped
header threshold. Credential-operation exports, real operation behavior,
authenticator inventory, and cleanup remain unverified.

## Journal and cleanup limits

`SyntheticJournalStore` exercises schema, revision, transition, operation ID,
atomic-commit, rollback, and bounded-history rules using memory only. Crash and
torn-write behavior are deterministic simulations. Reconstructing a workflow
from a shared in-memory store simulates handoff; it is not crash-durable,
tamper-resistant, or production-grade replay storage. The fake store
independently rejects invalid continuations and imported terminal snapshots;
only its initial in-flight snapshot may bootstrap an empty store. A replaced
replay ledger loses prior consumption and explicitly loses continuity. Its
original store rejects further nonce consumption, while a new unrelated store
can accept old values; that is a demonstration of the remaining replay risk.

Cleanup evidence records the fixed test RP ID, exact synthetic credential ID,
operation ID, pre-cleanup state, revocation, response category, inventory
result, ambiguity, and synthetic-only outcome. Absence in one fake inventory
does not establish deletion from every authenticator or synchronized store.
Reconciliation is exact-ID only; broad RP matching is never a deletion target.

RP ID and origin are fixed to `lab.example.test` and
`https://approval.lab.example.test`. A native caller-controlled origin does
not authenticate the calling executable. Same-user malware can inspect or
replace user-writable binaries, spoof UI, and issue its own WebAuthn requests.

## Readiness

The evaluator reports synthetic test status as unverified until it receives
test-run evidence, and read-only runtime capability as not observed unless a
diagnostic actually ran. It does not infer current machine facts from a prior
observation. Real enrollment, assertion, deletion, and production authorization
remain blocked. See `BATCH_3C_4I_ASSURANCE.md` for the invariant audit and
current evidence categories. No status in the report converts into permission.

Statuses: `SYNTHETIC_TEST_READY`, `READ_ONLY_DIAGNOSTIC_READY`,
`REAL_CREDENTIAL_ENROLLMENT_BLOCKED`, `REAL_CREDENTIAL_ASSERTION_BLOCKED`,
`REAL_CREDENTIAL_DELETION_BLOCKED`, and
`PRODUCTION_AUTHORIZATION_BLOCKED`.

**Final decision: NO-GO for real credential operations and production
authorization.**
