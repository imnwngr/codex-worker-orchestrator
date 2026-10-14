# Phase 3C.4J synthetic-only readiness

## Current decision

The package is an **experimental synthetic-only baseline**. The manifest at
[`experimental-readiness.json`](experimental-readiness.json) is static policy,
not a runtime report. Local build and test outcomes belong in the delivery
record for the exact patch; this file does not claim that those checks have
run. Read-only host capability is **not observed by this package summary**.
Real credential operations and production authorization are **NO-GO**.

Historical evidence remains in [3C.4G/4H/4I records](README.md#historical-readiness).
Those records describe their own runs and must not be read as current host
observations.

## Architecture and dependency map

```text
USER (sole final authority)
  -> Codex (sole AI coordinator; evaluates external advice)
      -> Broker (deterministic request validation, authorization boundary,
         provider registry and dispatch; batch dispatch default-deny)
      -> external AI providers (advisory output only)

Broker -> broker/providers/webauthn-approval.js
       -> broker/providers/approval-core.js (offline verifier)
       -> experiments/webauthn-contract-lab (contract tests only)

ApprovalAgent.Mock (WPF presentation + mock proposal source)
  -> WebAuthnCapabilityDiagnostics
     -> system-directory webauthn.dll, two read-only exports only
  X-> no Broker, grant minting, or credential ceremony API

WebAuthn.WindowsLab (standalone .NET console)
  -> LabWorkflow -> IFakeNativeWebAuthn -> FakeNativeWebAuthn
  -> FakeAssertionGate -> RecoveryJournal -> SyntheticJournalStore
  -> SyntheticInventory; no production verifier, WPF, Broker, IPC,
     network, native imports, or persistent storage
```

### Ownership and contract locations

| Concern | Owner and boundary |
|---|---|
| Production dispatch and default-deny authorization | Broker route/provider path; inspect `broker/README.md` and authorization tests. This batch makes no Broker/verifier edits. |
| Offline signature verification | `broker/providers/approval-core.js`; invoked through the production approval provider contract. A valid signature alone does not encode independent USER approval or application identity. |
| Mock UI proposal state | `ApprovalAgent.Mock` view model and `MockProposalSource`; display state is mock-only and creates no production grant. |
| Host diagnostics | `WindowsWebAuthnCapabilityDiagnosticService` and `WindowsWebAuthnNativeApi`; dynamically loads only the system-directory DLL and resolves the version and platform authenticator availability queries. No ceremonies are exposed. |
| Fake native boundary and buffer ownership | `IFakeNativeWebAuthn` and `FakeNativeWebAuthn`; deterministic in-memory fixture behavior only. |
| Credential lifecycle and state | `LabWorkflow`; fake credential is held in memory, revoked before cleanup, and ambiguity requires reconciliation. |
| Journal and replay state | `RecoveryJournal` owns transitions/revisions and delegates commit/replay storage to the shared `SyntheticJournalStore`. This is an atomic in-memory simulation, not persistence. |
| Inventory identity | `SyntheticInventory` bounds, canonicalizes, deduplicates and exact-count checks snapshots; workflow applies operation-specific baseline/target rules. |
| Trust evidence and readiness | `TrustBoundary.cs`; fixture-source evidence can satisfy synthetic checks only. Readiness is an informational report with blocked/unobserved statuses. |
| Serialization | Manifest is static JSON policy; readiness/cleanup evidence is structured synthetic output. No private key or signature material is serialized. |

## Security invariant matrix

Assurance levels: **tested synthetic** means deterministic local fake tests; **source-isolated** means reviewed project/API boundary; **unverified** means no real OS/device/production experiment establishes it.

| ID | Invariant / threat addressed | Enforcement | Relevant tests | Assurance / limit |
|---|---|---|---|---|
| AUTH-1 | Mock approval and synthetic trust cannot authorize dispatch | Mock-only proposal/view model; separate projects; Broker has independent default-deny authorization | Mock tests; Broker authorization regression suite; lab `TrustBoundary*` and `ReadinessIsInformational` | Source-isolated + tested synthetic; no live dispatch |
| AUTH-2 | Signature validity is not independent USER approval | Offline verifier contract remains separate from approval authority | `experiments/webauthn-contract-lab`; Broker approval tests | Contract-tested; user approval pathway remains unimplemented/default-deny |
| ID-1 | UV/capability and caller metadata do not establish app identity | Diagnostics report capability only; synthetic evaluator classifies metadata as unverified | `TrustBoundaryRejectsMetadata`, `TrustBoundaryContradictions`, Mock diagnostic tests | Synthetic/source review; real executable identity unverified |
| LIFE-1 | Revocation precedes cleanup and stale results cannot restore trust | `LabWorkflow.RevokeAndCleanFakeAsync` clears pinned credential before deletion; cleanup transitions do not repin | `CleanupFailure`, `CleanupCancellationUnknown`, `ConcurrentCleanupReconciliation` | Tested synthetic; no real credentials |
| LIFE-2 | Unknown enrollment/deletion is never treated as success | Workflow stays unknown until inventory reconciliation; unknown cleanup cannot retry blindly | `UnknownEnrollment`, `CleanupOutcomeUnknown`, `CleanupUnknownStillPresent`, `OrphanCleanupUnknown` | Tested synthetic; inventory is fake |
| INV-1 | Credential IDs are canonical, bounded and exact; aliases/collisions do not target deletion | `SyntheticInventory.IsCanonicalCredentialId`, exact inventory validation, operation-bound orphan provenance | `RegistrationIdCollision`, `MalformedOrphanIdCannotBeDeleted`, `UnboundValidOrphanIdCannotBeDeleted`, duplicate/oversize tests | Tested synthetic; does not validate OS identity |
| INV-2 | Baseline loss/additions or unexpected IDs cannot resolve ambiguity or authorize deletion | Exact baseline equality for enrollment; baseline-plus-exact-target for cleanup | `EnrollmentBaselineLossRemainsUnknown`, `DisappearingCollisionRemainsUnknown`, `CleanupRejectsUnexpectedInventoryIdentity` | Tested synthetic |
| JOURNAL-1 | Invalid transitions, fabricated snapshots and revision rollback fail closed | `RecoveryJournal.CanBegin/CanRecord`; store independently validates transitions, sequence, genesis and expected revision | `JournalTransitionMatrix`, `StoreContinuationIsValidated`, `StoreRestoreRequiresValidGenesis`, `StoreRejectsCorruption` | Tested memory simulation; no tamper resistance/durability |
| REPLAY-1 | Lost replay continuity blocks additional consumption | Shared store atomically consumes challenge/nonce; replaced ledger disables consumption | `ConcurrentFakeConsumption`, `ReplayAcrossGates`, `StoreReplacedLedgerBlocksConsumption`, `ReplayWithFreshJournal` | Tested in-process only; restart continuity unverified |
| EVID-1 | Evidence distinguishes observed, simulated and assumed; cleanup cannot imply global deletion | typed fixture source labels and cleanup evidence scope; manifest labels host observation unobserved | `TrustBoundaryPositiveControl`, `TrustBoundaryRejectsMetadata`, `ReadinessIsInformational`; manifest regression | Tested synthetic; no global authenticator inventory |
| DIAG-1 | Readiness and read-only diagnostics never perform credential operations | Diagnostic API only resolves two read-only exports; readiness evaluator has no authorization dependency | Approval Agent diagnostics tests and readiness test | Source-isolated + tests; runtime diagnostic not observed in this package |
| SER-1 | Evidence serialization contains no private material | evidence records contain status, IDs/labels and public-key fingerprint only; fake assertion has no signature | `FakeOwnership`, trust/readiness serialization tests | Source review + tests; no secret-bearing artifacts are produced |

## Evidence categories

- **Tested synthetic behavior:** established only by the actual verification commands recorded with the delivered patch. Fakes use in-memory data and do not sign assertions.
- **Observed read-only host capability:** none in this static package. A user-run diagnostic may report a timestamped machine result, but this manifest does not assert one.
- **Windows SDK requirement:** ABI snapshots and version thresholds are source/header-derived and x64-specific; SDK headers do not prove runtime export availability or supported behavior.
- **Unverified:** live enrollment/assertion/listing/deletion; app identity; independent user approval; actual OS restart replay persistence; synced passkeys; external authenticators; platform inventory completeness; attestation and cleanup guarantees.

## GO / NO-GO matrix

| Capability | Decision | Evidence required / reason |
|---|---|---|
| Synthetic regression integration | CONDITIONAL GO after all required CI jobs pass | Local/CI test report for exact patch; fake-only |
| Read-only runtime diagnostics | NOT OBSERVED | Must be run separately; results are informational |
| WPF mock demonstration | NOT OBSERVED (GUI) | CI builds WPF and tests the mock/binding contract; it does not launch the GUI. A separate Windows demonstration is required. |
| Real credential enrollment | NO-GO | Explicit separate authorization and dedicated safety/recovery review required |
| Real credential assertion | NO-GO | No live ceremony or proof of application identity/user approval |
| Real credential enumeration | NO-GO | No listing API in approved scope; host inventory completeness unverified |
| Real credential deletion | NO-GO | No deletion API in approved scope; scope and recovery unverified |
| Application identity | NO-GO / UNVERIFIED | UV, origin strings, and caller metadata do not prove trusted executable identity |
| Replay across actual OS restarts | NO-GO / UNVERIFIED | Current store is in-memory only |
| Synced passkeys / external authenticators | NO-GO / UNVERIFIED | Not modeled by fake platform inventory |
| Production authorization | NO-GO; DEFAULT-DENY | No authorization path is created by this experimental package |

## CI and reproducibility

The existing workflow retains five effective categories: Windows Node 22, Windows
Node 24, Ubuntu Node 22, Ubuntu Node 24, and Windows .NET 8. The .NET job builds
the WPF mock, runs Mock tests, builds the fake lab, and runs Lab tests. The
manifest test parses the checked-in JSON copied to test output and asserts its
schema version, prohibited capabilities, default-deny policy, and all five CI
categories. No new package dependency or hardware/GUI automation is required.

Historical records: [3C.4G](BATCH_3C_4G_DEF_READINESS.md), [3C.4H](BATCH_3C_4H_READINESS.md), and [3C.4I](BATCH_3C_4I_ASSURANCE.md).
