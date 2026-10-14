# Phase 3C.4I security assurance

## Scope and result

Review and tests are limited to the fake WebAuthn experiment, read-only Mock
diagnostics, and existing regression workflow. The lab has no native
credential calls, WPF reference, Broker authorization dependency, provider
dispatch, or production grant path. Production batch authorization remains
default-deny.

## Invariant audit

| Invariant | Classification | Implementation and independent evidence |
|---|---|---|
| Revocation precedes cleanup and is not restored | Enforced and tested | `LabWorkflow.RevokeAndCleanFakeAsync` clears `Credential` before delete; `CleanupFailure`, `CleanupCancellationUnknown`, and `CleanupRejectsUnexpectedInventoryIdentity` assert trust stays revoked. |
| Unknown enrollment blocks unsafe reuse | Enforced and tested | `LabWorkflow.EnrollAsync` requires `Ready`; `UnknownEnrollmentIdRemainsUntrusted` verifies inventory delta cannot become a credential or authorize retry. |
| Unknown cleanup blocks retry | Enforced and tested | `RetryFakeCleanupAsync` accepts only reconciled pending state; `CleanupOutcomeUnknown`, `DuplicateCleanupInventory`, and `CleanupRejectsUnexpectedInventoryIdentity` cover response loss and ambiguous inventory. |
| Inventory is bounded, canonical, exact, and unambiguous | Enforced and tested | `SyntheticInventory.Validate` validates declared and enumerated counts; cleanup additionally checks recognized IDs. `LyingInventoryCountIsRejected`, `OversizedInventory`, duplicate, malformed, and unexpected-ID tests cover rejection. |
| Journal schema, transitions, and revisions fail closed | Enforced and tested | `RecoveryJournal` and `SyntheticJournalStore` validate schema, operation sequence, transition, and expected revision. `JournalTransitionMatrix`, `StoreRejectsCorruption`, and `StoreContinuationIsValidated` cover valid and forbidden cases. |
| Rollback and replay-ledger loss do not regain trust | Enforced in the simulation and tested | `Restore` restricts an empty store to a valid genesis entry; lost replay continuity disables consumption. `StoreRestoreRequiresValidGenesis`, `StoreReplacedLedgerBlocksConsumption`, and replay tests cover these limits. This is not tamper-resistant storage. |
| Challenge/nonce consumption is atomic within a shared store | Enforced and tested | `SyntheticJournalStore.TryConsume` locks both sets and rolls back a partial addition. `ConcurrentFakeConsumption` and `StoreReplayContinuity` cover contention and reconstruction. |
| Trust evidence is complete, linked, and fixture-only | Enforced and tested | `SyntheticTrustEvaluator` checks sources, completeness, process/user consistency, executable/integrity linkage, authenticator/credential linkage, and fixed RP/origin. Trust positive, missing, metadata, contradiction, and substitution tests cover the evaluator. It does not attest a real application. |
| Caller metadata cannot prove application identity | Enforced and tested | `CallerSuppliedMetadata` returns `UNVERIFIED`; trust tests reject plausible same-user process metadata. Paths, usernames, certificate text, and origin strings remain fixture data. |
| Cleanup evidence does not imply global deletion | Enforced and tested | `SyntheticCleanupEvidence.ClaimsEveryAuthenticatorStoreCleaned` remains false; cleanup tests assert the result is only absence from the test inventory. External authenticators and synced passkeys are outside scope. |
| Readiness cannot grant authorization | Enforced and tested | `ExperimentalReadinessEvaluator` emits unverified/not-observed and blocked statuses; it has no permission conversion. JSON readiness tests assert no optimistic ready state without evidence. |
| Experimental state cannot enable provider dispatch | Out of scope and architecture-separated | The lab project does not reference Broker, verifier, or provider dispatch; the existing Node authorization tests remain unchanged and pass. |

## Findings corrected

1. `IReadOnlyCollection.Count` was treated as a trustworthy bound. A dishonest
   count could hide extra inventory items. Validation now checks the declared
   count, independently stops enumeration at the fixed maximum, and rejects a
   count mismatch.
2. One newly appearing inventory ID was treated as the credential from an
   unknown registration. Inventory does not bind an identity to an operation.
   New IDs now keep enrollment unknown; they are never promoted to cleanup
   targets. Reconciliation requires exact equality with the baseline (including
   no missing pre-existing IDs). A returned malformed or colliding ID remains
   ambiguous even if its inventory entry later vanishes; it cannot be deleted.
3. Cleanup reconciliation ignored valid-looking unexpected IDs. It now accepts
   only baseline IDs and the exact expected synthetic target; any other ID
   leaves cleanup unknown until a valid snapshot arrives.
4. Readiness unconditionally claimed synthetic and read-only diagnostic
   readiness. It now reports test execution as unverified and current runtime
   capability as not observed. SDK header thresholds and the historical
   user-reported historical observations are not baked into static application
   output; no runtime version is hardcoded as current or universal.
5. Synthetic executable and binary-integrity labels, and authenticator and
   credential labels, were not linked. The evaluator now rejects mismatched
   subjects while still labeling all accepted evidence synthetic-only.

The bounded transition matrix explores every valid enum pair and every
operation/state/outcome record combination. Its small reference model is
independent of the journal implementation and reports the direct failing
transition, which is the shortest possible sequence for this matrix.

## Evidence categories and limitations

- **Synthetic behavior:** the deterministic fake suite result is established
  by the test runner output; the informational readiness evaluator does not
  infer that the suite ran.
- **Read-only Windows observation:** this run did not call the native
  capability diagnostic. Historical machine-specific observations are external
  evidence and are not embedded in the evaluator or independently verified here.
- **SDK requirements:** API v1 and v4 gates are documented header thresholds;
  they do not establish runtime exports or operation readiness.
- **Unverified:** real enrollment, assertion, inventory, deletion, authenticator
  behavior, application identity/integrity, independent USER approval,
  production-grade replay persistence, synced passkeys, and external
  authenticators.

The simulated store uses memory, bounded journal history, atomic locking, and
fault injection. It is not crash-durable or tamper-resistant. An unkeyed hash
would not authenticate a record and would not defeat same-user tampering; this
batch adds no evidence checksum or production trust anchor.

Real credential operations require a dedicated disposable environment and
separate explicit USER approval for enrollment, assertion, and deletion.
A valid signature, RP ID, origin, capability result, or Windows Hello prompt
does not establish application identity or USER authority.

**Decision: NO-GO for real credential operations and production
authorization.**

## Reviewed-patch safety corrections

- An unchanged or smaller inventory is not proof of recovery unless it exactly
  matches the entire pre-enrollment baseline; a missing baseline identity stays
  unknown.
- A returned malformed or colliding recovery identity permanently blocks this
  synthetic enrollment attempt, even if a later inventory omits that ID.
- The fake registration injector does not remove seeded credentials on failure
  when its overridden ID collides with an existing fake credential.
- The informational readiness evaluator does not embed any user's historical
  machine details into generic generated output.
- New tests: `EnrollmentBaselineLossRemainsUnknown`,
  `DisappearingCollisionRemainsUnknown`,
  `MalformedRecoveryIdentityRemainsUnknown`, and
  `CollisionInjectionPreservesExistingCredential`.

- An orphan recovery ID in a simulated lost-response exception needs
  operation-bound provenance issued by the deterministic fake adapter. A
  canonical but unbound injected ID is not a deletion target; the workflow
  remains unknown (`UnboundValidOrphanIdCannotBeDeleted`). This provenance
  flag is *not* an OS attestation or a production credential proof.

- Readiness JSON serializes explicit named status strings rather than opaque
  enum ordinals. The evaluator remains informational and non-authorizing.
