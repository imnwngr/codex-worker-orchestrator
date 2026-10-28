# 3C.4L synthetic candidate closure

## Decision and authority

Recommend closure of the synthetic hardening track when the accompanying local
verification and exact-baseline patch checks pass. GO covers synthetic integration
only. Real enrollment, assertion, enumeration, deletion, production authorization
and deployment remain hard NO-GO. No further synthetic batch is justified by the
current bounded analysis. A new demonstrated defect can reopen this decision.

USER is the sole final authority; Codex coordinates AI work; other AI output is
advisory. The production Broker remains deterministic and DEFAULT-DENY. Offline
Assurance observes policy and supplied evidence; it never issues authorization.
The Lab uses in-memory fake credentials. Mock approval records local mock state.
The existing Windows diagnostic surface remains read-only. None of these facts,
a successful signature, an executable path, a Hello prompt, a hash or a commit
string independently proves USER approval. Production source and the review UI
are outside this patch's changes.

## Twelve-phase disposition

| Phase | Result and reviewable implementation |
| --- | --- |
| A | Threat model and actual findings below; exact symbol and source references |
| B | Per-evidence source classification; local and CI reports remain unauthenticated |
| C | Strict schemas, digest/payload linkage, conflicting-group rejection, pinned trace policy; candidate binds revision, report, evidence and inventory |
| D | Existing manifest mutations retained; CI omission, enabled prohibition, contradictory readiness and nested permission cases added |
| E | Every mandatory invariant tested for deletion, duplication, corrupt status, wrong domain, missing tests and missing source; substitution and false enforcement cases |
| F | Bounded strict UTF-8 file reads; nesting, bytes, identifier, duplicate property, null/type/enum/digest/path failures |
| G | Independent restricted readiness oracle with accepting controls and rejecting mutations; deterministic result checks |
| H | Existing journal, state explorer and recovery tests reviewed and retained; no competing lifecycle or unsupported durability claim |
| I | Local allowlisted data/document directory; canonical JSON and normalized documentation bytes; no archive or executable |
| J | Four Node matrix executions plus one Windows .NET job; self-tests and local package audit retained/added |
| K | Read-only audit rejects tampering, extra/missing members, traversal, changed revision, and rehashed contradictory evidence/reports |
| L | This consolidated closure decision, verification procedure and limitations |

## Threat model and security findings

All manifest, registry, evidence, file paths, revision strings, candidate inventory,
candidate members and execution claims crossing the CLI are untrusted. An attacker
can fabricate successful summaries, choose matching hashes, substitute a checkout,
alter source references, supply obsolete or conflicting revisions, or promote
fixtures to claimed execution. The repository used as the audit comparison and
the verifier binary are caller-selected trust anchors, not independently verified
producers. A hostile machine controlling both can fabricate the entire result.

Baseline source references are relative to baseline
`c8026dd1766a5178616ee63864be5d035e542037`:

| Finding | Baseline source location | Disposition |
| --- | --- | --- |
| Invalid UTF-8 replaced during reads; input is not the exact supplied byte sequence | `Program.cs:51`, `ReadBounded` final file read | Corrected by `BoundedInput.Read/Decode`: bounded stream and throwing UTF-8 decoder; stable sanitized rejection |
| Any existing repository file could replace enforcement location; unrelated existing test could replace required reference | `Assurance.cs:218` and `Assurance.cs:221`, `TraceError` existence/test-name checks | Corrected by `TraceContract` explicit per-invariant paths/tests and domain checks; reference resolution still does not prove execution |
| Multiple internally valid summaries could contradict one another | `Assurance.cs:206`, `Evidence` final revision conflict check | Corrected by `EVIDENCE_RESULT_CONFLICT`; FAIL/UNKNOWN still prevent reported completeness |
| Local and CI reports lacked separate provenance labels | `Assurance.cs:185`, `Evidence` origin allowlist | Classification limitation corrected; new origins explicitly remain unverified |
| Self-consistent payload hashes and caller revision cannot authenticate a producer | `Assurance.cs:130`, `Report` provenance limitations | Existing limitation retained, not a cryptographic vulnerability; no authentication keys or independent evidence channel introduced |
| Text scans and named test references cannot prove absence of all forbidden behavior | `Assurance.cs:208`, `TraceError`; regex enumeration at line 221 | Explicit source-review limitation; actual regression execution is reported separately |

Final symbols and test names provide stable exact references even when line numbers
shift. `PhaseLSelfTests.Cases` contains the mutation and tampering corpus;
`SyntheticCandidate.Audit` performs member and regenerated-content comparisons.
The original 41 self-tests and assertions remain; the report golden fixture moves
to schema 2 to include per-item provenance without changing its fixture-only result.

## Evidence and lineage

Policy validation means the repository policy contract was parsed and checked.
`fixed-test-fixture` means synthetic fixture, never execution. `self-reported`,
`locally-reported` and `ci-reported-unverified` mean claims with unverified provenance.
`user-supplied-historical` means timestamped, unverified historical observation.
No input category can assert independently authenticated evidence: no genuine
producer authentication exists in this design. Unknown categories and schemas fail
closed. Report schema 2 is experimental; policy/registry/evidence schemas remain 1.

Payload digests bind canonical supplied payloads. Duplicate identifiers, multiple
source revisions, envelope/payload mismatches and conflicting results reject.
An expected revision mismatch yields incomplete evidence and a nonzero exit, never
regression completion. Invariant metadata is policy-pinned. The candidate inventory
links all member sizes/digests; verification metadata links the report digest and
all schema versions. Audit regenerates expected bytes from the explicitly supplied
repository and revision, so merely rehashing tampered claims cannot pass.

The revision in a candidate denotes the **caller-supplied base commit**, not a claim
that uncommitted patch content is already committed. Digests describe packaged member
content only. The externally exported patch and exact-baseline validation describe
the proposed source changes. Neither the revision nor these digests authenticates
producer identity. Local command logs are local observations, not CI attestation.

## Recovery and replay review

Existing `LabTests.cs` cases cover the requested meaningful paths:

| Concern | Existing executable regression references |
| --- | --- |
| Enrollment response loss / unknown reconciliation | `UnknownEnrollment`, `EnrollmentReconciliationFailure`, `UnknownEnrollmentIdRemainsUntrusted` |
| Interrupted update / stale revision / repeated recovery | `StoreAtomicRecovery`, `StoreRejectsCorruption`, `JournalReconstructionUsesSharedStore` |
| Replay ledger replacement | `StoreReplayContinuity`, `StoreReplacedLedgerBlocksConsumption`, `ReplayWithFreshJournal` |
| Revocation before cleanup / failed cleanup | `CleanupFailure`, `ConcurrentCleanupReconciliation`, `CleanupUnknownStillPresent` |
| Inventory ambiguity / credential collision | `DuplicateInventory`, `RegistrationIdCollision`, `DisappearingCollisionRemainsUnknown`, `CollisionInjectionPreservesExistingCredential` |
| Cancellation racing fake success | `CancellationRace`, `CleanupCancellationUnknown` |
| Multi-step transition coverage | `JournalTransitionMatrix`, `BoundedRecoverySequenceExploration` (depth 8, cap 6000) |

No new lifecycle implementation is necessary. The bounded explorer is not a proof
over unbounded executions. Synthetic snapshots are not durable, authenticated OS
storage; replay continuity across real OS restarts remains unverified. No trust can
be recovered from an ambiguous inventory identity or a replaced replay ledger.

## Reproducibility, audit and rollback

`--candidate-create <repo> <base-revision> <new-directory>` packages only
`manifest.json`, `invariant-registry.json`, `evidence.json`, `assurance-report.json`,
`documentation-index.json`, `closure.md`, `verification.json`, and `candidate.json`.
Generated evidence is deliberately fixture-only; its deterministic assurance report
must remain `POLICY_VALID_EVIDENCE_INCOMPLETE`. This is a valid *content* candidate,
not a claim that the package proves executed regressions. Required execution is
verified with the local regression procedure and separately by future CI runs.

JSON uses ordinal key ordering, stable array ordering, UTF-8 without BOM and a
terminal LF; closure documentation normalizes CRLF to LF. Member names are literal
flat allowlisted paths. Inventory order is ordinal and sizes are bounded at 262144
bytes per file, with depth 16 JSON and a fixed eight-file package. Directory entries
are bounded and reparse points are rejected in the candidate and its ancestors.
No executable, credential, signing key, log or arbitrary user file is packaged.
Only member and inventory bytes are reproducible for identical source contents and
revision; filesystem timestamps, permissions and directory metadata are excluded.
No archive is produced and no archive-byte reproducibility is claimed.

`--candidate-audit <repo> <base-revision> <directory>` reads only and has no
authorization or credential effects. Exact member comparison catches rehashed
fabrications as well as digest failures. It compares against a caller-selected
repository; it is not independent source authentication. Filesystem checks assume
a stable local workspace; they are not race-proof against a process concurrently
replacing directories. Keep candidate generation/audit in a disposable directory
under the reviewer's control. Audit does not execute package members.

On failure, retain the directory for inspection or discard only that disposable
candidate directory after checking its resolved path. Do not touch Broker state,
OS credentials, journals outside the synthetic test process, or the primary working
tree. A failed create may leave partial data; it is never published or activated.

## Verification and unresolved blockers

Run `Verify-Phase3C4L.ps1` from this directory with the repository and baseline SHA.
It builds all four projects with installed SDK assets and a local restore source,
runs Mock, Fake Lab, Offline Assurance and Node tests, validates policy, creates
two candidates, compares every member byte and audits both. Logs and a summary are
local observations; counts are measured from execution, not used as proof inputs.
CI retains exactly five expanded jobs; only Windows .NET performs WPF and candidate
checks. Linux/Node versions not installed locally are future CI evidence, not local
success claims. Manual visual/accessibility UI review remains separately pending.

Application identity is not bound to an authenticated installed application.
Real Windows Hello credential operations remain disabled and require a separate
security/authority design. Synced passkeys and external authenticators are unverified;
synthetic RP/credential bindings do not establish their custody or lifecycle.
Durable replay across actual restarts, authenticated execution provenance, trusted
source checkout, OS storage and rollback resistance remain unsolved for production.
These are explicit real-system blockers, not reasons to keep extending a completed
synthetic-only exercise. Production authorization and deployment remain prohibited.
