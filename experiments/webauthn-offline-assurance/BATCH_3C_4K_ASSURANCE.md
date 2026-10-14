# Phase 3C.4K offline assurance

## Scope and authority

This .NET 8 console utility validates local experimental policy, invariant traceability, and supplied synthetic evidence. It only reads named local files and writes a JSON result to standard output. It has no provider, Broker, grant, WPF, or native credential-operation interface. It makes no network or WebAuthn calls. Its result classifies evidence and policy; it cannot authorize an operation.

The production Broker and offline verifier are unchanged. The five existing effective CI categories remain Windows Node 22/24, Ubuntu Node 22/24, and Windows .NET 8. CI adds build and offline self-test steps within the existing .NET job.

## Commands and exit codes

From the repository root in PowerShell:

```powershell
& {
  dotnet build .\experiments\webauthn-offline-assurance\WebAuthn.OfflineAssurance.csproj --configuration Release
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  dotnet run --no-build --no-restore --configuration Release --project .\experiments\webauthn-offline-assurance\WebAuthn.OfflineAssurance.csproj -- --policy-check .\experiments\webauthn-windows-lab\experimental-readiness.json .\experiments\webauthn-offline-assurance\invariant-registry.json
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  dotnet run --no-build --no-restore --configuration Release --project .\experiments\webauthn-offline-assurance\WebAuthn.OfflineAssurance.csproj -- --self-test .\experiments\webauthn-windows-lab\experimental-readiness.json .\experiments\webauthn-offline-assurance\invariant-registry.json .\experiments\webauthn-offline-assurance\fixtures .
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  dotnet run --no-build --no-restore --configuration Release --project .\experiments\webauthn-offline-assurance\WebAuthn.OfflineAssurance.csproj -- --report .\experiments\webauthn-windows-lab\experimental-readiness.json .\experiments\webauthn-offline-assurance\invariant-registry.json .\experiments\webauthn-offline-assurance\fixtures\evidence-reported-fixture.json aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa .
}
```

`--policy-check` returns 0 when static manifest and registry policy validate. It says nothing about runtime or test execution. `--self-test` returns 0 when the verifier's deterministic policy, traceability, source-boundary and adversarial checks pass. `--report` returns 0 only when structurally valid **self-reported** PASS claims cover every required group with matching supplied revisions; this is still unverified reporting, not execution attestation. Fixture-only claims return 1 with `FIXTURE_ONLY` classifications, as do valid but incomplete/unmatched claims. Malformed or contradictory input returns 2. Invalid CLI usage returns 64. Reports go to stdout; the utility does not create or overwrite files.

The `evidence-reported-fixture.json` and `expected-report.json` are fixtures, not execution records. The PASS labels are deliberately accompanied by `fixed offline fixture; does not claim a test was executed`. The golden report test normalizes platform line endings and compares deterministic report content. Never use the fixture as evidence that CI or tests ran.

## Manifest and invariant registry

The existing manifest remains schema version 1. The validator uses strict field allowlists, exact security policy values, exact test groups and five CI categories, required prohibited capabilities, and fixed readiness statuses. It rejects duplicate properties, unsupported versions, wrong types, oversized input/strings/collections, unknown keys, and contradictory values with stable category codes. There is no coercion from unknown to ready.

`invariant-registry.json` records stable IDs, threats, domains, enforcement paths, test method references, evidence categories, limitations and assurance status. The self-test checks all required invariant IDs, verifies paths remain under the supplied repository root and exist, resolves referenced lab test methods, and scans the lab/verifier source for the explicitly prohibited native or dispatch dependencies. This is a targeted regression check, not a general-purpose static analyzer or binary attestation. `SOURCE_REVIEWED` remains a source review classification; JSON status alone is not proof.

## Evidence and report semantics

Evidence schema version 1 is a bounded envelope with unique IDs, fixed categories/origins, optional user-supplied source revision and UTC observation time, test group/result, assumptions, payload, and SHA-256 of canonical payload JSON. The verifier checks digest equality, payload/envelope linkage, source revision consistency, and required group coverage. Reports sort invariant IDs, evidence IDs and issue categories for repeatable output and contain no current time or machine facts unless explicitly included as an observation.

The hash establishes only that the digest matches the payload presented to this verifier. It does not authenticate a producer. A matching Git revision is a user-supplied comparison value, not proof of the executing binary or source tree. A self-reported PASS is not proof the test ran. Historical host observations remain user-supplied and unverified. This offline tool never emits `SYNTHETIC_REGRESSION_INDEPENDENTLY_VERIFIED`; it does not fetch or validate trusted CI attestations.

`SYNTHETIC_POLICY_VALIDATED`, `SYNTHETIC_REGRESSION_REPORTED`, `SYNTHETIC_EVIDENCE_INCOMPLETE`, and `READ_ONLY_RUNTIME_UNOBSERVED` describe classifications only. Every report keeps real credential operations `NO_GO` and production authorization `DEFAULT_DENY`. A user-supplied historical host observation adds `READ_ONLY_RUNTIME_HISTORICAL_REPORT_UNVERIFIED` and is listed as `REPORTED_UNVERIFIED_USER_SUPPLIED`; the verifier runtime status remains `READ_ONLY_RUNTIME_UNOBSERVED`.

## Invariant registry status

The registry includes 15 required invariants. `CODE_ENFORCED_TESTED` points to implementation and deterministic tests; it does not assert this command executed them. `SOURCE_REVIEWED` marks boundaries checked in source, with stated limitations. Traceability failures cause the self-test to fail. See the registry itself for per-invariant locations and test identifiers.

Baseline synthetic recovery already covers crash-before-commit, simulated post-commit interruption, torn writes, stale revision, duplicate operation IDs, conflicting/rollback snapshots, replay ledger replacement, response loss, unavailable or mismatched inventory, cancellation racing with fake creation, and repeated reconciliation. Relevant existing tests include `StoreAtomicRecovery`, `StoreRejectsCorruption`, `StoreReplayContinuity`, `StoreRestoreRequiresValidGenesis`, `CleanupOutcomeUnknown`, `CleanupUnknownStillPresent`, `CleanupRejectsUnexpectedInventoryIdentity`, `CancellationRace`, `OrphanCleanupUnknown`, and `ReconciliationFailure`. These were retained; no parallel journal subsystem was added.

The new bounded reachable-sequence explorer uses a finite enum/action alphabet, depth 8 and 6,000-state cap, breadth-first stable ordering, and a minimal independent transition reference. It compares reachable Begin/Record decisions and rejects any path that restores a pinned state within a revoked credential lifecycle. It has no sleeps, external services, hardware, or timing races.

## Assurance categories and current evidence

| Category | Meaning for this batch |
|---|---|
| A. Policy structurally validated | Manifest and registry validator ran locally; 15 invariants and required fields validated. |
| B. Synthetic behavior tested | Lab and Mock test runners were actually executed locally; reports below record results. |
| C. Test execution reported | The offline report format can display supplied claims, explicitly unverified. Fixed fixtures are not actual run evidence. |
| D. Test execution independently verified | Not established by this tool; no signed CI provenance is consumed. |
| E. Native runtime observed | Not observed in this batch; no native diagnostic was invoked. |
| F. Real credential behavior | Unverified and outside scope. |
| G. Production authorization | DEFAULT-DENY; no experimental output carries authority. |

Actual local verification during this batch: WPF Mock build succeeded; Mock tests 25/25; fake lab build succeeded; fake lab tests 60/60 (59 baseline plus bounded explorer); Node tests 105/105 on Windows Node 24; offline assurance build succeeded; offline assurance self-tests 37/37 **before this review**. The reviewed patch adds four additional self-tests; those updated C# tests have not yet been executed here. CI was modified but not run remotely. Windows Node 22, Ubuntu Node 22/24 remain unexecuted here.

## GO / NO-GO

| Area | Decision |
|---|---|
| Offline manifest and invariant policy validation | GO for structural validation only |
| Synthetic lab regression | GO for local tested fake behavior; CI matrix not fully observed |
| Evidence/report classification | GO as deterministic observational output; provenance remains untrusted |
| Read-only runtime diagnostics | NOT OBSERVED |
| WPF mock | Build and tests pass; interactive demonstration not run |
| Real WebAuthn enrollment/assertion/enumeration/deletion | **NO-GO** |
| Application identity and synced/external authenticator behavior | **UNVERIFIED / NO-GO** |
| Replay across actual OS restarts | **UNVERIFIED / NO-GO** |
| Production authorization or dispatch from experimental evidence | **NO-GO; DEFAULT-DENY** |

Historical context is retained in [3C.4G](../webauthn-windows-lab/BATCH_3C_4G_DEF_READINESS.md), [3C.4H](../webauthn-windows-lab/BATCH_3C_4H_READINESS.md), [3C.4I](../webauthn-windows-lab/BATCH_3C_4I_ASSURANCE.md), and [3C.4J](../webauthn-windows-lab/BATCH_3C_4J_READINESS.md).
