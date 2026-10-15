namespace WebAuthn.OfflineAssurance;

// Reviewable repository policy, not a certificate of code behavior or test execution.
internal static class TraceContract
{
    private const string Lab = "experiments/webauthn-windows-lab/";
    private static readonly Dictionary<string, (string Domain, string Files, string Tests)> Required = new(StringComparer.Ordinal) {
        ["RP-ORIGIN-01"] = ("synthetic-lifecycle", "RecoveryJournal.cs|ClientData.cs", "FixedOrigin"),
        ["CRED-ID-01"] = ("synthetic-lifecycle", "SyntheticInventory.cs|LabWorkflow.cs", "RegistrationIdCollision|MalformedOrphanIdCannotBeDeleted|UnboundValidOrphanIdCannotBeDeleted"),
        ["INVENTORY-01"] = ("synthetic-lifecycle", "SyntheticInventory.cs|LabWorkflow.cs", "UnknownEnrollmentIdRemainsUntrusted|EnrollmentBaselineLossRemainsUnknown|CleanupRejectsUnexpectedInventoryIdentity"),
        ["COLLISION-01"] = ("synthetic-lifecycle", "LabWorkflow.cs|FakeNativeWebAuthn.cs", "RegistrationIdCollision|DisappearingCollisionRemainsUnknown|CollisionInjectionPreservesExistingCredential"),
        ["UNKNOWN-01"] = ("synthetic-lifecycle", "LabWorkflow.cs|RecoveryJournal.cs", "UnknownEnrollment|CleanupOutcomeUnknown|CleanupCancellationUnknown|ReconciliationFailure"),
        ["REVOKE-01"] = ("synthetic-lifecycle", "LabWorkflow.cs", "CleanupFailure|ConcurrentCleanupReconciliation|CleanupCancellationUnknown"),
        ["REVOKE-02"] = ("synthetic-lifecycle", "LabWorkflow.cs|RecoveryJournal.cs", "ConcurrentCleanupReconciliation|CleanupOutcomeUnknown|BoundedRecoverySequenceExploration"),
        ["JOURNAL-01"] = ("synthetic-recovery", "RecoveryJournal.cs|SyntheticJournalStore.cs", "JournalTransitionMatrix|StoreContinuationIsValidated|JournalRejectsInvalidTransitions|BoundedRecoverySequenceExploration"),
        ["REVISION-01"] = ("synthetic-recovery", "SyntheticJournalStore.cs", "StoreRejectsCorruption|JournalReconstructionUsesSharedStore"),
        ["REPLAY-01"] = ("synthetic-recovery", "SyntheticJournalStore.cs", "StoreReplayContinuity|StoreReplacedLedgerBlocksConsumption|ReplayWithFreshJournal"),
        ["RESTORE-01"] = ("synthetic-recovery", "SyntheticJournalStore.cs", "StoreRestoreRequiresValidGenesis|JournalReconstructionUsesSharedStore"),
        ["TRUST-01"] = ("synthetic-trust", "TrustBoundary.cs", "TrustBoundaryPositiveControl|TrustBoundaryRejectsMetadata|TrustBoundaryContradictions"),
        ["READY-01"] = ("readiness-policy", "TrustBoundary.cs|experimental-readiness.json", "ReadinessIsInformational|ExperimentalManifest"),
        ["NATIVE-01"] = ("component-boundary", "FakeNativeWebAuthn.cs|README.md", "FakeOwnership|RegistrationFailures"),
        ["AUTH-01"] = ("component-boundary", "WebAuthn.WindowsLab.csproj|experimental-readiness.json|@broker/README.md", "ReadinessIsInformational|ExperimentalManifest")
    };
    private static string[] Paths(string files) => files.Split('|').Select(x => x.StartsWith('@') ? x[1..] : Lab + x).ToArray();
    internal static readonly string[] AllowedLocations = Required.Values.SelectMany(x => Paths(x.Files)).Distinct(StringComparer.Ordinal).ToArray();
    internal static bool DomainMatches(string id, string domain) => Required.TryGetValue(id, out var rule) && rule.Domain == domain;
    internal static bool Matches(string id, string[] locations, string[] tests) => Required.TryGetValue(id, out var rule) &&
        locations.Order(StringComparer.Ordinal).SequenceEqual(Paths(rule.Files).Order(StringComparer.Ordinal)) &&
        tests.Order(StringComparer.Ordinal).SequenceEqual(rule.Tests.Split('|').Order(StringComparer.Ordinal));
}
