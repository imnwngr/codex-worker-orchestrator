namespace WebAuthn.WindowsLab;

internal enum SyntheticEvidenceSource { Missing, SyntheticFixture, CallerSuppliedMetadata, Contradictory }
internal enum TrustAssessment { SATISFIED_FOR_SYNTHETIC_TEST, INSUFFICIENT_EVIDENCE, CONTRADICTORY_EVIDENCE, UNVERIFIED, BLOCKED }

// Each dimension has its own evidence type. Values are fixture labels, never
// OS attestations, certificate validation, Windows identity, or credential data.
internal sealed record Evidence<T>(T? Value, SyntheticEvidenceSource Source);
internal sealed record ExecutableIdentityEvidence(Evidence<string> Fixture);
internal sealed record BinaryIntegrityEvidence(Evidence<string> DigestFixture);
internal sealed record ProcessIdentityEvidence(Evidence<int> ProcessFixture, Evidence<string> UserFixture);
internal sealed record WindowsUserEvidence(Evidence<string> UserFixture);
internal sealed record AuthenticatorIdentityEvidence(Evidence<string> AuthenticatorFixture);
internal sealed record RelyingPartyEvidence(Evidence<string> RpId, Evidence<string> Origin);
internal sealed record CredentialPossessionEvidence(Evidence<string> CredentialFixture);
internal sealed record UserVerificationEvidence(Evidence<bool> Presence, Evidence<bool> Verification);
internal sealed record IndependentUserApprovalEvidence(Evidence<bool> Approval);

internal sealed record SyntheticTrustEvidence(
    ExecutableIdentityEvidence Executable,
    BinaryIntegrityEvidence Binary,
    ProcessIdentityEvidence Process,
    WindowsUserEvidence WindowsUser,
    AuthenticatorIdentityEvidence Authenticator,
    RelyingPartyEvidence RelyingParty,
    CredentialPossessionEvidence Credential,
    UserVerificationEvidence UserVerification,
    IndependentUserApprovalEvidence IndependentApproval);

internal sealed record TrustAssessmentResult(TrustAssessment Status, string Reason)
{
    // Deliberately no grant, token, or production authorization conversion.
}

internal static class SyntheticTrustEvaluator
{
    public static TrustAssessmentResult Evaluate(SyntheticTrustEvidence? evidence)
    {
        if (evidence is null ||
            evidence.Executable?.Fixture is null ||
            evidence.Binary?.DigestFixture is null ||
            evidence.Process?.ProcessFixture is null ||
            evidence.Process.UserFixture is null ||
            evidence.WindowsUser?.UserFixture is null ||
            evidence.Authenticator?.AuthenticatorFixture is null ||
            evidence.RelyingParty?.RpId is null ||
            evidence.RelyingParty.Origin is null ||
            evidence.Credential?.CredentialFixture is null ||
            evidence.UserVerification?.Presence is null ||
            evidence.UserVerification.Verification is null ||
            evidence.IndependentApproval?.Approval is null)
            return new(TrustAssessment.INSUFFICIENT_EVIDENCE, "evidence_missing");
        var values = new (string? Value, SyntheticEvidenceSource Source)[]
        {
            (evidence.Executable.Fixture.Value, evidence.Executable.Fixture.Source),
            (evidence.Binary.DigestFixture.Value, evidence.Binary.DigestFixture.Source),
            (evidence.Process.ProcessFixture.Value.ToString(), evidence.Process.ProcessFixture.Source),
            (evidence.Process.UserFixture.Value, evidence.Process.UserFixture.Source),
            (evidence.WindowsUser.UserFixture.Value, evidence.WindowsUser.UserFixture.Source),
            (evidence.Authenticator.AuthenticatorFixture.Value, evidence.Authenticator.AuthenticatorFixture.Source),
            (evidence.RelyingParty.RpId.Value, evidence.RelyingParty.RpId.Source),
            (evidence.RelyingParty.Origin.Value, evidence.RelyingParty.Origin.Source),
            (evidence.Credential.CredentialFixture.Value, evidence.Credential.CredentialFixture.Source),
            (evidence.UserVerification.Presence.Value.ToString(), evidence.UserVerification.Presence.Source),
            (evidence.UserVerification.Verification.Value.ToString(), evidence.UserVerification.Verification.Source),
            (evidence.IndependentApproval.Approval.Value.ToString(), evidence.IndependentApproval.Approval.Source)
        };
        if (values.Any(item => item.Source == SyntheticEvidenceSource.Contradictory))
            return new(TrustAssessment.CONTRADICTORY_EVIDENCE, "contradictory_evidence");
        if (values.Any(item => item.Source == SyntheticEvidenceSource.CallerSuppliedMetadata))
            return new(TrustAssessment.UNVERIFIED, "caller_metadata_is_not_identity_proof");
        if (values.Any(item => item.Source != SyntheticEvidenceSource.SyntheticFixture ||
            string.IsNullOrWhiteSpace(item.Value)))
            return new(TrustAssessment.INSUFFICIENT_EVIDENCE, "synthetic_evidence_incomplete");
        if (evidence.Process.ProcessFixture.Value <= 0)
            return new(TrustAssessment.BLOCKED, "invalid_synthetic_process_fixture");
        if (!StringComparer.Ordinal.Equals(evidence.Process.UserFixture.Value, evidence.WindowsUser.UserFixture.Value))
            return new(TrustAssessment.CONTRADICTORY_EVIDENCE, "process_and_user_fixture_conflict");
        if (!StringComparer.Ordinal.Equals(evidence.RelyingParty.RpId.Value, RecoveryJournal.TestRpId) ||
            !StringComparer.Ordinal.Equals(evidence.RelyingParty.Origin.Value, RecoveryJournal.TestOrigin))
            return new(TrustAssessment.BLOCKED, "rp_origin_not_fixed_synthetic_pair");
        if (evidence.UserVerification.Presence.Value != true ||
            evidence.UserVerification.Verification.Value != true ||
            evidence.IndependentApproval.Approval.Value != true)
            return new(TrustAssessment.BLOCKED, "user_action_does_not_establish_independent_approval");
        return new(TrustAssessment.SATISFIED_FOR_SYNTHETIC_TEST, "synthetic_fixture_only_no_authorization");
    }
}

internal enum ReadinessStatus
{
    SYNTHETIC_TEST_READY,
    READ_ONLY_DIAGNOSTIC_READY,
    REAL_CREDENTIAL_ENROLLMENT_BLOCKED,
    REAL_CREDENTIAL_ASSERTION_BLOCKED,
    REAL_CREDENTIAL_DELETION_BLOCKED,
    PRODUCTION_AUTHORIZATION_BLOCKED
}

internal sealed record ExperimentalReadinessReport(
    ReadinessStatus[] Statuses,
    string SyntheticImplementationCoverage,
    string RuntimeDiagnosticEvidence,
    string ApiVersionGates,
    string CredentialOperationExports,
    string RealAuthenticatorBehavior,
    string CleanupEvidence,
    string ApplicationIdentity,
    string ReplayProtection,
    string DisposableEnvironment,
    string UserApproval);

internal static class ExperimentalReadinessEvaluator
{
    public static ExperimentalReadinessReport Evaluate() => new(
        [ReadinessStatus.SYNTHETIC_TEST_READY, ReadinessStatus.READ_ONLY_DIAGNOSTIC_READY,
         ReadinessStatus.REAL_CREDENTIAL_ENROLLMENT_BLOCKED, ReadinessStatus.REAL_CREDENTIAL_ASSERTION_BLOCKED,
         ReadinessStatus.REAL_CREDENTIAL_DELETION_BLOCKED, ReadinessStatus.PRODUCTION_AUTHORIZATION_BLOCKED],
        "Fake-only deterministic test coverage; no real credential operation.",
        "Read-only Windows capability diagnostic is separate from credential authorization.",
        "Reported API version can satisfy mapped header gates; it does not prove exports or operation readiness.",
        "Credential-operation export availability and behavior remain unverified.",
        "Real authenticator behavior remains unverified.",
        "Real cleanup and complete authenticator or synchronized-store inventory remain unverified.",
        "Application identity remains untrusted or incomplete; metadata and authenticator signatures do not attest the caller.",
        "No production-grade durable replay protection; synthetic memory state is not durable or tamper resistant.",
        "A dedicated disposable test environment is required.",
        "Separate explicit USER approval is required for enrollment, assertion, and deletion.");
}

internal sealed record SyntheticCleanupEvidence(
    string RpId,
    string ExpectedCredentialId,
    string OperationId,
    LabState PreCleanupState,
    bool TrustRevokedBeforeCleanup,
    string CleanupResponseCategory,
    string InventoryReconciliationResult,
    string AmbiguityOrMissingEvidence,
    string FinalOutcome,
    bool ClaimsEveryAuthenticatorStoreCleaned);
