using System.Security.Cryptography;

namespace WebAuthn.WindowsLab;

internal enum LabState
{
    Ready,
    EnrollmentStarted,
    CredentialPinnedInMemory,
    AssertionStarted,
    AssertionContractMatched,
    Cancelled,
    Failed,
    OrphanedCredential,
    RevokedCleanupPending,
    RevokedAndCleaned,
    EnrollmentOutcomeUnknown,
    CreatedUnpinned,
    CleanupOutcomeUnknown,
    OrphanCleanupOutcomeUnknown
}

internal sealed record TestCredential(
    string CredentialId,
    int Algorithm,
    string PublicKeySha256);

internal sealed class LabWorkflow
{
    private readonly IFakeNativeWebAuthn _native;
    private readonly FakeAssertionGate _gate;
    private readonly RecoveryJournal _journal;
    private HashSet<string> _credentialIdsBeforeEnrollment =
        new(StringComparer.Ordinal);
    private string? _enrollmentOperationId;
    private int _cleanupAttempts;
    private LabState _cleanupPreState;
    // A malformed or colliding returned ID cannot be resolved by inventory alone.
    private bool _enrollmentIdentityConflict;

    public LabWorkflow(
        IFakeNativeWebAuthn native,
        FakeAssertionGate gate,
        RecoveryJournal? journal = null)
    {
        _native = native;
        _gate = gate;
        _journal = journal ?? gate.Journal;
        if (!ReferenceEquals(_journal, gate.Journal))
            throw new ArgumentException("Gate and workflow must share one fake journal.", nameof(journal));
    }

    public LabState State { get; private set; } = LabState.Ready;
    public TestCredential? Credential { get; private set; }
    public string? OrphanCredentialId { get; private set; }
    public string? PendingCleanupCredentialId { get; private set; }
    public RecoveryJournal Journal => _journal;
    public SyntheticCleanupEvidence? LastCleanupEvidence { get; private set; }

    public async Task EnrollAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.Ready)
            throw new InvalidOperationException("Enrollment requires Ready state.");

        // A cancellation before the operation begins is a confirmed
        // not-started result, not an ambiguous native-operation outcome.
        if (cancellationToken.IsCancellationRequested)
        {
            State = LabState.Cancelled;
            cancellationToken.ThrowIfCancellationRequested();
        }
        _credentialIdsBeforeEnrollment = SyntheticInventory.Validate(
            await _native.SimulateCredentialInventoryAsync(cancellationToken));
        State = LabState.EnrollmentStarted;
        _enrollmentOperationId =
            _journal.Begin(RecoveryOperation.Enrollment, State);
        try
        {
            using var result = await _native.SimulateRegistrationAsync(cancellationToken);
            var idBytes = result.CredentialId.Copy();
            if (idBytes.Length is < 16 or > 512)
                throw new InvalidDataException("credential_id_length");
            var id = ToBase64Url(idBytes);
            if (_credentialIdsBeforeEnrollment.Contains(id))
            {
                _enrollmentIdentityConflict = true;
                throw new FakeNativeFailureException(
                    "Registration returned an ID present before the operation.",
                    outcomeUnknown: true);
            }
            OrphanCredentialId = id;
            State = LabState.CreatedUnpinned;
            _journal.Record(_enrollmentOperationId, RecoveryOperation.Enrollment,
                State, RecoveryOutcome.Succeeded, credentialId: id,
                cancellationRequested: cancellationToken.IsCancellationRequested);

            var coseBytes = result.CoseKey.Copy();
            var parsed = CoseKeyParser.Parse(coseBytes);
            Credential = new TestCredential(id, parsed.Algorithm, parsed.PublicKeySha256);
            OrphanCredentialId = null;
            State = LabState.CredentialPinnedInMemory;
            _journal.Record(_enrollmentOperationId, RecoveryOperation.Enrollment,
                State, RecoveryOutcome.Succeeded, credentialId: id,
                algorithm: parsed.Algorithm,
                publicKeySha256: parsed.PublicKeySha256,
                cancellationRequested: cancellationToken.IsCancellationRequested);
        }
        catch (OperationCanceledException)
        {
            State = LabState.EnrollmentOutcomeUnknown;
            _journal.Record(_enrollmentOperationId!, RecoveryOperation.Enrollment,
                State, RecoveryOutcome.Unknown,
                cancellationRequested: true, errorCode: "registration_cancelled_outcome_unknown");
            throw;
        }
        catch (FakeNativeFailureException error) when (error.OrphanCredentialId is not null)
        {
            // A well-formed claimed ID alone is not evidence that this fake
            // operation created it. Require operation-bound synthetic provenance.
            if (!error.SyntheticOrphanIdBoundToOperation ||
                !SyntheticInventory.IsCanonicalCredentialId(error.OrphanCredentialId) ||
                _credentialIdsBeforeEnrollment.Contains(error.OrphanCredentialId))
            {
                _enrollmentIdentityConflict = true;
                State = LabState.EnrollmentOutcomeUnknown;
                _journal.Record(_enrollmentOperationId!, RecoveryOperation.Enrollment,
                    State, RecoveryOutcome.Unknown,
                    errorCode: "registration_recovery_id_invalid_or_preexisting");
                throw;
            }
            OrphanCredentialId = error.OrphanCredentialId;
            State = LabState.OrphanedCredential;
            _journal.Record(_enrollmentOperationId!, RecoveryOperation.Enrollment,
                State, error.OutcomeUnknown ? RecoveryOutcome.Unknown : RecoveryOutcome.Failed,
                credentialId: OrphanCredentialId, errorCode: "registration_response_lost");
            throw;
        }
        catch (FakeNativeFailureException error) when (error.OutcomeUnknown)
        {
            State = LabState.EnrollmentOutcomeUnknown;
            _journal.Record(_enrollmentOperationId!, RecoveryOperation.Enrollment,
                State, RecoveryOutcome.Unknown, errorCode: "registration_outcome_unknown");
            throw;
        }
        catch
        {
            if (State != LabState.CreatedUnpinned)
                State = LabState.Failed;
            _journal.Record(_enrollmentOperationId!, RecoveryOperation.Enrollment,
                State, RecoveryOutcome.Failed, credentialId: OrphanCredentialId,
                errorCode: "registration_failed_or_validation_rejected");
            throw;
        }
    }

    public async Task ReconcileUnknownEnrollmentAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.EnrollmentOutcomeUnknown ||
            _enrollmentOperationId is null)
            throw new InvalidOperationException("No unknown enrollment needs reconciliation.");

        cancellationToken.ThrowIfCancellationRequested();
        var operationId = _journal.Begin(RecoveryOperation.Reconciliation, State);
        try
        {
            var inventory = SyntheticInventory.Validate(
                await _native.SimulateCredentialInventoryAsync(cancellationToken));
            // A reported malformed or pre-existing registration identity cannot
            // be disambiguated by a later inventory snapshot, even if it vanishes.
            if (_enrollmentIdentityConflict)
            {
                _journal.Record(operationId, RecoveryOperation.Reconciliation,
                    State, RecoveryOutcome.Unknown,
                    errorCode: "registration_identity_conflict_unresolved");
                return;
            }

            // Equality must cover BOTH additions and losses. Merely observing
            // no new IDs would incorrectly reset Unknown when a baseline ID
            // disappeared or was replaced during the interrupted operation.
            if (!inventory.SetEquals(_credentialIdsBeforeEnrollment))
            {
                _journal.Record(operationId, RecoveryOperation.Reconciliation,
                    State, RecoveryOutcome.Unknown,
                    errorCode: "inventory_changed_without_operation_binding");
                return;
            }

            State = LabState.Ready;
            _journal.Record(operationId, RecoveryOperation.Reconciliation,
                State, RecoveryOutcome.Succeeded,
                errorCode: "fake_inventory_matches_pre_operation_snapshot");
        }
        catch
        {
            State = LabState.EnrollmentOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Reconciliation,
                State, RecoveryOutcome.Unknown, errorCode: "fake_enrollment_inventory_unavailable");
            throw;
        }
    }

    public async Task RecoverOrphanAsync(CancellationToken cancellationToken)
    {
        if (State is not (LabState.OrphanedCredential or LabState.CreatedUnpinned) ||
            OrphanCredentialId is null ||
            !SyntheticInventory.IsCanonicalCredentialId(OrphanCredentialId) ||
            _credentialIdsBeforeEnrollment.Contains(OrphanCredentialId))
            throw new InvalidOperationException("No simulated orphan is available.");
        await DeleteAndReconcileAsync(OrphanCredentialId, cancellationToken, isOrphan: true);
    }

    public async Task<FakeGateResult> RunAssertionAsync(
        string challenge,
        string origin,
        long expiry,
        string nonce,
        long now,
        CancellationToken cancellationToken)
    {
        if (!StringComparer.Ordinal.Equals(origin, StrictClientData.TestOrigin))
            throw new InvalidDataException("test_origin_is_fixed");
        if (State != LabState.CredentialPinnedInMemory || Credential is null)
            throw new InvalidOperationException("Assertion requires an in-memory fake credential.");
        State = LabState.AssertionStarted;
        var operationId = _journal.Begin(RecoveryOperation.Assertion, State);
        try
        {
            using var result = await _native.SimulateAssertionAsync(
                challenge, origin, expiry, nonce, Credential, cancellationToken);
            var payload = result.Copy();
            var gateResult = _gate.Evaluate(Credential, payload, challenge, origin, now);
            State = LabState.AssertionContractMatched;
            _journal.Record(operationId, RecoveryOperation.Assertion, State,
                RecoveryOutcome.Succeeded);
            return gateResult;
        }
        catch (OperationCanceledException)
        {
            State = LabState.Cancelled;
            _journal.Record(operationId, RecoveryOperation.Assertion, State,
                RecoveryOutcome.Unknown, cancellationRequested: true,
                errorCode: "assertion_cancelled_outcome_unknown");
            throw;
        }
        catch
        {
            State = LabState.Failed;
            _journal.Record(operationId, RecoveryOperation.Assertion, State,
                RecoveryOutcome.Failed, errorCode: "assertion_rejected");
            throw;
        }
    }

    public async Task RevokeAndCleanFakeAsync(CancellationToken cancellationToken)
    {
        if (State is not (LabState.CredentialPinnedInMemory or LabState.AssertionContractMatched) ||
            Credential is null)
            throw new InvalidOperationException("Cleanup requires a fake pinned credential.");
        _cleanupPreState = State;
        PendingCleanupCredentialId = Credential.CredentialId;
        Credential = null; // Revoke fake trust BEFORE any deletion attempt.
        State = LabState.RevokedCleanupPending;
        LastCleanupEvidence = new SyntheticCleanupEvidence(
            RecoveryJournal.TestRpId, PendingCleanupCredentialId, "not_started",
            _cleanupPreState, true, "not_attempted", "not_reconciled",
            "cleanup_not_yet_attempted", "SYNTHETIC_CLEANUP_PENDING", false);
        _cleanupAttempts = 0;
        _journal.Record(
            _journal.Begin(RecoveryOperation.Cleanup, State),
            RecoveryOperation.Cleanup, State, RecoveryOutcome.Started,
            credentialId: PendingCleanupCredentialId, cleanupAttempts: _cleanupAttempts);
        await RetryFakeCleanupAsync(cancellationToken);
    }

    public async Task RetryFakeCleanupAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.RevokedCleanupPending || PendingCleanupCredentialId is null)
            throw new InvalidOperationException("No revoked fake credential needs cleanup.");
        await DeleteAndReconcileAsync(
            PendingCleanupCredentialId, cancellationToken, isOrphan: false);
    }

    public async Task ReconcileUnknownCleanupAsync(CancellationToken cancellationToken)
    {
        var isOrphan = State == LabState.OrphanCleanupOutcomeUnknown;
        if (!isOrphan && State != LabState.CleanupOutcomeUnknown)
            throw new InvalidOperationException("No unknown cleanup needs reconciliation.");
        var id = isOrphan ? OrphanCredentialId : PendingCleanupCredentialId;
        if (id is null)
            throw new InvalidOperationException("No synthetic ID is available for reconciliation.");
        cancellationToken.ThrowIfCancellationRequested();
        var operationId = _journal.Begin(RecoveryOperation.Reconciliation, State);
        try
        {
            var inventory = ValidateCleanupInventory(
                await _native.SimulateCredentialInventoryAsync(cancellationToken), id);
            if (!inventory.Contains(id))
            {
                if (isOrphan)
                {
                    OrphanCredentialId = null;
                    State = LabState.Ready;
                }
                else
                {
                    PendingCleanupCredentialId = null;
                    State = LabState.RevokedAndCleaned;
                }
                _journal.Record(operationId, RecoveryOperation.Reconciliation, State,
                    RecoveryOutcome.Succeeded, errorCode: "fake_inventory_confirms_absence");
                if (!isOrphan)
                    UpdateCleanupEvidence("response_unknown_or_lost",
                        "synthetic_inventory_confirms_absence", "none_within_fake_inventory_scope",
                        "SYNTHETIC_ID_ABSENT_FROM_TEST_INVENTORY");
                return;
            }

            State = isOrphan ? LabState.OrphanedCredential : LabState.RevokedCleanupPending;
            _journal.Record(operationId, RecoveryOperation.Reconciliation, State,
                RecoveryOutcome.Succeeded, credentialId: id,
                errorCode: "fake_inventory_confirms_present_retry_allowed");
            if (!isOrphan)
                UpdateCleanupEvidence("response_unknown_or_lost",
                    "synthetic_inventory_confirms_present", "deletion_not_confirmed",
                    "SYNTHETIC_CLEANUP_PENDING");
        }
        catch
        {
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Reconciliation, State,
                RecoveryOutcome.Unknown, credentialId: id,
                errorCode: "fake_inventory_reconciliation_failed");
            if (!isOrphan)
                UpdateCleanupEvidence("response_unknown_or_lost",
                    "inventory_unavailable_or_invalid", "inventory_reconciliation_incomplete",
                    "SYNTHETIC_CLEANUP_UNKNOWN");
            throw;
        }
    }

    private async Task DeleteAndReconcileAsync(
        string credentialId,
        CancellationToken cancellationToken,
        bool isOrphan)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _cleanupAttempts++;
        var operationId = _journal.Begin(RecoveryOperation.Cleanup,
            isOrphan ? State : LabState.RevokedCleanupPending);
        if (!isOrphan && PendingCleanupCredentialId is not null)
            LastCleanupEvidence = new SyntheticCleanupEvidence(
                RecoveryJournal.TestRpId, PendingCleanupCredentialId, operationId,
                _cleanupPreState, Credential is null, "pending", "not_reconciled",
                "inventory_not_yet_checked", "SYNTHETIC_CLEANUP_PENDING", false);
        try
        {
            await _native.SimulatePlatformCredentialDeletionAsync(
                credentialId, cancellationToken);
            var inventory = ValidateCleanupInventory(
                await _native.SimulateCredentialInventoryAsync(cancellationToken), credentialId);
            if (inventory.Contains(credentialId))
                throw new FakeNativeFailureException("Fake inventory still contains the ID.");

            if (isOrphan)
            {
                OrphanCredentialId = null;
                State = LabState.Ready;
            }
            else
            {
                PendingCleanupCredentialId = null;
                State = LabState.RevokedAndCleaned;
            }
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Succeeded, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts,
                errorCode: "fake_inventory_confirms_absence");
            if (!isOrphan && LastCleanupEvidence is not null)
                LastCleanupEvidence = LastCleanupEvidence with
                {
                    CleanupResponseCategory = "synthetic_delete_reported_success",
                    InventoryReconciliationResult = "synthetic_inventory_confirms_absence",
                    AmbiguityOrMissingEvidence = "none_within_fake_inventory_scope",
                    FinalOutcome = "SYNTHETIC_ID_ABSENT_FROM_TEST_INVENTORY"
                };
        }
        catch (FakeNativeFailureException error) when (error.OutcomeUnknown)
        {
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Unknown, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_response_lost");
            UpdateCleanupEvidence("response_lost_or_unknown", "not_reconciled",
                "deletion_outcome_unknown", "SYNTHETIC_CLEANUP_UNKNOWN");
            throw;
        }
        catch (FakeNativeFailureException error) when (!error.OutcomeUnknown)
        {
            // The fake adapter guarantees this failure occurred before deletion.
            State = isOrphan ? LabState.OrphanedCredential : LabState.RevokedCleanupPending;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Failed, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_confirmed_failure");
            UpdateCleanupEvidence("synthetic_delete_reported_failure", "not_reconciled",
                "retry_requires_reconciliation_policy", "SYNTHETIC_CLEANUP_PENDING");
            throw;
        }
        catch (OperationCanceledException)
        {
            // Cancellation can race with a successful deletion. Never retry blindly.
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Unknown, credentialId: credentialId,
                cancellationRequested: true, cleanupAttempts: _cleanupAttempts,
                errorCode: "cleanup_cancelled_outcome_unknown");
            UpdateCleanupEvidence("cancelled_response_unknown", "not_reconciled",
                "cancellation_does_not_prove_deletion_failure", "SYNTHETIC_CLEANUP_UNKNOWN");
            throw;
        }
        catch
        {
            // A failed inventory after an acknowledged deletion is also ambiguous.
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Unknown, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_unconfirmed");
            UpdateCleanupEvidence("response_unconfirmed", "inventory_unavailable_or_invalid",
                "cleanup_outcome_unknown", "SYNTHETIC_CLEANUP_UNKNOWN");
            throw;
        }
    }

    private void UpdateCleanupEvidence(string response, string inventory,
        string ambiguity, string outcome)
    {
        if (LastCleanupEvidence is null) return;
        LastCleanupEvidence = LastCleanupEvidence with
        {
            CleanupResponseCategory = response,
            InventoryReconciliationResult = inventory,
            AmbiguityOrMissingEvidence = ambiguity,
            FinalOutcome = outcome
        };
    }

    private HashSet<string> ValidateCleanupInventory(
        IReadOnlyCollection<string>? inventory, string expectedCredentialId)
    {
        var identities = SyntheticInventory.Validate(inventory);
        foreach (var identity in identities)
        {
            if (!_credentialIdsBeforeEnrollment.Contains(identity) &&
                !StringComparer.Ordinal.Equals(identity, expectedCredentialId))
                throw new InvalidDataException("fake_inventory_contains_unrecognized_id");
        }
        return identities;
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed record FakeGateResult(string Outcome, string Nonce);

internal sealed class FakeAssertionGate
{
    public FakeAssertionGate(RecoveryJournal? journal = null) =>
        Journal = journal ?? new RecoveryJournal();

    public RecoveryJournal Journal { get; }

    public FakeGateResult Evaluate(
        TestCredential trusted,
        FakeAssertionPayload assertion,
        string expectedChallenge,
        string expectedOrigin,
        long now)
    {
        if (!StringComparer.Ordinal.Equals(expectedOrigin, StrictClientData.TestOrigin))
            throw new InvalidDataException("test_origin_is_fixed");
        var client = StrictClientData.Parse(
            assertion.ClientDataJson, "webauthn.get",
            expectedChallenge, expectedOrigin);
        if (!StringComparer.Ordinal.Equals(
                Convert.ToBase64String(assertion.CredentialId).TrimEnd('=')
                    .Replace('+', '-').Replace('/', '_'),
                trusted.CredentialId))
            throw new InvalidDataException("credential_id_mismatch");
        if (assertion.Algorithm != trusted.Algorithm)
            throw new InvalidDataException("credential_algorithm_mismatch");
        if (!StringComparer.Ordinal.Equals(
                assertion.PublicKeySha256, trusted.PublicKeySha256))
            throw new InvalidDataException("credential_public_key_mismatch");
        if (assertion.ExpiresAtUnixMilliseconds <= now)
            throw new InvalidDataException("challenge_expired");
        if (string.IsNullOrWhiteSpace(assertion.Nonce))
            throw new InvalidDataException("nonce_required");
        if (!Journal.TryConsume(expectedChallenge, assertion.Nonce))
            throw new InvalidDataException("challenge_replayed");

        // This is a field-contract result only. No signature exists or is checked.
        return new FakeGateResult(
            $"Fake fields matched; preserved {client.OriginalBytes.Length} JSON bytes.",
            assertion.Nonce);
    }
}
