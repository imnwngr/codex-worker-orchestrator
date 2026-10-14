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
            var added = inventory.Where(id => !_credentialIdsBeforeEnrollment.Contains(id))
                .ToArray();
            if (added.Length == 1)
            {
                OrphanCredentialId = added[0];
                State = LabState.OrphanedCredential;
                _journal.Record(operationId, RecoveryOperation.Reconciliation,
                    State, RecoveryOutcome.Succeeded, credentialId: OrphanCredentialId);
                return;
            }

            if (added.Length == 0)
            {
                State = LabState.Ready;
                _journal.Record(operationId, RecoveryOperation.Reconciliation,
                    State, RecoveryOutcome.Succeeded, errorCode: "fake_inventory_confirms_no_new_id");
                return;
            }

            _journal.Record(operationId, RecoveryOperation.Reconciliation,
                State, RecoveryOutcome.Unknown, errorCode: "multiple_new_fake_ids");
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
            OrphanCredentialId is null)
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
        PendingCleanupCredentialId = Credential.CredentialId;
        Credential = null; // Revoke fake trust BEFORE any deletion attempt.
        State = LabState.RevokedCleanupPending;
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
            var inventory = SyntheticInventory.Validate(
                await _native.SimulateCredentialInventoryAsync(cancellationToken));
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
                return;
            }

            State = isOrphan ? LabState.OrphanedCredential : LabState.RevokedCleanupPending;
            _journal.Record(operationId, RecoveryOperation.Reconciliation, State,
                RecoveryOutcome.Succeeded, credentialId: id,
                errorCode: "fake_inventory_confirms_present_retry_allowed");
        }
        catch
        {
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Reconciliation, State,
                RecoveryOutcome.Unknown, credentialId: id,
                errorCode: "fake_inventory_reconciliation_failed");
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
        try
        {
            await _native.SimulatePlatformCredentialDeletionAsync(
                credentialId, cancellationToken);
            var inventory = SyntheticInventory.Validate(
                await _native.SimulateCredentialInventoryAsync(cancellationToken));
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
        }
        catch (FakeNativeFailureException error) when (error.OutcomeUnknown)
        {
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Unknown, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_response_lost");
            throw;
        }
        catch (FakeNativeFailureException error) when (!error.OutcomeUnknown)
        {
            // The fake adapter guarantees this failure occurred before deletion.
            State = isOrphan ? LabState.OrphanedCredential : LabState.RevokedCleanupPending;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Failed, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_confirmed_failure");
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
            throw;
        }
        catch
        {
            // A failed inventory after an acknowledged deletion is also ambiguous.
            State = isOrphan ? LabState.OrphanCleanupOutcomeUnknown : LabState.CleanupOutcomeUnknown;
            _journal.Record(operationId, RecoveryOperation.Cleanup, State,
                RecoveryOutcome.Unknown, credentialId: credentialId,
                cleanupAttempts: _cleanupAttempts, errorCode: "cleanup_unconfirmed");
            throw;
        }
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
