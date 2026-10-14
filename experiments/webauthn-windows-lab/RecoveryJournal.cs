namespace WebAuthn.WindowsLab;

internal enum RecoveryOperation
{
    None,
    Enrollment,
    Assertion,
    Cleanup,
    Reconciliation
}

internal enum RecoveryOutcome
{
    NotStarted,
    Started,
    Succeeded,
    Failed,
    Unknown
}

internal sealed record RecoveryJournalEntry(
    int SchemaVersion,
    long Revision,
    string OperationId,
    RecoveryOperation Operation,
    LabState State,
    RecoveryOutcome Outcome,
    string RpId,
    string Origin,
    string? CredentialId,
    int? Algorithm,
    string? PublicKeySha256,
    bool CancellationRequested,
    int CleanupAttempts,
    string? ErrorCode);

/// <summary>
/// Synthetic, process-local journal. It deliberately has no file or registry
/// persistence and must never be used as an authorization trust store.
/// </summary>
internal sealed class RecoveryJournal
{
    public const int CurrentSchemaVersion = 1;
    public const string TestRpId = "lab.example.test";
    public const string TestOrigin = "https://approval.lab.example.test";

    private readonly HashSet<string> _consumedChallenges =
        new(StringComparer.Ordinal);
    private readonly HashSet<string> _consumedNonces =
        new(StringComparer.Ordinal);
    private long _operationSequence;
    private long _revision;

    public RecoveryJournalEntry Current { get; private set; } = new(
        CurrentSchemaVersion, 0, "synthetic-op-000000", RecoveryOperation.None,
        LabState.Ready, RecoveryOutcome.NotStarted, TestRpId, TestOrigin,
        null, null, null, false, 0, null);

    public int ConsumedChallengeCount => _consumedChallenges.Count;
    public int ConsumedNonceCount => _consumedNonces.Count;

    public string Begin(RecoveryOperation operation, LabState state)
    {
        if (operation == RecoveryOperation.None)
            throw new ArgumentOutOfRangeException(nameof(operation));
        if (!CanBegin(operation, Current.State, state))
            throw new InvalidOperationException("fake_journal_invalid_operation_transition");
        var operationId = $"synthetic-op-{++_operationSequence:D6}";
        Update(operationId, operation, state, RecoveryOutcome.Started);
        return operationId;
    }

    public void Record(
        string operationId,
        RecoveryOperation operation,
        LabState state,
        RecoveryOutcome outcome,
        string? credentialId = null,
        int? algorithm = null,
        string? publicKeySha256 = null,
        bool cancellationRequested = false,
        int? cleanupAttempts = null,
        string? errorCode = null)
    {
        if (string.IsNullOrWhiteSpace(operationId))
            throw new ArgumentException("operation_id_required", nameof(operationId));
        if (!StringComparer.Ordinal.Equals(operationId, Current.OperationId) ||
            operation != Current.Operation ||
            !CanRecord(operation, Current.State, Current.Outcome, state, outcome))
            throw new InvalidOperationException("fake_journal_invalid_record_transition");
        Update(operationId, operation, state, outcome, credentialId, algorithm,
            publicKeySha256, cancellationRequested, cleanupAttempts, errorCode);
    }

    private static bool CanBegin(RecoveryOperation operation, LabState previous, LabState next) =>
        operation switch
        {
            RecoveryOperation.Enrollment => previous == LabState.Ready &&
                next == LabState.EnrollmentStarted,
            RecoveryOperation.Assertion => previous == LabState.CredentialPinnedInMemory &&
                next == LabState.AssertionStarted,
            RecoveryOperation.Cleanup =>
                (previous is LabState.CredentialPinnedInMemory or LabState.AssertionContractMatched &&
                    next == LabState.RevokedCleanupPending) ||
                (previous == next && next is
                    (LabState.RevokedCleanupPending or LabState.OrphanedCredential or LabState.CreatedUnpinned)),
            RecoveryOperation.Reconciliation => previous == next && next is
                (LabState.EnrollmentOutcomeUnknown or LabState.CleanupOutcomeUnknown or
                    LabState.OrphanCleanupOutcomeUnknown),
            _ => false
        };

    private static bool CanRecord(
        RecoveryOperation operation, LabState previous, RecoveryOutcome previousOutcome,
        LabState next, RecoveryOutcome outcome)
    {
        if (previousOutcome is not (RecoveryOutcome.Started or RecoveryOutcome.Succeeded))
            return false;
        return operation switch
        {
            RecoveryOperation.Enrollment =>
                (next == LabState.CreatedUnpinned && outcome is
                    RecoveryOutcome.Succeeded or RecoveryOutcome.Failed) ||
                (next == LabState.CredentialPinnedInMemory &&
                    previous == LabState.CreatedUnpinned && outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.OrphanedCredential && outcome is
                    RecoveryOutcome.Failed or RecoveryOutcome.Unknown) ||
                (next == LabState.EnrollmentOutcomeUnknown && outcome == RecoveryOutcome.Unknown) ||
                (next == LabState.Failed && outcome == RecoveryOutcome.Failed),
            RecoveryOperation.Assertion =>
                (next == LabState.AssertionContractMatched && outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.Cancelled && outcome == RecoveryOutcome.Unknown) ||
                (next == LabState.Failed && outcome == RecoveryOutcome.Failed),
            RecoveryOperation.Cleanup =>
                (next == LabState.RevokedCleanupPending && outcome is
                    RecoveryOutcome.Started or RecoveryOutcome.Failed) ||
                (next == LabState.OrphanedCredential && outcome == RecoveryOutcome.Failed) ||
                (next == LabState.Ready && outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.RevokedAndCleaned && outcome == RecoveryOutcome.Succeeded) ||
                (next is (LabState.CleanupOutcomeUnknown or LabState.OrphanCleanupOutcomeUnknown) &&
                    outcome == RecoveryOutcome.Unknown),
            RecoveryOperation.Reconciliation =>
                (next is (LabState.Ready or LabState.OrphanedCredential or
                    LabState.RevokedCleanupPending or LabState.RevokedAndCleaned) &&
                    outcome == RecoveryOutcome.Succeeded) ||
                (next is (LabState.EnrollmentOutcomeUnknown or LabState.CleanupOutcomeUnknown or
                    LabState.OrphanCleanupOutcomeUnknown) && outcome == RecoveryOutcome.Unknown),
            _ => false
        };
    }

    public bool TryConsume(string challengeId, string nonce)
    {
        if (string.IsNullOrWhiteSpace(challengeId) ||
            string.IsNullOrWhiteSpace(nonce))
            return false;
        lock (_consumedNonces)
        {
            if (_consumedChallenges.Contains(challengeId) ||
                _consumedNonces.Contains(nonce))
                return false;
            _consumedChallenges.Add(challengeId);
            _consumedNonces.Add(nonce);
            return true;
        }
    }

    private void Update(
        string operationId,
        RecoveryOperation operation,
        LabState state,
        RecoveryOutcome outcome,
        string? credentialId = null,
        int? algorithm = null,
        string? publicKeySha256 = null,
        bool cancellationRequested = false,
        int? cleanupAttempts = null,
        string? errorCode = null)
    {
        Current = new RecoveryJournalEntry(
            CurrentSchemaVersion,
            ++_revision,
            operationId,
            operation,
            state,
            outcome,
            TestRpId,
            TestOrigin,
            credentialId ?? Current.CredentialId,
            algorithm ?? Current.Algorithm,
            publicKeySha256 ?? Current.PublicKeySha256,
            cancellationRequested,
            cleanupAttempts ?? Current.CleanupAttempts,
            errorCode);
    }
}
