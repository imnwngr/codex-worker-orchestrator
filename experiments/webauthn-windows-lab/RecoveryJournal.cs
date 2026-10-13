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
        Update(operationId, operation, state, outcome, credentialId, algorithm,
            publicKeySha256, cancellationRequested, cleanupAttempts, errorCode);
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
