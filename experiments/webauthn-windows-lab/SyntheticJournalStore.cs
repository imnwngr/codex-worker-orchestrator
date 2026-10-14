namespace WebAuthn.WindowsLab;

internal enum SyntheticWriteFault
{
    None,
    CrashBeforeInitiation,
    CrashAfterInitiation,
    ResultReturnedBeforeJournalUpdate,
    TornWrite
}
internal enum SyntheticStoreResult { Committed, Unknown, StaleRevision, InvalidRecord }

/// <summary>
/// Deterministic in-memory simulation of an atomic durable-store contract.
/// It is neither actual persistence nor tamper-resistant storage.
/// </summary>
internal sealed class SyntheticJournalStore
{
    public const int MaximumHistory = 256;
    private readonly object _sync = new();
    private readonly List<RecoveryJournalEntry> _history = [];
    private readonly HashSet<string> _challengeIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
    private long _operationSequence;

    public long Revision { get; private set; }
    public RecoveryJournalEntry? Current { get; private set; }
    public bool ReplayContinuityEstablished { get; private set; } = true;
    public int ConsumedChallengeCount { get { lock (_sync) return _challengeIds.Count; } }
    public int ConsumedNonceCount { get { lock (_sync) return _nonces.Count; } }
    public IReadOnlyList<RecoveryJournalEntry> History { get { lock (_sync) return _history.ToArray(); } }

    public SyntheticStoreResult Commit(long expectedRevision, RecoveryJournalEntry entry,
        SyntheticWriteFault fault = SyntheticWriteFault.None,
        bool continuationOfCurrentOperation = false)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_sync)
        {
            if (fault is SyntheticWriteFault.CrashBeforeInitiation or
                SyntheticWriteFault.ResultReturnedBeforeJournalUpdate)
                return SyntheticStoreResult.Unknown;
            if (expectedRevision != Revision) return SyntheticStoreResult.StaleRevision;
            var operationIdReused = _history.Any(old =>
                StringComparer.Ordinal.Equals(old.OperationId, entry.OperationId)) &&
                !(continuationOfCurrentOperation && Current is not null &&
                    StringComparer.Ordinal.Equals(Current.OperationId, entry.OperationId));
            var sequenceValid = TryOperationSequence(entry.OperationId, out var sequence) &&
                (continuationOfCurrentOperation
                    ? Current is not null && Current.OperationId == entry.OperationId && sequence == _operationSequence
                    : sequence > _operationSequence);
            // The storage boundary validates the *same* transition policy as the
            // workflow. A caller cannot bypass it by setting continuation=true.
            var transitionValid = Current is null
                ? !continuationOfCurrentOperation && sequence == 1 &&
                    entry.Operation == RecoveryOperation.Enrollment &&
                    entry.State == LabState.EnrollmentStarted &&
                    entry.Outcome == RecoveryOutcome.Started
                : continuationOfCurrentOperation
                    ? entry.Operation == Current.Operation &&
                        RecoveryJournal.CanRecord(Current.Operation, Current.State,
                            Current.Outcome, entry.State, entry.Outcome)
                    : entry.Outcome == RecoveryOutcome.Started &&
                        RecoveryJournal.CanBegin(entry.Operation, Current.State, entry.State);
            if (!IsValid(entry) || entry.Revision != Revision + 1 || operationIdReused ||
                !sequenceValid || !transitionValid)
                return SyntheticStoreResult.InvalidRecord;
            // Crash-after-initiation stores an explicit Started record so restore
            // can classify the in-flight operation as unknown. Torn writes never
            // publish a partial record because publication is one locked commit.
            if (fault == SyntheticWriteFault.TornWrite) return SyntheticStoreResult.Unknown;
            _history.Add(entry);
            if (_history.Count > MaximumHistory) _history.RemoveAt(0);
            Current = entry;
            Revision = entry.Revision;
            if (sequence > _operationSequence) _operationSequence = sequence;
            return fault == SyntheticWriteFault.CrashAfterInitiation
                ? SyntheticStoreResult.Unknown : SyntheticStoreResult.Committed;
        }
    }

    public SyntheticStoreResult Restore(RecoveryJournalEntry? snapshot)
    {
        lock (_sync)
        {
            if (snapshot is null || !IsValid(snapshot) || snapshot.Revision < Revision)
                return SyntheticStoreResult.InvalidRecord;
            if (Current is null && Revision == 0)
            {
                // Importing an arbitrary terminal state as a new store would
                // fabricate history. Only an initial, in-flight record can be
                // transferred without a validated history; all later phases
                // require sharing the already established synthetic store.
                if (snapshot.Revision != 1 ||
                    snapshot.OperationId != "synthetic-op-000001" ||
                    snapshot.Operation != RecoveryOperation.Enrollment ||
                    snapshot.State != LabState.EnrollmentStarted ||
                    snapshot.Outcome != RecoveryOutcome.Started)
                    return SyntheticStoreResult.InvalidRecord;
                Current = snapshot;
                Revision = snapshot.Revision;
                if (TryOperationSequence(snapshot.OperationId, out var restoredSequence))
                    _operationSequence = restoredSequence;
                _history.Add(snapshot);
                return SyntheticStoreResult.Committed;
            }
            if (snapshot.Revision == Revision && Current is not null && snapshot != Current)
                return SyntheticStoreResult.InvalidRecord;
            if (snapshot.Revision > Revision)
                return SyntheticStoreResult.StaleRevision;
            return SyntheticStoreResult.Committed;
        }
    }

    public bool TryConsume(string challengeId, string nonce)
    {
        if (string.IsNullOrWhiteSpace(challengeId) || string.IsNullOrWhiteSpace(nonce)) return false;
        lock (_sync)
        {
            // A ledger whose continuity was lost cannot claim fresh one-use
            // consumption. A separate fresh store still demonstrates why
            // lost history is not durable replay protection.
            if (!ReplayContinuityEstablished) return false;
            if (!_challengeIds.Add(challengeId)) return false;
            if (!_nonces.Add(nonce)) { _challengeIds.Remove(challengeId); return false; }
            return true;
        }
    }

    public void MarkReplayLedgerReplaced()
    {
        lock (_sync) ReplayContinuityEstablished = false;
    }

    private static bool IsValid(RecoveryJournalEntry entry) =>
        entry.SchemaVersion == RecoveryJournal.CurrentSchemaVersion && entry.Revision > 0 &&
        TryOperationSequence(entry.OperationId, out _) &&
        entry.RpId == RecoveryJournal.TestRpId && entry.Origin == RecoveryJournal.TestOrigin &&
        Enum.IsDefined(entry.Operation) && Enum.IsDefined(entry.State) && Enum.IsDefined(entry.Outcome) &&
        entry.CleanupAttempts >= 0 && entry.Operation != RecoveryOperation.None;

    private static bool TryOperationSequence(string operationId, out long sequence)
    {
        const string prefix = "synthetic-op-";
        sequence = 0;
        if (!operationId.StartsWith(prefix, StringComparison.Ordinal) ||
            operationId.Length != prefix.Length + 6)
            return false;
        var digits = operationId.AsSpan(prefix.Length);
        foreach (var digit in digits)
            if (digit < '0' || digit > '9') return false;
        return long.TryParse(digits, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out sequence) && sequence > 0;
    }

}
