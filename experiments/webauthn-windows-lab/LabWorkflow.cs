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
    RevokedAndCleaned
}

internal sealed record TestCredential(
    string CredentialId,
    int Algorithm,
    string PublicKeySha256);

internal sealed class LabWorkflow
{
    private readonly IFakeNativeWebAuthn _native;
    private readonly FakeAssertionGate _gate;

    public LabWorkflow(
        IFakeNativeWebAuthn native,
        FakeAssertionGate gate)
    {
        _native = native;
        _gate = gate;
    }

    public LabState State { get; private set; } = LabState.Ready;
    public TestCredential? Credential { get; private set; }
    public string? OrphanCredentialId { get; private set; }
    public string? PendingCleanupCredentialId { get; private set; }

    public async Task EnrollAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.Ready)
            throw new InvalidOperationException("Enrollment requires Ready state.");
        State = LabState.EnrollmentStarted;
        try
        {
            using var result = await _native.SimulateRegistrationAsync(cancellationToken);
            var idBytes = result.CredentialId.Copy();
            if (idBytes.Length is < 16 or > 512)
                throw new InvalidDataException("credential_id_length");
            var coseBytes = result.CoseKey.Copy();
            var parsed = CoseKeyParser.Parse(coseBytes);
            var id = Convert.ToBase64String(idBytes).TrimEnd('=')
                .Replace('+', '-').Replace('/', '_');
            Credential = new TestCredential(id, parsed.Algorithm, parsed.PublicKeySha256);
            State = LabState.CredentialPinnedInMemory;
        }
        catch (OperationCanceledException)
        {
            State = LabState.Cancelled;
            throw;
        }
        catch (FakeNativeFailureException error) when (error.OrphanCredentialId is not null)
        {
            OrphanCredentialId = error.OrphanCredentialId;
            State = LabState.OrphanedCredential;
            throw;
        }
        catch
        {
            State = LabState.Failed;
            throw;
        }
    }

    public async Task RecoverOrphanAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.OrphanedCredential || OrphanCredentialId is null)
            throw new InvalidOperationException("No simulated orphan is available.");
        try
        {
            await _native.SimulatePlatformCredentialDeletionAsync(
                OrphanCredentialId, cancellationToken);
            OrphanCredentialId = null;
            State = LabState.Ready;
        }
        catch (OperationCanceledException)
        {
            State = LabState.OrphanedCredential;
            throw;
        }
        catch
        {
            State = LabState.OrphanedCredential;
            throw;
        }
    }

    public async Task<FakeGateResult> RunAssertionAsync(
        string challenge,
        string origin,
        long expiry,
        string nonce,
        long now,
        CancellationToken cancellationToken)
    {
        if (State != LabState.CredentialPinnedInMemory || Credential is null)
            throw new InvalidOperationException("Assertion requires an in-memory fake credential.");
        State = LabState.AssertionStarted;
        try
        {
            using var result = await _native.SimulateAssertionAsync(
                challenge, origin, expiry, nonce, Credential, cancellationToken);
            var payload = result.Copy();
            var gateResult = _gate.Evaluate(Credential, payload, challenge, origin, now);
            State = LabState.AssertionContractMatched;
            return gateResult;
        }
        catch (OperationCanceledException)
        {
            State = LabState.Cancelled;
            throw;
        }
        catch
        {
            State = LabState.Failed;
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
        await RetryFakeCleanupAsync(cancellationToken);
    }

    public async Task RetryFakeCleanupAsync(CancellationToken cancellationToken)
    {
        if (State != LabState.RevokedCleanupPending || PendingCleanupCredentialId is null)
            throw new InvalidOperationException("No revoked fake credential needs cleanup.");
        try
        {
            await _native.SimulatePlatformCredentialDeletionAsync(
                PendingCleanupCredentialId, cancellationToken);
            PendingCleanupCredentialId = null;
            State = LabState.RevokedAndCleaned;
        }
        catch
        {
            // Retain the fake ID for an explicit retry. Never restore trust.
            State = LabState.RevokedCleanupPending;
            throw;
        }
    }
}

internal sealed record FakeGateResult(string Outcome, string Nonce);

internal sealed class FakeAssertionGate
{
    private readonly HashSet<string> _usedNonces = new(StringComparer.Ordinal);

    public FakeGateResult Evaluate(
        TestCredential trusted,
        FakeAssertionPayload assertion,
        string expectedChallenge,
        string expectedOrigin,
        long now)
    {
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
        if (!_usedNonces.Add(assertion.Nonce))
            throw new InvalidDataException("challenge_replayed");

        // This is a field-contract result only. No signature exists or is checked.
        return new FakeGateResult(
            $"Fake fields matched; preserved {client.OriginalBytes.Length} JSON bytes.",
            assertion.Nonce);
    }
}
