namespace WebAuthn.WindowsLab;

internal interface IFakeNativeWebAuthn
{
    Task<FakeRegistrationResult> SimulateRegistrationAsync(
        CancellationToken cancellationToken);

    Task<FakeAssertionResult> SimulateAssertionAsync(
        string challenge,
        string origin,
        long expiresAtUnixMilliseconds,
        string nonce,
        TestCredential credential,
        CancellationToken cancellationToken);

    Task SimulatePlatformCredentialDeletionAsync(
        string credentialId,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<string>> SimulateCredentialInventoryAsync(
        CancellationToken cancellationToken);
}

internal sealed class FakeNativeFailureException : Exception
{
    public FakeNativeFailureException(
        string message,
        string? orphanCredentialId = null,
        bool outcomeUnknown = false)
        : base(message)
    {
        OrphanCredentialId = orphanCredentialId;
        OutcomeUnknown = outcomeUnknown;
    }

    public string? OrphanCredentialId { get; }
    public bool OutcomeUnknown { get; }
}

internal sealed class FakeNativeBuffer : IDisposable
{
    private static int _outstanding;
    private readonly byte[] _bytes;
    private bool _disposed;

    public FakeNativeBuffer(ReadOnlySpan<byte> bytes)
    {
        _bytes = bytes.ToArray();
        Interlocked.Increment(ref _outstanding);
    }

    public static int Outstanding => Volatile.Read(ref _outstanding);

    public byte[] Copy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _bytes.ToArray();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Interlocked.Decrement(ref _outstanding);
    }
}

internal sealed class FakeRegistrationResult : IDisposable
{
    public FakeRegistrationResult(byte[] credentialId, byte[] coseKey)
    {
        CredentialId = new FakeNativeBuffer(credentialId);
        CoseKey = new FakeNativeBuffer(coseKey);
    }

    public FakeNativeBuffer CredentialId { get; }
    public FakeNativeBuffer CoseKey { get; }

    public void Dispose()
    {
        CredentialId.Dispose();
        CoseKey.Dispose();
    }
}

internal sealed record FakeAssertionPayload(
    byte[] CredentialId,
    int Algorithm,
    string PublicKeySha256,
    byte[] ClientDataJson,
    long ExpiresAtUnixMilliseconds,
    string Nonce);

internal sealed class FakeAssertionResult : IDisposable
{
    public FakeAssertionResult(FakeAssertionPayload payload)
    {
        CredentialId = new FakeNativeBuffer(payload.CredentialId);
        ClientDataJson = new FakeNativeBuffer(payload.ClientDataJson);
        Algorithm = payload.Algorithm;
        PublicKeySha256 = payload.PublicKeySha256;
        ExpiresAtUnixMilliseconds = payload.ExpiresAtUnixMilliseconds;
        Nonce = payload.Nonce;
    }

    public FakeNativeBuffer CredentialId { get; }
    public FakeNativeBuffer ClientDataJson { get; }
    public int Algorithm { get; }
    public string PublicKeySha256 { get; }
    public long ExpiresAtUnixMilliseconds { get; }
    public string Nonce { get; }

    public FakeAssertionPayload Copy()
    {
        return new FakeAssertionPayload(
            CredentialId.Copy(), Algorithm, PublicKeySha256, ClientDataJson.Copy(),
            ExpiresAtUnixMilliseconds, Nonce);
    }

    public void Dispose()
    {
        CredentialId.Dispose();
        ClientDataJson.Dispose();
    }
}

internal sealed class FakeNativeWebAuthn : IFakeNativeWebAuthn
{
    private readonly HashSet<string> _fakePlatformCredentialIds =
        new(StringComparer.Ordinal);
    private int _nextId = 1;

    public bool FailRegistration { get; set; }
    public bool CreateOrphanThenFail { get; set; }
    public bool RegistrationOutcomeUnknown { get; set; }
    public bool UnknownOutcomeCreatesCredential { get; set; } = true;
    public bool ReturnMalformedCose { get; set; }
    public Action? AfterRegistrationCreated { get; set; }
    public bool FailAssertion { get; set; }
    public bool FailDeletion { get; set; }
    public bool DeleteThenLoseResponse { get; set; }
    public bool DeleteUnknownWithoutEffect { get; set; }
    public bool FailNextInventory { get; set; }
    public bool CancelAfterDeletion { get; set; }
    public int DeletionCalls { get; private set; }
    public IReadOnlyCollection<string> FakeCredentialIds => _fakePlatformCredentialIds;

    public Task<FakeRegistrationResult> SimulateRegistrationAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var idBytes = System.Text.Encoding.ASCII.GetBytes(
            $"fake-credential-{_nextId++:D4}");
        var id = Convert.ToBase64String(idBytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _fakePlatformCredentialIds.Add(id);
        AfterRegistrationCreated?.Invoke();

        if (RegistrationOutcomeUnknown)
        {
            RegistrationOutcomeUnknown = false;
            if (!UnknownOutcomeCreatesCredential)
                _fakePlatformCredentialIds.Remove(id);
            throw new FakeNativeFailureException(
                "Simulated registration with unknown outcome.",
                outcomeUnknown: true);
        }

        if (CreateOrphanThenFail)
        {
            CreateOrphanThenFail = false;
            throw new FakeNativeFailureException(
                "Simulated lost registration response.", id);
        }
        if (FailRegistration)
        {
            FailRegistration = false;
            _fakePlatformCredentialIds.Remove(id);
            throw new FakeNativeFailureException("Simulated registration failure.");
        }

        return Task.FromResult(new FakeRegistrationResult(
            idBytes, ReturnMalformedCose
                ? new byte[] { 0xa1, 0x01 }
                : SyntheticCbor.Es256Key()));
    }

    public Task<FakeAssertionResult> SimulateAssertionAsync(
        string challenge,
        string origin,
        long expiresAtUnixMilliseconds,
        string nonce,
        TestCredential credential,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (FailAssertion)
        {
            FailAssertion = false;
            throw new FakeNativeFailureException("Simulated assertion failure.");
        }
        var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "webauthn.get",
            challenge,
            origin
        });
        return Task.FromResult(new FakeAssertionResult(new FakeAssertionPayload(
            Convert.FromBase64String(credential.CredentialId.Replace('-', '+')
                .Replace('_', '/') + new string('=', (4 - credential.CredentialId.Length % 4) % 4)),
            credential.Algorithm,
            credential.PublicKeySha256,
            json,
            expiresAtUnixMilliseconds,
            nonce)));
    }

    public Task SimulatePlatformCredentialDeletionAsync(
        string credentialId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (FailDeletion)
        {
            FailDeletion = false;
            throw new FakeNativeFailureException("Simulated cleanup failure.");
        }
        DeletionCalls++;
        if (DeleteUnknownWithoutEffect)
        {
            DeleteUnknownWithoutEffect = false;
            throw new FakeNativeFailureException(
                "Simulated delete response lost without changing the fake inventory.",
                outcomeUnknown: true);
        }
        if (DeleteThenLoseResponse)
        {
            DeleteThenLoseResponse = false;
            _fakePlatformCredentialIds.Remove(credentialId);
            throw new FakeNativeFailureException(
                "Simulated delete succeeded but response was lost.",
                outcomeUnknown: true);
        }
        _fakePlatformCredentialIds.Remove(credentialId);
        if (CancelAfterDeletion)
        {
            CancelAfterDeletion = false;
            throw new OperationCanceledException("Synthetic deletion completed before cancellation.");
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<string>> SimulateCredentialInventoryAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (FailNextInventory)
        {
            FailNextInventory = false;
            throw new FakeNativeFailureException("Synthetic inventory unavailable.", outcomeUnknown: true);
        }
        return Task.FromResult<IReadOnlyCollection<string>>(
            _fakePlatformCredentialIds.ToArray());
    }
}
