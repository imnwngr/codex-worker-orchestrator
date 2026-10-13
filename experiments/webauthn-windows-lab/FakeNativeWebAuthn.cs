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
}

internal sealed class FakeNativeFailureException : Exception
{
    public FakeNativeFailureException(string message, string? orphanCredentialId = null)
        : base(message) => OrphanCredentialId = orphanCredentialId;

    public string? OrphanCredentialId { get; }
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
    public bool FailAssertion { get; set; }
    public bool FailDeletion { get; set; }
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
            idBytes, SyntheticCbor.Es256Key()));
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
        _fakePlatformCredentialIds.Remove(credentialId);
        return Task.CompletedTask;
    }
}
