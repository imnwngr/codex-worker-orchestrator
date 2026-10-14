using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WebAuthn.WindowsLab;

internal static class LabTests
{
    private static readonly List<(string Name, Func<Task> Run)> Tests =
    [
        ("x64 native structure sizes, offsets, and pointer width", AbiLayouts),
        ("header API versions select only their mapped structure versions", ApiVersions),
        ("WINAPI metadata and HRESULT interpretation are exact", CallingConventionAndHResult),
        ("duplicate clientDataJSON properties are rejected", DuplicateClientData),
        ("challenge and origin are exact and raw bytes are preserved", ExactClientData),
        ("truncated, malformed, oversized, and trailing CBOR are rejected", MalformedCbor),
        ("ES256 and RS256 COSE shapes are accepted", SupportedCose),
        ("unsupported algorithm, curve, and malformed key sizes are rejected", InvalidCose),
        ("fake native buffers are copied and released exactly once", FakeOwnership),
        ("fake registration cancellation and failure are deterministic", RegistrationFailures),
        ("an interrupted fake registration is orphaned and recoverable", OrphanRecovery),
        ("fake assertion ID, algorithm, key, expiry, and replay checks fail closed", AssertionChecks),
        ("fake revocation precedes cleanup and survives cleanup failure", CleanupFailure),
        ("completed fake assertions can be revoked and cleaned", CleanupAfterAssertion),
        ("displayed task text and effective UTF-8 hash use normalized bytes", TaskBytes),
        ("unknown enrollment outcome blocks until inventory reconciliation", UnknownEnrollment),
        ("created but unpinned fake credential is retained and recoverable", CreatedUnpinned),
        ("cancellation racing with success preserves the returned credential", CancellationRace),
        ("cleanup response loss requires inventory reconciliation", CleanupOutcomeUnknown),
        ("shared journal rejects replay across gate instances", ReplayAcrossGates),
        ("a fresh journal does not claim durable replay protection", ReplayWithFreshJournal),
        ("fixed test origin cannot be overridden", FixedOrigin),
        ("orphan cleanup response loss remains blocked until reconciliation", OrphanCleanupUnknown),
        ("cancellation during cleanup remains unknown until reconciliation", CleanupCancellationUnknown),
        ("reconciliation returning an error remains unknown", ReconciliationFailure),
        ("incompatible gate and workflow journals are rejected", MismatchedJournals),
        ("failed fake enrollment reconciliation remains unknown", EnrollmentReconciliationFailure),
        ("parallel fake replay attempts consume one nonce once", ConcurrentFakeConsumption),
        ("unknown deletion that did not take effect requires reconciliation before retry", CleanupUnknownStillPresent),
        ("duplicate inventory identity blocks unknown enrollment reconciliation", DuplicateInventory),
        ("malformed inventory blocks cleanup confirmation", MalformedCleanupInventory),
        ("duplicate inventory blocks cleanup confirmation", DuplicateCleanupInventory),
        ("oversized inventory is rejected by synthetic validator", OversizedInventory),
        ("recovery journal rejects forged operations and invalid outcomes", JournalRejectsInvalidTransitions)
    ];

    public static int Count => Tests.Count;

    public static async Task<int> RunAsync()
    {
        var failures = 0;
        foreach (var (name, run) in Tests)
        {
            try
            {
                await run();
                Console.WriteLine($"PASS {name}");
            }
            catch (Exception error)
            {
                failures++;
                Console.Error.WriteLine($"FAIL {name}: {error.Message}");
            }
        }
        return failures;
    }

    private static Task AbiLayouts()
    {
        Equal(8, IntPtr.Size, "Project must run as x64.");
        Layout<AbiRpEntityV1>(32, ("Version", 0), ("Id", 8), ("Name", 16), ("Icon", 24));
        Layout<AbiUserEntityV1>(40, ("Version", 0), ("IdLength", 4), ("Id", 8),
            ("Name", 16), ("Icon", 24), ("DisplayName", 32));
        Layout<AbiClientDataV1>(24, ("Version", 0), ("JsonLength", 4),
            ("Json", 8), ("HashAlgorithm", 16));
        Layout<AbiCoseCredentialParameterV1>(24, ("Version", 0),
            ("CredentialType", 8), ("Algorithm", 16));
        Layout<AbiCoseCredentialParameters>(16, ("Count", 0), ("Parameters", 8));
        Layout<AbiCredentialV1>(24, ("Version", 0), ("IdLength", 4),
            ("Id", 8), ("CredentialType", 16));
        Layout<AbiCredentials>(16, ("Count", 0), ("Credentials", 8));
        Layout<AbiExtension>(24, ("Identifier", 0), ("Length", 8), ("Value", 16));
        Layout<AbiExtensions>(16, ("Count", 0), ("Extensions", 8));
        Layout<AbiMakeCredentialOptionsV1>(64, ("Version", 0),
            ("TimeoutMilliseconds", 4), ("ExcludeCredentials", 8),
            ("Extensions", 24), ("AuthenticatorAttachment", 40),
            ("RequireResidentKey", 44), ("UserVerificationRequirement", 48),
            ("AttestationConveyancePreference", 52), ("Flags", 56));
        Layout<AbiGetAssertionOptionsV1>(56, ("Version", 0),
            ("TimeoutMilliseconds", 4), ("Credentials", 8), ("Extensions", 24),
            ("AuthenticatorAttachment", 40), ("UserVerificationRequirement", 44),
            ("Flags", 48));
        Layout<AbiCredentialAttestationV1>(96, ("Version", 0), ("FormatType", 8),
            ("AuthenticatorDataLength", 16), ("AuthenticatorData", 24),
            ("AttestationLength", 32), ("Attestation", 40), ("DecodeType", 48),
            ("DecodedAttestation", 56), ("AttestationObjectLength", 64),
            ("AttestationObject", 72), ("CredentialIdLength", 80), ("CredentialId", 88));
        Layout<AbiAssertionV1>(72, ("Version", 0), ("AuthenticatorDataLength", 4),
            ("AuthenticatorData", 8), ("SignatureLength", 16), ("Signature", 24),
            ("Credential", 32), ("UserIdLength", 56), ("UserId", 64));
        Equal(4, Marshal.SizeOf<int>(), "BOOL/LONG snapshots are 32-bit.");
        return Task.CompletedTask;
    }

    private static Task ApiVersions()
    {
        var v1 = NativeApiProfile.ForHeaderVersion(1);
        Equal((uint)3, v1.MakeCredentialOptionsVersion, "API 1 make options version.");
        Equal((uint)4, v1.GetAssertionOptionsVersion, "API 1 get options version.");
        Equal((uint)3, v1.AttestationVersion, "API 1 attestation version.");
        Equal((uint)1, v1.AssertionVersion, "API 1 assertion version.");

        var v9 = NativeApiProfile.ForHeaderVersion(9);
        True(v9.SupportsStructureVersions(9, 9, 8, 6),
            "API 9 structure mapping must match the installed header.");
        True(!v1.SupportsStructureVersions(9, 9, 8, 6),
            "A newer structure set must not be accepted for API 1.");
        Throws<NotSupportedException>(() => NativeApiProfile.ForHeaderVersion(0));
        Throws<NotSupportedException>(() => NativeApiProfile.ForHeaderVersion(10));
        return Task.CompletedTask;
    }

    private static Task CallingConventionAndHResult()
    {
        Equal(CallingConvention.Winapi, NativeAbiContract.CallingConvention,
            "Header declares WINAPI.");
        True(NativeAbiContract.HResultSucceeded(0), "S_OK must succeed.");
        True(!NativeAbiContract.HResultSucceeded(1), "Positive nonzero HRESULT fails.");
        True(!NativeAbiContract.HResultSucceeded(unchecked((int)0x80004005)),
            "Failure HRESULT fails.");
        Equal(NativeResultOwnership.CallerOwnedForCall,
            NativeAbiContract.InputBufferOwnership, "Input ownership metadata.");
        Equal(NativeResultOwnership.ApiOwnedUntilMatchingFreeFunction,
            NativeAbiContract.ReturnedResultOwnership, "Output ownership metadata.");
        return Task.CompletedTask;
    }

    private static Task DuplicateClientData()
    {
        var duplicate = Encoding.UTF8.GetBytes(
            "{\"type\":\"webauthn.get\",\"type\":\"webauthn.create\"," +
            "\"challenge\":\"c\",\"origin\":\"https://approval.lab.example.test\"}");
        Throws<InvalidDataException>(() => StrictClientData.Parse(
            duplicate, "webauthn.get", "c", StrictClientData.TestOrigin));
        return Task.CompletedTask;
    }

    private static Task ExactClientData()
    {
        var raw = Encoding.UTF8.GetBytes(
            "{ \"origin\":\"https://approval.lab.example.test\", " +
            "\"challenge\":\"abc_123\", \"type\":\"webauthn.get\" }");
        var parsed = StrictClientData.Parse(
            raw, "webauthn.get", "abc_123", StrictClientData.TestOrigin);
        SequenceEqual(raw, parsed.OriginalBytes, "Original JSON bytes must be retained.");
        Throws<InvalidDataException>(() => StrictClientData.Parse(
            raw, "webauthn.get", "ABC_123", StrictClientData.TestOrigin));
        Throws<InvalidDataException>(() => StrictClientData.Parse(
            raw, "webauthn.get", "abc_123", "https://other.example.test"));
        return Task.CompletedTask;
    }

    private static Task MalformedCbor()
    {
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] { 0x58 }));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] { 0x9f, 0xff }));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] { 0xa2, 0x01, 0x00, 0x01, 0x01 }));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] { 0x00, 0x00 }));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[BoundedCborReader.MaximumInputBytes + 1]));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] {
                0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0 }));
        Throws<InvalidDataException>(() =>
            BoundedCborReader.ReadSingle(new byte[] {
                0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0 }));
        Throws<InvalidDataException>(() =>
            CoseKeyParser.Parse(SyntheticCbor.EncodeMap(
                (1, 2), (3, -7), (-1, 1), (-2, new byte[31]), (-3, new byte[32]))));
        return Task.CompletedTask;
    }

    private static Task SupportedCose()
    {
        var es = CoseKeyParser.Parse(SyntheticCbor.Es256Key());
        Equal(-7, es.Algorithm, "Expected ES256.");
        Equal("P-256", es.Curve, "Expected P-256.");
        Equal(64, es.PublicKeySha256.Length, "Expected SHA-256 fingerprint.");

        var rs = CoseKeyParser.Parse(SyntheticCbor.Rs256Key());
        Equal(-257, rs.Algorithm, "Expected RS256.");
        Equal("RSA", rs.KeyType, "Expected RSA.");
        return Task.CompletedTask;
    }

    private static Task InvalidCose()
    {
        Throws<InvalidDataException>(() => CoseKeyParser.Parse(
            SyntheticCbor.EncodeMap((1, 2), (3, -8), (-1, 1),
                (-2, new byte[32]), (-3, new byte[32]))));
        Throws<InvalidDataException>(() => CoseKeyParser.Parse(
            SyntheticCbor.EncodeMap((1, 2), (3, -7), (-1, 2),
                (-2, new byte[32]), (-3, new byte[32]))));
        Throws<InvalidDataException>(() => CoseKeyParser.Parse(
            SyntheticCbor.EncodeMap((1, 3), (3, -257),
                (-1, new byte[128]), (-2, new byte[] { 1, 0, 1 }))));
        Throws<InvalidDataException>(() => CoseKeyParser.Parse(
            SyntheticCbor.EncodeMap((1, 2), (3, -7), (-1, 1),
                (-2, new byte[32]), (-3, new byte[32]), (4, new byte[] { 1 }))));
        return Task.CompletedTask;
    }

    private static async Task FakeOwnership()
    {
        Equal(0, FakeNativeBuffer.Outstanding, "No fake buffers should be outstanding.");
        var native = new FakeNativeWebAuthn();
        byte[] copiedId;
        using (var result = await native.SimulateRegistrationAsync(default))
        {
            copiedId = result.CredentialId.Copy();
            True(FakeNativeBuffer.Outstanding >= 2, "Fake result owns allocated buffers.");
        }
        Equal(0, FakeNativeBuffer.Outstanding, "Disposal releases both fake buffers.");
        True(copiedId.Length >= 16, "Copied bytes survive result disposal.");
    }

    private static async Task RegistrationFailures()
    {
        var canceledNative = new FakeNativeWebAuthn();
        var canceledWorkflow = new LabWorkflow(canceledNative, new FakeAssertionGate());
        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            await ThrowsAsync<OperationCanceledException>(() =>
                canceledWorkflow.EnrollAsync(cancellation.Token));
        }
        Equal(LabState.Cancelled, canceledWorkflow.State, "Cancellation state.");
        Equal(RecoveryOutcome.NotStarted, canceledWorkflow.Journal.Current.Outcome,
            "Pre-cancelled enrollment is explicitly not started.");

        var failedNative = new FakeNativeWebAuthn { FailRegistration = true };
        var failedWorkflow = new LabWorkflow(failedNative, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() =>
            failedWorkflow.EnrollAsync(default));
        Equal(LabState.Failed, failedWorkflow.State, "Failure state.");
        True(failedWorkflow.Credential is null, "Failed enrollment is not pinned.");
    }

    private static async Task OrphanRecovery()
    {
        var native = new FakeNativeWebAuthn { CreateOrphanThenFail = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.EnrollAsync(default));
        Equal(LabState.OrphanedCredential, workflow.State, "Orphan state.");
        True(workflow.OrphanCredentialId is not null, "Fake orphan ID is retained in memory.");
        await workflow.RecoverOrphanAsync(default);
        Equal(LabState.Ready, workflow.State, "Recovery returns to Ready.");
        Equal(0, native.FakeCredentialIds.Count, "Fake cleanup removed the orphan.");
    }

    private static async Task AssertionChecks()
    {
        var native = new FakeNativeWebAuthn();
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        var credential = workflow.Credential!;
        var now = 1800000000000;
        const string challenge = "one-use-test-challenge";
        const string nonce = "one-use-test-nonce";

        var accepted = await workflow.RunAssertionAsync(
            challenge, StrictClientData.TestOrigin, now + 1000, nonce, now, default);
        True(accepted.Outcome.Contains("Fake fields matched", StringComparison.Ordinal),
            "Outcome must remain expressly fake.");
        Equal(LabState.AssertionContractMatched, workflow.State, "Fake matched state.");

        var gate = new FakeAssertionGate();
        var goodPayload = new FakeAssertionPayload(
            DecodeBase64Url(credential.CredentialId), credential.Algorithm,
            credential.PublicKeySha256,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get", challenge, origin = StrictClientData.TestOrigin
            }),
            now + 1000, nonce);

        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, goodPayload with { CredentialId = new byte[20] },
            challenge, StrictClientData.TestOrigin, now));
        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, goodPayload with { Algorithm = -257 },
            challenge, StrictClientData.TestOrigin, now));
        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, goodPayload with { PublicKeySha256 = new string('0', 64) },
            challenge, StrictClientData.TestOrigin, now));
        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, goodPayload with { ExpiresAtUnixMilliseconds = now },
            challenge, StrictClientData.TestOrigin, now));
        _ = gate.Evaluate(credential, goodPayload, challenge,
            StrictClientData.TestOrigin, now);
        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, goodPayload, challenge, StrictClientData.TestOrigin, now));
    }

    private static async Task CleanupFailure()
    {
        var native = new FakeNativeWebAuthn { FailDeletion = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        Equal(LabState.RevokedCleanupPending, workflow.State,
            "Trust is revoked even when fake cleanup fails.");
        True(workflow.Credential is null, "Credential is no longer trusted.");
        True(workflow.PendingCleanupCredentialId is not null,
            "Pending fake credential ID must be retained for recovery.");
        await workflow.RetryFakeCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Explicit fake cleanup retry transitions to cleaned.");
        True(workflow.PendingCleanupCredentialId is null,
            "Completed cleanup clears its fake recovery ID.");
        Equal(0, native.FakeCredentialIds.Count, "Explicit fake cleanup recovery.");
    }

    private static async Task CleanupAfterAssertion()
    {
        var native = new FakeNativeWebAuthn();
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        var now = 1800000000000;
        await workflow.RunAssertionAsync("test-challenge", StrictClientData.TestOrigin,
            now + 1000, "unique-nonce", now, default);
        Equal(LabState.AssertionContractMatched, workflow.State,
            "Fake assertion must complete before cleanup.");
        await workflow.RevokeAndCleanFakeAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Fake credential can be cleaned after successful contract matching.");
        Equal(0, native.FakeCredentialIds.Count,
            "Fake authenticator contains no credential after cleanup.");
    }

    private static Task TaskBytes()
    {
        const string raw = "\uFEFF \r\n task content \t\u00A0";
        var binding = TaskByteBindingFactory.Create(raw);
        Equal("task content", binding.DisplayedEffectiveText, "Displayed effective task.");
        SequenceEqual(Encoding.UTF8.GetBytes("task content"), binding.EffectiveUtf8Bytes,
            "Hash input must use effective UTF-8 bytes.");
        Equal(Convert.ToHexString(SHA256.HashData(binding.EffectiveUtf8Bytes))
            .ToLowerInvariant(), binding.Sha256, "Task hash.");
        return Task.CompletedTask;
    }

    private static async Task UnknownEnrollment()
    {
        var native = new FakeNativeWebAuthn { RegistrationOutcomeUnknown = true };
        var journal = new RecoveryJournal();
        var workflow = new LabWorkflow(native, new FakeAssertionGate(journal), journal);
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State, "Unknown state.");
        Equal(RecoveryOutcome.Unknown, journal.Current.Outcome, "Journal outcome.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.EnrollAsync(default));

        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.OrphanedCredential, workflow.State,
            "One new fake inventory ID becomes an orphan.");
        await workflow.RecoverOrphanAsync(default);
        Equal(LabState.Ready, workflow.State, "Known orphan is removed and reconciled.");

        var noCreateNative = new FakeNativeWebAuthn
        {
            RegistrationOutcomeUnknown = true,
            UnknownOutcomeCreatesCredential = false
        };
        var noCreate = new LabWorkflow(noCreateNative, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => noCreate.EnrollAsync(default));
        await noCreate.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.Ready, noCreate.State,
            "Empty fake inventory confirms no new synthetic ID.");
    }

    private static async Task CreatedUnpinned()
    {
        var native = new FakeNativeWebAuthn { ReturnMalformedCose = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<InvalidDataException>(() => workflow.EnrollAsync(default));
        Equal(LabState.CreatedUnpinned, workflow.State, "Unpinned state retained.");
        True(workflow.OrphanCredentialId is not null, "Known ID remains available.");
        True(workflow.Credential is null, "Invalid COSE is never pinned.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.RunAssertionAsync(
            "challenge", StrictClientData.TestOrigin, 2000, "nonce", 1000, default));
        await workflow.RecoverOrphanAsync(default);
        Equal(LabState.Ready, workflow.State, "Unpinned fake is explicitly recovered.");
    }

    private static async Task CancellationRace()
    {
        var native = new FakeNativeWebAuthn();
        using var source = new CancellationTokenSource();
        native.AfterRegistrationCreated = source.Cancel;
        var journal = new RecoveryJournal();
        var workflow = new LabWorkflow(native, new FakeAssertionGate(journal), journal);
        await workflow.EnrollAsync(source.Token);
        Equal(LabState.CredentialPinnedInMemory, workflow.State,
            "Successful result wins over a concurrent cancellation request.");
        True(workflow.Credential is not null, "Successful synthetic result is preserved.");
        True(journal.Current.CancellationRequested,
            "Journal records the overlapping cancellation request.");
        Equal(RecoveryOutcome.Succeeded, journal.Current.Outcome,
            "Returned and validated result is reconciled as succeeded.");
    }

    private static async Task CleanupOutcomeUnknown()
    {
        var native = new FakeNativeWebAuthn { DeleteThenLoseResponse = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        var id = workflow.Credential!.CredentialId;
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Lost delete response remains unknown.");
        True(workflow.Credential is null, "Revocation is never undone.");
        Equal(id, workflow.PendingCleanupCredentialId, "ID retained for reconciliation.");
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Absence from fake inventory confirms fake cleanup.");
        Equal(1, native.DeletionCalls, "Reconciliation does not repeat deletion.");
        await ThrowsAsync<InvalidOperationException>(() =>
            workflow.RetryFakeCleanupAsync(default));
    }

    private static async Task ReplayAcrossGates()
    {
        var journal = new RecoveryJournal();
        var native = new FakeNativeWebAuthn();
        var workflow = new LabWorkflow(native, new FakeAssertionGate(journal), journal);
        await workflow.EnrollAsync(default);
        var credential = workflow.Credential!;
        const long now = 1800000000000;
        const string challenge = "restart-shared-challenge";
        const string nonce = "restart-shared-nonce";
        await workflow.RunAssertionAsync(challenge, StrictClientData.TestOrigin,
            now + 1000, nonce, now, default);

        var payload = new FakeAssertionPayload(
            DecodeBase64Url(credential.CredentialId), credential.Algorithm,
            credential.PublicKeySha256,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get", challenge, origin = StrictClientData.TestOrigin
            }),
            now + 1000, nonce);
        var restartedGate = new FakeAssertionGate(journal);
        Throws<InvalidDataException>(() => restartedGate.Evaluate(
            credential, payload, challenge, StrictClientData.TestOrigin, now));
    }

    private static async Task ReplayWithFreshJournal()
    {
        var native = new FakeNativeWebAuthn();
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        var credential = workflow.Credential!;
        const long now = 1800000000000;
        const string challenge = "restart-fresh-challenge";
        const string nonce = "restart-fresh-nonce";
        var payload = new FakeAssertionPayload(
            DecodeBase64Url(credential.CredentialId), credential.Algorithm,
            credential.PublicKeySha256,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get", challenge, origin = StrictClientData.TestOrigin
            }),
            now + 1000, nonce);
        var firstJournal = new RecoveryJournal();
        _ = new FakeAssertionGate(firstJournal).Evaluate(
            credential, payload, challenge, StrictClientData.TestOrigin, now);
        Throws<InvalidDataException>(() => new FakeAssertionGate(firstJournal).Evaluate(
            credential, payload, challenge, StrictClientData.TestOrigin, now));
        var freshJournal = new RecoveryJournal();
        var replayAccepted = new FakeAssertionGate(freshJournal).Evaluate(
            credential, payload, challenge, StrictClientData.TestOrigin, now);
        True(replayAccepted.Outcome.Contains("Fake fields matched", StringComparison.Ordinal),
            "A fresh in-memory journal lacks the previous nonce and accepts the replay.");
        Equal(RecoveryJournal.CurrentSchemaVersion,
            freshJournal.Current.SchemaVersion, "Journal schema is versioned.");
    }

    private static Task FixedOrigin()
    {
        Equal(RecoveryJournal.TestRpId, "lab.example.test", "Fixed test RP ID.");
        Equal(RecoveryJournal.TestOrigin, StrictClientData.TestOrigin,
            "Journal and parser use the same fixed origin.");
        var gate = new FakeAssertionGate();
        var credential = new TestCredential("ZmFrZS1jcmVkZW50aWFsLTAwMDE",
            -7, new string('a', 64));
        var payload = new FakeAssertionPayload(new byte[20], -7, new string('a', 64),
            Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":\"c\"," +
                "\"origin\":\"https://approval.lab.example.test\"}"),
            2000, "n");
        Throws<InvalidDataException>(() => gate.Evaluate(
            credential, payload, "c", "https://user-input.example", 1000));
        return Task.CompletedTask;
    }

    private static async Task OrphanCleanupUnknown()
    {
        var native = new FakeNativeWebAuthn { CreateOrphanThenFail = true,
            DeleteThenLoseResponse = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        var orphan = workflow.OrphanCredentialId;
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.RecoverOrphanAsync(default));
        Equal(LabState.OrphanCleanupOutcomeUnknown, workflow.State,
            "Orphan cleanup response loss blocks immediate retry.");
        Equal(orphan, workflow.OrphanCredentialId, "Orphan ID remains for reconciliation.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.RecoverOrphanAsync(default));
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.Ready, workflow.State, "Absent synthetic ID reconciles orphan cleanup.");
        Equal(1, native.DeletionCalls, "No blind duplicate deletion.");
    }

    private static async Task CleanupCancellationUnknown()
    {
        var native = new FakeNativeWebAuthn { CancelAfterDeletion = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<OperationCanceledException>(() => workflow.RevokeAndCleanFakeAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Cancellation after synthetic deletion must remain unknown.");
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Cleanup is confirmed only after fake inventory reconciliation.");
    }

    private static async Task ReconciliationFailure()
    {
        var native = new FakeNativeWebAuthn { DeleteThenLoseResponse = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.RevokeAndCleanFakeAsync(default));
        native.FailNextInventory = true;
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.ReconcileUnknownCleanupAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Unavailable fake inventory must preserve unknown state.");
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Recovery is possible after fake inventory responds.");
    }

    private static Task MismatchedJournals()
    {
        var first = new RecoveryJournal();
        var second = new RecoveryJournal();
        Throws<ArgumentException>(() => new LabWorkflow(
            new FakeNativeWebAuthn(), new FakeAssertionGate(first), second));
        return Task.CompletedTask;
    }

    private static async Task EnrollmentReconciliationFailure()
    {
        var native = new FakeNativeWebAuthn { RegistrationOutcomeUnknown = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        native.FailNextInventory = true;
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.ReconcileUnknownEnrollmentAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Unavailable fake inventory cannot unblock another enrollment.");
        Equal(RecoveryOutcome.Unknown, workflow.Journal.Current.Outcome,
            "Journal preserves unknown outcome when reconciliation fails.");
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.OrphanedCredential, workflow.State,
            "Known synthetic orphan becomes recoverable after inventory responds.");
    }

    private static Task ConcurrentFakeConsumption()
    {
        var journal = new RecoveryJournal();
        var results = new bool[32];
        Parallel.For(0, results.Length, index =>
        {
            results[index] = journal.TryConsume("same-challenge", "same-nonce");
        });
        Equal(1, results.Count(accepted => accepted),
            "Exactly one in-process fake replay attempt may consume a pair.");
        Equal(1, journal.ConsumedNonceCount,
            "Consumed set must remain internally consistent.");
        return Task.CompletedTask;
    }

    private static async Task CleanupUnknownStillPresent()
    {
        var native = new FakeNativeWebAuthn { DeleteUnknownWithoutEffect = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Uncertain deletion outcome blocks retries.");
        await ThrowsAsync<InvalidOperationException>(() =>
            workflow.RetryFakeCleanupAsync(default));
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedCleanupPending, workflow.State,
            "Fake inventory confirms presence and allows an explicit retry.");
        True(workflow.Credential is null, "Revoked trust remains unavailable.");
        await workflow.RetryFakeCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "A second fake deletion must be independently inventoried.");
        Equal(2, native.DeletionCalls,
            "One uncertain attempt and one explicit post-reconciliation retry.");
    }

    private static async Task DuplicateInventory()
    {
        var native = new FakeNativeWebAuthn { RegistrationOutcomeUnknown = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        var id = native.FakeCredentialIds.Single();
        native.NextInventorySnapshot = [id, id];
        await ThrowsAsync<InvalidDataException>(() =>
            workflow.ReconcileUnknownEnrollmentAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Duplicate IDs cannot be silently deduplicated or confirm an orphan.");
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.OrphanedCredential, workflow.State,
            "A subsequent valid snapshot permits explicit recovery.");
    }

    private static async Task MalformedCleanupInventory()
    {
        var native = new FakeNativeWebAuthn();
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        native.NextInventorySnapshot = ["%%%invalid%%%"];
        await ThrowsAsync<InvalidDataException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Unparseable inventory must not establish cleanup success.");
        True(workflow.Credential is null, "Trust remains revoked.");
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Valid inventory subsequently confirms fake ID absence.");
    }

    private static async Task DuplicateCleanupInventory()
    {
        var native = new FakeNativeWebAuthn { DeleteUnknownWithoutEffect = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        var id = workflow.Credential!.CredentialId;
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        native.NextInventorySnapshot = [id, id];
        await ThrowsAsync<InvalidDataException>(() =>
            workflow.ReconcileUnknownCleanupAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "Duplicated inventory cannot unblock cleanup retries.");
        await ThrowsAsync<InvalidOperationException>(() =>
            workflow.RetryFakeCleanupAsync(default));
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedCleanupPending, workflow.State,
            "Valid inventory restores an explicit retry path only.");
    }

    private static Task OversizedInventory()
    {
        var valid = Convert.ToBase64String(Encoding.ASCII.GetBytes("fake-credential-9999"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var tooMany = Enumerable.Repeat(valid, 129).ToArray();
        Throws<InvalidDataException>(() => SyntheticInventory.Validate(tooMany));
        Throws<InvalidDataException>(() => SyntheticInventory.Validate(["not*canonical"]));
        return Task.CompletedTask;
    }

    private static Task JournalRejectsInvalidTransitions()
    {
        var journal = new RecoveryJournal();
        Throws<InvalidOperationException>(() => journal.Begin(
            RecoveryOperation.Cleanup, LabState.RevokedCleanupPending));
        var id = journal.Begin(RecoveryOperation.Enrollment, LabState.EnrollmentStarted);
        Throws<InvalidOperationException>(() => journal.Record(
            "forged-operation-id", RecoveryOperation.Enrollment,
            LabState.CredentialPinnedInMemory, RecoveryOutcome.Succeeded));
        Throws<InvalidOperationException>(() => journal.Record(
            id, RecoveryOperation.Enrollment,
            LabState.RevokedAndCleaned, RecoveryOutcome.Succeeded));
        Throws<InvalidOperationException>(() => journal.Begin(
            RecoveryOperation.Assertion, LabState.AssertionStarted));
        journal.Record(id, RecoveryOperation.Enrollment,
            LabState.EnrollmentOutcomeUnknown, RecoveryOutcome.Unknown);
        Throws<InvalidOperationException>(() => journal.Record(
            id, RecoveryOperation.Enrollment,
            LabState.CredentialPinnedInMemory, RecoveryOutcome.Succeeded));
        var reconciliationId = journal.Begin(
            RecoveryOperation.Reconciliation, LabState.EnrollmentOutcomeUnknown);
        journal.Record(reconciliationId, RecoveryOperation.Reconciliation,
            LabState.Ready, RecoveryOutcome.Succeeded);
        return Task.CompletedTask;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var standard = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(standard +
            new string('=', (4 - standard.Length % 4) % 4));
    }

    private static void Layout<T>(
        int expectedSize, params (string Field, int Offset)[] fields)
    {
        Equal(expectedSize, Marshal.SizeOf<T>(), $"{typeof(T).Name} size.");
        foreach (var (field, expectedOffset) in fields)
            Equal(expectedOffset, Marshal.OffsetOf<T>(field).ToInt32(),
                $"{typeof(T).Name}.{field} offset.");
    }

    private static void True(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void Equal<T>(T expected, T actual, string message)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException(
                $"{message} Expected {expected}; got {actual}.");
    }

    private static void SequenceEqual(
        ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string message)
    {
        if (!expected.SequenceEqual(actual))
            throw new InvalidOperationException(message);
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
