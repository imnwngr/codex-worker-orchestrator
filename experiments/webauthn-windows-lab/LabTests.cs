using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
        ("recovery journal rejects forged operations and invalid outcomes", JournalRejectsInvalidTransitions),
        ("synthetic trust dimensions cannot be substituted by caller metadata", TrustBoundaryRejectsMetadata),
        ("complete consistent fixture evidence is synthetic-only", TrustBoundaryPositiveControl),
        ("conflicting trust evidence and RP origin pairs fail closed", TrustBoundaryContradictions),
        ("readiness evaluator blocks all real and production operations", ReadinessIsInformational),
        ("synthetic store commits atomically and restores interrupted initiation", StoreAtomicRecovery),
        ("synthetic store rejects stale rollback duplicate IDs and partial writes", StoreRejectsCorruption),
        ("replay continuity is explicitly lost when the ledger is replaced", StoreReplayContinuity),
        ("reconstructed recovery journal preserves revision and unknown state", JournalReconstructionUsesSharedStore),
        ("concurrent cleanup reconciliation cannot restore trust", ConcurrentCleanupReconciliation),
        ("store continuation cannot bypass validated transitions", StoreContinuationIsValidated),
        ("unanchored synthetic restore cannot fabricate credential state", StoreRestoreRequiresValidGenesis),
        ("replaced replay ledger blocks further consumption", StoreReplacedLedgerBlocksConsumption),
        ("synthetic trust handles missing nested evidence and empty labels", TrustMissingNestedEvidence),
        ("inventory enumeration is bounded independently of Count", LyingInventoryCountIsRejected),
        ("unknown enrollment inventory delta is never treated as the operation credential", UnknownEnrollmentIdRemainsUntrusted),
        ("registration ID colliding with baseline cannot be cleaned or trusted", RegistrationIdCollision),
        ("cleanup reconciliation rejects unrecognized inventory identities", CleanupRejectsUnexpectedInventoryIdentity),
        ("malformed lost-response ID cannot become a deletion target", MalformedOrphanIdCannotBeDeleted),
        ("all journal transition pairs match an independent bounded model", JournalTransitionMatrix),
        ("unknown enrollment cannot become ready after losing a baseline ID", EnrollmentBaselineLossRemainsUnknown),
        ("disappearing collided identity cannot resolve ambiguous enrollment", DisappearingCollisionRemainsUnknown),
        ("malformed response identity stays blocked even with matching inventory", MalformedRecoveryIdentityRemainsUnknown),
        ("synthetic collision injection never removes an existing credential", CollisionInjectionPreservesExistingCredential),
        ("valid-looking unbound orphan ID cannot become a deletion target", UnboundValidOrphanIdCannotBeDeleted)
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
        Equal(RecoveryJournal.TestRpId, workflow.LastCleanupEvidence!.RpId,
            "Cleanup evidence fixes the synthetic RP ID.");
        Equal("SYNTHETIC_ID_ABSENT_FROM_TEST_INVENTORY",
            workflow.LastCleanupEvidence.FinalOutcome,
            "Cleanup evidence reports only absence from fake inventory.");
        True(!workflow.LastCleanupEvidence.ClaimsEveryAuthenticatorStoreCleaned,
            "One synthetic inventory cannot prove cleanup of all authenticators or synced stores.");
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
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Inventory delta alone does not identify the credential from the attempted operation.");
        True(workflow.OrphanCredentialId is null,
            "Unbound inventory IDs are never promoted to cleanup targets.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.EnrollAsync(default));

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
        Equal("SYNTHETIC_CLEANUP_UNKNOWN", workflow.LastCleanupEvidence!.FinalOutcome,
            "Lost response is recorded as unknown.");
        True(workflow.Credential is null, "Revocation is never undone.");
        Equal(id, workflow.PendingCleanupCredentialId, "ID retained for reconciliation.");
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Absence from fake inventory confirms fake cleanup.");
        Equal("SYNTHETIC_ID_ABSENT_FROM_TEST_INVENTORY",
            workflow.LastCleanupEvidence!.FinalOutcome,
            "Reconciliation records synthetic inventory evidence only.");
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
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Inventory availability cannot bind the new ID to the unknown registration.");
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
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "A valid but unbound new inventory ID remains unknown.");
        True(workflow.OrphanCredentialId is null,
            "Reconciliation does not turn an arbitrary inventory ID into an orphan.");
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

    private static Task TrustBoundaryRejectsMetadata()
    {
        var evidence = CompleteTrustEvidence();
        var forged = evidence with
        {
            Process = evidence.Process with
            {
                ProcessFixture = new Evidence<int>(1234, SyntheticEvidenceSource.CallerSuppliedMetadata),
                UserFixture = new Evidence<string>("same-user", SyntheticEvidenceSource.CallerSuppliedMetadata)
            },
            WindowsUser = new WindowsUserEvidence(
                new Evidence<string>("same-user", SyntheticEvidenceSource.CallerSuppliedMetadata))
        };
        Equal(TrustAssessment.UNVERIFIED, SyntheticTrustEvaluator.Evaluate(forged).Status,
            "Plausible same-user process fields are not verified identity.");
        Equal(TrustAssessment.INSUFFICIENT_EVIDENCE, SyntheticTrustEvaluator.Evaluate(null).Status,
            "Missing evidence cannot satisfy trust.");
        return Task.CompletedTask;
    }

    private static Task TrustBoundaryPositiveControl()
    {
        Equal(TrustAssessment.SATISFIED_FOR_SYNTHETIC_TEST,
            SyntheticTrustEvaluator.Evaluate(CompleteTrustEvidence()).Status,
            "A complete consistent fixture is accepted only for synthetic testing.");
        return Task.CompletedTask;
    }

    private static Task TrustBoundaryContradictions()
    {
        var evidence = CompleteTrustEvidence();
        var conflict = evidence with
        {
            WindowsUser = new WindowsUserEvidence(
                new Evidence<string>("different-fixture-user", SyntheticEvidenceSource.SyntheticFixture))
        };
        Equal(TrustAssessment.CONTRADICTORY_EVIDENCE,
            SyntheticTrustEvaluator.Evaluate(conflict).Status, "Conflicting identities are rejected.");
        var rp = evidence with
        {
            RelyingParty = new RelyingPartyEvidence(
                new Evidence<string>("attacker.example", SyntheticEvidenceSource.SyntheticFixture),
                new Evidence<string>(RecoveryJournal.TestOrigin, SyntheticEvidenceSource.SyntheticFixture))
        };
        Equal(TrustAssessment.BLOCKED, SyntheticTrustEvaluator.Evaluate(rp).Status,
            "Caller substituted RP configuration is blocked.");
        var binaryConflict = evidence with
        {
            Binary = new BinaryIntegrityEvidence(
                new Evidence<string>("different-executable", SyntheticEvidenceSource.SyntheticFixture),
                evidence.Binary.DigestFixture)
        };
        Equal(TrustAssessment.CONTRADICTORY_EVIDENCE,
            SyntheticTrustEvaluator.Evaluate(binaryConflict).Status,
            "Integrity evidence bound to another executable fixture is contradictory.");
        var credentialConflict = evidence with
        {
            Credential = new CredentialPossessionEvidence(
                new Evidence<string>("different-authenticator", SyntheticEvidenceSource.SyntheticFixture),
                evidence.Credential.CredentialFixture)
        };
        Equal(TrustAssessment.CONTRADICTORY_EVIDENCE,
            SyntheticTrustEvaluator.Evaluate(credentialConflict).Status,
            "Credential evidence bound to another authenticator is contradictory.");
        return Task.CompletedTask;
    }

    private static Task ReadinessIsInformational()
    {
        var report = ExperimentalReadinessEvaluator.Evaluate();
        foreach (var status in new[]
        {
            ReadinessStatus.SYNTHETIC_TEST_UNVERIFIED,
            ReadinessStatus.READ_ONLY_DIAGNOSTIC_NOT_OBSERVED,
            ReadinessStatus.REAL_CREDENTIAL_ENROLLMENT_BLOCKED,
            ReadinessStatus.REAL_CREDENTIAL_ASSERTION_BLOCKED,
            ReadinessStatus.REAL_CREDENTIAL_DELETION_BLOCKED,
            ReadinessStatus.PRODUCTION_AUTHORIZATION_BLOCKED
        })
            True(report.Statuses.Contains(status), $"Readiness must report {status}.");
        True(!report.Statuses.Contains(ReadinessStatus.SYNTHETIC_TEST_READY) &&
            !report.Statuses.Contains(ReadinessStatus.READ_ONLY_DIAGNOSTIC_READY),
            "Readiness must not mark tests or runtime diagnostics ready without evidence.");
        True(report.ApplicationIdentity.Contains("untrusted", StringComparison.OrdinalIgnoreCase),
            "Runtime identity remains untrusted.");
        True(report.ReplayProtection.Contains("not durable", StringComparison.OrdinalIgnoreCase),
            "No production-grade durable replay protection is claimed.");
        True(report.ObservedReadOnlyRuntimeCapability.Contains("NOT_OBSERVED", StringComparison.Ordinal),
            "Evaluator does not invent a current runtime observation.");
        True(report.DocumentedSdkRequirements.Contains("SDK_DOCUMENTED_ONLY", StringComparison.Ordinal),
            "SDK thresholds are separated from runtime observations.");
        True(report.UserReportedRuntimeObservation.Contains("NOT_SUPPLIED", StringComparison.Ordinal) &&
            !report.UserReportedRuntimeObservation.Contains("22631", StringComparison.Ordinal),
            "Generic readiness output must not embed a specific machine's history.");
        using var json = JsonDocument.Parse(report.ToJson());
        True(json.RootElement.TryGetProperty("Statuses", out var serializedStatuses) &&
            serializedStatuses.EnumerateArray().All(value =>
                value.ValueKind == JsonValueKind.String),
            "Machine-readable readiness statuses use stable enum names, not integers.");
        True(serializedStatuses.EnumerateArray().Any(value =>
            value.GetString() == nameof(ReadinessStatus.PRODUCTION_AUTHORIZATION_BLOCKED)),
            "Serialized status names explicitly preserve the production blocker.");
        True(json.RootElement.TryGetProperty("ObservedReadOnlyRuntimeCapability", out _),
            "Runtime observation category is serialized separately.");
        return Task.CompletedTask;
    }

    private static Task StoreAtomicRecovery()
    {
        var store = new SyntheticJournalStore();
        var started = StoreEntry(1, "synthetic-op-000001", LabState.EnrollmentStarted,
            RecoveryOutcome.Started);
        Equal(SyntheticStoreResult.Unknown,
            store.Commit(0, started, SyntheticWriteFault.CrashAfterInitiation),
            "Crash after initiation is unknown to caller.");
        Equal(1L, store.Revision, "Initiated operation is atomically journaled.");
        var reconstructed = new SyntheticJournalStore();
        Equal(SyntheticStoreResult.Committed, reconstructed.Restore(store.Current),
            "Synthetic workflow reconstruction can receive the stored snapshot.");
        Equal(RecoveryOutcome.Started, reconstructed.Current!.Outcome,
            "Interrupted operation is not inferred successful.");
        return Task.CompletedTask;
    }

    private static Task StoreRejectsCorruption()
    {
        var store = new SyntheticJournalStore();
        var entry = StoreEntry(1, "synthetic-op-000001", LabState.EnrollmentStarted,
            RecoveryOutcome.Started);
        Equal(SyntheticStoreResult.Unknown,
            store.Commit(0, entry, SyntheticWriteFault.TornWrite), "Torn commit is not published.");
        Equal(0L, store.Revision, "Atomic store leaves no partial revision.");
        Equal(SyntheticStoreResult.Committed, store.Commit(0, entry), "Valid commit succeeds.");
        Equal(SyntheticStoreResult.InvalidRecord, store.Commit(1,
            StoreEntry(2, "synthetic-op-000002", LabState.RevokedAndCleaned,
                RecoveryOutcome.Succeeded)), "Invalid state transition is rejected.");
        Equal(SyntheticStoreResult.StaleRevision, store.Commit(0,
            StoreEntry(3, "synthetic-op-000003", LabState.Failed, RecoveryOutcome.Failed)),
            "Stale expected revision is rejected.");
        Equal(SyntheticStoreResult.InvalidRecord, store.Commit(1,
            StoreEntry(2, "synthetic-op-000001", LabState.Failed, RecoveryOutcome.Failed)),
            "Duplicate operation identifier is rejected.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Restore(entry with { Revision = 0 }), "Rollback snapshot is rejected.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Restore(entry with { State = LabState.CredentialPinnedInMemory }),
            "Conflicting same-revision copy is rejected.");
        Equal(SyntheticStoreResult.Unknown,
            store.Commit(1, StoreEntry(2, "synthetic-op-000002", LabState.Failed,
                RecoveryOutcome.Failed), SyntheticWriteFault.CrashBeforeInitiation),
            "A crash before initiation records no new state.");
        Equal(SyntheticStoreResult.Unknown,
            store.Commit(1, StoreEntry(2, "synthetic-op-000002", LabState.Failed,
                RecoveryOutcome.Failed), SyntheticWriteFault.ResultReturnedBeforeJournalUpdate),
            "A returned result without journal update remains unknown.");
        Equal(1L, store.Revision, "Neither pre-initiation fault advances the stored revision.");
        return Task.CompletedTask;
    }

    private static Task StoreReplayContinuity()
    {
        var store = new SyntheticJournalStore();
        var firstJournal = new RecoveryJournal(store);
        True(firstJournal.TryConsume("challenge-a", "nonce-a"), "First replay consumption succeeds.");
        var reconstructedJournal = new RecoveryJournal(store);
        Equal(1, reconstructedJournal.ConsumedNonceCount,
            "Reconstructed journal sees the shared synthetic replay ledger.");
        True(!reconstructedJournal.TryConsume("challenge-a", "nonce-a"),
            "Replay is rejected across synthetic journal reconstruction.");
        store.MarkReplayLedgerReplaced();
        True(!store.ReplayContinuityEstablished,
            "Replacement/loss is explicit and cannot be called durable replay protection.");
        var replacement = new SyntheticJournalStore();
        True(replacement.TryConsume("challenge-a", "nonce-a"),
            "Fresh synthetic ledger demonstrates loss of prior replay state.");
        return Task.CompletedTask;
    }

    private static Task JournalReconstructionUsesSharedStore()
    {
        var store = new SyntheticJournalStore();
        var first = new RecoveryJournal(store);
        var operationId = first.Begin(RecoveryOperation.Enrollment, LabState.EnrollmentStarted);
        first.Record(operationId, RecoveryOperation.Enrollment,
            LabState.EnrollmentOutcomeUnknown, RecoveryOutcome.Unknown,
            errorCode: "simulated_interruption");
        var restored = new RecoveryJournal(store);
        Equal(LabState.EnrollmentOutcomeUnknown, restored.Current.State,
            "A reconstructed journal preserves unknown operation state.");
        Equal(first.Current.Revision, restored.Current.Revision,
            "A reconstructed journal keeps the monotonic revision.");
        var next = restored.Begin(RecoveryOperation.Reconciliation,
            LabState.EnrollmentOutcomeUnknown);
        True(next != operationId, "Reconstruction allocates a fresh operation ID.");
        return Task.CompletedTask;
    }

    private static async Task ConcurrentCleanupReconciliation()
    {
        var native = new FakeNativeWebAuthn { DeleteThenLoseResponse = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.RevokeAndCleanFakeAsync(default));
        var attempts = new[] { Reconcile(), Reconcile() };
        var results = await Task.WhenAll(attempts);
        Equal(1, results.Count(result => result),
            "Exactly one reconciliation may complete from the captured unknown state.");
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Successful reconciliation preserves revoked trust.");
        True(workflow.Credential is null, "Reconciliation never restores the credential trust.");

        async Task<bool> Reconcile()
        {
            try { await workflow.ReconcileUnknownCleanupAsync(default); return true; }
            catch (InvalidOperationException) { return false; }
        }
    }

    private static Task StoreContinuationIsValidated()
    {
        var store = new SyntheticJournalStore();
        var started = StoreEntry(1, "synthetic-op-000001", LabState.EnrollmentStarted,
            RecoveryOutcome.Started);
        Equal(SyntheticStoreResult.Committed, store.Commit(0, started),
            "Valid enrollment starts in the store.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Commit(1, StoreEntry(2, started.OperationId, LabState.RevokedAndCleaned,
                RecoveryOutcome.Succeeded), continuationOfCurrentOperation: true),
            "A continuation cannot forge an impossible transition.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Commit(1, StoreEntry(2, started.OperationId, LabState.Failed,
                RecoveryOutcome.Succeeded), continuationOfCurrentOperation: true),
            "A failed state cannot be labeled successful.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Commit(1, StoreEntry(2, started.OperationId, LabState.CreatedUnpinned,
                RecoveryOutcome.Succeeded) with { Operation = RecoveryOperation.Cleanup },
                continuationOfCurrentOperation: true),
            "A continuation cannot change operation kind.");
        Equal(SyntheticStoreResult.Committed,
            store.Commit(1, StoreEntry(2, started.OperationId, LabState.CreatedUnpinned,
                RecoveryOutcome.Succeeded), continuationOfCurrentOperation: true),
            "Valid continuation still succeeds.");
        Equal(2L, store.Revision, "Rejected transitions do not advance state.");
        return Task.CompletedTask;
    }

    private static Task StoreRestoreRequiresValidGenesis()
    {
        var store = new SyntheticJournalStore();
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Commit(0, StoreEntry(1, "synthetic-op-000002", LabState.EnrollmentStarted,
                RecoveryOutcome.Started)),
            "A new store must begin with the first synthetic operation ID.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Restore(StoreEntry(4, "synthetic-op-000004", LabState.RevokedAndCleaned,
                RecoveryOutcome.Succeeded)),
            "A fabricated terminal state cannot bootstrap an empty store.");
        Equal(SyntheticStoreResult.InvalidRecord,
            store.Restore(StoreEntry(1, "synthetic-op-000999", LabState.EnrollmentStarted,
                RecoveryOutcome.Started)),
            "A forged initial sequence cannot bootstrap an empty store.");
        Equal(0L, store.Revision, "Invalid restore cannot mutate the synthetic store.");
        Equal(SyntheticStoreResult.Committed,
            store.Restore(StoreEntry(1, "synthetic-op-000001", LabState.EnrollmentStarted,
                RecoveryOutcome.Started)),
            "An initial in-flight record can be restored for the fake-only test.");
        return Task.CompletedTask;
    }

    private static Task StoreReplacedLedgerBlocksConsumption()
    {
        var store = new SyntheticJournalStore();
        True(store.TryConsume("challenge-1", "nonce-1"), "Before loss, consume works.");
        store.MarkReplayLedgerReplaced();
        True(!store.TryConsume("challenge-2", "nonce-2"),
            "A store with lost replay continuity cannot mint a clean replay history.");
        True(!new RecoveryJournal(store).TryConsume("challenge-3", "nonce-3"),
            "Restoring a journal cannot bypass lost replay continuity.");
        return Task.CompletedTask;
    }

    private static Task TrustMissingNestedEvidence()
    {
        var complete = CompleteTrustEvidence();
        Equal(TrustAssessment.INSUFFICIENT_EVIDENCE,
            SyntheticTrustEvaluator.Evaluate(complete with { Executable = null! }).Status,
            "A missing nested dimension must fail closed rather than throwing.");
        Equal(TrustAssessment.INSUFFICIENT_EVIDENCE,
            SyntheticTrustEvaluator.Evaluate(complete with
            {
                Executable = new ExecutableIdentityEvidence(
                    new Evidence<string>(" ", SyntheticEvidenceSource.SyntheticFixture))
            }).Status, "Whitespace-only synthetic identities are incomplete.");
        Equal(TrustAssessment.BLOCKED,
            SyntheticTrustEvaluator.Evaluate(complete with
            {
                Process = complete.Process with
                {
                    ProcessFixture = new Evidence<int>(0, SyntheticEvidenceSource.SyntheticFixture)
                }
            }).Status, "A zero synthetic process identity is blocked.");
        return Task.CompletedTask;
    }

    private static Task LyingInventoryCountIsRejected()
    {
        var one = FakeId("count-lie-000001");
        Throws<InvalidDataException>(() => SyntheticInventory.Validate(
            new LyingInventoryCollection(0, [one])));
        var moreThanLimit = Enumerable.Range(0, 129)
            .Select(index => FakeId($"bound-check-{index:D4}"))
            .ToArray();
        Throws<InvalidDataException>(() => SyntheticInventory.Validate(
            new LyingInventoryCollection(128, moreThanLimit)));
        return Task.CompletedTask;
    }

    private static async Task UnknownEnrollmentIdRemainsUntrusted()
    {
        var native = new FakeNativeWebAuthn { RegistrationOutcomeUnknown = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "One new inventory ID cannot be attributed to the registration attempt.");
        True(workflow.OrphanCredentialId is null && workflow.Credential is null,
            "An unbound ID is not trusted or made a cleanup target.");
        Equal(0, native.DeletionCalls, "Reconciliation never deletes the arbitrary new ID.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.EnrollAsync(default));
    }

    private static async Task RegistrationIdCollision()
    {
        var native = new FakeNativeWebAuthn();
        var existingId = FakeId("existing-cred-01");
        native.SeedFakeCredential(existingId);
        native.RegistrationCredentialIdOverride = Encoding.ASCII.GetBytes(
            "existing-cred-01");
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "A returned ID already present in the baseline is ambiguous.");
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "An unchanged colliding ID cannot reconcile the operation.");
        True(workflow.Credential is null && workflow.OrphanCredentialId is null,
            "The pre-existing identity never becomes trusted or deletable.");
        Equal(0, native.DeletionCalls, "Collision handling never deletes the existing fake ID.");
    }

    private static async Task CleanupRejectsUnexpectedInventoryIdentity()
    {
        var native = new FakeNativeWebAuthn { DeleteUnknownWithoutEffect = true };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await workflow.EnrollAsync(default);
        await ThrowsAsync<FakeNativeFailureException>(() =>
            workflow.RevokeAndCleanFakeAsync(default));
        native.NextInventorySnapshot = [FakeId("unexpected-id-001")];
        await ThrowsAsync<InvalidDataException>(() =>
            workflow.ReconcileUnknownCleanupAsync(default));
        Equal(LabState.CleanupOutcomeUnknown, workflow.State,
            "An unexpected valid-looking ID cannot prove target absence.");
        True(workflow.Credential is null, "Failed reconciliation does not restore trust.");
        await ThrowsAsync<InvalidOperationException>(() =>
            workflow.RetryFakeCleanupAsync(default));
        await workflow.ReconcileUnknownCleanupAsync(default);
        Equal(LabState.RevokedCleanupPending, workflow.State,
            "Only a subsequent recognized snapshot permits an explicit retry.");
        await workflow.RetryFakeCleanupAsync(default);
        Equal(LabState.RevokedAndCleaned, workflow.State,
            "Exact synthetic target cleanup still has a positive control.");
    }

    private static async Task MalformedOrphanIdCannotBeDeleted()
    {
        var native = new FakeNativeWebAuthn
        {
            CreateOrphanThenFail = true,
            RegistrationOrphanIdOverride = "attacker-controlled-id"
        };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Malformed recovery identity keeps enrollment outcome unknown.");
        True(workflow.OrphanCredentialId is null,
            "Malformed response ID is never retained as trusted cleanup identity.");
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Inventory delta cannot repair a malformed operation identity.");
        Equal(0, native.DeletionCalls,
            "No deletion is issued for malformed or unbound inventory identity.");
    }

    private static async Task EnrollmentBaselineLossRemainsUnknown()
    {
        var existing = FakeId("baseline-id-00001");
        var native = new FakeNativeWebAuthn
        {
            RegistrationOutcomeUnknown = true,
            UnknownOutcomeCreatesCredential = false
        };
        native.SeedFakeCredential(existing);
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));

        // The inventory has no additions, but one original credential is gone.
        native.NextInventorySnapshot = Array.Empty<string>();
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "Absence of new IDs cannot prove unchanged inventory when baseline IDs disappeared.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.EnrollAsync(default));

        // An exact subsequent snapshot is the narrowly permitted positive control.
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.Ready, workflow.State,
            "A later exact fake baseline match permits synthetic recovery.");
    }

    private static async Task DisappearingCollisionRemainsUnknown()
    {
        var existing = FakeId("baseline-id-00002");
        var native = new FakeNativeWebAuthn
        {
            RegistrationCredentialIdOverride = Encoding.ASCII.GetBytes("baseline-id-00002")
        };
        native.SeedFakeCredential(existing);
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        native.NextInventorySnapshot = Array.Empty<string>();
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "A known collision cannot be cleared when its inventory entry disappears.");
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "A later exact baseline snapshot cannot establish collision ownership.");
        True(workflow.Credential is null && workflow.OrphanCredentialId is null,
            "Collision recovery must not grant trust or create a deletion target.");
        Equal(0, native.DeletionCalls, "Collision recovery cannot delete the original ID.");
    }

    private static async Task MalformedRecoveryIdentityRemainsUnknown()
    {
        var native = new FakeNativeWebAuthn
        {
            CreateOrphanThenFail = true,
            RegistrationOrphanIdOverride = "not a valid base64url ID"
        };
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        native.NextInventorySnapshot = Array.Empty<string>();
        await workflow.ReconcileUnknownEnrollmentAsync(default);
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "An invalid returned recovery identity cannot be cured by an empty inventory.");
        True(workflow.OrphanCredentialId is null, "Invalid identity is never stored as orphan.");
        Equal(0, native.DeletionCalls, "Unknown enrollment cannot trigger deletion.");
    }

    private static async Task CollisionInjectionPreservesExistingCredential()
    {
        var existing = FakeId("baseline-id-00003");
        var native = new FakeNativeWebAuthn
        {
            RegistrationCredentialIdOverride = Encoding.ASCII.GetBytes("baseline-id-00003"),
            FailRegistration = true
        };
        native.SeedFakeCredential(existing);
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        True(native.FakeCredentialIds.Contains(existing),
            "A failed duplicate fake registration cannot remove a pre-existing credential.");
        Equal(0, native.DeletionCalls, "Fake collision injection cannot call deletion.");
    }

    private static async Task UnboundValidOrphanIdCannotBeDeleted()
    {
        var unbound = FakeId("unbound-fake-id-01");
        var native = new FakeNativeWebAuthn
        {
            CreateOrphanThenFail = true,
            RegistrationOrphanIdOverride = unbound
        };
        // A separate synthetic identity appears only after the pre-enrollment
        // inventory snapshot; the claimed recovery ID must not target it.
        native.AfterRegistrationCreated = () => native.SeedFakeCredential(unbound);
        var workflow = new LabWorkflow(native, new FakeAssertionGate());
        await ThrowsAsync<FakeNativeFailureException>(() => workflow.EnrollAsync(default));
        Equal(LabState.EnrollmentOutcomeUnknown, workflow.State,
            "A canonical but operation-unbound ID cannot be recovered as a known orphan.");
        True(workflow.OrphanCredentialId is null,
            "A fake exception claim does not establish registration identity.");
        await ThrowsAsync<InvalidOperationException>(() => workflow.RecoverOrphanAsync(default));
        Equal(0, native.DeletionCalls, "Unbound claimed identity is never deleted.");
        True(native.FakeCredentialIds.Contains(unbound),
            "The unrelated synthetic credential must remain intact.");
    }

    private static Task JournalTransitionMatrix()
    {
        var states = Enum.GetValues<LabState>();
        var operations = Enum.GetValues<RecoveryOperation>();
        var outcomes = Enum.GetValues<RecoveryOutcome>();
        foreach (var operation in operations)
        foreach (var prior in states)
        foreach (var next in states)
        {
            var expected = ReferenceCanBegin(operation, prior, next);
            var actual = RecoveryJournal.CanBegin(operation, prior, next);
            if (expected != actual)
                throw new InvalidOperationException(
                    $"Shortest failing sequence: Begin({operation}) from {prior} to {next}.");
        }

        foreach (var operation in operations)
        foreach (var prior in states)
        foreach (var priorOutcome in outcomes)
        foreach (var next in states)
        foreach (var outcome in outcomes)
        {
            var expected = ReferenceCanRecord(
                operation, prior, priorOutcome, next, outcome);
            var actual = RecoveryJournal.CanRecord(
                operation, prior, priorOutcome, next, outcome);
            if (expected != actual)
                throw new InvalidOperationException(
                    $"Shortest failing sequence: Record({operation},{priorOutcome}) " +
                    $"from {prior} to {next} as {outcome}.");
        }
        return Task.CompletedTask;
    }

    private static bool ReferenceCanBegin(
        RecoveryOperation operation, LabState prior, LabState next)
    {
        if (operation == RecoveryOperation.Enrollment)
            return prior == LabState.Ready && next == LabState.EnrollmentStarted;
        if (operation == RecoveryOperation.Assertion)
            return prior == LabState.CredentialPinnedInMemory && next == LabState.AssertionStarted;
        if (operation == RecoveryOperation.Cleanup)
            return ((prior == LabState.CredentialPinnedInMemory ||
                prior == LabState.AssertionContractMatched) &&
                next == LabState.RevokedCleanupPending) ||
                (prior == next && (prior == LabState.RevokedCleanupPending ||
                    prior == LabState.OrphanedCredential || prior == LabState.CreatedUnpinned));
        return operation == RecoveryOperation.Reconciliation && prior == next &&
            (prior == LabState.EnrollmentOutcomeUnknown ||
             prior == LabState.CleanupOutcomeUnknown ||
             prior == LabState.OrphanCleanupOutcomeUnknown);
    }

    private static bool ReferenceCanRecord(
        RecoveryOperation operation, LabState prior, RecoveryOutcome priorOutcome,
        LabState next, RecoveryOutcome outcome)
    {
        if (priorOutcome != RecoveryOutcome.Started && priorOutcome != RecoveryOutcome.Succeeded)
            return false;
        return operation switch
        {
            RecoveryOperation.Enrollment =>
                (next == LabState.CreatedUnpinned &&
                    (outcome == RecoveryOutcome.Succeeded || outcome == RecoveryOutcome.Failed)) ||
                (next == LabState.CredentialPinnedInMemory && prior == LabState.CreatedUnpinned &&
                    outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.OrphanedCredential &&
                    (outcome == RecoveryOutcome.Failed || outcome == RecoveryOutcome.Unknown)) ||
                (next == LabState.EnrollmentOutcomeUnknown && outcome == RecoveryOutcome.Unknown) ||
                (next == LabState.Failed && outcome == RecoveryOutcome.Failed),
            RecoveryOperation.Assertion =>
                (next == LabState.AssertionContractMatched && outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.Cancelled && outcome == RecoveryOutcome.Unknown) ||
                (next == LabState.Failed && outcome == RecoveryOutcome.Failed),
            RecoveryOperation.Cleanup =>
                (next == LabState.RevokedCleanupPending &&
                    (outcome == RecoveryOutcome.Started || outcome == RecoveryOutcome.Failed)) ||
                (next == LabState.OrphanedCredential && outcome == RecoveryOutcome.Failed) ||
                (next == LabState.Ready && outcome == RecoveryOutcome.Succeeded) ||
                (next == LabState.RevokedAndCleaned && outcome == RecoveryOutcome.Succeeded) ||
                ((next == LabState.CleanupOutcomeUnknown ||
                    next == LabState.OrphanCleanupOutcomeUnknown) && outcome == RecoveryOutcome.Unknown),
            RecoveryOperation.Reconciliation =>
                ((next == LabState.Ready || next == LabState.OrphanedCredential ||
                    next == LabState.RevokedCleanupPending || next == LabState.RevokedAndCleaned) &&
                    outcome == RecoveryOutcome.Succeeded) ||
                ((next == LabState.EnrollmentOutcomeUnknown ||
                    next == LabState.CleanupOutcomeUnknown ||
                    next == LabState.OrphanCleanupOutcomeUnknown) && outcome == RecoveryOutcome.Unknown),
            _ => false
        };
    }

    private static string FakeId(string label) => Convert.ToBase64String(Encoding.ASCII.GetBytes(label))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class LyingInventoryCollection(
        int declaredCount, IReadOnlyList<string> items) : IReadOnlyCollection<string>
    {
        public int Count => declaredCount;
        public IEnumerator<string> GetEnumerator() => items.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private static RecoveryJournalEntry StoreEntry(long revision, string operationId,
        LabState state, RecoveryOutcome outcome) => new(
        RecoveryJournal.CurrentSchemaVersion, revision, operationId, RecoveryOperation.Enrollment,
        state, outcome, RecoveryJournal.TestRpId, RecoveryJournal.TestOrigin,
        null, null, null, false, 0, null);

    private static SyntheticTrustEvidence CompleteTrustEvidence()
    {
        static Evidence<string> Text(string value) => new(value, SyntheticEvidenceSource.SyntheticFixture);
        static Evidence<bool> Flag(bool value) => new(value, SyntheticEvidenceSource.SyntheticFixture);
        return new(
            new ExecutableIdentityEvidence(Text("fixture-executable-a")),
            new BinaryIntegrityEvidence(Text("fixture-executable-a"), Text("fixture-digest-a")),
            new ProcessIdentityEvidence(new Evidence<int>(42, SyntheticEvidenceSource.SyntheticFixture), Text("fixture-user")),
            new WindowsUserEvidence(Text("fixture-user")),
            new AuthenticatorIdentityEvidence(Text("fixture-authenticator")),
            new RelyingPartyEvidence(Text(RecoveryJournal.TestRpId), Text(RecoveryJournal.TestOrigin)),
            new CredentialPossessionEvidence(Text("fixture-authenticator"), Text("fixture-credential")),
            new UserVerificationEvidence(Flag(true), Flag(true)),
            new IndependentUserApprovalEvidence(Flag(true)));
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
