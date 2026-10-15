using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebAuthn.OfflineAssurance;

// Local content package only. No binaries, credentials, execution claims, or publication.
internal static class SyntheticCandidate
{
    internal static readonly string[] Members = ["assurance-report.json", "closure.md", "documentation-index.json", "evidence.json", "invariant-registry.json", "manifest.json", "verification.json"];
    internal static readonly string[] Groups = ["approval-agent-mock", "webauthn-fake-lab", "node-regression"];
    internal const string Inventory = "candidate.json";
    internal static string Digest(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static byte[] Json(string text)
    {
        using var d = StrictJson.Parse(text);
        return CanonicalJson.Bytes(d.RootElement).Concat(new byte[] { 10 }).ToArray();
    }
    private static byte[] Serialize(object value) => Json(JsonSerializer.Serialize(value, JsonDefaults.Options));

    internal static string FixtureEvidence(string revision)
    {
        Contract.Revision(revision);
        return JsonSerializer.Serialize(new EvidenceDocument(1, Groups.Select((group, i) => {
            var assumptions = new[] { "Generated synthetic fixture; never evidence of test execution" };
            var payload = new EvidencePayload(group, "PASS", revision, null, assumptions);
            var digest = Digest(CanonicalJson.Bytes(JsonSerializer.SerializeToElement(payload, JsonDefaults.Options)));
            return new EvidenceEnvelope($"candidate-fixture-{i}", "test-run-summary", "fixed-test-fixture", revision, group, "PASS", null, digest, assumptions, payload);
        }).ToArray()), JsonDefaults.Options);
    }

    internal static SortedDictionary<string, byte[]> Contents(string repo, string revision)
    {
        Contract.Revision(revision);
        var manifest = BoundedInput.Read(Path.Combine(repo, "experiments/webauthn-windows-lab/experimental-readiness.json"));
        var registry = BoundedInput.Read(Path.Combine(repo, "experiments/webauthn-offline-assurance/invariant-registry.json"));
        var policy = AssuranceVerifier.PolicyCheck(manifest, registry);
        if (policy.ExitCode != 0) throw new AssuranceInputException("CANDIDATE_POLICY_INVALID");
        var evidence = FixtureEvidence(revision);
        var report = AssuranceVerifier.Report(manifest, registry, evidence, revision, repo);
        if (report.ExitCode != 1) throw new AssuranceInputException("CANDIDATE_REPORT_INVALID");
        using (var parsed = StrictJson.Parse(report.Json))
            if (parsed.RootElement.GetProperty("finalSyntheticAssuranceStatus").GetString() != "POLICY_VALID_EVIDENCE_INCOMPLETE")
                throw new AssuranceInputException("CANDIDATE_REPORT_INVALID");
        var closure = BoundedInput.Read(Path.Combine(repo, "experiments/webauthn-offline-assurance/BATCH_3C_4L_CLOSURE.md")).Replace("\r\n", "\n");
        var contents = new SortedDictionary<string, byte[]>(StringComparer.Ordinal) {
            ["manifest.json"] = Json(manifest), ["invariant-registry.json"] = Json(registry),
            ["evidence.json"] = Json(evidence), ["assurance-report.json"] = Json(report.Json),
            ["closure.md"] = Encoding.UTF8.GetBytes(closure),
            ["documentation-index.json"] = Serialize(new { schemaVersion = 1, documents = new[] { "closure.md" } })
        };
        contents["verification.json"] = Serialize(new {
            schemaVersion = 1, designation = "SYNTHETIC_ONLY", sourceRevision = revision,
            sourceRevisionSemantics = "CALLER_SUPPLIED_BASE_COMMIT; MEMBER_DIGESTS_DESCRIBE_CANDIDATE_CONTENT",
            manifestSchemaVersion = 1, invariantRegistrySchemaVersion = 1, reportSchemaVersion = 2,
            classification = "REPOSITORY_POLICY_VALIDATED; SYNTHETIC_FIXTURES_ONLY",
            assuranceReportSha256 = Digest(contents["assurance-report.json"]),
            producerAuthentication = "NONE", productionAuthorization = "DEFAULT_DENY", realCredentialOperations = "NO_GO"
        });
        if (contents.Values.Any(x => x.Length > StrictJson.MaximumBytes)) throw new AssuranceInputException("INPUT_OVERSIZED");
        return contents;
    }

    internal static byte[] InventoryBytes(SortedDictionary<string, byte[]> contents, string revision) => Serialize(new {
        schemaVersion = 1, designation = "SYNTHETIC_ONLY", sourceRevision = revision,
        members = contents.Select(x => new { path = x.Key, size = x.Value.Length, sha256 = Digest(x.Value) }).ToArray(),
        reproducibility = "UTF8_MEMBER_AND_INVENTORY_BYTES_ONLY; FILESYSTEM_METADATA_EXCLUDED",
        producerAuthentication = "NONE"
    });

    internal static void CheckDirectory(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new AssuranceInputException("CANDIDATE_LINK_REJECTED");
    }

    internal static void Create(string repo, string revision, string destination)
    {
        CheckDirectory(destination);
        if (Directory.Exists(destination) || File.Exists(destination)) throw new AssuranceInputException("CANDIDATE_DESTINATION_EXISTS");
        var contents = Contents(repo, revision); // Validate before any output mutation.
        Directory.CreateDirectory(destination);
        foreach (var item in contents) WriteNew(Path.Combine(destination, item.Key), item.Value);
        WriteNew(Path.Combine(destination, Inventory), InventoryBytes(contents, revision));
    }
    private static void WriteNew(string path, byte[] bytes)
    { using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None); output.Write(bytes); }

    internal static void Audit(string repo, string revision, string directory)
    {
        CheckDirectory(directory);
        if (!Directory.Exists(directory)) throw new AssuranceInputException("CANDIDATE_MISSING");
        var paths = Directory.EnumerateFileSystemEntries(directory).Take(Members.Length + 2).ToArray();
        if (paths.Length != Members.Length + 1 || paths.Any(x => !Members.Append(Inventory).Contains(Path.GetFileName(x), StringComparer.Ordinal)))
            throw new AssuranceInputException("CANDIDATE_MEMBER_SET_INVALID");
        foreach (var path in paths)
            if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new AssuranceInputException("CANDIDATE_LINK_OR_DIRECTORY_REJECTED");
        var inventoryText = BoundedInput.Read(Path.Combine(directory, Inventory));
        using var doc = StrictJson.Parse(inventoryText);
        var root = doc.RootElement;
        Contract.Obj(root, "schemaVersion", "designation", "sourceRevision", "members", "reproducibility", "producerAuthentication");
        if (Contract.I(root, "schemaVersion", 100) != 1) throw new AssuranceInputException("CANDIDATE_SCHEMA_UNSUPPORTED");
        if (Contract.S(root, "sourceRevision", 64) != revision) throw new AssuranceInputException("CANDIDATE_REVISION_MISMATCH");
        var members = root.GetProperty("members");
        if (members.ValueKind != JsonValueKind.Array || members.GetArrayLength() != Members.Length)
            throw new AssuranceInputException("CANDIDATE_MEMBER_SET_INVALID");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var member in members.EnumerateArray())
        {
            Contract.Obj(member, "path", "size", "sha256");
            var path = Contract.S(member, "path", 80);
            // Only literal normalized allowlisted names can ever reach the filesystem.
            if (!Members.Contains(path, StringComparer.Ordinal) || !seen.Add(path)) throw new AssuranceInputException("CANDIDATE_PATH_INVALID");
            var size = Contract.I(member, "size", StrictJson.MaximumBytes);
            var hash = Contract.S(member, "sha256", 64);
            if (hash.Length != 64 || hash.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
                throw new AssuranceInputException("CANDIDATE_DIGEST_INVALID");
            var bytes = Encoding.UTF8.GetBytes(BoundedInput.Read(Path.Combine(directory, path)));
            if (bytes.Length != size || Digest(bytes) != hash) throw new AssuranceInputException("CANDIDATE_DIGEST_MISMATCH");
        }
        var expected = Contents(repo, revision);
        // Rehashing a forged report or substituted evidence cannot satisfy this consistency check.
        foreach (var item in expected)
            if (!Encoding.UTF8.GetBytes(BoundedInput.Read(Path.Combine(directory, item.Key))).SequenceEqual(item.Value))
                throw new AssuranceInputException("CANDIDATE_CONTENT_CONTRADICTION");
        if (!Encoding.UTF8.GetBytes(inventoryText).SequenceEqual(InventoryBytes(expected, revision)))
            throw new AssuranceInputException("CANDIDATE_INVENTORY_CONTRADICTION");
    }
}
