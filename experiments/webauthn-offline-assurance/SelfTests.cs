using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WebAuthn.OfflineAssurance;

internal sealed record SelfTestSummary(int Passed, int Failures, string[] FailedCases,
    string Scope = "OFFLINE_STRUCTURAL_AND_SYNTHETIC_FIXTURES_ONLY");
internal sealed record EvidencePayload(string? TestGroup, string ReportedResult,
    string? SourceRevision, string? ObservationTimestampUtc, string[] Assumptions);
internal sealed record EvidenceEnvelope(string EvidenceId, string Category, string Origin,
    string? SourceRevision, string? TestGroup, string ReportedResult,
    string? ObservationTimestampUtc, string InputSha256, string[] Assumptions,
    EvidencePayload Payload);
internal sealed record EvidenceDocument(int SchemaVersion, EvidenceEnvelope[] Evidence);

internal static class OfflineAssuranceSelfTests
{
    private static readonly string[] Groups = ["approval-agent-mock", "webauthn-fake-lab", "node-regression"];

    public static SelfTestSummary Run(string manifest, string registry, string fixtureDirectory, string repoRoot)
    {
        _manifest = manifest;
        _registry = registry;
        _repoRoot = repoRoot;
        var failed = new List<string>();
        var cases = new (string Name, Action Test)[] {
            ("baseline manifest and invariant registry validate", () => Must(AssuranceVerifier.PolicyCheck(manifest, registry).ExitCode == 0)),
            ("all invariant source and regression test references resolve", () => { var error=AssuranceVerifier.TraceError(registry, repoRoot); if(error is not null) throw new InvalidOperationException(error); }),
            ("missing invariant source location is detected", () => {
                var changed = MutateRegistry(registry, j => j["invariants"]![0]!["enforcementLocations"]![0] = "experiments/missing.cs");
                Must(AssuranceVerifier.TraceError(changed, repoRoot) == "INVARIANT_SOURCE_LOCATION_MISSING");
            }),
            ("duplicate JSON properties are rejected", () => RejectManifest(File.ReadAllText(Path.Combine(fixtureDirectory, "duplicate-property.json")), "JSON_DUPLICATE_PROPERTY")),
            ("unsupported manifest schema fails closed", () => RejectManifest(MutateManifest(manifest, j => j["manifestSchemaVersion"] = 99), "MANIFEST_SCHEMA_UNSUPPORTED")),
            ("unknown permission-like field is rejected", () => RejectManifest(MutateManifest(manifest, j => j["authorizationGrant"] = "enabled"), "SCHEMA_UNKNOWN_FIELD")),
            ("production default-deny cannot be relaxed", () => RejectManifest(MutateManifest(manifest, j => j["securityScope"]!["productionAuthorization"] = "ALLOW"), "POLICY_SECURITY_SCOPE_INVALID")),
            ("prohibited capability removal is detected", () => RejectManifest(MutateManifest(manifest, j => j["prohibitedCapabilities"]!.AsArray().RemoveAt(0)), "POLICY_ENUMERATION_INVALID")),
            ("real-operation NO-GO promotion is detected", () => RejectManifest(MutateManifest(manifest, j => j["readinessGates"]!["realCredentialAssertion"] = "GO"), "POLICY_READINESS_CONTRADICTION")),
            ("required regression group removal is detected", () => RejectManifest(MutateManifest(manifest, j => j["requiredTestGroups"]!.AsArray().RemoveAt(0)), "POLICY_ENUMERATION_INVALID")),
            ("unexpected CI identity is detected", () => RejectManifest(MutateManifest(manifest, j => j["expectedCiJobCategories"]![0] = "windows-node-latest"), "POLICY_ENUMERATION_INVALID")),
            ("missing manifest field is rejected", () => RejectManifest(MutateManifest(manifest, j => j.AsObject().Remove("designation")), "SCHEMA_REQUIRED_FIELD_MISSING")),
            ("oversized policy collection is rejected", () => RejectManifest(MutateManifest(manifest, j => j["prohibitedCapabilities"] = new JsonArray(Enumerable.Range(0, 17).Select(_ => (JsonNode?)JsonValue.Create("extra-capability")).ToArray())), "SCHEMA_COLLECTION_INVALID")),
            ("incorrect manifest field type is rejected", () => RejectManifest(MutateManifest(manifest, j => j["requiredTestGroups"] = "all-tests"), "SCHEMA_COLLECTION_INVALID")),
            ("malformed registry and missing invariant fail closed", () => RejectRegistry(MutateRegistry(registry, j => j["invariants"]!.AsArray().RemoveAt(0)), "POLICY_ENUMERATION_INVALID")),
            ("duplicate invariant ID is rejected", () => RejectRegistry(MutateRegistry(registry, j => j["invariants"]![1]!["id"] = j["invariants"]![0]!["id"]!.GetValue<string>()), "INVARIANT_ID_DUPLICATE")),
            ("unrecognized invariant status is rejected", () => RejectRegistry(MutateRegistry(registry, j => j["invariants"]![0]!["status"] = "VERIFIED_BY_HASH"), "INVARIANT_STATUS_UNKNOWN")),
            ("evidence structure rejects duplicate properties", () => RejectEvidence(File.ReadAllText(Path.Combine(fixtureDirectory, "duplicate-property.json")), "JSON_DUPLICATE_PROPERTY")),
            ("positive self-reported evidence is classified as reported only", () => {
                var ev = BuildEvidence(Groups, new string('a', 40), "self-reported");
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.ExitCode == 0);
                Must(report.Json.Contains("SYNTHETIC_REGRESSION_REPORTED", StringComparison.Ordinal));
                Must(report.Json.Contains("SELF_REPORTED_UNVERIFIED", StringComparison.Ordinal));
                Must(report.Json.Contains("READ_ONLY_RUNTIME_UNOBSERVED", StringComparison.Ordinal));
                Must(report.Json.Contains("DEFAULT_DENY", StringComparison.Ordinal));
                Must(report.Json.Contains("\"independentlyCertified\": false", StringComparison.Ordinal));
            }),
            ("checked-in report fixture reproduces byte-for-byte", () => {
                var evidence = File.ReadAllText(Path.Combine(fixtureDirectory, "evidence-reported-fixture.json"));
                var expected = File.ReadAllText(Path.Combine(fixtureDirectory, "expected-report.json")).Replace("\r\n", "\n").Trim();
                var report = AssuranceVerifier.Report(manifest, registry, evidence, new string('a', 40), repoRoot);
                Must(report.ExitCode == 1 && StringComparer.Ordinal.Equals(expected, report.Json.Replace("\r\n", "\n").Trim()));
            }),            ("deterministic report bytes are stable for identical inputs", () => {
                var ev = BuildEvidence(Groups, new string('a', 40));
                var first = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot).Json;
                var second = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot).Json;
                Must(StringComparer.Ordinal.Equals(first, second));
            }),
            ("self-consistent hash does not authenticate the producer", () => {
                var ev = BuildEvidence(Groups, new string('a', 40), "self-reported");
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.Json.Contains("PRODUCER_UNAUTHENTICATED", StringComparison.Ordinal));
                Must(report.Json.Contains("SELF_REPORTED_UNVERIFIED", StringComparison.Ordinal));
                Must(!report.Json.Contains("INDEPENDENTLY_VERIFIED\",\n", StringComparison.Ordinal));
            }),
            ("fixed fixtures cannot claim executed regression coverage", () => {
                var ev = BuildEvidence(Groups, new string('a', 40));
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.ExitCode == 1 && report.Json.Contains("required_test_group_fixture_only", StringComparison.Ordinal));
                Must(report.Json.Contains("FIXTURE_NOT_EXECUTION_EVIDENCE", StringComparison.Ordinal));
                Must(!report.Json.Contains("\"SYNTHETIC_REGRESSION_REPORTED\"", StringComparison.Ordinal));
            }),
            ("partially self-reported groups do not promote fixture-only groups", () => {
                var fixture=JsonNode.Parse(BuildEvidence(Groups, new string('a', 40)))!.AsObject();
                fixture["evidence"]![0]!["origin"]="self-reported";
                var report=AssuranceVerifier.Report(manifest, registry, fixture.ToJsonString(), new string('a', 40), repoRoot);
                Must(report.ExitCode==1 && report.Json.Contains("required_test_group_fixture_only", StringComparison.Ordinal));
            }),
            ("historical origin cannot forge test-run summaries", () => {
                RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["origin"]="user-supplied-historical"), "EVIDENCE_ORIGIN_CATEGORY_MISMATCH");
            }),
            ("historical observations require an explicit timestamp", () => {
                var ev=AddHistoricalObservation(BuildEvidence(Groups, new string('a', 40)), new string('a', 40));
                RejectEvidence(MutateEvidence(ev,j=>j["evidence"]!.AsArray().Last()!["observationTimestampUtc"]=null),"EVIDENCE_TIMESTAMP_REQUIRED");
            }),
            ("digest alteration is rejected", () => RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["inputSha256"] = new string('0', 64)), "EVIDENCE_DIGEST_MISMATCH")),
            ("registry cannot promote a source-reviewed invariant", () => RejectRegistry(MutateRegistry(registry, j => { var item=j["invariants"]!.AsArray().First(x=>x!["id"]!.GetValue<string>()=="NATIVE-01"); item!["status"]="CODE_ENFORCED_TESTED"; }), "INVARIANT_ASSURANCE_CLASSIFICATION_INVALID")),
            ("reported regression failure blocks complete evidence", () => {
                var ev = ChangeEvidenceResult(BuildEvidence(Groups, new string('a', 40)), "node-regression", "FAIL");
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.ExitCode == 1 && report.Json.Contains("required_test_group_reported_failure", StringComparison.Ordinal));
            }),            ("missing required test group remains incomplete", () => {
                var ev = BuildEvidence(Groups[..2], new string('a', 40));
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.ExitCode == 1 && report.Json.Contains("SYNTHETIC_EVIDENCE_INCOMPLETE", StringComparison.Ordinal));
            }),
            ("missing source revision remains incomplete", () => {
                var ev = BuildEvidence(Groups, null);
                var report = AssuranceVerifier.Report(manifest, registry, ev, null, repoRoot);
                Must(report.ExitCode == 1 && report.Json.Contains("expected_source_revision_not_supplied", StringComparison.Ordinal));
            }),
            ("stale evidence revision remains incomplete", () => {
                var ev = BuildEvidence(Groups, new string('b', 40));
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.ExitCode == 1 && report.Json.Contains("evidence_source_revision_unmatched", StringComparison.Ordinal));
            }),
            ("unknown test group and result enums are rejected", () => RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["testGroup"] = "production"), "EVIDENCE_ENUM_INVALID")),
            ("invalid evidence category is rejected", () => RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["category"] = "production-authorization"), "EVIDENCE_CATEGORY_INVALID")),
            ("overlong evidence identifier is rejected", () => RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["evidenceId"] = new string('x', 81)), "SCHEMA_STRING_INVALID")),
            ("malformed digest encoding is rejected", () => RejectEvidence(MutateEvidence(BuildEvidence(Groups, new string('a', 40)), j => j["evidence"]![0]!["inputSha256"] = new string('g', 64)), "EVIDENCE_DIGEST_INVALID")),
            ("reused evidence IDs are rejected", () => RejectEvidence(DuplicateEvidenceId(BuildEvidence(Groups, new string('a', 40))), "EVIDENCE_ID_DUPLICATE")),
            ("conflicting source revisions are rejected", () => RejectEvidence(ConflictingRevisions(), "EVIDENCE_SOURCE_CONFLICT")),
            ("historical runtime observation stays unverified", () => {
                var ev = AddHistoricalObservation(BuildEvidence(Groups, new string('a', 40)), new string('a', 40));
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.Json.Contains("REPORTED_UNVERIFIED_USER_SUPPLIED", StringComparison.Ordinal));
                Must(report.Json.Contains("READ_ONLY_RUNTIME_HISTORICAL_REPORT_UNVERIFIED", StringComparison.Ordinal));
                Must(!report.Json.Contains("\"READ_ONLY_RUNTIME_OBSERVED\"", StringComparison.Ordinal));
                Must(report.Json.Contains("READ_ONLY_RUNTIME_UNOBSERVED", StringComparison.Ordinal));
            }),
            ("synthetic evidence cannot promote real readiness", () => {
                var ev = BuildEvidence(Groups, new string('a', 40));
                var report = AssuranceVerifier.Report(manifest, registry, ev, new string('a', 40), repoRoot);
                Must(report.Json.Contains("REAL_CREDENTIAL_OPERATIONS_BLOCKED", StringComparison.Ordinal));
                Must(report.Json.Contains("\"realCredentialOperations\": \"NO_GO\"", StringComparison.Ordinal));
            }),
            ("oversized assurance input is rejected with stable category", () => RejectManifest(new string(' ', StrictJson.MaximumBytes + 1), "INPUT_OVERSIZED"))
        };
        foreach (var (name, test) in cases)
        {
            try { test(); }
            catch(Exception error) { failed.Add($"{name} ({error.Message})"); }
        }
        return new(cases.Length - failed.Count, failed.Count, failed.ToArray());
    }

    private static void Must(bool condition) { if (!condition) throw new InvalidOperationException(); }
    private static string MutateManifest(string input, Action<JsonObject> mutate) => Mutate(input, mutate);
    private static string MutateRegistry(string input, Action<JsonObject> mutate) => Mutate(input, mutate);
    private static string MutateEvidence(string input, Action<JsonObject> mutate) => Mutate(input, mutate);
    private static string Mutate(string input, Action<JsonObject> mutate)
    { var root = JsonNode.Parse(input)!.AsObject(); mutate(root); return root.ToJsonString(); }
    private static void RejectManifest(string input, string category) => Reject(AssuranceVerifier.PolicyCheck(input, ReadDefaultRegistry()).Json, category);
    private static void RejectRegistry(string input, string category) => Reject(AssuranceVerifier.PolicyCheck(ReadDefaultManifest(), input).Json, category);
    private static void RejectEvidence(string input, string category) => Reject(AssuranceVerifier.Report(ReadDefaultManifest(), ReadDefaultRegistry(), input, new string('a', 40), _repoRoot).Json, category);
    private static void Reject(string json, string category) => Must(json.Contains($"\"errorCategory\": \"{category}\"", StringComparison.Ordinal));
    private static string _manifest = "";
    private static string _registry = "";
    private static string _repoRoot = "";
    private static string ReadDefaultManifest() => _manifest;
    private static string ReadDefaultRegistry() => _registry;

    private static string BuildEvidence(IEnumerable<string> groups, string? revision, string origin = "fixed-test-fixture")
    {
        var items = new List<EvidenceEnvelope>();
        var index = 0;
        foreach (var group in groups)
        {
            var assumptions = new[] { "offline self-test fixture; not proof of execution" };
            var payload = new EvidencePayload(group, "PASS", revision, null, assumptions);
            var payloadElement = JsonSerializer.SerializeToElement(payload, JsonDefaults.Options);
            var digest = Convert.ToHexString(SHA256.HashData(CanonicalJson.Bytes(payloadElement))).ToLowerInvariant();
            items.Add(new($"fixture-{index++}", "test-run-summary", origin, revision,
                group, "PASS", null, digest, assumptions, payload));
        }
        return JsonSerializer.Serialize(new EvidenceDocument(1, items.ToArray()), JsonDefaults.Options);
    }

    private static string ChangeEvidenceResult(string json, string group, string result)
    {
        var root = JsonNode.Parse(json)!.AsObject();
        foreach (var item in root["evidence"]!.AsArray().Where(x => x!["testGroup"]!.GetValue<string>() == group))
        {
            item!["reportedResult"] = result;
            item["payload"]!["reportedResult"] = result;
            using var payload = JsonDocument.Parse(item["payload"]!.ToJsonString());
            item["inputSha256"] = Convert.ToHexString(SHA256.HashData(CanonicalJson.Bytes(payload.RootElement))).ToLowerInvariant();
        }
        return root.ToJsonString();
    }
    private static string DuplicateEvidenceId(string json)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        var array = node["evidence"]!.AsArray();
        array[1]!["evidenceId"] = array[0]!["evidenceId"]!.GetValue<string>();
        return node.ToJsonString();
    }

    private static string ConflictingRevisions()
    {
        var first = JsonNode.Parse(BuildEvidence(Groups[..1], new string('a', 40)))!["evidence"]![0]!.DeepClone();
        var second = JsonNode.Parse(BuildEvidence(Groups[1..2], new string('b', 40)))!["evidence"]![0]!.DeepClone();
        second!["evidenceId"] = "fixture-1";
        var root = new JsonObject { ["schemaVersion"] = 1, ["evidence"] = new JsonArray(first, second) };
        return root.ToJsonString();
    }

    private static string AddHistoricalObservation(string json, string revision)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        var assumptions = new[] { "user supplied historical observation; not independently observed" };
        var payload = new EvidencePayload(null, "OBSERVED", revision,
            "2025-01-01T00:00:00Z", assumptions);
        var element = JsonSerializer.SerializeToElement(payload, JsonDefaults.Options);
        var digest = Convert.ToHexString(SHA256.HashData(CanonicalJson.Bytes(element))).ToLowerInvariant();
        var item = new EvidenceEnvelope("historical-1", "historical-readonly-observation",
            "user-supplied-historical", revision, null, "OBSERVED", payload.ObservationTimestampUtc,
            digest, assumptions, payload);
        var arr = node["evidence"]!.AsArray();
        arr.Add(JsonNode.Parse(JsonSerializer.Serialize(item, JsonDefaults.Options)));
        return node.ToJsonString();
    }
}
