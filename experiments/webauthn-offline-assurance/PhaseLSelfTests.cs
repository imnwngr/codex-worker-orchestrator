using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WebAuthn.OfflineAssurance;

internal static class PhaseLSelfTests
{
    private const string Revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("assertion failed"); }
    private static string Mutate(string json, Action<JsonNode> action)
    { var node = JsonNode.Parse(json)!; action(node); return node.ToJsonString(); }
    private static void Reject(VerificationResult result, string category)
    {
        using var d = JsonDocument.Parse(result.Json);
        Must(result.ExitCode == 2 && d.RootElement.GetProperty("errorCategory").GetString() == category);
        Must(d.RootElement.EnumerateObject().Count() == 3); // No input, path, or exception detail leaks.
    }
    private static void Throws(Action action, string category)
    {
        try { action(); } catch (AssuranceInputException e) { Must(e.Category == category); return; }
        throw new InvalidOperationException("unsafe acceptance");
    }

    internal static IEnumerable<(string Name, Action Test)> Cases(string manifest, string registry, string repo)
    {
        var cases = new List<(string, Action)>();
        void Add(string name, Action test) => cases.Add(("3C.4L: " + name, test));
        void Policy(string name, string changed, string category) => Add(name, () => Reject(AssuranceVerifier.PolicyCheck(changed, registry), category));
        void Registry(string name, string changed, string category) => Add(name, () => Reject(AssuranceVerifier.PolicyCheck(manifest, changed), category));
        var fixture = SyntheticCandidate.FixtureEvidence(Revision);
        VerificationResult Report(string evidence) => AssuranceVerifier.Report(manifest, registry, evidence, Revision, repo);
        void Evidence(string name, string changed, string category) => Add(name, () => Reject(Report(changed), category));

        Policy("missing CI job", Mutate(manifest, x => x["expectedCiJobCategories"]!.AsArray().RemoveAt(0)), "POLICY_ENUMERATION_INVALID");
        Policy("enabled prohibition", Mutate(manifest, x => x["prohibitedCapabilities"]![0] = "enabled-real-webauthn-enrollment"), "POLICY_ENUMERATION_INVALID");
        Policy("contradictory synthetic readiness", Mutate(manifest, x => x["readinessGates"]!["syntheticRegressionIntegration"] = "GO"), "POLICY_READINESS_CONTRADICTION");
        Policy("nested permission", Mutate(manifest, x => x["securityScope"]!["permission"] = true), "SCHEMA_UNKNOWN_FIELD");
        Policy("null scope", Mutate(manifest, x => x["securityScope"] = null), "SCHEMA_TYPE_INVALID");
        Policy("excessive nesting", new string('[', 18) + "0" + new string(']', 18), "JSON_MALFORMED");
        Policy("nested duplicate", manifest.Replace("\"productionAuthorization\": \"DEFAULT_DENY\"", "\"productionAuthorization\": \"DEFAULT_DENY\", \"productionAuthorization\": \"ALLOW\""), "JSON_DUPLICATE_PROPERTY");
        Registry("unsupported registry version", Mutate(registry, x => x["schemaVersion"] = 2), "INVARIANT_SCHEMA_UNSUPPORTED");

        var count = JsonNode.Parse(registry)!["invariants"]!.AsArray().Count;
        for (var i = 0; i < count; i++)
        {
            var index = i;
            Registry($"delete invariant {i}", Mutate(registry, x => x["invariants"]!.AsArray().RemoveAt(index)), "POLICY_ENUMERATION_INVALID");
            Registry($"duplicate invariant {i}", Mutate(registry, x => x["invariants"]!.AsArray().Add(x["invariants"]![index]!.DeepClone())), "INVARIANT_ID_DUPLICATE");
            Registry($"corrupt status {i}", Mutate(registry, x => x["invariants"]![index]!["status"] = "EXECUTED"), "INVARIANT_STATUS_UNKNOWN");
            Registry($"contradictory domain {i}", Mutate(registry, x => x["invariants"]![index]!["domain"] = "production"), "INVARIANT_METADATA_CONTRADICTION");
            Registry($"missing references {i}", Mutate(registry, x => x["invariants"]![index]!["testReferences"] = new JsonArray()), "INVARIANT_TRACEABILITY_INCOMPLETE");
            var trace = Mutate(registry, x => x["invariants"]![index]!["enforcementLocations"]![0] = "experiments/nonexistent.cs");
            Add($"nonexistent enforcement {i}", () => Must(AssuranceVerifier.TraceError(trace, repo) == "INVARIANT_SOURCE_LOCATION_MISSING"));
        }
        foreach (var path in new[] { "../outside.cs", "experiments/../broker/README.md", "C:/absolute.cs" })
        {
            var changed = Mutate(registry, x => x["invariants"]![0]!["enforcementLocations"]![0] = path);
            Add("traversal " + path, () => Must(AssuranceVerifier.TraceError(changed, repo) == "INVARIANT_SOURCE_PATH_INVALID"));
        }
        Add("existing unrelated enforcement rejected", () => Must(AssuranceVerifier.TraceError(Mutate(registry, x => x["invariants"]![0]!["enforcementLocations"]![0] = "README.md"), repo) == "INVARIANT_SOURCE_PATH_UNEXPECTED"));
        Add("existing wrong test cannot substitute mandatory test", () => Must(AssuranceVerifier.TraceError(Mutate(registry, x => x["invariants"]![0]!["testReferences"]![0] = "FakeOwnership"), repo) == "INVARIANT_TRACEABILITY_CONTRADICTION"));
        Add("absent test cannot prove enforcement", () => Must(AssuranceVerifier.TraceError(Mutate(registry, x => x["invariants"]![0]!["testReferences"]![0] = "MissingTest"), repo) == "INVARIANT_TRACEABILITY_CONTRADICTION"));
        Registry("false executable enforcement", Mutate(registry, x => x["invariants"]!.AsArray().First(n => n!["id"]!.GetValue<string>() == "AUTH-01")!["status"] = "CODE_ENFORCED_TESTED"), "INVARIANT_ASSURANCE_CLASSIFICATION_INVALID");

        Evidence("unsupported evidence version", Mutate(fixture, x => x["schemaVersion"] = 2), "EVIDENCE_SCHEMA_UNSUPPORTED");
        Evidence("very long identifier", Mutate(fixture, x => x["evidence"]![0]!["evidenceId"] = new string('x', 8192)), "SCHEMA_STRING_INVALID");
        Evidence("null evidence", Mutate(fixture, x => x["evidence"]![0] = null), "SCHEMA_TYPE_INVALID");
        Evidence("wrong digest type", Mutate(fixture, x => x["evidence"]![0]!["inputSha256"] = 7), "SCHEMA_TYPE_INVALID");
        Evidence("null payload", Mutate(fixture, x => x["evidence"]![0]!["payload"] = null), "SCHEMA_TYPE_INVALID");
        Evidence("fabricated authentication origin", Mutate(fixture, x => x["evidence"]![0]!["origin"] = "independently-authenticated"), "EVIDENCE_ORIGIN_INVALID");
        Evidence("mismatched result linkage", Mutate(fixture, x => x["evidence"]![0]!["payload"]!["reportedResult"] = "FAIL"), "EVIDENCE_LINKAGE_INVALID");
        Add("conflicting group results rejected despite valid digests", () => {
            var node = JsonNode.Parse(fixture)!;
            var fail = node["evidence"]![0]!.DeepClone();
            fail["evidenceId"] = "contradiction"; fail["reportedResult"] = "FAIL"; fail["payload"]!["reportedResult"] = "FAIL";
            RehashEvidence(fail); node["evidence"]!.AsArray().Add(fail);
            Reject(Report(node.ToJsonString()), "EVIDENCE_RESULT_CONFLICT");
        });
        foreach (var (origin, classification) in new[] {
            ("self-reported", "SELF_REPORTED_UNVERIFIED"), ("locally-reported", "LOCAL_EXECUTION_REPORTED_UNVERIFIED"),
            ("ci-reported-unverified", "CI_EXECUTION_REPORTED_PROVENANCE_UNVERIFIED"), ("fixed-test-fixture", "SYNTHETIC_FIXTURE_NOT_EXECUTION") })
            Add("source classification " + origin, () => {
                var changed = Mutate(fixture, x => { foreach (var item in x["evidence"]!.AsArray()) item!["origin"] = origin; });
                var result = Report(changed);
                Must(result.ExitCode == (origin == "fixed-test-fixture" ? 1 : 0));
                using var d = JsonDocument.Parse(result.Json);
                Must(d.RootElement.GetProperty("evidence").EnumerateArray().All(x => x.GetProperty("sourceClassification").GetString() == classification));
                Must(!d.RootElement.GetProperty("independentlyCertified").GetBoolean());
            });
        Add("strict UTF8 decoding", () => Throws(() => BoundedInput.Decode(new byte[] { 0xc3, 0x28 }), "INPUT_UTF8_INVALID"));
        Add("UTF8 bounded before decoding", () => Throws(() => BoundedInput.Decode(new byte[StrictJson.MaximumBytes + 1]), "INPUT_OVERSIZED"));
        Policy("multibyte JSON byte bound", "\"" + new string('é', StrictJson.MaximumBytes / 2) + "\"", "INPUT_OVERSIZED");
        Add("reject diagnostics deterministic", () => {
            var input = Mutate(manifest, x => x["securityScope"]!["productionAuthorization"] = "ALLOW");
            var first = AssuranceVerifier.PolicyCheck(input, registry);
            Reject(first, "POLICY_SECURITY_SCOPE_INVALID");
            Must(first == AssuranceVerifier.PolicyCheck(input, registry));
        });
        Add("evidence input order does not alter report bytes", () => {
            var reordered = Mutate(fixture, x => {
                var items = x["evidence"]!.AsArray().Select(n => n!.DeepClone()).Reverse().ToArray();
                x["evidence"] = new JsonArray(items);
            });
            Must(Report(fixture).Json == Report(reordered).Json);
        });

        // Independent restricted oracle: reads critical fields directly and never invokes AssuranceVerifier.
        var differential = new List<(string Json, bool Accept)> { (manifest, true), (JsonNode.Parse(manifest)!.ToJsonString(), true), (Encoding.UTF8.GetString(SyntheticCandidate.Json(manifest)), true) };
        foreach (var gate in new[] { "realCredentialEnrollment", "realCredentialAssertion", "realCredentialEnumeration", "realCredentialDeletion", "productionAuthorization" })
            differential.Add((Mutate(manifest, x => x["readinessGates"]![gate] = "GO"), false));
        differential.Add((Mutate(manifest, x => x["securityScope"]!["productionAuthorization"] = "ALLOW"), false));
        differential.Add((Mutate(manifest, x => x["securityScope"]!["userApprovalAuthority"] = "MODEL"), false));
        differential.Add((Mutate(manifest, x => x["prohibitedCapabilities"]!.AsArray().RemoveAt(0)), false));
        differential.Add((Mutate(manifest, x => x["manifestSchemaVersion"] = 9), false));
        differential.Add((Mutate(manifest, x => x["designation"] = "PRODUCTION"), false));
        differential.Add((Mutate(manifest, x => x["securityScope"]!["syntheticCredentialLifecycle"] = "REAL"), false));
        differential.Add((Mutate(manifest, x => x["securityScope"]!["hostDiagnostics"] = "LIVE_CEREMONIES"), false));
        foreach (var (json, accept) in differential)
            Add("differential " + cases.Count, () => {
                Must(ReferenceAllows(json) == accept);
                var result = AssuranceVerifier.PolicyCheck(json, registry);
                Must((result.ExitCode == 0) == accept);
                Must(result.Json == AssuranceVerifier.PolicyCheck(json, registry).Json);
            });

        Add("candidate reproducible positive controls and audit has no writes", () => InSandbox(root => {
            var first = Path.Combine(root, "a"); var second = Path.Combine(root, "b");
            SyntheticCandidate.Create(repo, Revision, first); SyntheticCandidate.Create(repo, Revision, second);
            var before = Snapshot(first);
            SyntheticCandidate.Audit(repo, Revision, first);
            Must(before.SequenceEqual(Snapshot(first)) && before.SequenceEqual(Snapshot(second)));
        }));
        void Tamper(string name, Action<string> mutate, string category) => Add(name, () => InSandbox(root => {
            var path = Path.Combine(root, "candidate"); SyntheticCandidate.Create(repo, Revision, path); mutate(path);
            var before = Snapshot(path);
            Throws(() => SyntheticCandidate.Audit(repo, Revision, path), category);
            Must(before.SequenceEqual(Snapshot(path)));
        }));
        Tamper("missing package member", p => File.Delete(Path.Combine(p, "evidence.json")), "CANDIDATE_MEMBER_SET_INVALID");
        Tamper("extra executable", p => File.WriteAllText(Path.Combine(p, "unexpected.exe"), "fake"), "CANDIDATE_MEMBER_SET_INVALID");
        Tamper("altered member", p => File.AppendAllText(Path.Combine(p, "closure.md"), "tampered"), "CANDIDATE_DIGEST_MISMATCH");
        Tamper("traversal inventory", p => ChangeInventory(p, x => x["members"]![0]!["path"] = "../escape"), "CANDIDATE_PATH_INVALID");
        Tamper("backslash inventory", p => ChangeInventory(p, x => x["members"]![0]!["path"] = "folder\\escape"), "CANDIDATE_PATH_INVALID");
        Tamper("duplicate inventory", p => ChangeInventory(p, x => x["members"]![1]!["path"] = x["members"]![0]!["path"]!.GetValue<string>()), "CANDIDATE_PATH_INVALID");
        Tamper("unsupported inventory schema", p => ChangeInventory(p, x => x["schemaVersion"] = 2), "CANDIDATE_SCHEMA_UNSUPPORTED");
        Tamper("nested duplicate package property", p => {
            var file = Path.Combine(p, SyntheticCandidate.Inventory);
            File.WriteAllText(file, File.ReadAllText(file).Replace("\"size\":", "\"size\":0,\"size\":"));
        }, "JSON_DUPLICATE_PROPERTY");
        Tamper("incorrect candidate revision", p => ChangeInventory(p, x => x["sourceRevision"] = new string('b', 40)), "CANDIDATE_REVISION_MISMATCH");
        Tamper("malformed package digest", p => ChangeInventory(p, x => x["members"]![0]!["sha256"] = new string('z', 64)), "CANDIDATE_DIGEST_INVALID");
        Tamper("invalid UTF8 package member", p => File.WriteAllBytes(Path.Combine(p, "closure.md"), new byte[] { 0xff }), "INPUT_UTF8_INVALID");
        Tamper("oversized package member", p => File.WriteAllBytes(Path.Combine(p, "closure.md"), new byte[StrictJson.MaximumBytes + 1]), "INPUT_OVERSIZED");
        Tamper("rehash permissive manifest", p => ReplaceMember(p, "manifest.json", x => x["securityScope"]!["productionAuthorization"] = "ALLOW"), "CANDIDATE_CONTENT_CONTRADICTION");
        Tamper("rehash contradictory report", p => ReplaceMember(p, "assurance-report.json", x => x["realCredentialOperations"] = "GO"), "CANDIDATE_CONTENT_CONTRADICTION");
        Tamper("rehash missing evidence", p => ReplaceMember(p, "evidence.json", x => x["evidence"]!.AsArray().Clear()), "CANDIDATE_CONTENT_CONTRADICTION");
        Tamper("rehash promoted verification", p => ReplaceMember(p, "verification.json", x => x["classification"] = "INDEPENDENTLY_AUTHENTICATED"), "CANDIDATE_CONTENT_CONTRADICTION");
        Tamper("unexpected subdirectory", p => { File.Delete(Path.Combine(p, "closure.md")); Directory.CreateDirectory(Path.Combine(p, "closure.md")); }, "CANDIDATE_LINK_OR_DIRECTORY_REJECTED");
        Add("create never overwrites existing candidate", () => InSandbox(root => {
            var path = Path.Combine(root, "candidate"); SyntheticCandidate.Create(repo, Revision, path);
            var before = Snapshot(path);
            Throws(() => SyntheticCandidate.Create(repo, Revision, path), "CANDIDATE_DESTINATION_EXISTS");
            Must(before.SequenceEqual(Snapshot(path)));
        }));
        return cases;
    }

    private static bool ReferenceAllows(string json)
    {
        using var d = JsonDocument.Parse(json); var r = d.RootElement;
        var scope = r.GetProperty("securityScope"); var gates = r.GetProperty("readinessGates");
        return r.GetProperty("manifestSchemaVersion").GetInt32() == 1 &&
            r.GetProperty("designation").GetString() == "EXPERIMENTAL_SYNTHETIC_ONLY" &&
            scope.GetProperty("productionAuthorization").GetString() == "DEFAULT_DENY" &&
            scope.GetProperty("userApprovalAuthority").GetString() == "USER_ONLY" &&
            scope.GetProperty("syntheticCredentialLifecycle").GetString() == "IN_MEMORY_FAKE_ONLY" &&
            scope.GetProperty("hostDiagnostics").GetString() == "READ_ONLY_RUNTIME_CAPABILITY_QUERIES_ONLY" &&
            new[] { "realCredentialEnrollment", "realCredentialAssertion", "realCredentialEnumeration", "realCredentialDeletion", "productionAuthorization" }.All(g => gates.GetProperty(g).GetString() == "NO_GO") &&
            r.GetProperty("prohibitedCapabilities").EnumerateArray().Select(x => x.GetString()).ToHashSet().SetEquals(new[] {
                "real-webauthn-enrollment", "real-webauthn-assertion", "real-credential-enumeration", "real-credential-deletion", "production-dispatch-from-lab", "mock-approval-grant-minting", "credential-material-persistence" });
    }
    private static void RehashEvidence(JsonNode node)
    { using var d = JsonDocument.Parse(node["payload"]!.ToJsonString()); node["inputSha256"] = SyntheticCandidate.Digest(CanonicalJson.Bytes(d.RootElement)); }
    private static void ChangeInventory(string path, Action<JsonNode> action)
    { var file = Path.Combine(path, SyntheticCandidate.Inventory); File.WriteAllBytes(file, SyntheticCandidate.Json(Mutate(File.ReadAllText(file), action))); }
    private static void ReplaceMember(string path, string name, Action<JsonNode> action)
    {
        var bytes = SyntheticCandidate.Json(Mutate(File.ReadAllText(Path.Combine(path, name)), action));
        File.WriteAllBytes(Path.Combine(path, name), bytes);
        ChangeInventory(path, x => { var item = x["members"]!.AsArray().First(n => n!["path"]!.GetValue<string>() == name)!; item["sha256"] = SyntheticCandidate.Digest(bytes); item["size"] = bytes.Length; });
    }
    private static string[] Snapshot(string path) => Directory.GetFileSystemEntries(path).Order(StringComparer.Ordinal).Select(p => Path.GetFileName(p) + ":" + (Directory.Exists(p) ? "directory" : SyntheticCandidate.Digest(File.ReadAllBytes(p)))).ToArray();
    private static void InSandbox(Action<string> action)
    {
        var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "phase-3c-4l-selftests"));
        var root = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
        if (!root.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("invalid test root");
        SyntheticCandidate.CheckDirectory(parent);
        Directory.CreateDirectory(root);
        try { action(root); }
        finally { SyntheticCandidate.CheckDirectory(root); Directory.Delete(root, true); }
    }
}
