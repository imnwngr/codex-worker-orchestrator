using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn.OfflineAssurance;

public sealed class AssuranceInputException(string category) : Exception(category)
{ public string Category { get; } = category; }

internal static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new() {
        PropertyNamingPolicy=JsonNamingPolicy.CamelCase, Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented=true, DefaultIgnoreCondition=JsonIgnoreCondition.Never };
}

internal static class StrictJson
{
    public const int MaximumBytes = 262_144;
    public static JsonDocument Parse(string text)
    {
        if (Encoding.UTF8.GetByteCount(text)>MaximumBytes) throw new AssuranceInputException("INPUT_OVERSIZED");
        JsonDocument d;
        try { d=JsonDocument.Parse(text,new JsonDocumentOptions { MaxDepth=16 }); }
        catch (JsonException) { throw new AssuranceInputException("JSON_MALFORMED"); }
        try { Duplicates(d.RootElement); } catch { d.Dispose(); throw; }
        return d;
    }
    private static void Duplicates(JsonElement e)
    {
        if(e.ValueKind==JsonValueKind.Object) { var names=new HashSet<string>(StringComparer.Ordinal);
            foreach(var p in e.EnumerateObject()) { if(!names.Add(p.Name)) throw new AssuranceInputException("JSON_DUPLICATE_PROPERTY"); Duplicates(p.Value); } }
        else if(e.ValueKind==JsonValueKind.Array) foreach(var x in e.EnumerateArray()) Duplicates(x);
    }
}

internal static class Contract
{
    public static void Obj(JsonElement e, params string[] fields)
    {
        if(e.ValueKind!=JsonValueKind.Object) throw new AssuranceInputException("SCHEMA_TYPE_INVALID");
        var allowed=fields.ToHashSet(StringComparer.Ordinal);
        foreach(var p in e.EnumerateObject()) if(!allowed.Contains(p.Name)) throw new AssuranceInputException("SCHEMA_UNKNOWN_FIELD");
        foreach(var f in fields) if(!e.TryGetProperty(f,out _)) throw new AssuranceInputException("SCHEMA_REQUIRED_FIELD_MISSING");
    }
    public static string S(JsonElement e,string key,int max=512)
    {
        if(!e.TryGetProperty(key,out var v)||v.ValueKind!=JsonValueKind.String) throw new AssuranceInputException("SCHEMA_TYPE_INVALID");
        var s=v.GetString()!; if(s.Length is 0 || s.Length>max || s.Any(char.IsControl)) throw new AssuranceInputException("SCHEMA_STRING_INVALID"); return s;
    }
    public static string? NS(JsonElement e,string key,int max=512)
    {
        var v=e.GetProperty(key); if(v.ValueKind==JsonValueKind.Null) return null;
        if(v.ValueKind!=JsonValueKind.String) throw new AssuranceInputException("SCHEMA_TYPE_INVALID");
        var s=v.GetString()!; if(s.Length>max||s.Any(char.IsControl)) throw new AssuranceInputException("SCHEMA_STRING_INVALID"); return s.Length==0?null:s;
    }
    public static int I(JsonElement e,string key,int max)
    { if(!e.TryGetProperty(key,out var v)||v.ValueKind!=JsonValueKind.Number||!v.TryGetInt32(out var n)||n<0||n>max) throw new AssuranceInputException("SCHEMA_TYPE_INVALID"); return n; }
    public static string[] A(JsonElement e,string key,int max=32)
    {
        var a=e.GetProperty(key); if(a.ValueKind!=JsonValueKind.Array||a.GetArrayLength()>max) throw new AssuranceInputException("SCHEMA_COLLECTION_INVALID");
        var values=a.EnumerateArray().Select(x=>{if(x.ValueKind!=JsonValueKind.String) throw new AssuranceInputException("SCHEMA_TYPE_INVALID"); var s=x.GetString()!; if(s.Length is 0 or >512||s.Any(char.IsControl)) throw new AssuranceInputException("SCHEMA_STRING_INVALID"); return s;}).ToArray();
        if(values.Distinct(StringComparer.Ordinal).Count()!=values.Length) throw new AssuranceInputException("SCHEMA_DUPLICATE_VALUE"); return values;
    }
    public static void Exact(IEnumerable<string> actual,params string[] expected)
    { if(!actual.Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal),StringComparer.Ordinal)) throw new AssuranceInputException("POLICY_ENUMERATION_INVALID"); }
    public static void Revision(string? s)
    { if(s is not null&&(s.Length is not (40 or 64)||s.Any(c=>!(c is >= '0' and <= '9' or >= 'a' and <= 'f')))) throw new AssuranceInputException("SOURCE_REVISION_INVALID"); }
}

internal sealed record M(string[] Groups,string[] Jobs);
internal sealed record Inv(string Id,string Status,string Category,string[] Locations,string[] Tests,string Limitations);
internal sealed record E(string Id,string Category,string Origin,string? Revision,string? Group,string Result,string? Timestamp,string Digest,string[] Assumptions);
public sealed record VerificationResult(int ExitCode,string Json);
internal sealed record GroupReport(string TestGroup,string Status,string VerificationStatus);
internal sealed record EvidenceReport(string EvidenceId,string Category,string Origin,string? SourceRevision,string? TestGroup,string ReportedResult,string? ObservationTimestampUtc,string InputSha256,string IntegrityStatus,string[] Assumptions)
{
    public string SourceClassification => Origin switch {
        "fixed-test-fixture" => "SYNTHETIC_FIXTURE_NOT_EXECUTION",
        "self-reported" => "SELF_REPORTED_UNVERIFIED",
        "locally-reported" => "LOCAL_EXECUTION_REPORTED_UNVERIFIED",
        "ci-reported-unverified" => "CI_EXECUTION_REPORTED_PROVENANCE_UNVERIFIED",
        "user-supplied-historical" => "HISTORICAL_OBSERVATION_UNVERIFIED",
        _ => throw new AssuranceInputException("EVIDENCE_ORIGIN_INVALID") };
}
internal sealed record InvariantReport(string InvariantId,string RegistryStatus,string EvidenceCategory,string[] TestReferences,string Limitations,string VerificationStatus);
internal sealed record ReportModel(int ReportSchemaVersion,int ManifestSchemaVersion,int InvariantRegistrySchemaVersion,string UserSuppliedExpectedSourceRevision,string[] Classifications,InvariantReport[] Invariants,GroupReport[] TestGroups,EvidenceReport[] Evidence,string[] MissingOrUnverifiedEvidence,string RuntimeObservation,string ProvenanceLimitations,string ReadOnlyRuntimeReadiness,string RealCredentialOperations,string ProductionAuthorization,string FinalSyntheticAssuranceStatus,bool IndependentlyCertified);

public static class AssuranceVerifier
{
    private static readonly string[] Groups=["approval-agent-mock","webauthn-fake-lab","node-regression"];
    private static readonly string[] Jobs=["windows-node-22","windows-node-24","ubuntu-node-22","ubuntu-node-24","windows-dotnet-8"];
    private static readonly string[] Prohibitions=["real-webauthn-enrollment","real-webauthn-assertion","real-credential-enumeration","real-credential-deletion","production-dispatch-from-lab","mock-approval-grant-minting","credential-material-persistence"];
    private static readonly string[] Gates=["syntheticRegressionIntegration","readOnlyRuntimeDiagnostics","wpfMockDemonstration","realCredentialEnrollment","realCredentialAssertion","realCredentialEnumeration","realCredentialDeletion","applicationIdentity","replayProtectionAcrossOsRestarts","syncedPasskeysAndExternalAuthenticators","productionAuthorization"];
    private static readonly string[] InvariantIds=["RP-ORIGIN-01","CRED-ID-01","INVENTORY-01","COLLISION-01","UNKNOWN-01","REVOKE-01","REVOKE-02","JOURNAL-01","REVISION-01","REPLAY-01","RESTORE-01","TRUST-01","READY-01","NATIVE-01","AUTH-01"];
    private static readonly Dictionary<string,string> ExpectedInvariantStatus=new(StringComparer.Ordinal) {
        ["NATIVE-01"]="SOURCE_REVIEWED",["AUTH-01"]="SOURCE_REVIEWED",
        ["RP-ORIGIN-01"]="CODE_ENFORCED_TESTED",["CRED-ID-01"]="CODE_ENFORCED_TESTED",["INVENTORY-01"]="CODE_ENFORCED_TESTED",["COLLISION-01"]="CODE_ENFORCED_TESTED",["UNKNOWN-01"]="CODE_ENFORCED_TESTED",["REVOKE-01"]="CODE_ENFORCED_TESTED",["REVOKE-02"]="CODE_ENFORCED_TESTED",["JOURNAL-01"]="CODE_ENFORCED_TESTED",["REVISION-01"]="CODE_ENFORCED_TESTED",["REPLAY-01"]="CODE_ENFORCED_TESTED",["RESTORE-01"]="CODE_ENFORCED_TESTED",["TRUST-01"]="CODE_ENFORCED_TESTED",["READY-01"]="CODE_ENFORCED_TESTED" };
    private static readonly Dictionary<string,string> ExpectedInvariantCategory=new(StringComparer.Ordinal) {
        ["NATIVE-01"]="source-review",["AUTH-01"]="source-review",
        ["RP-ORIGIN-01"]="synthetic-regression",["CRED-ID-01"]="synthetic-regression",["INVENTORY-01"]="synthetic-regression",["COLLISION-01"]="synthetic-regression",["UNKNOWN-01"]="synthetic-regression",["REVOKE-01"]="synthetic-regression",["REVOKE-02"]="synthetic-regression",["JOURNAL-01"]="synthetic-regression",["REVISION-01"]="synthetic-regression",["REPLAY-01"]="synthetic-regression",["RESTORE-01"]="synthetic-regression",["TRUST-01"]="synthetic-regression",["READY-01"]="synthetic-regression" };

    public static VerificationResult PolicyCheck(string manifest,string registry)
    {
        try { var m=Manifest(manifest); var r=Registry(registry); return new(0,JsonSerializer.Serialize(new { reportSchemaVersion=1,verificationStatus="SYNTHETIC_POLICY_VALIDATED",manifestSchemaVersion=1,invariantRegistrySchemaVersion=1,invariantCount=r.Length,requiredTestGroups=m.Groups,expectedCiJobCategories=m.Jobs,productionAuthorization="DEFAULT_DENY",realCredentialOperations="NO_GO",assuranceIsObservational=true },JsonDefaults.Options)); }
        catch(AssuranceInputException x) { return Reject(x.Category); }
    }

    public static VerificationResult Report(string manifest,string registry,string evidence,string? expectedRevision,string repoRoot)
    {
        try {
            Contract.Revision(expectedRevision); var m=Manifest(manifest); var invariants=Registry(registry); var traceError=TraceError(registry,repoRoot); if(traceError is not null) throw new AssuranceInputException(traceError); var ev=Evidence(evidence);
            var issues=new SortedSet<string>(StringComparer.Ordinal);
            if(invariants.Any(i=>i.Status is "INCOMPLETE" or "DOCUMENTATION_ONLY")) issues.Add("invariant_test_coverage_incomplete");
            if(expectedRevision is null) issues.Add("expected_source_revision_not_supplied");
            foreach(var item in ev) { if(item.Revision is null) issues.Add("evidence_source_revision_missing"); else if(expectedRevision is not null&&item.Revision!=expectedRevision) issues.Add("evidence_source_revision_unmatched"); }
            var tests=m.Groups.Select(g=>{
                var group=ev.Where(x=>x.Category=="test-run-summary"&&x.Group==g).ToArray();
                var hasReportedPass=group.Any(x=>(x.Origin is "self-reported" or "locally-reported" or "ci-reported-unverified") && x.Result=="PASS");
                var fixtureOnly=group.Length>0&&group.All(x=>x.Origin=="fixed-test-fixture");
                var pass=hasReportedPass&&group.All(x=>x.Result=="PASS");
                if(!pass) issues.Add(group.Any(x=>x.Result=="FAIL")?"required_test_group_reported_failure":
                    fixtureOnly?"required_test_group_fixture_only":"required_test_group_missing_or_unknown");
                return new GroupReport(g,pass?"PASS_REPORTED":fixtureOnly?"FIXTURE_ONLY":
                    group.Length==0?"MISSING":"FAIL_OR_UNKNOWN",
                    fixtureOnly?"FIXTURE_NOT_EXECUTION_EVIDENCE":
                    group.Length>0&&group.All(x=>x.Origin=="locally-reported")?"LOCAL_EXECUTION_REPORTED_UNVERIFIED":
                    group.Length>0&&group.All(x=>x.Origin=="ci-reported-unverified")?"CI_EXECUTION_REPORTED_PROVENANCE_UNVERIFIED":"SELF_REPORTED_UNVERIFIED");
            }).ToArray();
            var complete=issues.Count==0;
            var runtimeReported=ev.Any(x=>x.Category=="historical-readonly-observation");
            var classifications=new List<string>{"SYNTHETIC_POLICY_VALIDATED",complete?"SYNTHETIC_REGRESSION_REPORTED":"SYNTHETIC_EVIDENCE_INCOMPLETE"};
            if(runtimeReported) classifications.Add("READ_ONLY_RUNTIME_HISTORICAL_REPORT_UNVERIFIED");
            classifications.AddRange(["READ_ONLY_RUNTIME_UNOBSERVED","REAL_CREDENTIAL_OPERATIONS_BLOCKED","PRODUCTION_AUTHORIZATION_BLOCKED"]);
            var report=new ReportModel(2,1,1,expectedRevision??"NOT_SUPPLIED",classifications.ToArray(),
                invariants.Select(i=>new InvariantReport(i.Id,i.Status,i.Category,i.Tests,i.Limitations,i.Status=="CODE_ENFORCED_TESTED"?"TEST_REFERENCES_REPORTED_NOT_EXECUTED_HERE":"SOURCE_REVIEW_OR_DOCUMENTATION_ONLY")).ToArray(),
                tests,ev.Select(x=>new EvidenceReport(x.Id,x.Category,x.Origin,x.Revision,x.Group,x.Result,x.Timestamp,x.Digest,"DIGEST_MATCHES_SUPPLIED_PAYLOAD; PRODUCER_UNAUTHENTICATED",x.Assumptions)).ToArray(),issues.ToArray(),
                runtimeReported?"REPORTED_UNVERIFIED_USER_SUPPLIED":"NOT_SUPPLIED",
                "EXPECTED_REVISION_IS_USER_SUPPLIED; SELF_REPORTED_OUTPUT_AND_UNKEYED_HASHES_DO_NOT_AUTHENTICATE_EXECUTION_OR_PRODUCER","READ_ONLY_RUNTIME_UNOBSERVED","NO_GO","DEFAULT_DENY",complete?"REPORTED_REGRESSION_COMPLETE_UNVERIFIED":"POLICY_VALID_EVIDENCE_INCOMPLETE",false);
            return new(complete?0:1,JsonSerializer.Serialize(report,JsonDefaults.Options));
        } catch(AssuranceInputException x) { return Reject(x.Category); }
    }

    private static M Manifest(string json)
    {
        using var d=StrictJson.Parse(json); var r=d.RootElement;
        Contract.Obj(r,"manifestSchemaVersion","designation","securityScope","requiredTestGroups","expectedCiJobCategories","prohibitedCapabilities","readinessGates","outstandingVerificationGates");
        if(Contract.I(r,"manifestSchemaVersion",100)!=1) throw new AssuranceInputException("MANIFEST_SCHEMA_UNSUPPORTED");
        if(Contract.S(r,"designation")!="EXPERIMENTAL_SYNTHETIC_ONLY") throw new AssuranceInputException("POLICY_DESIGNATION_INVALID");
        var s=r.GetProperty("securityScope"); Contract.Obj(s,"syntheticCredentialLifecycle","hostDiagnostics","productionAuthorization","userApprovalAuthority");
        if(Contract.S(s,"syntheticCredentialLifecycle")!="IN_MEMORY_FAKE_ONLY"||Contract.S(s,"hostDiagnostics")!="READ_ONLY_RUNTIME_CAPABILITY_QUERIES_ONLY"||Contract.S(s,"productionAuthorization")!="DEFAULT_DENY"||Contract.S(s,"userApprovalAuthority")!="USER_ONLY") throw new AssuranceInputException("POLICY_SECURITY_SCOPE_INVALID");
        var groups=Contract.A(r,"requiredTestGroups",8); Contract.Exact(groups,Groups);
        var jobs=Contract.A(r,"expectedCiJobCategories",8); Contract.Exact(jobs,Jobs);
        Contract.Exact(Contract.A(r,"prohibitedCapabilities",16),Prohibitions);
        var gates=r.GetProperty("readinessGates"); Contract.Obj(gates,Gates);
        var required=new Dictionary<string,string>(StringComparer.Ordinal) {
            ["syntheticRegressionIntegration"]="VERIFY_IN_CI",["readOnlyRuntimeDiagnostics"]="NOT_OBSERVED_BY_STATIC_MANIFEST",["wpfMockDemonstration"]="NOT_OBSERVED_BY_CI",
            ["realCredentialEnrollment"]="NO_GO",["realCredentialAssertion"]="NO_GO",["realCredentialEnumeration"]="NO_GO",["realCredentialDeletion"]="NO_GO",["applicationIdentity"]="UNVERIFIED",["replayProtectionAcrossOsRestarts"]="UNVERIFIED",["syncedPasskeysAndExternalAuthenticators"]="UNVERIFIED",["productionAuthorization"]="NO_GO"};
        foreach(var (k,v) in required) if(Contract.S(gates,k)!=v) throw new AssuranceInputException("POLICY_READINESS_CONTRADICTION");
        Contract.Exact(Contract.A(r,"outstandingVerificationGates",8),"Run required CI and local regression groups on the proposed patch.","Perform any host capability observation separately and label it with its timestamp and machine context.","Keep all real credential operations and production authorization disabled pending separate security review and explicit authorization.");
        return new(groups,jobs);
    }

    private static Inv[] Registry(string json)
    {
        using var d=StrictJson.Parse(json); var r=d.RootElement; Contract.Obj(r,"schemaVersion","invariants");
        if(Contract.I(r,"schemaVersion",100)!=1) throw new AssuranceInputException("INVARIANT_SCHEMA_UNSUPPORTED");
        var a=r.GetProperty("invariants"); if(a.ValueKind!=JsonValueKind.Array||a.GetArrayLength() is <1 or >64) throw new AssuranceInputException("INVARIANT_COLLECTION_INVALID");
        var list=new List<Inv>(); var ids=new HashSet<string>(StringComparer.Ordinal);
        foreach(var x in a.EnumerateArray()) {
            Contract.Obj(x,"id","description","threat","domain","enforcementLocations","testReferences","evidenceCategory","limitations","status");
            var id=Contract.S(x,"id",64); if(!ids.Add(id)) throw new AssuranceInputException("INVARIANT_ID_DUPLICATE");
            var locations=Contract.A(x,"enforcementLocations",8); var tests=Contract.A(x,"testReferences",12);
            if(locations.Length==0||tests.Length==0) throw new AssuranceInputException("INVARIANT_TRACEABILITY_INCOMPLETE");
            var status=Contract.S(x,"status",32); if(status is not("CODE_ENFORCED_TESTED" or "SOURCE_REVIEWED" or "DOCUMENTATION_ONLY" or "INCOMPLETE")) throw new AssuranceInputException("INVARIANT_STATUS_UNKNOWN");
            var category=Contract.S(x,"evidenceCategory",64); if(category is not("synthetic-regression" or "source-review" or "documentation-only")) throw new AssuranceInputException("INVARIANT_EVIDENCE_CATEGORY_INVALID");
            if(!ExpectedInvariantStatus.TryGetValue(id,out var expectedStatus)||status!=expectedStatus||ExpectedInvariantCategory[id]!=category) throw new AssuranceInputException("INVARIANT_ASSURANCE_CLASSIFICATION_INVALID");
            _=Contract.S(x,"description"); _=Contract.S(x,"threat");
            if(!TraceContract.DomainMatches(id,Contract.S(x,"domain",64))) throw new AssuranceInputException("INVARIANT_METADATA_CONTRADICTION");
            list.Add(new(id,status,category,locations,tests,Contract.S(x,"limitations")));
        }
        Contract.Exact(ids,InvariantIds); return list.OrderBy(i=>i.Id,StringComparer.Ordinal).ToArray();
    }

    private static E[] Evidence(string json)
    {
        using var d=StrictJson.Parse(json); var r=d.RootElement; Contract.Obj(r,"schemaVersion","evidence");
        if(Contract.I(r,"schemaVersion",100)!=1) throw new AssuranceInputException("EVIDENCE_SCHEMA_UNSUPPORTED");
        var a=r.GetProperty("evidence"); if(a.ValueKind!=JsonValueKind.Array||a.GetArrayLength()>64) throw new AssuranceInputException("EVIDENCE_COLLECTION_INVALID");
        var ids=new HashSet<string>(StringComparer.Ordinal); var revs=new HashSet<string>(StringComparer.Ordinal); var list=new List<E>();
        foreach(var x in a.EnumerateArray()) {
            Contract.Obj(x,"evidenceId","category","origin","sourceRevision","testGroup","reportedResult","observationTimestampUtc","inputSha256","assumptions","payload");
            var id=Contract.S(x,"evidenceId",80); if(!ids.Add(id)) throw new AssuranceInputException("EVIDENCE_ID_DUPLICATE");
            var cat=Contract.S(x,"category",64); if(cat is not("test-run-summary" or "historical-readonly-observation")) throw new AssuranceInputException("EVIDENCE_CATEGORY_INVALID");
            var origin=Contract.S(x,"origin",64); if(origin is not("self-reported" or "fixed-test-fixture" or "user-supplied-historical" or "locally-reported" or "ci-reported-unverified")) throw new AssuranceInputException("EVIDENCE_ORIGIN_INVALID");
            var rev=Contract.NS(x,"sourceRevision",64); Contract.Revision(rev); if(rev is not null) revs.Add(rev);
            var group=Contract.NS(x,"testGroup",64); var result=Contract.S(x,"reportedResult",16);
            if(cat=="test-run-summary") {
                if(origin is not("self-reported" or "fixed-test-fixture" or "locally-reported" or "ci-reported-unverified")) throw new AssuranceInputException("EVIDENCE_ORIGIN_CATEGORY_MISMATCH");
                if(group is not("approval-agent-mock" or "webauthn-fake-lab" or "node-regression")||result is not("PASS" or "FAIL" or "UNKNOWN")) throw new AssuranceInputException("EVIDENCE_ENUM_INVALID");
            }
            else {
                if(origin!="user-supplied-historical") throw new AssuranceInputException("EVIDENCE_ORIGIN_CATEGORY_MISMATCH");
                if(group is not null||result!="OBSERVED") throw new AssuranceInputException("EVIDENCE_ENUM_INVALID");
            }
            var time=Contract.NS(x,"observationTimestampUtc",40);
            if(cat=="historical-readonly-observation"&&time is null) throw new AssuranceInputException("EVIDENCE_TIMESTAMP_REQUIRED");
            if(time is not null&&(!DateTimeOffset.TryParse(time,System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.AssumeUniversal|System.Globalization.DateTimeStyles.AdjustToUniversal,out var parsed)||parsed.Offset!=TimeSpan.Zero||!time.EndsWith("Z",StringComparison.Ordinal))) throw new AssuranceInputException("EVIDENCE_TIMESTAMP_INVALID");
            var assumptions=Contract.A(x,"assumptions",16); var digest=Contract.S(x,"inputSha256",64);
            if(digest.Length!=64||digest.Any(c=>!(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) throw new AssuranceInputException("EVIDENCE_DIGEST_INVALID");
            var payload=x.GetProperty("payload"); Contract.Obj(payload,"testGroup","reportedResult","sourceRevision","observationTimestampUtc","assumptions");
            if(Contract.NS(payload,"testGroup",64)!=group||Contract.S(payload,"reportedResult",16)!=result||Contract.NS(payload,"sourceRevision",64)!=rev||Contract.NS(payload,"observationTimestampUtc",40)!=time||!Contract.A(payload,"assumptions",16).SequenceEqual(assumptions,StringComparer.Ordinal)) throw new AssuranceInputException("EVIDENCE_LINKAGE_INVALID");
            var actual=Convert.ToHexString(SHA256.HashData(CanonicalJson.Bytes(payload))).ToLowerInvariant(); if(actual!=digest) throw new AssuranceInputException("EVIDENCE_DIGEST_MISMATCH");
            list.Add(new(id,cat,origin,rev,group,result,time,digest,assumptions));
        }
        if(revs.Count>1) throw new AssuranceInputException("EVIDENCE_SOURCE_CONFLICT");
        if(list.Where(x=>x.Category=="test-run-summary").GroupBy(x=>x.Group).Any(g=>g.Select(x=>x.Result).Distinct(StringComparer.Ordinal).Count()>1))
            throw new AssuranceInputException("EVIDENCE_RESULT_CONFLICT");
        return list.OrderBy(x=>x.Id,StringComparer.Ordinal).ToArray();
    }
    internal static string? TraceError(string registryJson,string repoRoot)
    {
        try
        {
            var items=Registry(registryJson);
            var root=Path.GetFullPath(repoRoot);
            foreach(var item in items) foreach(var rel in item.Locations)
            {
                if(Path.IsPathRooted(rel)||rel.Contains(':')||rel.Contains('\\')||rel.Split('/').Any(x=>x is ".." or "." or "")) return "INVARIANT_SOURCE_PATH_INVALID";
                var file=Path.GetFullPath(Path.Combine(root,rel.Replace('/',Path.DirectorySeparatorChar)));
                if(!file.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!File.Exists(file)) return "INVARIANT_SOURCE_LOCATION_MISSING";
                if(!TraceContract.AllowedLocations.Contains(rel,StringComparer.Ordinal)) return "INVARIANT_SOURCE_PATH_UNEXPECTED";
            }
            foreach(var item in items)
                if(!TraceContract.Matches(item.Id,item.Locations,item.Tests)) return "INVARIANT_TRACEABILITY_CONTRADICTION";
            var lab=File.ReadAllText(Path.Combine(root,"experiments","webauthn-windows-lab","LabTests.cs"));
            var ids=System.Text.RegularExpressions.Regex.Matches(lab,@"^\s*\(""[^""]+"",\s*(?<id>[A-Za-z0-9_]+)\)",System.Text.RegularExpressions.RegexOptions.Multiline).Select(m=>m.Groups["id"].Value).ToHashSet(StringComparer.Ordinal);
            foreach(var item in items) foreach(var test in item.Tests) if(!ids.Contains(test)) return "INVARIANT_TEST_REFERENCE_MISSING";
            var labDir=Path.Combine(root,"experiments","webauthn-windows-lab");
            var forbiddenLab=new[]{"Dll"+"Import","Library"+"Import","Native"+"Library","WebAuthN"+"MakeCredential","WebAuthN"+"GetAssertion","WebAuthN"+"DeletePlatformCredential","System."+"Net","Http"+"Client","Named"+"Pipe","Tcp"+"Client","Udp"+"Client","Process."+"Start"};
            foreach(var source in Directory.GetFiles(labDir,"*.cs",SearchOption.TopDirectoryOnly))
                if(forbiddenLab.Any(token=>File.ReadAllText(source).Contains(token,StringComparison.OrdinalIgnoreCase))) return "LAB_NATIVE_CREDENTIAL_BOUNDARY_VIOLATION";
            var labProject=File.ReadAllText(Path.Combine(labDir,"WebAuthn.WindowsLab.csproj"));
            if(System.Text.RegularExpressions.Regex.IsMatch(labProject,@"ProjectReference|PackageReference",System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return "LAB_DEPENDENCY_BOUNDARY_VIOLATION";
            var verifierDir=Path.Combine(root,"experiments","webauthn-offline-assurance");
            var forbidden=new[]{"System."+"Net","Native"+"Library","Dll"+"Import","Library"+"Import","Process."+"Start","Http"+"Client","Named"+"Pipe","Tcp"+"Client","Udp"+"Client","WebAuthN"+"MakeCredential","WebAuthN"+"GetAssertion","WebAuthN"+"DeletePlatformCredential"};
            foreach(var source in Directory.GetFiles(verifierDir,"*.cs",SearchOption.TopDirectoryOnly))
            {
                var text=File.ReadAllText(source);
                if(forbidden.Any(token=>text.Contains(token,StringComparison.OrdinalIgnoreCase))) return "ASSURANCE_AUTHORITY_BOUNDARY_VIOLATION";
            }
            var assuranceProject=File.ReadAllText(Path.Combine(verifierDir,"WebAuthn.OfflineAssurance.csproj"));
            if(System.Text.RegularExpressions.Regex.IsMatch(assuranceProject,@"ProjectReference|PackageReference",System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                return "ASSURANCE_DEPENDENCY_BOUNDARY_VIOLATION";
            return null;
        }
        catch(AssuranceInputException x) { return x.Category; }
        catch(Exception) { return "TRACE_INPUT_INVALID"; }
    }
    private static VerificationResult Reject(string category)=>new(2,JsonSerializer.Serialize(new{reportSchemaVersion=1,verificationStatus="INPUT_REJECTED",errorCategory=category},JsonDefaults.Options));
}

internal static class CanonicalJson
{
    public static byte[] Bytes(JsonElement e) { using var m=new MemoryStream(); using(var w=new Utf8JsonWriter(m)) Write(w,e); return m.ToArray(); }
    private static void Write(Utf8JsonWriter w,JsonElement e)
    {
        switch(e.ValueKind) {
        case JsonValueKind.Object: w.WriteStartObject(); foreach(var p in e.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal)){w.WritePropertyName(p.Name);Write(w,p.Value);} w.WriteEndObject(); break;
        case JsonValueKind.Array: w.WriteStartArray(); foreach(var x in e.EnumerateArray())Write(w,x); w.WriteEndArray(); break;
        case JsonValueKind.String:w.WriteStringValue(e.GetString());break;
        case JsonValueKind.Number:if(e.TryGetInt64(out var n))w.WriteNumberValue(n);else if(e.TryGetDecimal(out var dec))w.WriteNumberValue(dec);else throw new AssuranceInputException("EVIDENCE_PAYLOAD_NUMBER_INVALID");break;
        case JsonValueKind.True:w.WriteBooleanValue(true);break;case JsonValueKind.False:w.WriteBooleanValue(false);break;case JsonValueKind.Null:w.WriteNullValue();break;
        default:throw new AssuranceInputException("EVIDENCE_PAYLOAD_INVALID");
        }
    }
}
