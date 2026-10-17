using System.Diagnostics;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

internal static class OfflineTrustTests
{
    private const long Now = 1800000002000;
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("offline trust boundary assertion failed"); }
    private static OfflineReviewViewModel Vm(string method, Func<long>? clock = null, HybridPolicy? policy = null)
    {
        var vm = new OfflineReviewViewModel(clock ?? (() => Now), policy);
        Must(vm.SetPreference(method));
        Must(vm.LoadBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "golden.review.json"))));
        return vm;
    }
    private static OfflineTrustSession Ready(string method, OfflineReviewViewModel vm)
    {
        var session = new OfflineTrustSession(vm, () => Now);
        if (method == HybridMethods.Protected) Must(session.Negotiate(session.Fixture("HELLO")));
        if (method == HybridMethods.Remote) Must(session.Register(session.Fixture("REGISTRATION")));
        Must(session.Start(session.Fixture("CONSENT_REQUEST")));
        return session;
    }
    internal static IEnumerable<(string Name, Action Run)> Cases()
    {
        foreach (var method in new[]{ HybridMethods.Local, HybridMethods.Protected, HybridMethods.Remote }) {
            foreach (var outcome in new[]{ "GRANT", "DENY", "CANCEL", "UNKNOWN" }) {
                var m=method; var o=outcome;
                yield return ($"5/6 {m} {o} canonical synthetic consumption", () => {
                    var vm=Vm(m); var session=Ready(m, vm);
                    var response=session.Fixture("CONSENT_RESPONSE",o);
                    Must(OfflineTrustProtocol.TryParse(response,out var parsed)); parsed?.Dispose();
                    Must(session.Receive(response) && !session.Receive(response));
                    Must(!session.Authorized && session.ProductionAuthorization=="DEFAULT_DENY" && !vm.Authorized);
                    if(o=="UNKNOWN") { Must(session.State=="Unknown"); Must(session.Recover() && session.State=="Abandoned" && vm.State==OfflineMockState.Cancelled); }
                    else Must(session.State==(o=="GRANT"?"ApprovedMock":o=="DENY"?"Rejected":"Cancelled"));
                });
            }
            var id=method;
            yield return ($"5/6 {id} cannot complete on expired canonical clock", () => {
                long now=Now; var vm=Vm(id,()=>now); var session=Ready(id,vm);
                now=vm.Context!.ExpiresAt;
                Must(!session.Receive(session.Fixture("CONSENT_RESPONSE","GRANT")) && session.State=="Expired");
                Must(vm.State==OfflineMockState.Pending || vm.State==OfflineMockState.Expired);
                vm.RefreshExpiry(); Must(vm.State==OfflineMockState.Expired && !vm.Authorized);
            });
        }
        yield return ("6D crash versus response is serialized with canonical consumption", () => {
            for (var i=0;i<64;i++) {
                var vm=Vm(HybridMethods.Local);var s=Ready(HybridMethods.Local,vm);
                var response=s.Fixture("CONSENT_RESPONSE","GRANT");
                var granted=false;var crashed=false;
                Parallel.Invoke(()=>granted=s.Receive(response),()=>crashed=s.Crash());
                Must(granted != crashed);
                if(granted) Must(s.State=="ApprovedMock" && vm.State==OfflineMockState.ApprovedMock && !s.Recover());
                else Must(s.State=="Unknown" && vm.State==OfflineMockState.Pending && s.Recover() && vm.State==OfflineMockState.Cancelled);
                Must(!s.Receive(response) && !vm.Authorized);
            }
        });
        yield return ("5B/6B strict fake component negotiation and replay denial", () => {
            var vm=Vm(HybridMethods.Protected); var s=new OfflineTrustSession(vm,()=>Now); var hello=s.Fixture("HELLO");
            Must(!s.Start(s.Fixture("CONSENT_REQUEST")));
            Must(!s.Negotiate(hello.Replace("FAKE_PROTECTED_COMPONENT","FAKE_REMOTE_DEVICE")));
            Must(!s.Negotiate(hello.Replace("\"version\":1","\"version\":0")));
            Must(s.Negotiate(hello) && !s.Negotiate(hello));
            Must(s.Start(s.Fixture("CONSENT_REQUEST")) && !s.Start(s.Fixture("CONSENT_REQUEST")));
        });
        yield return ("5C/6C simulated registration revoked and abandoned", () => {
            var s=new OfflineTrustSession(Vm(HybridMethods.Remote),()=>Now);
            Must(s.Register(s.Fixture("REGISTRATION")) && s.Registered);
            Must(s.Revoke(s.Fixture("REVOCATION")) && !s.Registered);
            Must(!s.Start(s.Fixture("CONSENT_REQUEST")) && s.Recover() && s.State=="Abandoned");
        });
        yield return ("5D strict UTF-8 canonical duplicate and unknown field rejection", () => {
            var vm=Vm(HybridMethods.Local); var s=new OfflineTrustSession(vm,()=>Now);
            var request=s.Fixture("CONSENT_REQUEST");
            foreach(var bad in new[]{request+" ",request.Replace("{","{\"version\":1,"),request.Replace("\"authorized\":false","\"authorized\":true"),
                request.Replace("\"version\":1","\"version\":0"),request.Replace("\"outcome\":\"NONE\"","\"outcome\":\"GRANT\""),"{}",new string('X',4097),request+"\ud800"}) {
                Must(!OfflineTrustProtocol.TryParse(bad,out var parsed));parsed?.Dispose();
                Must(!s.Start(bad));
            }
            Must(s.Start(request));
        });
        yield return ("6D switch and independent instance block stale messages", () => {
            var vm=Vm(HybridMethods.Protected); var s=Ready(HybridMethods.Protected, vm);
            var c=vm.Context!;
            Must(vm.SwitchMethod(HybridMethods.Local,c.RequestId,c.SessionId,c.ContextSha256,vm.ReviewGeneration));
            Must(!s.Receive(s.Fixture("CONSENT_RESPONSE","GRANT")));
            var other=Ready(HybridMethods.Protected,Vm(HybridMethods.Protected));
            Must(!other.Receive(s.Fixture("CONSENT_RESPONSE","GRANT")));
        });
        yield return ("6D interrupted local receipt requires explicit local abandonment", () => {
            var vm=Vm(HybridMethods.Local);var s=Ready(HybridMethods.Local,vm);
            Must(s.Crash() && !s.Receive(s.Fixture("CONSENT_RESPONSE","GRANT")));
            Must(s.Recover() && vm.State==OfflineMockState.Cancelled && !s.Recover());
        });
        yield return ("5A/6A consent statement and fake endpoint claims are exact", () => {
            var vm=Vm(HybridMethods.Local); var s=new OfflineTrustSession(vm,()=>Now);
            var wire=s.Fixture("CONSENT_REQUEST");
            foreach (var (oldValue,newValue) in new[] {
                ("FAKE_IN_PROCESS", "AUTHENTICATED_IPC"), ("UNESTABLISHED", "TRUSTED"),
                ("no production authorization.", "production authorization."),
                ("UNVERIFIED_SIMULATION_ONLY", "AUTHENTICATED_DEVICE")
            }) {
                var changed=wire.Replace(oldValue,newValue);
                Must(changed!=wire); Must(!OfflineTrustProtocol.TryParse(changed,out var invalid));invalid?.Dispose();
                Must(!s.Start(changed));
            }
            Must(wire.Contains(vm.Context!.ContextSha256,StringComparison.Ordinal) && s.Start(wire));
        });
        yield return ("5D Node safe integer bounds enforced by .NET parser", () => {
            var s=new OfflineTrustSession(Vm(HybridMethods.Local),()=>Now);
            var wire=s.Fixture("CONSENT_REQUEST");
            var tooLarge=wire.Replace("\"generation\":1", "\"generation\":9007199254740992");
            Must(tooLarge != wire); Must(!OfflineTrustProtocol.TryParse(tooLarge,out var bad));bad?.Dispose();
        });
        yield return ("6A-D expiry inside canonical decision denies every synthetic outcome", () => {
            foreach(var method in new[] {HybridMethods.Local,HybridMethods.Protected,HybridMethods.Remote}) {
                var armed=false; var calls=0; long expiry=long.MaxValue;
                var vm=Vm(method,()=>!armed?Now:++calls==1?expiry-1:expiry);
                var s=Ready(method,vm); expiry=vm.Context!.ExpiresAt;armed=true;
                Must(!s.Receive(s.Fixture("CONSENT_RESPONSE","GRANT")));
                Must(vm.State==OfflineMockState.Expired && s.State=="Expired" && !vm.Authorized);
            }
        });
        yield return ("6B fake transport bounded delayed duplicate and strict framing", () => {
            var vm=Vm(HybridMethods.Protected);var s=Ready(HybridMethods.Protected,vm);
            var t=new OfflineTrustFakeTransport();
            Must(!t.Send("{}") && !t.Send(s.Fixture("HELLO")));
            var grant=s.Fixture("CONSENT_RESPONSE","GRANT");
            for(var i=0;i<4;i++) Must(t.Send(grant));
            Must(!t.Send(grant) && t.Pending==4);
            t.Disconnect();Must(!t.Deliver(s) && !t.Send(grant) && t.Pending==4);
            t.Reconnect(); Must(t.Deliver(s) && !t.Deliver(s) && t.Pending==2);
            t.Clear();Must(t.Pending==0 && !t.Deliver(s) && vm.State==OfflineMockState.ApprovedMock);
        });
        yield return ("6C offline remote and revoked device cannot recover as a grant", () => {
            var vm=Vm(HybridMethods.Remote);var s=Ready(HybridMethods.Remote,vm);
            var t=new OfflineTrustFakeTransport();
            Must(t.Send(s.Fixture("CONSENT_RESPONSE","GRANT")));
            t.Disconnect();Must(!t.Deliver(s));
            Must(s.Crash() && !s.Receive(s.Fixture("CONSENT_RESPONSE","GRANT")));
            t.Reconnect();Must(!t.Deliver(s) && s.Recover() && !s.Recover());
            Must(vm.State==OfflineMockState.Cancelled && !vm.Authorized);
        });
        yield return ("6D concurrent fake delivery consumes canonical result exactly once", () => {
            var vm=Vm(HybridMethods.Local);var s=Ready(HybridMethods.Local,vm);
            var frame=s.Fixture("CONSENT_RESPONSE","GRANT");
            var results=new bool[24];
            Parallel.For(0,results.Length,i=>results[i]=s.Receive(frame));
            Must(results.Count(result=>result)==1 && vm.State==OfflineMockState.ApprovedMock && !vm.Authorized);
        });        yield return ("6D real Node/.NET versioned offline protocol vectors", ActualInterop);
    }
    private static void ActualInterop()
    {
        var repo=new DirectoryInfo(AppContext.BaseDirectory);
        while(repo is not null && !File.Exists(Path.Combine(repo.FullName,"experiments/integration-contracts/offline-trust-vector-cli.js"))) repo=repo.Parent;
        Must(repo is not null);
        var info=new ProcessStartInfo("node") { WorkingDirectory=repo!.FullName,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
        info.ArgumentList.Add("experiments/integration-contracts/offline-trust-vector-cli.js");
        using var process=Process.Start(info)!;
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(10000)) {process.Kill(true); throw new InvalidOperationException("protocol vector timeout");}
        Must(process.ExitCode==0); _=error.GetAwaiter().GetResult();
        using var document=JsonDocument.Parse(output.GetAwaiter().GetResult());
        foreach(var row in document.RootElement.EnumerateArray()) {
            var id=row.GetProperty("method").GetString()!;var outcome=row.GetProperty("outcome").GetString()!;
            var request=row.GetProperty("request").GetString()!;var response=row.GetProperty("response").GetString()!;
            Must(OfflineTrustProtocol.TryParse(request,out var nodeRequest));nodeRequest?.Dispose();
            Must(OfflineTrustProtocol.TryParse(response,out var nodeResponse));nodeResponse?.Dispose();
            var vm=Vm(id);var local=new OfflineTrustSession(vm,()=>Now);
            Must(vm.Context!.ContextSha256==row.GetProperty("digest").GetString() && vm.Context.ExpiresAt==row.GetProperty("expiresAt").GetInt64());
            // A Node instance marker must be refused by a distinct .NET instance.
            Must(!local.Start(request));
            if(id==HybridMethods.Protected) Must(local.Negotiate(local.Fixture("HELLO")));
            if(id==HybridMethods.Remote) Must(local.Register(local.Fixture("REGISTRATION")));
            Must(local.Start(local.Fixture("CONSENT_REQUEST")));
            Must(!local.Receive(response));
            Must(local.Receive(local.Fixture("CONSENT_RESPONSE",outcome))==row.GetProperty("accepted").GetBoolean());
            if(outcome=="UNKNOWN") Must(local.Recover());
            Must(local.State==row.GetProperty("state").GetString() && vm.State.ToString()==row.GetProperty("canonicalState").GetString());
            Must(!row.GetProperty("authorized").GetBoolean() && row.GetProperty("productionAuthorization").GetString()==local.ProductionAuthorization);
        }
    }
}
