using System.Diagnostics;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.ViewModels;

internal static class IntegratedHybridTests
{
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("integrated hybrid assertion failed"); }
    private const long Now = 1800000002000;
    private static OfflineReviewViewModel Review(string method, Func<long>? clock = null, HybridPolicy? policy = null)
    {
        var vm = new OfflineReviewViewModel(clock ?? (() => Now), policy); vm.SetPreference(method);
        Must(vm.LoadBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"Fixtures","golden.review.json")))); return vm;
    }
    private static bool Send(OfflineReviewViewModel vm, string action) => vm.Simulate(action,vm.SimulationToken!,vm.Simulation.FixtureId);
    private static bool Switch(OfflineReviewViewModel vm, string method)
    { var c=vm.Context!; return vm.SwitchMethod(method,c.RequestId,c.SessionId,c.ContextSha256,vm.ReviewGeneration); }
    private static void ActualInterop()
    {
        var repo=new DirectoryInfo(AppContext.BaseDirectory);
        while(repo is not null && !File.Exists(Path.Combine(repo.FullName,"experiments/integration-contracts/hybrid-vector-cli.js"))) repo=repo.Parent;
        Must(repo is not null);
        var info=new ProcessStartInfo("node") { WorkingDirectory=repo!.FullName,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
        info.ArgumentList.Add("experiments/integration-contracts/hybrid-vector-cli.js");
        using var p=Process.Start(info)!; var output=p.StandardOutput.ReadToEndAsync(); var error=p.StandardError.ReadToEndAsync();
        if(!p.WaitForExit(10000)) { p.Kill(true); throw new InvalidOperationException("vector timeout"); }
        Must(p.ExitCode==0); _=error.GetAwaiter().GetResult();
        using var doc=JsonDocument.Parse(output.GetAwaiter().GetResult());
        OfflineReviewViewModel? vm=null; string? method=null;
        foreach(var row in doc.RootElement.EnumerateArray()) {
            if(row.TryGetProperty("expiryBoundary",out var boundary) && boundary.GetBoolean()) {
                method=row.GetProperty("method").GetString()!; bool armed=false; int checks=0;
                vm=Review(method,()=>armed?(++checks==1?1800000299999L:1800000300000L):Now);
                Must(Send(vm,"START")); if(method==HybridMethods.Remote) Must(Send(vm,"DELIVER"));
                armed=true;
            }
            else if(method!=row.GetProperty("method").GetString()) { method=row.GetProperty("method").GetString()!; vm=Review(method); }
            Must(Send(vm!,row.GetProperty("action").GetString()!)==row.GetProperty("accepted").GetBoolean());
            Must(vm!.State.ToString()==row.GetProperty("state").GetString() && vm.Simulation.State==row.GetProperty("simulation").GetString());
            Must(vm.Context!.ContextSha256==row.GetProperty("digest").GetString() && vm.Context.ExpiresAt==row.GetProperty("expiresAt").GetInt64());
            Must(!row.GetProperty("authorized").GetBoolean() && row.GetProperty("productionAuthorization").GetString()==vm.ProductionAuthorization);
        }
    }
    internal static IEnumerable<(string Name, Action Run)> Cases()
    {
        yield return ("4H terminal simulation reports rejection when second clock check expires", () => {
            foreach(var method in new[]{HybridMethods.Protected,HybridMethods.Remote}) {
                foreach(var action in new[]{"COMPLETE","REJECT","CANCEL","REVOKE","RECOVER"}) {
                    if(method==HybridMethods.Protected && action=="RECOVER") continue;
                    bool armed=false; int checks=0;
                    var vm=Review(method,()=>armed ? (++checks==1 ? 1800000299999L : 1800000300000L) : Now);
                    Must(Send(vm,"START")); if(method==HybridMethods.Remote) Must(Send(vm,"DELIVER"));
                    if(action=="RECOVER") Must(Send(vm,"UNKNOWN"));
                    var context=vm.Context; var token=vm.SimulationToken!; var fixture=vm.Simulation.FixtureId;
                    armed=true;
                    Must(!vm.Simulate(action,token,fixture)); Must(checks==2);
                    Must(vm.State==OfflineMockState.Expired && vm.Simulation.State=="Expired" && !vm.Simulation.Registered);
                    Must(ReferenceEquals(context,vm.Context) && vm.SimulationToken==token && vm.Context!.ExpiresAt==1800000300000L);
                    Must(!vm.Authorized && !vm.Simulation.Authorized && vm.ProductionAuthorization=="DEFAULT_DENY");
                    Must(!vm.Simulate("COMPLETE",token,fixture) && !Switch(vm,HybridMethods.Local));
                }
            }
        });
        yield return ("4H generation exhaustion cancels and clears simulation binding", () => {
            var vm=Review(HybridMethods.Protected); Must(Send(vm,"START")); var context=vm.Context;
            // Test-only reflection reaches an otherwise impractical counter boundary; no production setter.
            typeof(OfflineReviewViewModel).GetField("<ReviewGeneration>k__BackingField",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.SetValue(vm,long.MaxValue);
            var token=vm.SimulationToken!; var fixture=vm.Simulation.FixtureId;
            Must(!Switch(vm,HybridMethods.Remote)); Must(vm.State==OfflineMockState.Cancelled);
            Must(vm.Simulation.State=="Cancelled" && !vm.Simulation.Registered);
            Must(!vm.Simulation.Apply("COMPLETE",token,fixture) && !vm.Simulate("COMPLETE",token,fixture));
            Must(ReferenceEquals(context,vm.Context) && vm.ReviewGeneration==long.MaxValue && vm.SelectedMethod==HybridMethods.Protected);
            Must(!vm.Authorized && vm.ProductionAuthorization=="DEFAULT_DENY");
        });
        yield return ("4H actual Node and .NET lifecycle vectors agree", ActualInterop);
        foreach(var method in new[]{HybridMethods.Protected,HybridMethods.Remote}) {
            yield return ("4F-H " + method + " positive scripted complete rejects duplicates", () => {
                var vm=Review(method); Must(vm.Simulation.State=="ReadyForSimulation"); Must(!Send(vm,"COMPLETE"));
                Must(Send(vm,"START") && !Send(vm,"START"));
                if(method==HybridMethods.Remote) { Must(!Send(vm,"COMPLETE")); Must(Send(vm,"DELIVER") && !Send(vm,"DELIVER")); }
                Must(Send(vm,"COMPLETE") && vm.State==OfflineMockState.ApprovedMock); Must(!Send(vm,"REJECT"));
                Must(!vm.Authorized && vm.ProductionAuthorization=="DEFAULT_DENY" && vm.Simulation.State=="SimulatedComplete");
            });
            yield return ("4F-H " + method + " exact correlation and fake identity", () => {
                var vm=Review(method); var t=vm.SimulationToken!;
                foreach(var wrong in new[]{t with { RequestId="wrong" },t with { SessionId="wrong" },t with { ContextSha256=new string('0',64) },t with { Generation=t.Generation+1 },t with { MethodId=HybridMethods.Local }})
                    Must(!vm.Simulate("START",wrong,vm.Simulation.FixtureId));
                Must(!vm.Simulate("START",t,"authenticated-component")); Must(!Send(vm,"BAD") && !Send(vm,"RECOVER")); Must(Send(vm,"START"));
            });
            foreach(var action in new[]{"CANCEL","REJECT","REVOKE"}) {
                var captured=action;
                yield return ("4F-H " + method + " " + captured + " terminal late response denial", () => {
                    var vm=Review(method); Must(Send(vm,"START") && Send(vm,captured));
                    Must(vm.State==(captured=="REJECT"?OfflineMockState.Rejected:OfflineMockState.Cancelled)); Must(!Send(vm,"COMPLETE"));
                });
            }
            yield return ("4F-H " + method + " failed simulation requires explicit method recovery", () => {
                var vm=Review(method); Must(Send(vm,"START") && Send(vm,"FAIL")); Must(vm.Simulation.State=="Failed");
                Must(!Send(vm,"START") && !Send(vm,"COMPLETE")); Must(Switch(vm,HybridMethods.Local));
                Must(vm.Simulation.State=="Unavailable"); Must(Switch(vm,method) && Send(vm,"START"));
            });
        }
        yield return ("4F-G unavailable fake prerequisite requires explicit recovery", () => {
            foreach(var id in new[]{HybridMethods.Protected,HybridMethods.Remote}) {
                var vm=Review(id); Must(Send(vm,"UNAVAILABLE") && vm.Simulation.State=="Unavailable");
                Must(!Send(vm,"START") && vm.SelectedMethod==id); Must(Switch(vm,HybridMethods.Local) && Switch(vm,id) && Send(vm,"START"));
            }
        });
        yield return ("4G unknown response recovery abandons without retry", () => {
            var vm=Review(HybridMethods.Remote); var expiry=vm.Context!.ExpiresAt;
            Must(Send(vm,"START") && Send(vm,"DELIVER") && Send(vm,"UNKNOWN")); Must(!Send(vm,"COMPLETE") && !Send(vm,"DELIVER"));
            Must(Send(vm,"RECOVER") && vm.State==OfflineMockState.Cancelled && vm.Context.ExpiresAt==expiry);
        });
        yield return ("4H switch cleanup rejects all old scripted generations", () => {
            var vm=Review(HybridMethods.Local); var context=vm.Context;
            foreach(var id in new[]{HybridMethods.Protected,HybridMethods.Remote,HybridMethods.Local}) {
                var token=vm.SimulationToken!; Must(Switch(vm,id)); Must(!vm.Simulate("COMPLETE",token,"fake-device-v1"));
                Must(ReferenceEquals(context,vm.Context)); if(id!=HybridMethods.Local) Must(Send(vm,"START"));
            }
            Must(vm.Simulation.State=="Unavailable");
        });
        yield return ("4H expiry and invalid clock terminate simulation", () => {
            foreach(var time in new[]{1800000300000L,1799999999999L}) {
                long now=Now; var vm=Review(HybridMethods.Remote,()=>now); Must(Send(vm,"START") && Send(vm,"DELIVER"));
                now=time; Must(!Send(vm,"COMPLETE") && vm.State==OfflineMockState.Expired && vm.Simulation.State=="Expired");
            }
        });
        yield return ("4H unavailable policy permits explicit cancellation without fallback", () => {
            var vm=Review(HybridMethods.Remote,policy:new HybridPolicy(new[]{HybridMethods.Local}));
            Must(!Send(vm,"START") && vm.Simulation.State=="Unavailable" && vm.SelectedMethod==HybridMethods.Remote);
            vm.DecideCurrent(OfflineMockState.Cancelled); Must(vm.State==OfflineMockState.Cancelled);
        });
        yield return ("4E invalid replacement retains pending fixture and future preference", () => {
            var vm=Review(HybridMethods.Remote); Must(Send(vm,"START")); var token=vm.SimulationToken;
            Must(!vm.LoadBytes(new byte[]{0xff})); Must(vm.SimulationToken==token && vm.Simulation.State=="Pending");
            Must(vm.SetPreference(HybridMethods.Local) && vm.SelectedMethod==HybridMethods.Remote); Must(Send(vm,"DELIVER"));
        });
        yield return ("4H identical sessions reject another instance token", () => {
            var first=Review(HybridMethods.Remote); var second=Review(HybridMethods.Remote);
            Must(Send(first,"START") && Send(first,"DELIVER") && Send(second,"START") && Send(second,"DELIVER"));
            Must(!first.Simulate("COMPLETE",second.SimulationToken!,"fake-device-v1")); Must(Send(first,"COMPLETE"));
        });
        yield return ("4E rollback within valid lifetime expires pending review", () => {
            long now=Now; var vm=Review(HybridMethods.Protected,()=>now); now=Now+1000; Must(Send(vm,"START"));
            now=Now+500; Must(!Send(vm,"COMPLETE") && vm.State==OfflineMockState.Expired);
        });
        yield return ("4H concurrent simulations remain independently pending", () => {
            var first=Review(HybridMethods.Remote); var second=Review(HybridMethods.Protected);
            Must(Send(first,"START") && Send(second,"START")); Must(!first.Simulate("COMPLETE",second.SimulationToken!,"fake-component-v1"));
            Must(Send(first,"DELIVER") && Send(first,"COMPLETE")); Must(second.State==OfflineMockState.Pending);
        });
    }
}
