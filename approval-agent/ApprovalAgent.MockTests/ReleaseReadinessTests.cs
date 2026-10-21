using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;
internal static class ReleaseReadinessTests
{
    private const long Now = 1800000002000;
    private static void Must(bool value) { if (!value) throw new InvalidOperationException("RELEASE_ACCEPTANCE_FAILED"); }
    private static OfflineReviewViewModel Vm(Func<long>? clock = null) {
        var vm = new OfflineReviewViewModel(clock ?? (() => Now));
        Must(vm.LoadBytes(OfflineDemoFiles.Create(Now, new string('a',32)))); return vm;
    }
    private static bool Switch(OfflineReviewViewModel vm, string method) {
        var c = vm.Context!; return vm.SwitchMethod(method,c.RequestId,c.SessionId,c.ContextSha256,vm.ReviewGeneration);
    }
    internal static IEnumerable<(string Name, Action Run)> Cases()
    {
        yield return ("9D fresh demo is deterministic with injected time and marker and strictly validated", () => {
            var a = OfflineDemoFiles.Create(Now,new string('a',32));
            Must(a.SequenceEqual(OfflineDemoFiles.Create(Now,new string('a',32))));
            var c = OfflineReviewValidator.Validate(a,Now);
            Must(c.ExpiresAt == Now+300000 && c.RequestId == "demo-"+new string('a',32));
            foreach(var bad in new[]{0L,-1L,long.MaxValue}) {
                var rejected=false; try { OfflineDemoFiles.Create(bad,new string('a',32)); } catch { rejected=true; } Must(rejected);
            }
        });
        yield return ("9C failed future-default save can retry without extending expiry or changing current generation", () => {
            var root=Path.Combine(Path.GetTempPath(),"preference-retry-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            var preference=Path.Combine(root,"preference.json"); Directory.CreateDirectory(preference);
            try {
                var vm=Vm(); var deadline=vm.Context!.ExpiresAt;
                var selection=new ApprovalMethodSelection(vm,new ApprovalMethodPreferences(preference),true);
                Must(!selection.Apply(HybridMethods.Remote,true) && vm.IsRemote && vm.PreferredMethod is null);
                Must(selection.Status.Contains("PREFERENCE_SAVE_FAILED")); var generation=vm.ReviewGeneration;
                Directory.Delete(preference);
                Must(selection.Apply(HybridMethods.Remote,true));
                Must(vm.ReviewGeneration==generation && vm.Context.ExpiresAt==deadline && vm.PreferredMethod==HybridMethods.Remote);
            } finally { if(File.Exists(preference))File.Delete(preference); if(Directory.Exists(preference))Directory.Delete(preference); Directory.Delete(root); }
        });
        yield return ("11B diagnostic snapshot is bounded immutable synthetic and contains no request contents", () => {
            var vm=Vm(); var original=vm.Diagnostics;
            for(var i=0;i<100;i++) Must(Switch(vm,i%2==0?HybridMethods.Protected:HybridMethods.Local));
            Must(vm.Diagnostics.Count==32 && original.Count==1);
            Must(vm.Diagnostics.All(e=>!e.Authorized && e.ProductionAuthorization=="DEFAULT_DENY"));
            var encoded=JsonSerializer.Serialize(vm.Diagnostics);
            Must(!encoded.Contains(vm.Context!.RequestId) && !encoded.Contains(vm.Context.Targets[0].Task) && !encoded.Contains(vm.Context.ContextSha256));
            var count=vm.Diagnostics.Count; vm.RefreshExpiry(); Must(vm.Diagnostics.Count==count);
        });
        yield return ("9A guided state follows canonical terminal policy and protected recovery", () => {
            var vm=new OfflineReviewViewModel(()=>Now); Must(vm.NextStep.Contains("Create"));
            Must(vm.LoadBytes(OfflineDemoFiles.Create(Now,new string('b',32))) && vm.NextStep.Contains("complete task"));
            Must(Switch(vm,HybridMethods.Protected) && vm.NextStep.Contains("Initialize"));
            Must(vm.StartInteractivePreview() && vm.NextStep.Contains("synthetic consent"));
            Must(vm.CrashInteractivePreview() && vm.NextStep.Contains("unknown"));
            Must(vm.RecoverInteractivePreview() && vm.NextStep.Contains("terminal"));
        });
        yield return ("11A stale method dialog expires without changing default", () => {
            long now=Now;var vm=Vm(()=>now);
            var selection=new ApprovalMethodSelection(vm,new ApprovalMethodPreferences("unused"),true);
            now=vm.Context!.ExpiresAt;
            Must(!selection.Apply(HybridMethods.Remote,true) && vm.State==OfflineMockState.Expired && vm.PreferredMethod is null);
        });
        yield return ("11C preference relative and UNC paths fail closed without writes", () => {
            foreach (var path in new[]{"relative.json",@"\\server\share\preference.json"}) {
                var preferences=new ApprovalMethodPreferences(path);
                Must(preferences.Read().Status=="PREFERENCE_INVALID" && preferences.Save(HybridMethods.Local)=="PREFERENCE_SAVE_FAILED" && preferences.Reset()=="PREFERENCE_SAVE_FAILED");
            }
        });
        yield return ("9D fresh demo create-new preserves existing data", () => {
            var root=Path.Combine(Path.GetTempPath(),"demo-write-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            var file=Path.Combine(root,"demo.review.json");
            try {
                OfflineDemoFiles.WriteNew(file,Now); var bytes=File.ReadAllBytes(file);
                Must(OfflineReviewValidator.ReadFile(file,Now).ExpiresAt==Now+300000);
                var rejected=false;try { OfflineDemoFiles.WriteNew(file,Now+1); } catch { rejected=true; }
                Must(rejected && bytes.SequenceEqual(File.ReadAllBytes(file)));
            } finally { File.Delete(file); Directory.Delete(root); }
        });
    }
    internal static int Demo(string directory)
    {
        var stage = "CREATE";
        try {
            var path=Path.Combine(directory,"fresh.review.json");
            OfflineDemoFiles.WriteNew(path,DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            stage = "LOAD"; var vm=new OfflineReviewViewModel(); Must(vm.LoadFile(path));
            var bytes=File.ReadAllBytes(path);
            stage = "NODE_VALIDATE"; Must(Node("--validate",Encoding.UTF8.GetString(bytes)).Contains("DEFAULT_DENY"));
            stage = "METHOD_A"; vm.DecideCurrent(OfflineMockState.ApprovedMock);Must(vm.State==OfflineMockState.ApprovedMock && !vm.Authorized);
            stage = "METHOD_B"; Must(vm.LoadFile(path) && Switch(vm,HybridMethods.Protected) && vm.StartInteractivePreview());
            Must(vm.RespondInteractivePreview("DENY") && vm.State==OfflineMockState.Rejected);
            Must(vm.LoadFile(path));
            foreach(var order in new[]{new[]{HybridMethods.Protected,HybridMethods.Remote,HybridMethods.Local},new[]{HybridMethods.Remote,HybridMethods.Protected,HybridMethods.Local}})
                foreach(var method in order)Must(Switch(vm,method));
            Must(Switch(vm,HybridMethods.Remote) && vm.StartInteractivePreview());
            stage = "METHOD_C"; var package=vm.ExportBrowserPackage()!;
            BrowserPreviewFiles.WritePackage(Path.Combine(directory,"active.browser.json"),package);
            var response=Node("--response",package);
            var responsePath=Path.Combine(directory,"synthetic.response.json");
            using(var output=new FileStream(responsePath,FileMode.CreateNew,FileAccess.Write,FileShare.None))output.Write(Encoding.UTF8.GetBytes(response));
            Must(vm.ImportBrowserResponse(BrowserPreviewFiles.ReadResponse(responsePath)) && !vm.ImportBrowserResponse(response));
            Must(vm.State==OfflineMockState.ApprovedMock && !vm.Authorized);
            Console.WriteLine("PASS FRESH_DEMO_A_B_C_NODE_DOTNET_BROWSER_REPLAY_DEFAULT_DENY"); return 0;
        } catch (Exception error) { Console.Error.WriteLine("DEMO_ACCEPTANCE_FAILED/" + stage + "/" + (error is InvalidOperationException ? error.Message : error.GetType().Name)); return 1; }
    }
    private static string Node(string mode,string input)
    {
        var repo=new DirectoryInfo(AppContext.BaseDirectory);
        while(repo is not null && !File.Exists(Path.Combine(repo.FullName,"experiments/offline-release/demo-contract.js")))repo=repo.Parent;
        if(repo is null)throw new InvalidOperationException("DEMO_SOURCE_REQUIRED");
        var start=new ProcessStartInfo("node"){WorkingDirectory=repo.FullName,UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false,true),StandardOutputEncoding=new UTF8Encoding(false,true)};
        start.ArgumentList.Add("experiments/offline-release/demo-contract.js");start.ArgumentList.Add(mode);
        using var process=Process.Start(start)!;var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        process.StandardInput.Write(input);process.StandardInput.Close();
        if(!process.WaitForExit(10000)){process.Kill(true);throw new InvalidOperationException("DEMO_TIMEOUT");}
        if(process.ExitCode!=0)throw new InvalidOperationException("NODE_EXIT_"+process.ExitCode); _=error.GetAwaiter().GetResult();return output.GetAwaiter().GetResult();
    }
}
