using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Automation;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using DesktopAgent.Core;

namespace DesktopAgent.Windows;

public sealed class WindowsBackend(AgentPolicy policy, EvidenceStore evidence) : IDesktopBackend
{
    private sealed record WindowBinding(nint Handle, int Pid, string Runtime, long SeenAt);
    private readonly Dictionary<string, WindowBinding> bindings = new();
    public SessionIdentity Identity()
    {
        string desktop = Native.ObjectName(Native.GetThreadDesktop(Native.GetCurrentThreadId()));
        var input = Native.OpenInputDesktop(0, false, 1);
        string inputName = Native.ObjectName(input);
        if (input != 0) Native.CloseDesktop(input);
        return new(Process.GetCurrentProcess().SessionId, Native.ObjectName(Native.GetProcessWindowStation()),
            desktop, desktop == inputName);
    }
    private void CheckProcess(int pid)
    {
        var target = policy.Targets.SingleOrDefault(t => t.ProcessId == pid);
        if (target == null) throw new AgentException("TARGET_DENIED");
        try {
            using var process = Process.GetProcessById(pid);
            if (process.SessionId != policy.SessionId || process.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) != target.StartTicks)
                throw new AgentException("STALE_TARGET");
            string path = process.MainModule?.FileName ?? throw new AgentException("TARGET_DENIED");
            using var file = File.OpenRead(path);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(file)), target.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
                throw new AgentException("TARGET_HASH_MISMATCH");
        } catch (ArgumentException) { throw new AgentException("STALE_TARGET"); }
    }
    private static string Selector(AutomationElement element) => string.IsNullOrEmpty(element.Current.AutomationId) ? "name:" + element.Current.Name.Replace("_", "") : element.Current.AutomationId;
    private static string Runtime(AutomationElement element) => string.Join(".", element.GetRuntimeId());
    private (nint hwnd, AutomationElement root) Resolve(string token)
    {
        if (!bindings.TryGetValue(token, out var binding) || Environment.TickCount64 - binding.SeenAt > 3000 || !Native.IsWindow(binding.Handle))
            throw new AgentException("STALE_TARGET");
        Native.GetWindowThreadProcessId(binding.Handle, out var pid);
        if (pid != binding.Pid) throw new AgentException("STALE_TARGET");
        CheckProcess((int)pid);
        var root = AutomationElement.FromHandle(binding.Handle);
        if (Runtime(root) != binding.Runtime) throw new AgentException("STALE_TARGET");
        return (binding.Handle, root);
    }
    private static string SafeText(string value) => new(value.Where(c => !char.IsControl(c)).Take(200).ToArray());
    private List<AutomationElement> Elements(AutomationElement root, CancellationToken ct)
    {
        var queue = new Queue<AutomationElement>();
        var found = new List<AutomationElement>();
        queue.Enqueue(root);
        while (queue.Count > 0 && found.Count < 512) {
            ct.ThrowIfCancellationRequested();
            var current = queue.Dequeue(); found.Add(current);
            var child = TreeWalker.ControlViewWalker.GetFirstChild(current);
            while (child != null && queue.Count + found.Count < 512) {
                queue.Enqueue(child); child = TreeWalker.ControlViewWalker.GetNextSibling(child);
            }
        }
        if (found.Count >= 512) throw new AgentException("OBSERVATION_LIMIT");
        return found;
    }
    private AutomationElement Element(AutomationElement root, string id, CancellationToken ct)
    {
        var found = Elements(root, ct).Where(e => (id.StartsWith("name:", StringComparison.Ordinal) ? Selector(e) : e.Current.AutomationId) == id && !e.Current.IsOffscreen).ToArray();
        if (found.Length != 1 || !found[0].Current.IsEnabled || found[0].Current.IsPassword)
            throw new AgentException("ELEMENT_UNAVAILABLE");
        if (found[0].Current.ProcessId != root.Current.ProcessId) throw new AgentException("TARGET_DENIED");
        return found[0];
    }
    private Observation Observe(CancellationToken ct)
    {
        var windows = new List<WindowState>();
        var alive = new HashSet<string>();
        Exception? callbackError = null;
        Native.EnumWindows((hwnd, _) => {
            try {
            if (!Native.IsWindowVisible(hwnd)) return true;
            Native.GetWindowThreadProcessId(hwnd, out var pid);
            if (!policy.Targets.Any(t => t.ProcessId == pid)) return true;
            if (windows.Count >= 16) throw new AgentException("OBSERVATION_LIMIT");
            CheckProcess((int)pid);
            ct.ThrowIfCancellationRequested();
            var root = AutomationElement.FromHandle(hwnd);
            var runtime = Runtime(root);
            var existing = bindings.FirstOrDefault(pair => pair.Value.Handle == hwnd && pair.Value.Pid == (int)pid && pair.Value.Runtime == runtime);
            var token = existing.Key ?? Guid.NewGuid().ToString("D");
            bindings[token] = new(hwnd, (int)pid, runtime, Environment.TickCount64); alive.Add(token);
            var title = new StringBuilder(256); Native.GetWindowText(hwnd, title, title.Capacity);
            bool nativeDialog = root.Current.ClassName == "#32770";
            var elements = Elements(root, ct).Where(e => !nativeDialog || policy.AutomationIds.Contains(e.Current.AutomationId)).Select(e => {
                var state = e.Current; var rect = state.BoundingRectangle;
                return new ElementState(state.IsPassword ? "[REDACTED]" : nativeDialog ? SafeText(state.AutomationId) : SafeText(Selector(e)), state.ControlType.ProgrammaticName,
                    state.IsPassword || nativeDialog ? "[REDACTED]" : SafeText(state.Name), state.HasKeyboardFocus,
                    state.IsEnabled, state.IsOffscreen, rect.IsEmpty ? 0 : rect.X, rect.IsEmpty ? 0 : rect.Y,
                    rect.IsEmpty ? 0 : rect.Width, rect.IsEmpty ? 0 : rect.Height);
            }).ToArray();
            windows.Add(new(token, (int)pid, Native.GetForegroundWindow() == hwnd,
                Native.GetWindow(hwnd, 4) != 0, SafeText(title.ToString()), elements));
            return true;
            } catch (Exception error) { callbackError = error; return false; }
        }, 0);
        if (callbackError != null) throw callbackError;
        foreach (var old in bindings.Keys.Where(k => !alive.Contains(k)).ToArray()) bindings.Remove(old);
        return new(Identity(), windows.ToArray(), Protocol.Hash(Protocol.Bytes(windows)));
    }
    private static void Foreground(nint hwnd)
    {
        if (Native.IsIconic(hwnd)) throw new AgentException("TARGET_MINIMIZED");
        if (Native.GetForegroundWindow() != hwnd) Native.SetForegroundWindow(hwnd);
        if (Native.GetForegroundWindow() != hwnd) throw new AgentException("FOREGROUND_DENIED");
    }
    private static void SendKey(string key)
    {
        ushort vk = key switch { "Tab" or "ShiftTab" => 9, "Enter" => 13, "Escape" => 27,
            "Space" => 32, "Up" => 38, "Down" => 40, "Left" => 37, "Right" => 39,
            "Home" => 36, "End" => 35, _ => throw new AgentException("KEY_DENIED") };
        static Native.INPUT Input(ushort code, bool up) => new() { Type = 1,
            Data = new() { Keyboard = new() { Vk = code, Flags = up ? 2u : 0u } } };
        var inputs = key == "ShiftTab" ? new[] { Input(16, false), Input(vk, false), Input(vk, true), Input(16, true) }
            : new[] { Input(vk, false), Input(vk, true) };
        uint sent = Native.SendInput((uint)inputs.Length, inputs, System.Runtime.InteropServices.Marshal.SizeOf<Native.INPUT>());
        if (sent != inputs.Length) {
            var release = key == "ShiftTab" ? new[] { Input(vk, true), Input(16, true) } : new[] { Input(vk, true) };
            if (sent > 0) Native.SendInput((uint)release.Length, release, System.Runtime.InteropServices.Marshal.SizeOf<Native.INPUT>());
            throw new AgentException("INPUT_INCOMPLETE");
        }
    }
    private Evidence Capture(nint hwnd, string id)
    {
        if (Native.IsIconic(hwnd) || !Native.GetWindowRect(hwnd, out var rect)) throw new AgentException("SCREENSHOT_FAILED");
        int width = rect.Right - rect.Left, height = rect.Bottom - rect.Top;
        if (width < 2 || height < 2 || width > 4096 || height > 4096) throw new AgentException("SCREENSHOT_FAILED");
        nint dc = Native.GetDC(hwnd), memory = Native.CreateCompatibleDC(dc), bitmap = Native.CreateCompatibleBitmap(dc, width, height);
        nint old = Native.SelectObject(memory, bitmap);
        try {
            if (dc == 0 || memory == 0 || bitmap == 0 || !Native.PrintWindow(hwnd, memory, 2))
                throw new AgentException("SCREENSHOT_FAILED");
            var raw = Imaging.CreateBitmapSourceFromHBitmap(bitmap, 0, System.Windows.Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            var source = new FormatConvertedBitmap(raw, System.Windows.Media.PixelFormats.Bgra32, null, 0);
            var pixels = new byte[width * height * 4]; source.CopyPixels(pixels, width * 4, 0);
            var clientOrigin = new Native.POINT();
            if (!Native.GetClientRect(hwnd, out var client) || !Native.ClientToScreen(hwnd, ref clientOrigin))
                throw new AgentException("SCREENSHOT_FAILED");
            int left = clientOrigin.X - rect.Left, top = clientOrigin.Y - rect.Top;
            if (!CaptureValidation.HasClientContent(pixels, width, height, left, top, left + client.Right, top + client.Bottom))
                throw new AgentException("SCREENSHOT_FAILED");
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(source));
            using var stream = new MemoryStream(); encoder.Save(stream);
            return evidence.Save(id, stream.ToArray(), "png", "Win32.PrintWindow.PW_RENDERFULLCONTENT");
        } finally {
            Native.SelectObject(memory, old); Native.DeleteObject(bitmap); Native.DeleteDC(memory); Native.ReleaseDC(hwnd, dc);
        }
    }
    public ActionData Execute(Command command, CancellationToken ct)
    {
        Evidence? artifact = null;
        bool mayHaveActed = false;
        try {
            ct.ThrowIfCancellationRequested();
            if (command.Action is not ("observe" or "heartbeat")) {
                var (hwnd, root) = Resolve(command.Window!);
                if (command.Action == "capture") {
                    if (root.Current.ClassName == "#32770" || Elements(root, ct).Any(e => e.Current.IsPassword)) throw new AgentException("SENSITIVE_CAPTURE_DENIED");
                    artifact = Capture(hwnd, command.Id);
                }
                else {
                    if (!Identity().InputDesktop || Identity().Desktop != policy.Desktop) throw new AgentException("SESSION_OR_DESKTOP_DENIED");
                    if (new[] { 1, 2, 4, 16, 17, 18, 91, 92 }.Any(k => (Native.GetAsyncKeyState(k) & 0x8000) != 0)) throw new AgentException("MODIFIER_HELD");
                    Foreground(hwnd);
                    var element = command.Element == null ? AutomationElement.FocusedElement : Element(root, command.Element, ct);
                    if (element == null || element.Current.ProcessId != root.Current.ProcessId ||
                        !policy.AutomationIds.Contains(Selector(element)) || element.Current.IsPassword)
                        throw new AgentException("FOCUS_DENIED");
                    ct.ThrowIfCancellationRequested();
                    if (command.Action == "focus") { mayHaveActed = true; element.SetFocus(); }
                    else if (command.Action == "key") {
                        if (!element.Current.HasKeyboardFocus) throw new AgentException("FOCUS_DENIED");
                        if (Native.GetForegroundWindow() != hwnd) throw new AgentException("FOREGROUND_DENIED");
                        mayHaveActed = true; SendKey(command.Key!);
                    } else if (command.Action == "click") {
                        var rect = element.Current.BoundingRectangle;
                        var point = new Native.POINT { X = (int)(rect.X + rect.Width / 2), Y = (int)(rect.Y + rect.Height / 2) };
                        if (rect.IsEmpty || Native.GetAncestor(Native.WindowFromPoint(point), 2) != hwnd)
                            throw new AgentException("OCCLUDED_TARGET");
                        mayHaveActed = true;
                        if (!Native.SetCursorPos(point.X, point.Y) || Native.GetForegroundWindow() != hwnd)
                            throw new AgentException("FOREGROUND_DENIED");
                        Native.INPUT[] inputs = [new() { Data = new() { Mouse = new() { Flags = 2 } } },
                            new() { Data = new() { Mouse = new() { Flags = 4 } } }];
                        if (Native.SendInput(2, inputs, System.Runtime.InteropServices.Marshal.SizeOf<Native.INPUT>()) != 2)
                            throw new AgentException("INPUT_INCOMPLETE");
                    } else if (command.Action == "setFile") {
                        if (Native.GetWindow(hwnd, 4) == 0 || element.Current.ControlType != ControlType.Edit)
                            throw new AgentException("FILE_DIALOG_REQUIRED");
                        var name = command.File!;
                        if (Path.GetFileName(name) != name || name.Contains(':') || !name.EndsWith(".json", StringComparison.Ordinal) ||
                            name.Any(c => c is '/' or '\\') || name.Length > 100)
                            throw new AgentException("FILE_PATH_DENIED");
                        string file = Path.Combine(evidence.Root, name);
                        EvidenceStore.SafeRoot(evidence.Root);
                        if (File.Exists(file) && (File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                            throw new AgentException("REPARSE_DENIED");
                        if (!element.TryGetCurrentPattern(ValuePattern.Pattern, out var pattern))
                            throw new AgentException("ELEMENT_UNAVAILABLE");
                        mayHaveActed = true;
                        ((ValuePattern)pattern).SetValue(file);
                    }
                }
            }
            ct.ThrowIfCancellationRequested();
            return new(Observe(ct), artifact);
        } catch (OperationCanceledException) { throw; }
        catch (Exception) when (mayHaveActed) { throw new AgentException("UNKNOWN_OUTCOME"); }
        catch (ElementNotAvailableException) { throw new AgentException("STALE_TARGET"); }
    }
}
