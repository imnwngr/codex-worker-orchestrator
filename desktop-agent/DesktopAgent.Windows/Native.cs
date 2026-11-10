using System.Runtime.InteropServices;
using System.Text;

namespace DesktopAgent.Windows;

internal static class Native
{
    internal delegate bool EnumProc(nint hwnd, nint param);
    [DllImport("user32.dll")] internal static extern bool EnumWindows(EnumProc callback, nint param);
    [DllImport("user32.dll")] internal static extern bool IsWindow(nint hwnd);
    [DllImport("user32.dll")] internal static extern bool IsWindowVisible(nint hwnd);
    [DllImport("user32.dll")] internal static extern bool IsIconic(nint hwnd);
    [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(nint hwnd, out uint process);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] internal static extern int GetWindowText(nint hwnd, StringBuilder text, int count);
    [DllImport("user32.dll")] internal static extern nint GetForegroundWindow();
    [DllImport("user32.dll")] internal static extern nint GetWindow(nint hwnd, uint command);
    [DllImport("user32.dll")] internal static extern nint GetAncestor(nint hwnd, uint flags);
    [DllImport("user32.dll")] internal static extern nint WindowFromPoint(POINT point);
    [DllImport("user32.dll")] internal static extern bool SetForegroundWindow(nint hwnd);
    [DllImport("user32.dll")] internal static extern bool GetClientRect(nint hwnd, out RECT rect);
    [DllImport("user32.dll")] internal static extern bool ClientToScreen(nint hwnd, ref POINT point);
    [DllImport("user32.dll")] internal static extern bool GetWindowRect(nint hwnd, out RECT rect);
    [DllImport("user32.dll")] internal static extern nint GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll")] internal static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] internal static extern nint GetProcessWindowStation();
    [DllImport("user32.dll")] internal static extern nint OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] internal static extern bool CloseDesktop(nint desktop);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    internal static extern bool GetUserObjectInformation(nint handle, int index, StringBuilder text, int length, out int needed);
    [DllImport("user32.dll")] internal static extern short GetAsyncKeyState(int key);
    [DllImport("user32.dll")] internal static extern uint SendInput(uint count, INPUT[] input, int size);
    [DllImport("user32.dll")] internal static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] internal static extern bool PrintWindow(nint hwnd, nint dc, uint flags);
    [DllImport("user32.dll")] internal static extern nint GetDC(nint hwnd);
    [DllImport("user32.dll")] internal static extern int ReleaseDC(nint hwnd, nint dc);
    [DllImport("gdi32.dll")] internal static extern nint CreateCompatibleDC(nint dc);
    [DllImport("gdi32.dll")] internal static extern nint CreateCompatibleBitmap(nint dc, int width, int height);
    [DllImport("gdi32.dll")] internal static extern nint SelectObject(nint dc, nint obj);
    [DllImport("gdi32.dll")] internal static extern bool DeleteObject(nint obj);
    [DllImport("gdi32.dll")] internal static extern bool DeleteDC(nint dc);
    [StructLayout(LayoutKind.Sequential)] internal struct RECT { internal int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] internal struct POINT { internal int X, Y; }
    [StructLayout(LayoutKind.Sequential)] internal struct INPUT { internal uint Type; internal InputUnion Data; }
    [StructLayout(LayoutKind.Explicit)] internal struct InputUnion {
        [FieldOffset(0)] internal KEYBDINPUT Keyboard;
        [FieldOffset(0)] internal MOUSEINPUT Mouse;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct KEYBDINPUT {
        internal ushort Vk, Scan; internal uint Flags, Time; internal nuint Extra;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct MOUSEINPUT {
        internal int Dx, Dy; internal uint MouseData, Flags, Time; internal nuint Extra;
    }
    internal static string ObjectName(nint handle)
    {
        var text = new StringBuilder(256);
        return handle != 0 && GetUserObjectInformation(handle, 2, text, text.Capacity * 2, out _) ? text.ToString() : "Unavailable";
    }
}
