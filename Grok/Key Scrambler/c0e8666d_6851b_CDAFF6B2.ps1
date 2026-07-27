# Key Scrambler.ps1 - Fixed for Multiple Keyboard Layouts
# Author: Gorstak (Modified for layout support)

$Source = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const uint VK_A = 65;
    private const uint VK_Z = 90;
    private const uint VK_CONTROL = 0x11;
    private const uint VK_SHIFT = 0x10;
    private const uint VK_MENU = 0x12; // Alt key
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }

    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG lpMsg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG lpMsg);
    [DllImport("user32.dll")] private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;
        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
                                   Marshal.GetFunctionPointerForDelegate(_proc),
                                   GetModuleHandle(null), 0);
        if (_hookID == IntPtr.Zero) throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("Scrambler ON   you type normally, loggers see random A-Z sequences with varied patterns.");
        Console.WriteLine("Fixed for multiple keyboard layouts and special characters.");
        Console.WriteLine("Close window or Ctrl+C to stop.");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    public static void Stop()
    {
        if (_hookID != IntPtr.Zero) { UnhookWindowsHookEx(_hookID); _hookID = IntPtr.Zero; Console.WriteLine("Stopped."); }
    }

    private static bool AreModifiersPressed()
    {
        bool ctrlPressed = (GetKeyState((int)VK_CONTROL) & 0x8000) != 0;
        bool shiftPressed = (GetKeyState((int)VK_SHIFT) & 0x8000) != 0;
        bool altPressed = (GetKeyState((int)VK_MENU) & 0x8000) != 0;
        return ctrlPressed || shiftPressed || altPressed;
    }

    private static void InjectFakeKey()
    {
        byte fakeVk = (byte)_rnd.Next((int)VK_A, (int)VK_Z + 1);
        keybd_event(fakeVk, 0, 0, UIntPtr.Zero);    // Key down
        keybd_event(fakeVk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);  // Key up
        Thread.Sleep(_rnd.Next(1, 8)); // Reduced random delay 1-7ms
    }

    private static void InjectFakeModifier()
    {
        uint modifier = _rnd.Next(0, 2) == 0 ? VK_CONTROL : VK_SHIFT;
        keybd_event((byte)modifier, 0, KEYEVENTF_EXTENDEDKEY, UIntPtr.Zero); // Modifier down
        keybd_event((byte)modifier, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, UIntPtr.Zero); // Modifier up
        Thread.Sleep(_rnd.Next(1, 8)); // Reduced random delay 1-7ms
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT kbStruct = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
            
            if (AreModifiersPressed())
            {
                return CallNextHookEx(_hookID, nCode, wParam, lParam);
            }

            if (kbStruct.vkCode < VK_A || kbStruct.vkCode > VK_Z)
            {
                return CallNextHookEx(_hookID, nCode, wParam, lParam);
            }

            // 10% chance to skip fake injections entirely
            if (_rnd.NextDouble() < 0.1) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            // Choose injection pattern: 0=before only, 1=after only, 2=both
            int pattern = _rnd.Next(0, 3);
            bool injectBefore = pattern == 0 || pattern == 2;
            bool injectAfter = pattern == 1 || pattern == 2;

            // Inject fake modifier 15% of the time (reduced from 20%)
            if (_rnd.NextDouble() < 0.15) InjectFakeModifier();

            // Inject 0 to 3 random A-Z letters before the real key
            if (injectBefore)
            {
                int beforeCount = _rnd.Next(0, 4); // 0 to 3 fake keys
                for (int i = 0; i < beforeCount; i++) InjectFakeKey();
            }

            // Let the original key pass through unchanged
            IntPtr result = CallNextHookEx(_hookID, nCode, wParam, lParam);

            // Inject 0 to 3 random A-Z letters after the real key
            if (injectAfter)
            {
                int afterCount = _rnd.Next(0, 4); // 0 to 3 fake keys
                for (int i = 0; i < afterCount; i++) InjectFakeKey();
            }

            // Inject another fake modifier 15% of the time (reduced from 20%)
            if (_rnd.NextDouble() < 0.15) InjectFakeModifier();

            return result;
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

try { Add-Type -TypeDefinition $Source -ErrorAction Stop }
catch { Write-Error "Compile error: $($_.Exception.Message)"; exit }

while ($true) { [KeyScrambler]::Start() }
