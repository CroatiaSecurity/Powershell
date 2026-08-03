# Key Scrambler.ps1
# Author: Gorstak

function Register-SystemLogonScript {
    param ([string]$TaskName = "RunKeyScramblerAtLogon")
    
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Host "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Host "Copied script to: $targetPath"
    } catch {
        Write-Host "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Host "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Host "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript

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
    private const uint KEYEVENTF_UNICODE = 0x0004;
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

        Console.WriteLine("Scrambler ON - you type normally, loggers see random A-Z sequences with varied patterns.");
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

    private static void InjectFakeKey()
    {
        ushort fakeChar = (ushort)_rnd.Next((int)VK_A, (int)VK_Z + 1);
        keybd_event(0, 0, KEYEVENTF_UNICODE, (UIntPtr)fakeChar);    // Unicode down
        keybd_event(0, 0, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, (UIntPtr)fakeChar);  // Unicode up
        Thread.Sleep(_rnd.Next(1, 11)); // Random delay 1-10ms
    }

    private static void InjectFakeModifier()
    {
        uint modifier = _rnd.Next(0, 2) == 0 ? VK_CONTROL : VK_SHIFT;
        keybd_event((byte)modifier, 0, KEYEVENTF_EXTENDEDKEY, UIntPtr.Zero); // Modifier down
        keybd_event((byte)modifier, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, UIntPtr.Zero); // Modifier up
        Thread.Sleep(_rnd.Next(1, 11)); // Random delay 1-10ms
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            // 10% chance to skip fake injections entirely
            if (_rnd.NextDouble() < 0.1) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            // Choose injection pattern: 0=before only, 1=after only, 2=both
            int pattern = _rnd.Next(0, 3);
            bool injectBefore = pattern == 0 || pattern == 2;
            bool injectAfter = pattern == 1 || pattern == 2;

            // Inject fake modifier 20% of the time
            if (_rnd.NextDouble() < 0.2) InjectFakeModifier();

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

            // Inject another fake modifier 20% of the time
            if (_rnd.NextDouble() < 0.2) InjectFakeModifier();

            return result;
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

try { Add-Type -TypeDefinition $Source -ErrorAction Stop }
catch { Write-Error "Compile error: $($_.Exception.Message)"; exit }

try { [KeyScrambler]::Start() }
catch { Write-Error $_.Exception.Message }
finally { [KeyScrambler]::Stop() }