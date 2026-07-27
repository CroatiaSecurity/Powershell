# GShield.ps1
# Author: Gorstak
#Requires -RunAsAdministrator

param([string[]]$Path, [int]$IntervalMinutes=60)

# ==================== CONFIG ====================
$InstallDir     = "$env:ProgramData\Antivirus"
$LogDir         = "$InstallDir\logs"
$QuarDir        = "$InstallDir\quarantine"
$LogFile        = "$LogDir\scanner.log"
$HashCacheFile  = "$InstallDir\cache.csv"

$Ext = @('*.exe','*.dll','*.ocx','*.winmd','*.ps1','*.vbs','*.js','*.bat','*.cmd','*.scr','*.msi')

$Exclusions = @(
    "$env:ProgramFiles", "$env:ProgramFiles(x86)", "$env:windir",
    "$InstallDir", "C:\Windows\System32", "C:\Windows\SysWOW64",
    "C:\ProgramData", "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Local\Microsoft"
)

$SuspiciousAPIs = 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|VirtualProtect|LoadLibrary|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile'

# ==================== SELF-PROTECTION ====================
function Invoke-SelfProtection {
    # Kill duplicate instances
    $currentPID = $PID
    Get-Process -Name "powershell" -EA 0 | Where-Object { $_.Id -ne $currentPID } | ForEach-Object {
        try {
            $cmd = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
            if ($cmd -like "*GShield.ps1*") {
                Stop-Process -Id $_.Id -Force -EA 0
                Write-Log "Killed duplicate GShield instance (PID $($_.Id))" "WARN"
            }
        } catch {}
    }

    # Hide console window
    Add-Type -Name Win32 -Namespace Win32 -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@
    $hwnd = [Win32]::GetConsoleWindow()
    if ($hwnd) { [Win32]::ShowWindow($hwnd, 0) }
}

# ==================== LOGGING ====================
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp [$Level] $Message" | Add-Content $LogFile -Force -EA 0
    if ($Level -eq 'ALERT') { Write-Host $Message -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $Message -ForegroundColor Yellow }
    else { Write-Host $Message }
}

function Get-SHA256 { param($file); (Get-FileHash $file -Algorithm SHA256).Hash }

function Test-Excluded { param($p)
    $p = $p.ToLower()
    foreach ($ex in $Exclusions) {
        if ($p.StartsWith($ex.ToLower())) { return $true }
    }
    $false
}

# ==================== HASH CACHE ====================
$global:HashCache = @{}
$global:CacheDirty = $false

function Load-Cache {
    if (!(Test-Path $HashCacheFile)) { return }
    try {
        Import-Csv $HashCacheFile | ForEach-Object {
            try {
                $global:HashCache[$_.Path] = [pscustomobject]@{
                    Hash         = $_.Hash
                    Status       = $_.Status
                    LastModified = [datetime]::ParseExact($_.LastModified, "yyyy-MM-dd HH:mm:ss", $null)
                }
            } catch {}
        }
    } catch {}
}

function Save-Cache {
    if (-not $global:CacheDirty) { return }
    $global:HashCache.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            Path         = $_.Key
            Hash         = $_.Value.Hash
            Status       = $_.Value.Status
            LastModified = $_.Value.LastModified.ToString("yyyy-MM-dd HH:mm:ss")
        }
    } | Export-Csv $HashCacheFile -NoTypeInformation -Force
    $global:CacheDirty = $false
}

function Test-CacheHit {
    param($file)
    $cached = $global:HashCache[$file.FullName]
    if (-not $cached) { return $false }
    if ($cached.LastModified -lt $file.LastWriteTime) { return $false }
    return $cached.Status -eq 'clean'
}

function Update-Cache {
    param($file, $hash, $status)
    $global:HashCache[$file.FullName] = [pscustomobject]@{
        Hash         = $hash
        Status       = $status
        LastModified = $file.LastWriteTime
    }
    $global:CacheDirty = $true
}

# ==================== AMSI ====================
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public class Amsi{[DllImport("amsi.dll")]public static extern int AmsiInitialize(string a,out IntPtr c);[DllImport("amsi.dll")]public static extern int AmsiScanString(IntPtr c,string s,string n,string sess,out IntPtr r);[DllImport("amsi.dll")]public static extern void AmsiUninitialize(IntPtr c);
public static int Scan(string s){IntPtr ctx,rs;int hr=AmsiInitialize("GShield",out ctx);if(hr!=0)return 0;AmsiScanString(ctx,s,"", "",out rs);int res=(int)rs;AmsiUninitialize(ctx);return res;}}
'@ -ErrorAction SilentlyContinue

function Test-Amsi { param([string]$c); if(!$c) {return 0}; return [Amsi]::Scan($c) -ge 1 }

# ==================== STRONGER MEMORY SCANNER ====================
if (-not ([System.Management.Automation.PSTypeName]'MemScanner').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class MemScanner {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, int size, out int bytesRead);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

    const uint PROCESS_VM_READ = 0x0010;

    public static List<string> ScanProcess(int pid) {
        var findings = new List<string>();
        IntPtr hProc = OpenProcess(PROCESS_VM_READ, false, pid);
        if (hProc == IntPtr.Zero) return findings;

        try {
            byte[] buffer = new byte[32768];
            int bytesRead;
            Process proc = Process.GetProcessById(pid);

            foreach (ProcessModule mod in proc.Modules) {
                try {
                    long scanSize = Math.Min(0x200000, (long)mod.ModuleMemorySize);
                    for (long offset = 0; offset < scanSize; offset += 16384) {
                        ReadProcessMemory(hProc, mod.BaseAddress + offset, buffer, buffer.Length, out bytesRead);
                        if (bytesRead == 0) break;

                        string text = Encoding.ASCII.GetString(buffer, 0, bytesRead).ToLower();

                        if (text.Contains("virtualalloc") || text.Contains("createremotethread") || 
                            text.Contains("frombase64string") || text.Contains("downloadstring") || 
                            text.Contains("iex(") || text.Contains("-ep bypass") || 
                            text.Contains("urldownloadtofile") || text.Contains("shellcode") ||
                            text.Contains("reflective") || text.Contains("rundll")) {
                            findings.Add(mod.ModuleName);
                            break;
                        }
                    }
                } catch { }
            }
        } finally {
            CloseHandle(hProc);
        }
        return findings;
    }
}
'@
}

function Invoke-MemoryScan {
    Get-Process -EA 0 | Where-Object { $_.Path -and !(Test-Excluded $_.Path) -and $_.Id -ne $PID } | ForEach-Object {
        try {
            $findings = [MemScanner]::ScanProcess($_.Id)
            if ($findings.Count -gt 0) {
                Write-Log "MEMORY DETECTION: $($_.ProcessName) (PID $($_.Id)) - Suspicious patterns found" "ALERT"
            }
        } catch {}
    }
}

# ==================== AGGRESSIVE BROWSER GUARD ====================
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FreeLibrary(IntPtr module);
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

$BrowserNames = @('chrome','msedge','firefox','opera','brave','vivaldi')

function Invoke-BrowserModuleGuard {
    foreach ($name in $BrowserNames) {
        $procs = Get-Process -Name $name -EA 0
        foreach ($proc in $procs) {
            $removed = [ModuleGuard]::UnloadUnsignedModules($proc.Id)
            foreach ($mod in $removed) {
                Write-Log "UNLOADED unsigned browser module: $mod (from $($proc.ProcessName) PID $($proc.Id))" "ALERT"
            }
        }
    }
}

# ==================== HEURISTICS ====================
function Get-Entropy { param([byte[]]$b)
    if (!$b.Length) { return 0 }
    $f = @{}; foreach ($c in $b) { $f[$c]++ }
    $e = 0; foreach ($c in $f.Keys) { $p = $f[$c]/$b.Length; $e -= $p * [Math]::Log($p)/[Math]::Log(2) }
    $e
}

function IsSigned { param($path) 
    try { 
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        $chain.Build($cert)
        return $true 
    } catch { return $false } 
}

function Test-Heuristic {
    param([string]$path)
    $warn = @()
    $ext = [IO.Path]::GetExtension($path).ToLower()
    try {
        $bytes = [IO.File]::ReadAllBytes($path)
        if ((Get-Entropy $bytes) -gt 7.0) { $warn += "high-entropy" }

        if ($ext -in '.exe','.dll') {
            $str = [Text.Encoding]::ASCII.GetString($bytes)
            if ($str -match $SuspiciousAPIs) { $warn += "susp-api" }
            if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                if (-not (IsSigned $path) -and $path -notlike "*\Windows\*") { $warn += "unsigned-PE" }
            }
        }

        if ($ext -in '.ps1','.vbs','.js','.bat','.cmd') {
            $content = Get-Content $path -Raw -EA 0
            if ($content -match '[A-Za-z0-9+/]{100,}={0,2}') { $warn += "b64" }
            if ($content -match 'IEX|Invoke-Expression|FromBase64String|DownloadString|DownloadFile|Hidden') { $warn += "obf" }
        }

        if ($path -like "*\Temp\*") { $warn += "temp-location" }
    } catch {}
    return ($warn -join ',')
}

# ==================== FILE SCAN ====================
function Invoke-Scan {
    param([string]$p)

    Load-Cache

    Get-ChildItem $p -Recurse -Include $Ext -File -EA 0 |
        Where-Object { -not (Test-Excluded $_.FullName) } | ForEach-Object {
            $f = $_
            if (Test-CacheHit $f) { return }

            $hash = Get-SHA256 $f.FullName
            $heur = Test-Heuristic $f.FullName
            $isMalicious = $false

            if ($heur -match "high-entropy|susp-api|obf|unsigned-PE|temp-location") {
                Write-Log "THREAT (heuristic): $($f.FullName) [$heur]" "ALERT"
                Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
                $isMalicious = $true
            }

            if ($f.Extension -in '.ps1','.vbs','.js' -and (Test-Amsi (Get-Content $f.FullName -Raw -EA 0))) {
                Write-Log "THREAT (AMSI): $($f.FullName)" "ALERT"
                Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
                $isMalicious = $true
            }

            if ($isMalicious) {
                Update-Cache $f $hash 'malicious'
            } else {
                Update-Cache $f $hash 'clean'
            }
        }

    Save-Cache
    Write-Log "Scan completed: $p"
}

# ==================== PERSISTENCE ====================
function Install-Persistence {
    $taskName = "MicrosoftSysCache"
    $scriptPath = $PSCommandPath

    schtasks.exe /Delete /TN $taskName /F 2>$null
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    schtasks.exe /Create /TN $taskName /TR $cmd /SC ONLOGON /RL HIGHEST /F 2>$null | Out-Null
    Write-Log "Persistence installed as $taskName"
}

# ==================== MAIN ====================
try {
    if (!(Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
    
    Write-Log "GShield v2.9 starting - PID: $PID"
    
    Invoke-SelfProtection
    Install-Persistence
    Load-Cache

    # Clean old WMI subscriber
    Get-EventSubscriber -SourceIdentifier "ProcGuard" -EA 0 | Unregister-Event -Force

    function Get-ScanTargets {
        if ($Path -and $Path.Count -gt 0) { return $Path }
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -and (Test-Path $_.Root) } | Select-Object -ExpandProperty Root
    }

    if ($IntervalMinutes -le 0) {
        Get-ScanTargets | ForEach-Object { Invoke-Scan $_ }
        exit
    }

    Write-Log "Real-time protection + Strong Memory Scanner + Aggressive Browser Guard + Self-Protection enabled"

    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "ProcGuard" -Action {
        $procPath = $Event.SourceEventArgs.NewEvent.ExecutablePath
        if (!$procPath -or (Test-Excluded $procPath)) { return }
        $heur = Test-Heuristic $procPath
        if ($heur -match "high-entropy|susp-api|obf|unsigned-PE") {
            Stop-Process -Id $Event.SourceEventArgs.NewEvent.ProcessID -Force -EA 0
            Move-Item $procPath "$QuarDir\$([IO.Path]::GetFileName($procPath))" -Force -EA 0
            Write-Log "BLOCKED+QUARANTINED: $procPath [$heur]" "ALERT"
        }
    } | Out-Null

    $cycle = 0
    while ($true) {
        $cycle++
        $targets = Get-ScanTargets
        Write-Log "Periodic scan starting across drives..."
        $targets | ForEach-Object { Invoke-Scan $_ }
        
        Invoke-MemoryScan
        Invoke-BrowserModuleGuard   # Aggressive - runs every cycle

        Save-Cache
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
}