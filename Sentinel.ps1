#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Sentinel v1.0 - Behavioral EDR for Windows 10/11
.DESCRIPTION
    Behavioral endpoint detection and response. Detects threats by what
    processes DO, not what they're called. Assumes the attacker has read
    this source code.

    Active response (kill) and hash reputation are ON by default.
    Installs itself as a SYSTEM scheduled task for persistence.
    Use -Uninstall to remove.

.PARAMETER Uninstall
    Remove scheduled task, stop running instances, and exit.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "SilentlyContinue"
$Script:LogPath = "$env:ProgramData\WindowsSentinel\events.jsonl"
$Script:MonitorPath = $env:USERPROFILE
$Script:MaxLogSizeMB = 50
$Script:MaxLogFiles = 5
$Script:ScanIntervalSeconds = 5

# ============================================================================
# GLOBALS & STATE
# ============================================================================
$Script:Version = "3.5.0"
$Script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:Dedup = @{}
$Script:Correlation = @{}
$Script:CorrelationTTL = 120
$Script:ProcessAncestry = @{}
$Script:BeaconTracker = @{}
$Script:LogCount = 0; $Script:LogWindow = Get-Date; $Script:LogBurst = 200
$Script:FileEvents = [System.Collections.ArrayList]::new()
$Script:FileWatcher = $null
$Script:FileRateTracker = @{ Count = 0; Start = Get-Date }
$Script:ClipboardBaseline = ""
$Script:ClipboardChangeCount = 0; $Script:ClipboardWindow = Get-Date
$Script:ModuleBaseline = @{}
$Script:SelfHash = $null
$Script:HashCache = @{}
$Script:DnsQueryTracker = @{}
$Script:TaskName = "WindowsSentinel"

# JIT/Electron - legitimately have RWX memory (exclude from memory scan)
$Script:JitPaths = @(
    '*\java.exe','*\javaw.exe','*\node.exe','*\electron.exe',
    '*\chrome.exe','*\msedge.exe','*\firefox.exe','*\brave.exe',
    '*\Code.exe','*\kiro.exe','*\Discord.exe','*\Slack.exe','*\Teams.exe',
    '*\steam.exe','*\steamwebhelper.exe','*\obs64.exe','*\obs32.exe',
    '*\dotnet.exe','*\w3wp.exe','*\Spotify.exe','*\Signal.exe',
    '*\Notion.exe','*\Obsidian.exe','*\GitKraken.exe','*\Postman.exe',
    '*\1Password.exe','*\Bitwarden.exe','*\WindowsTerminal.exe'
)

# ============================================================================
# NATIVE METHODS
# ============================================================================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SN {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI buf, int len);
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr b, byte[] buf, int sz, out int read);
    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardOwner();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    public const uint QI = 0x0400, VMR = 0x0010, COMMIT = 0x1000, PRIV = 0x20000;
    public const uint RWX = 0x40, RWC = 0x80;
}
"@ -ErrorAction SilentlyContinue

# ============================================================================
# LOGGING (JSONL, rotation, rate-limited, concurrent-reader safe)
# ============================================================================
function Initialize-Log {
    $dir = Split-Path $Script:LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
function Rotate-Log {
    if (-not (Test-Path $Script:LogPath)) { return }
    if ((Get-Item $Script:LogPath -ErrorAction SilentlyContinue).Length / 1MB -ge $Script:MaxLogSizeMB) {
        for ($i = $Script:MaxLogFiles; $i -ge 1; $i--) {
            $o = "$($Script:LogPath).$i"
            if ($i -eq $Script:MaxLogFiles -and (Test-Path $o)) { Remove-Item $o -Force }
            if (Test-Path $o) { Rename-Item $o "$($Script:LogPath).$($i+1)" -Force }
        }
        Rename-Item $Script:LogPath "$($Script:LogPath).1" -Force
    }
}
function Log-Event {
    param([string]$Type,[string]$Rule,[string]$Evidence,[string]$Reasoning,
          [double]$Conf,[string]$Tier,[string]$PName="",[int]$PId=0,[hashtable]$Meta=@{})
    $now = Get-Date
    if (($now - $Script:LogWindow).TotalSeconds -ge 1) { $Script:LogCount = 0; $Script:LogWindow = $now }
    if ($Script:LogCount -ge $Script:LogBurst) { return }
    $Script:LogCount++
    $obj = @{ type=$Type; timestamp=$now.ToString("o"); data=@{
        ruleName=$Rule; evidence=$Evidence; reasoning=$Reasoning
        confidence=$Conf; tier=$Tier; processName=$PName; processId=$PId; metadata=$Meta
    }}
    $json = $obj | ConvertTo-Json -Depth 5 -Compress
    try { Rotate-Log; Add-Content -Path $Script:LogPath -Value $json -Encoding UTF8 -ErrorAction Stop } catch {}
}

# ============================================================================
# DEDUPLICATION & CORRELATION ENGINE
# ============================================================================
function Is-Dup { param([string]$K,[int]$TTL=60)
    $now = Get-Date
    $old = @($Script:Dedup.Keys | Where-Object { ($now - $Script:Dedup[$_]).TotalSeconds -gt $TTL })
    foreach ($k in $old) { $Script:Dedup.Remove($k) }
    if ($Script:Dedup.ContainsKey($K)) { return $true }
    $Script:Dedup[$K] = $now; return $false
}
function Add-Signal { param([int]$Pid,[string]$Cat,[double]$Conf)
    $now = Get-Date
    if (-not $Script:Correlation.ContainsKey($Pid)) { $Script:Correlation[$Pid] = @() }
    $Script:Correlation[$Pid] = @($Script:Correlation[$Pid] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL })
    $Script:Correlation[$Pid] += @{ C=$Cat; V=$Conf; T=$now }
}
function Get-Categories { param([int]$Pid)
    if (-not $Script:Correlation.ContainsKey($Pid)) { return @() }
    $now = Get-Date
    @($Script:Correlation[$Pid] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL } | ForEach-Object { $_.C } | Select-Object -Unique)
}
function Get-SignalCount { param([int]$Pid)
    if (-not $Script:Correlation.ContainsKey($Pid)) { return 0 }
    $now = Get-Date
    @($Script:Correlation[$Pid] | Where-Object { ($now - $_.T).TotalSeconds -le $Script:CorrelationTTL }).Count
}

# ============================================================================
# PROCESS ANCESTRY
# ============================================================================
function Update-Ancestry {
    $s = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate -ErrorAction Stop | ForEach-Object {
            $s[$_.ProcessId] = @{ N=$_.Name; PP=$_.ParentProcessId; CL=$_.CommandLine; P=$_.ExecutablePath; T=$_.CreationDate }
        }
    } catch {}
    $Script:ProcessAncestry = $s
}

# ============================================================================
# ENTROPY (Shannon) - used for DGA detection and DLL analysis
# ============================================================================
function Get-Entropy { param([string]$S)
    if ([string]::IsNullOrEmpty($S)) { return 0 }
    $f = @{}; foreach ($c in $S.ToCharArray()) { if ($f.ContainsKey($c)){$f[$c]++}else{$f[$c]=1} }
    $l = $S.Length; $e = 0.0
    foreach ($v in $f.Values) { $p = $v/$l; if ($p -gt 0) { $e -= $p * [Math]::Log($p,2) } }
    return $e
}

# ============================================================================
# HASH REPUTATION (Live API - like AV.ps1 approach)
# ============================================================================
function Test-HashReputation { param([string]$Hash)
    if ($Script:HashCache.ContainsKey($Hash)) { return $Script:HashCache[$Hash] }

    # CIRCL hashlookup - known good
    try {
        $r = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$Hash" -Method Get -TimeoutSec 6 -ErrorAction Stop
        if ($r.'hashlookup:trust' -and [int]$r.'hashlookup:trust' -gt 50) {
            $Script:HashCache[$Hash] = @{ Bad=$false; Src="CIRCL"; Detail="Trust=$($r.'hashlookup:trust')" }
            return $Script:HashCache[$Hash]
        }
    } catch {}

    # MalwareBazaar - known bad
    try {
        $body = @{ query="get_info"; hash=$Hash } | ConvertTo-Json -Compress
        $r = Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 8 -ErrorAction Stop
        if ($r.query_status -eq "ok" -or $r.query_status -eq "hash_found") {
            $Script:HashCache[$Hash] = @{ Bad=$true; Src="MalwareBazaar"; Detail="Known malware" }
            return $Script:HashCache[$Hash]
        }
    } catch {}

    $Script:HashCache[$Hash] = @{ Bad=$false; Src="Unknown"; Detail="Not in databases" }
    return $Script:HashCache[$Hash]
}

# ============================================================================
# SELF-PROTECTION (detect tampering of own script/process)
# ============================================================================
function Initialize-SelfProtection {
    if ($PSCommandPath) {
        try { $Script:SelfHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { $Script:SelfHash = $null }
    }
}
function Test-SelfIntegrity {
    if (-not $Script:SelfHash -or -not $PSCommandPath) { return }
    try {
        $current = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($current -ne $Script:SelfHash) {
            if (-not (Is-Dup -K "SelfTamper" -TTL 300)) {
                Log-Event -Type "detection" -Rule "SelfProtection" -Evidence "Script file modified on disk" `
                    -Reasoning "Sentinel script hash changed - possible tampering" -Conf 0.97 -Tier "Tier1Behavioral" -PName "Sentinel" -PId $PID
                Write-Host "[CRITICAL] Self-protection: script file tampered" -ForegroundColor Red
            }
        }
    } catch {}
}

# ============================================================================
# MEMORY ANALYSIS (strongest signal - can't be evaded by renaming)
# ============================================================================
function Invoke-MemoryAnalysis { param([int]$Pid,[string]$Name,[string]$Path)
    if ($Pid -le 4 -or $Pid -eq $PID) { return $null }
    $h = [SN]::OpenProcess(([SN]::QI -bor [SN]::VMR), $false, $Pid)
    if ($h -eq [IntPtr]::Zero) { return $null }
    $flags = @()
    try {
        $addr = [IntPtr]::Zero; $rwx = 0; $unbacked = 0; $privExec = [int64]0
        $mbi = New-Object SN+MBI
        for ($i = 0; $i -lt 2000; $i++) {
            if ([SN]::VirtualQueryEx($h, $addr, [ref]$mbi, [Runtime.InteropServices.Marshal]::SizeOf($mbi)) -eq 0) { break }
            if ($mbi.State -eq [SN]::COMMIT) {
                if ($mbi.Protect -eq [SN]::RWX -or $mbi.Protect -eq [SN]::RWC) { $rwx++ }
                if ($mbi.Type -eq [SN]::PRIV -and ($mbi.Protect -band 0xF0) -ne 0) {
                    $unbacked++; $privExec += [int64]$mbi.RegionSize
                }
            }
            $n = [int64]$addr + [int64]$mbi.RegionSize
            if ($n -le [int64]$addr) { break }
            $addr = [IntPtr]$n
        }
        if ($rwx -ge 5) { $flags += "RWX:$rwx" }
        if ($unbacked -ge 8) { $flags += "Unbacked:$unbacked" }
        if ($privExec -gt 50MB) { $flags += "PrivExec:$([Math]::Round($privExec/1MB))MB" }
    } finally { [SN]::CloseHandle($h) | Out-Null }

    # Hollowing: image path vs main module mismatch
    try {
        $p = Get-Process -Id $Pid -ErrorAction Stop
        if ($p.Path -and $p.Modules.Count -gt 0 -and $p.Modules[0].FileName) {
            if ($p.Modules[0].FileName.ToLower() -ne $p.Path.ToLower()) { $flags += "Hollowed" }
        }
        # High memory, few modules = packed/injected
        if ($p.PrivateMemorySize64 -gt 500MB -and $p.Modules.Count -lt 10) { $flags += "HighMemLowMod" }
        # No backing file on disk
        if ([string]::IsNullOrEmpty($p.Path) -or -not (Test-Path $p.Path -ErrorAction SilentlyContinue)) { $flags += "NoBackingFile" }
    } catch {}

    if ($flags.Count -ge 2) {
        $conf = [Math]::Min(0.96, 0.70 + $flags.Count * 0.08)
        return @{ Rule="MemoryAnomaly"; Evidence="$Name (PID $Pid): $($flags -join ' | ')"; Reasoning="Multiple memory anomalies indicate injected/hollowed/reflective code"; Conf=$conf; Tier="Tier1Behavioral"; Cat="memory" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: DESTRUCTIVE OPS (Ransomware)
# ============================================================================
function Test-Destructive { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    $hit = $null
    if ($c -match 'vssadmin.*delete|shadowcopy.*delete|shadows.*\/all|resize.*shadowstorage') {
        $hit = "Shadow copy destruction"
    } elseif ($c -match 'recoveryenabled.*no|bootstatuspolicy.*ignore') {
        $hit = "Boot recovery disabled"
    } elseif ($c -match 'wbadmin.*delete.*(catalog|systemstate)') {
        $hit = "Backup catalog destruction"
    } elseif ($c -match '(net\s+stop|sc\s+(stop|config.*disabled))' -and $c -match '(sql|exchange|backup|vss|veeam)') {
        $hit = "Critical service disruption"
    }
    if ($hit) { return @{ Rule="Destructive"; Evidence="$hit by $N (PID $Pid)"; Reasoning="Destroying recovery mechanisms - ransomware precursor"; Conf=0.93; Tier="Tier1Behavioral"; Cat="ransomware" } }
    return $null
}

# ============================================================================
# BEHAVIORAL: CREDENTIAL ACCESS
# ============================================================================
function Test-CredentialAccess { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # comsvcs MiniDump (structural Windows API export)
    if ($c -match 'comsvcs.*minidump|comsvcs\.dll.*#24|comsvcs.*full') {
        return @{ Rule="CredentialDump"; Evidence="MiniDump via comsvcs.dll (PID $Pid)"; Reasoning="Windows built-in DLL used for process memory dump"; Conf=0.92; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # LSASS targeting (structural - must reference the process)
    if ($c -match 'lsass' -and $c -match 'dump|mini|dbg|clone|fork|snap|\.dmp') {
        return @{ Rule="CredentialDump"; Evidence="LSASS memory targeting (PID $Pid)"; Reasoning="Explicit LSASS memory extraction attempt"; Conf=0.90; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Registry hive extraction (structural paths)
    if ($c -match 'reg.*save.*(sam|security|system)|hklm\\(sam|security|system)') {
        return @{ Rule="CredentialDump"; Evidence="Registry hive extraction (PID $Pid)"; Reasoning="Extracting credential hives for offline cracking"; Conf=0.91; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # DPAPI abuse
    if ($c -match 'dpapi' -and $c -match 'masterkey|credential|protect|unprotect') {
        return @{ Rule="CredentialDump"; Evidence="DPAPI credential extraction (PID $Pid)"; Reasoning="Targeting DPAPI for stored credential theft"; Conf=0.85; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Browser credential stores (structural file paths, not tool names)
    if ($c -match '(login\s*data|local\s*state|cookies).*chrome|key4\.db|logins\.json|cookies\.sqlite|\.tbres|tokenbroker') {
        if ($c -match 'copy|type|get-content|select-string|sqlite|cryptunprotect') {
            return @{ Rule="BrowserCredTheft"; Evidence="Browser credential store access (PID $Pid)"; Reasoning="Accessing browser credential files with extraction intent"; Conf=0.87; Tier="Tier1Behavioral"; Cat="credential" }
        }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: DEFENSE EVASION (structural Windows API/registry targets)
# ============================================================================
function Test-Evasion { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match 'amsiscanbuffer|amsiinitialized|amsicontext') {
        return @{ Rule="Evasion"; Evidence="AMSI manipulation (PID $Pid)"; Reasoning="Patching Windows AMSI interface"; Conf=0.92; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'nttracevent|etweventwrite') {
        return @{ Rule="Evasion"; Evidence="ETW blinding (PID $Pid)"; Reasoning="Patching ETW to blind security tools"; Conf=0.93; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'wevtutil.*(cl|clear-log)\s+(security|system|application)') {
        return @{ Rule="Evasion"; Evidence="Event log clearing (PID $Pid)"; Reasoning="Destroying forensic evidence"; Conf=0.90; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'set-mppreference.*-disable(realtimemonitoring|ioavprotection|behaviormonitoring)') {
        return @{ Rule="Evasion"; Evidence="Defender disabled (PID $Pid)"; Reasoning="Programmatically disabling endpoint protection"; Conf=0.91; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'add-mppreference.*-exclusion') {
        return @{ Rule="Evasion"; Evidence="Defender exclusion added (PID $Pid)"; Reasoning="Adding exclusion to hide malware"; Conf=0.85; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match 'fltmc.*unload') {
        return @{ Rule="Evasion"; Evidence="Minifilter unload (PID $Pid)"; Reasoning="Unloading security filter driver"; Conf=0.90; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: PERSISTENCE (structural locations, not tool names)
# ============================================================================
function Test-Persistence { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match '(reg\s+add|new-itemproperty|set-itemproperty).*\\(run|runonce)\b') {
        return @{ Rule="Persistence"; Evidence="Registry Run key (PID $Pid)"; Reasoning="Auto-start registry persistence"; Conf=0.82; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    if ($c -match '(__eventfilter|__eventconsumer|filtertoconsumerbinding)') {
        return @{ Rule="Persistence"; Evidence="WMI subscription (PID $Pid)"; Reasoning="Fileless WMI persistence"; Conf=0.88; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    if ($c -match '(schtasks\s*/create|register-scheduledtask)' -and $c -notmatch 'sentinel') {
        return @{ Rule="Persistence"; Evidence="Scheduled task (PID $Pid)"; Reasoning="Task-based persistence"; Conf=0.75; Tier="Tier2Indicator"; Cat="persistence" }
    }
    if ($c -match '(sc\s+create|new-service)' -and $c -notmatch 'sentinel') {
        return @{ Rule="Persistence"; Evidence="Service creation (PID $Pid)"; Reasoning="Service-based persistence"; Conf=0.78; Tier="Tier2Indicator"; Cat="persistence" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: OBFUSCATED EXECUTION (structural patterns)
# ============================================================================
function Test-Execution { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    # Large encoded payload (structural: -enc + base64 block)
    if ($CL -match '-[eE][nN][cC]\w*\s+[A-Za-z0-9+/=]{100,}') {
        return @{ Rule="EncodedExec"; Evidence="Encoded payload ($([Math]::Round($CL.Length/1024,1))KB) (PID $Pid)"; Reasoning="Large base64 payload in command line"; Conf=0.85; Tier="Tier1Behavioral"; Cat="execution" }
    }
    $c = $CL.ToLower()
    # Download + execute (structural .NET APIs)
    if (($c -match 'downloadstring|downloadfile|downloaddata|invoke-webrequest') -and ($c -match 'invoke-expression|iex\s|start-process|\.invoke\(')) {
        return @{ Rule="DownloadExec"; Evidence="Download-and-execute (PID $Pid)"; Reasoning="Downloading and immediately executing remote content"; Conf=0.87; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Reflective loading (.NET reflection APIs)
    if ($c -match 'reflection\.assembly.*load|gettype.*getmethod.*invoke|\[convert\]::frombase64.*load') {
        return @{ Rule="ReflectiveLoad"; Evidence="Reflective assembly load (PID $Pid)"; Reasoning="In-memory code loading via .NET reflection"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Raw socket shell (structural: TCPClient + Stream)
    if ($c -match 'net\.sockets\.tcpclient|system\.net\.sockets' -and $c -match 'getstream|networkstream') {
        return @{ Rule="ReverseShell"; Evidence="Socket shell (PID $Pid)"; Reasoning="Building network stream shell via .NET socket APIs"; Conf=0.92; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # Execution policy bypass + hidden window (staging pattern)
    if ($c -match '-executionpolicy\s*(bypass|unrestricted)' -and $c -match '-w(indowstyle)?\s*h(idden)?') {
        return @{ Rule="HiddenExec"; Evidence="Hidden+bypass execution (PID $Pid)"; Reasoning="PowerShell running hidden with policy bypass"; Conf=0.72; Tier="Tier2Indicator"; Cat="execution" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: PRIVILEGE ESCALATION (structural Windows mechanisms)
# ============================================================================
function Test-Escalation { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    if ($c -match 'duplicatetokenex|createprocesswithtoken|impersonateloggedonuser|adjusttokenprivileges.*sedebug') {
        return @{ Rule="Escalation"; Evidence="Token manipulation (PID $Pid)"; Reasoning="Windows token API abuse for privilege escalation"; Conf=0.88; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    if ($c -match 'impersonatenamedpipeclient|createnamedpipe.*impersonate') {
        return @{ Rule="Escalation"; Evidence="Pipe impersonation (PID $Pid)"; Reasoning="Named pipe impersonation for escalation"; Conf=0.90; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    if ($c -match 'fodhelper|computerdefaults|sdclt.*\/kickoffelev|eventvwr.*mmc') {
        return @{ Rule="Escalation"; Evidence="UAC bypass (PID $Pid)"; Reasoning="Exploiting auto-elevation for UAC bypass"; Conf=0.89; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    return $null
}

# ============================================================================
# BEHAVIORAL: LATERAL MOVEMENT (structural patterns)
# ============================================================================
function Test-LateralMovement { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Remote service/WMI execution (structural: must specify remote target)
    if ($c -match '(sc|wmic|invoke-wmimethod|invoke-command).*\\\\' -or $c -match '/node:.*process.*call.*create') {
        return @{ Rule="LateralMovement"; Evidence="Remote execution pattern (PID $Pid)"; Reasoning="Executing commands on remote system"; Conf=0.85; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    # WinRM/PSRemoting
    if ($c -match 'enter-pssession|invoke-command.*-computer|new-pssession.*-computer') {
        return @{ Rule="LateralMovement"; Evidence="PSRemoting (PID $Pid)"; Reasoning="PowerShell remoting to other systems"; Conf=0.70; Tier="Tier2Indicator"; Cat="lateral" }
    }
    return $null
}

# ============================================================================
# NETWORK MONITOR + STATISTICAL BEACONING
# ============================================================================
function Get-Connections {
    $conns = @()
    try {
        foreach ($line in (netstat -ano 2>$null)) {
            if ($line -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\w*)\s*(\d+)') {
                $r = $Matches[3]
                if ($r -eq '*:*' -or $r -eq '0.0.0.0:0' -or $r -eq '[::]:0') { continue }
                $ra=""; $rp=0
                if ($r -match '^\[(.+)\]:(\d+)$') { $ra=$Matches[1]; $rp=[int]$Matches[2] }
                elseif ($r -match '^(.+):(\d+)$') { $ra=$Matches[1]; $rp=[int]$Matches[2] }
                if ($ra -and $rp -gt 0) { $conns += @{ R=$ra; P=$rp; PID=[int]$Matches[5] } }
            }
        }
    } catch {}
    return $conns
}
function Is-Private { param([string]$IP)
    $IP -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|::1|fe80|fd)'
}

function Invoke-NetworkAnalysis { param($Conns)
    $byPid = @{}
    foreach ($c in $Conns) {
        if (-not $byPid.ContainsKey($c.PID)) { $byPid[$c.PID] = @() }
        $byPid[$c.PID] += $c
    }
    foreach ($pid in $byPid.Keys) {
        if ($pid -le 4 -or $pid -eq $PID) { continue }
        $info = $Script:ProcessAncestry[$pid]
        if (-not $info) { continue }
        $path = $info.P; $name = $info.N
        # Skip installed software (Program Files)
        if ($path -and ($path -like "$env:ProgramFiles*" -or $path -like "${env:ProgramFiles(x86)}*" -or $path -like "$env:SystemRoot*")) { continue }

        $pub = @($byPid[$pid] | Where-Object { -not (Is-Private $_.R) })
        if ($pub.Count -eq 0) { continue }

        # Staged binary with public connections
        $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","Downloads","Desktop","Public")
        $fromStaging = $false
        if ($path) { foreach ($sp in $staging) { if ($path -like "*$sp*") { $fromStaging=$true; break } } }

        if ($fromStaging) {
            $dk = "NetStage|$pid"
            if (-not (Is-Dup -K $dk -TTL 300)) {
                Log-Event -Type "detection" -Rule "StagedPayloadNetwork" -Evidence "$name from staging path -> $($pub.Count) public connections" `
                    -Reasoning "Binary in temp/download location making outbound connections" -Conf 0.82 -Tier "Tier1Behavioral" -PName $name -PId $pid
                Add-Signal -Pid $pid -Cat "network" -Conf 0.82
                Write-Host "[Tier1] StagedPayload: $name (PID $pid) from $path" -ForegroundColor Yellow
            }
        }

        # Beaconing tracking
        foreach ($c in $pub) { Track-Beacon -Pid $pid -Addr $c.R -Port $c.P -Name $name }
    }
}

function Track-Beacon { param([int]$Pid,[string]$Addr,[int]$Port,[string]$Name)
    $k = "${Pid}|${Addr}|${Port}"; $now = Get-Date
    if (-not $Script:BeaconTracker.ContainsKey($k)) { $Script:BeaconTracker[$k] = @{ T=@($now); N=$Name }; return }
    $t = $Script:BeaconTracker[$k]
    $t.T += $now
    $t.T = @($t.T | Where-Object { ($now-$_).TotalMinutes -le 10 }) | Select-Object -Last 20
    $Script:BeaconTracker[$k] = $t
    if ($t.T.Count -ge 5) {
        $iv = @(); for ($i=1; $i -lt $t.T.Count; $i++) { $iv += ($t.T[$i]-$t.T[$i-1]).TotalSeconds }
        $m = ($iv | Measure-Object -Average).Average
        if ($m -gt 0 -and $m -lt 300) {
            $var = ($iv | ForEach-Object { [Math]::Pow($_-$m,2) } | Measure-Object -Average).Average
            $cv = [Math]::Sqrt($var) / $m
            if ($cv -lt 0.40) {
                $dk = "Beacon|$k"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    $conf = [Math]::Min(0.95, 0.70 + (0.40-$cv)*0.6)
                    Log-Event -Type "detection" -Rule "Beaconing" -Evidence "$Name -> ${Addr}:${Port} CV=$([Math]::Round($cv,3)) int=$([Math]::Round($m,1))s obs=$($t.T.Count)" `
                        -Reasoning "Statistical regularity in connection intervals (low CV)" -Conf $conf -Tier "Tier1Behavioral" -PName $Name -PId $Pid
                    Add-Signal -Pid $Pid -Cat "beaconing" -Conf $conf
                    Write-Host "[Tier1] Beaconing: $Name (PID $Pid) CV=$([Math]::Round($cv,3))" -ForegroundColor Yellow
                    if ($conf -ge 0.85) { Invoke-Kill -Pid $Pid -Name $Name -Rule "Beaconing" -Conf $conf }
                }
            }
        }
    }
}

# ============================================================================
# CLIPBOARD MONITOR (crypto swappers, stealers, session hijack)
# ============================================================================
function Test-ClipboardAnomaly {
    try {
        $owner = [SN]::GetClipboardOwner()
        if ($owner -ne [IntPtr]::Zero) {
            $ownerPid = [uint32]0
            [SN]::GetWindowThreadProcessId($owner, [ref]$ownerPid) | Out-Null
            if ($ownerPid -gt 0 -and $ownerPid -ne $PID) {
                $info = $Script:ProcessAncestry[[int]$ownerPid]
                if ($info) {
                    $path = $info.P
                    # Background process holding clipboard (not explorer, not browser)
                    $legitimate = @('explorer.exe','chrome.exe','msedge.exe','firefox.exe',
                                    'powershell.exe','pwsh.exe','code.exe','WindowsTerminal.exe')
                    if ($info.N -notin $legitimate) {
                        # Check if from staging path
                        $staging = @("$env:TEMP","$env:APPDATA","Downloads")
                        $fromStaging = $false
                        if ($path) { foreach ($sp in $staging) { if ($path -like "*$sp*") { $fromStaging=$true; break } } }
                        if ($fromStaging) {
                            $dk = "Clipboard|$ownerPid"
                            if (-not (Is-Dup -K $dk -TTL 120)) {
                                Log-Event -Type "detection" -Rule "ClipboardHijack" `
                                    -Evidence "$($info.N) (PID $ownerPid) owns clipboard from staging path" `
                                    -Reasoning "Background process from temp location holding clipboard ownership" `
                                    -Conf 0.78 -Tier "Tier2Indicator" -PName $info.N -PId ([int]$ownerPid)
                                Add-Signal -Pid ([int]$ownerPid) -Cat "clipboard" -Conf 0.78
                            }
                        }
                    }
                }
            }
        }
    } catch {}
}

# ============================================================================
# DLL/MODULE INTEGRITY MONITOR
# ============================================================================
function Initialize-ModuleBaseline {
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            try {
                $mods = @($_.Modules | ForEach-Object { $_.FileName.ToLower() })
                $Script:ModuleBaseline[$_.Id] = $mods
            } catch {}
        }
    } catch {}
}

function Test-ModuleInjection {
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            $pid = $_.Id; $name = $_.ProcessName
            try {
                $currentMods = @($_.Modules | ForEach-Object { $_.FileName.ToLower() })
                if ($Script:ModuleBaseline.ContainsKey($pid)) {
                    $baseline = $Script:ModuleBaseline[$pid]
                    $newMods = @($currentMods | Where-Object { $_ -notin $baseline })
                    foreach ($mod in $newMods) {
                        # Phantom module: DLL loaded but file deleted from disk
                        if (-not (Test-Path $mod -ErrorAction SilentlyContinue)) {
                            $dk = "Phantom|$pid|$mod"
                            if (-not (Is-Dup -K $dk -TTL 300)) {
                                Log-Event -Type "detection" -Rule "PhantomModule" `
                                    -Evidence "$name (PID $pid) has loaded DLL with deleted backing file: $mod" `
                                    -Reasoning "Loaded module file deleted from disk - dropper pattern" `
                                    -Conf 0.82 -Tier "Tier2Indicator" -PName $name -PId $pid
                                Add-Signal -Pid $pid -Cat "dll_injection" -Conf 0.82
                            }
                        }
                        # DLL from staging/temp path loaded into established process
                        $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","downloads")
                        foreach ($sp in $staging) {
                            if ($mod -like "*$($sp.ToLower())*") {
                                $dk = "TempDLL|$pid|$mod"
                                if (-not (Is-Dup -K $dk -TTL 300)) {
                                    Log-Event -Type "detection" -Rule "StagedDllInjection" `
                                        -Evidence "$name (PID $pid) loaded DLL from staging: $mod" `
                                        -Reasoning "New DLL from temp/staging path injected into running process" `
                                        -Conf 0.80 -Tier "Tier2Indicator" -PName $name -PId $pid
                                    Add-Signal -Pid $pid -Cat "dll_injection" -Conf 0.80
                                }
                                break
                            }
                        }
                    }
                }
                # Update baseline
                $Script:ModuleBaseline[$pid] = $currentMods
            } catch {}
        }
    } catch {}
}

# ============================================================================
# SCREEN CAPTURE / WEBCAM DETECTION (DLL-based, behavioral)
# ============================================================================
function Test-SurveillanceAccess {
    $captureDlls = @('d3d11.dll','dxgi.dll','d3d9.dll')  # Screen capture
    $cameraDlls = @('mfplat.dll','mf.dll','mfreadwrite.dll','ksuser.dll')
    $micDlls = @('audioses.dll','mmdevapi.dll')
    $allowed = @('chrome','msedge','firefox','brave','Teams','Zoom','Discord',
                 'Skype','obs64','obs32','slack','WindowsCamera','dwm',
                 'explorer','SearchHost','ShellExperienceHost','Spotify')
    $results = @()
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -notin $allowed -and $_.Id -gt 4 -and $_.Id -ne $PID
        } | ForEach-Object {
            try {
                $mods = @($_.Modules | ForEach-Object { $_.ModuleName.ToLower() })
                $hasCapture = @($captureDlls | Where-Object { $mods -contains $_ }).Count -gt 0
                $hasCamera = @($cameraDlls | Where-Object { $mods -contains $_ }).Count -gt 0
                $hasMic = @($micDlls | Where-Object { $mods -contains $_ }).Count -gt 0

                # Only flag if process has NO visible window (background surveillance)
                $hasWindow = $_.MainWindowHandle -ne [IntPtr]::Zero

                if (($hasCapture -or $hasCamera -or $hasMic) -and -not $hasWindow) {
                    $device = if ($hasCapture) {"screen"} elseif ($hasCamera) {"camera"} else {"microphone"}
                    $dk = "Surveil|$($_.Id)|$device"
                    if (-not (Is-Dup -K $dk -TTL 120)) {
                        $results += @{
                            Rule = "BackgroundSurveillance"
                            Evidence = "$($_.ProcessName) (PID $($_.Id)) background $device access"
                            Reasoning = "Background process with no visible window accessing $device hardware"
                            Conf = 0.78; Tier = "Tier2Indicator"; Cat = "surveillance"
                            PName = $_.ProcessName; PId = $_.Id
                        }
                    }
                }
            } catch {}
        }
    } catch {}
    return $results
}

# ============================================================================
# DNS ENTROPY (DGA Detection) - via process command lines with DNS patterns
# ============================================================================
function Test-DnsAnomaly {
    # Check for high-entropy domain access in command lines
    foreach ($pid in $Script:ProcessAncestry.Keys) {
        $info = $Script:ProcessAncestry[$pid]
        if (-not $info -or [string]::IsNullOrEmpty($info.CL)) { continue }
        $cl = $info.CL

        # Extract potential domains from command lines (http/https URLs, nslookup, etc)
        $domains = @()
        if ($cl -match 'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)') {
            $domains += $Matches[1]
        }
        if ($cl -match '(nslookup|resolve-dnsname|dig)\s+(\S+)') {
            $domains += $Matches[2]
        }

        foreach ($domain in $domains) {
            # Split into labels, check entropy of longest non-TLD label
            $labels = $domain.Split('.')
            if ($labels.Count -lt 2) { continue }
            $mainLabel = ($labels[0..($labels.Count-2)] | Sort-Object { $_.Length } -Descending | Select-Object -First 1)
            if ($mainLabel.Length -lt 8) { continue }

            $entropy = Get-Entropy -S $mainLabel
            if ($entropy -gt 3.8) {
                $dk = "DGA|$pid|$domain"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    Log-Event -Type "detection" -Rule "DgaDomain" `
                        -Evidence "$($info.N) (PID $pid) accessing high-entropy domain: $domain (entropy=$([Math]::Round($entropy,2)))" `
                        -Reasoning "Domain label has high Shannon entropy suggesting DGA-generated name" `
                        -Conf 0.72 -Tier "Tier2Indicator" -PName $info.N -PId $pid
                    Add-Signal -Pid $pid -Cat "dga" -Conf 0.72
                }
            }
        }
    }
}

# ============================================================================
# UNSIGNED FROM STAGING (structural fact about the binary)
# ============================================================================
function Test-UnsignedStaged { param([int]$Pid,[string]$Name,[string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $null }
    # Skip trusted locations
    if ($Path -like "$env:SystemRoot*" -or $Path -like "$env:ProgramFiles*" -or $Path -like "${env:ProgramFiles(x86)}*") { return $null }
    # Must be in staging path
    $staging = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp","Downloads","Desktop","Public")
    $inStaging = $false
    foreach ($sp in $staging) { if ($Path -like "*$sp*") { $inStaging=$true; break } }
    if (-not $inStaging) { return $null }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            $conf = 0.68
            # Hash reputation boost
            try {
                $hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
                $rep = Test-HashReputation -Hash $hash
                if ($rep -and $rep.Bad) { $conf = 0.92 }
            } catch {}
            return @{ Rule="UnsignedStaged"; Evidence="$Name (PID $Pid) unsigned from $Path"; Reasoning="Unsigned binary executing from staging location"; Conf=$conf; Tier="Tier2Indicator"; Cat="unsigned" }
        }
    } catch {}
    return $null
}

# ============================================================================
# PROCESS GENEALOGY (structural parent-child anomalies)
# ============================================================================
function Test-Genealogy { param([int]$Pid,[string]$Name,[int]$PPid)
    if ($Pid -le 4) { return $null }
    $parent = $Script:ProcessAncestry[$PPid]
    $pName = if ($parent) { $parent.N } else { "DEAD" }
    $info = $Script:ProcessAncestry[$Pid]

    # Shell spawned by unusual parent
    $shells = @('cmd.exe','powershell.exe','pwsh.exe')
    $normalParents = @('explorer.exe','cmd.exe','powershell.exe','pwsh.exe','svchost.exe',
                       'services.exe','code.exe','WindowsTerminal.exe','wt.exe','conhost.exe')
    if ($Name -in $shells -and $pName -notin $normalParents -and $pName -ne "DEAD") {
        return @{ Rule="UnusualShellParent"; Evidence="$Name spawned by $pName (PID $PPid)"; Reasoning="Shell from unexpected parent - possible exploitation"; Conf=0.72; Tier="Tier2Indicator"; Cat="genealogy" }
    }

    # Office/browser spawning shell (classic macro/exploit delivery)
    $officeApps = @('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE','MSACCESS.EXE')
    if ($Name -in $shells -and $pName -in $officeApps) {
        return @{ Rule="OfficeShellSpawn"; Evidence="$pName spawned $Name (PID $Pid)"; Reasoning="Office application spawning command shell - macro/exploit execution"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }

    # Orphan from staging (parent dead, running from temp)
    if ($pName -eq "DEAD" -and $info -and $info.P) {
        $staging = @("$env:TEMP","$env:APPDATA","Downloads")
        foreach ($sp in $staging) {
            if ($info.P -like "*$sp*") {
                return @{ Rule="OrphanStaged"; Evidence="$Name (PID $Pid) orphaned from $($info.P)"; Reasoning="Orphan process from staging path - dropped payload"; Conf=0.70; Tier="Tier2Indicator"; Cat="genealogy" }
            }
        }
    }
    return $null
}

# ============================================================================
# WMI PERSISTENCE SCAN
# ============================================================================
function Test-WmiPersistence {
    try {
        Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -ErrorAction Stop | ForEach-Object {
            $dk = "WMI|$($_.Name)"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "WmiPersistence" -Evidence "WMI consumer: $($_.Name) -> $($_.CommandLineTemplate)" `
                    -Reasoning "WMI event subscription for fileless persistence" -Conf 0.88 -Tier "Tier1Behavioral" -PName "WMI" -PId 0
                Write-Host "[Tier1] WMI Persistence: $($_.Name)" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# ============================================================================
# FILE ACTIVITY (ransomware rate detection)
# ============================================================================
$Script:RansomExts = @('.encrypted','.enc','.locked','.crypto','.crypt','.locky',
    '.wncry','.ryuk','.lockbit','.conti','.hive','.blackcat','.play','.royal',
    '.clop','.akira','.blackbasta','.rhysida','.medusa','.trigona')

function Initialize-FileMonitor {
    try {
        if (-not (Test-Path $Script:MonitorPath)) { return $false }
        $Script:FileWatcher = New-Object System.IO.FileSystemWatcher
        $Script:FileWatcher.Path = $Script:MonitorPath
        $Script:FileWatcher.IncludeSubdirectories = $true
        $Script:FileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
        $Script:FileWatcher.Filter = "*.*"
        Register-ObjectEvent -InputObject $Script:FileWatcher -EventName Renamed -Action {
            $Script:FileEvents.Add(@{ P=$Event.SourceEventArgs.FullPath; T=Get-Date }) | Out-Null
        } | Out-Null
        Register-ObjectEvent -InputObject $Script:FileWatcher -EventName Created -Action {
            $Script:FileEvents.Add(@{ P=$Event.SourceEventArgs.FullPath; T=Get-Date }) | Out-Null
        } | Out-Null
        $Script:FileWatcher.EnableRaisingEvents = $true
        return $true
    } catch { return $false }
}

function Invoke-FileAnalysis {
    if ($Script:FileEvents.Count -eq 0) { return }
    $evts = @($Script:FileEvents.ToArray()); $Script:FileEvents.Clear()
    $now = Get-Date; $ransomHits = 0

    foreach ($e in $evts) {
        $ext = [System.IO.Path]::GetExtension($e.P)
        if ($ext -in $Script:RansomExts) { $ransomHits++ }
    }

    $Script:FileRateTracker.Count += $evts.Count
    $elapsed = ($now - $Script:FileRateTracker.Start).TotalSeconds

    # Reset window every 30s
    if ($elapsed -gt 30) { $Script:FileRateTracker = @{ Count=0; Start=$now }; return }

    # Bulk file ops (rate-based, extension-agnostic)
    if ($Script:FileRateTracker.Count -ge 50 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "BulkFile" -TTL 60)) {
            $conf = [Math]::Min(0.95, 0.75 + $Script:FileRateTracker.Count * 0.002)
            Log-Event -Type "detection" -Rule "BulkFileOps" -Evidence "$($Script:FileRateTracker.Count) file ops in $([Math]::Round($elapsed))s" `
                -Reasoning "Extremely high file modification rate indicates bulk encryption" -Conf $conf -Tier "Tier1Behavioral" -PName "FileSystem" -PId 0
            Add-Signal -Pid 0 -Cat "ransomware_rate" -Conf $conf
            Write-Host "[RANSOMWARE] Bulk: $($Script:FileRateTracker.Count) ops in ${elapsed}s" -ForegroundColor Red
        }
    }
    # Ransomware extensions
    if ($ransomHits -ge 5 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "RansomExt" -TTL 60)) {
            Log-Event -Type "detection" -Rule "RansomwareExtensions" -Evidence "$ransomHits files with ransomware extensions in $([Math]::Round($elapsed))s" `
                -Reasoning "Mass rename to known encryption extensions" -Conf 0.92 -Tier "Tier1Behavioral" -PName "FileSystem" -PId 0
            Add-Signal -Pid 0 -Cat "ransomware_ext" -Conf 0.92
            Write-Host "[RANSOMWARE] Extensions: $ransomHits files" -ForegroundColor Red
        }
    }
}

# ============================================================================
# COMPOSITE CORRELATION ENGINE (multi-signal kills)
# ============================================================================
function Invoke-Composite { param([int]$Pid,[string]$Name)
    $cats = Get-Categories -Pid $Pid
    $cnt = Get-SignalCount -Pid $Pid
    if ($cnt -lt 2) { return }

    $composites = @()
    # Memory + Network = Injected C2 Beacon (0.96)
    if ($cats -contains "memory" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedC2Beacon"; Conf=0.96 }
    }
    # Credential + Network = Exfiltration (0.95)
    if ($cats -contains "credential" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CredentialExfiltration"; Conf=0.95 }
    }
    # Evasion + Execution = Fileless (0.93)
    if ($cats -contains "evasion" -and ($cats -contains "execution" -or $cats -contains "c2")) {
        $composites += @{ N="FilelessAttack"; Conf=0.93 }
    }
    # Unsigned + Network/Beaconing = Covert RAT (0.90)
    if ($cats -contains "unsigned" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CovertRAT"; Conf=0.90 }
    }
    # Ransomware multi-signal (0.98)
    $rCats = @($cats | Where-Object { $_ -match "ransomware" })
    if ($rCats.Count -ge 2) { $composites += @{ N="ActiveRansomware"; Conf=0.98 } }
    # Escalation + Persistence (0.91)
    if ($cats -contains "escalation" -and $cats -contains "persistence") {
        $composites += @{ N="PostExploitation"; Conf=0.91 }
    }
    # DLL injection + Network (0.95)
    if ($cats -contains "dll_injection" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedImplantC2"; Conf=0.95 }
    }
    # Clipboard + Network (0.93)
    if ($cats -contains "clipboard" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="ClipboardExfil"; Conf=0.93 }
    }
    # Surveillance + Network (0.94)
    if ($cats -contains "surveillance" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="SurveillanceExfil"; Conf=0.94 }
    }
    # DGA + Beaconing (0.94)
    if ($cats -contains "dga" -and $cats -contains "beaconing") {
        $composites += @{ N="DgaC2Beacon"; Conf=0.94 }
    }
    # Lateral + Credential (0.95)
    if ($cats -contains "lateral" -and $cats -contains "credential") {
        $composites += @{ N="LateralCredTheft"; Conf=0.95 }
    }
    # Genealogy + Network (orphan phoning home) (0.88)
    if ($cats -contains "genealogy" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="OrphanPhoneHome"; Conf=0.88 }
    }
    # 3+ distinct categories = Advanced Attack Chain (0.96)
    if ($cats.Count -ge 3) {
        $composites += @{ N="AdvancedAttackChain"; Conf=0.96 }
    }

    foreach ($comp in $composites) {
        $dk = "Comp|$($comp.N)|$Pid"
        if (Is-Dup -K $dk -TTL 120) { continue }
        Log-Event -Type "detection" -Rule "Composite:$($comp.N)" `
            -Evidence "$Name (PID $Pid): $($cats -join '+') [$cnt signals in 120s]" `
            -Reasoning "Multiple behavioral signals correlated on same process" `
            -Conf $comp.Conf -Tier "Tier1Behavioral" -PName $Name -PId $Pid
        Write-Host "[COMPOSITE] $($comp.N): $Name (PID $Pid) conf=$($comp.Conf)" -ForegroundColor Magenta
        if ($comp.Conf -ge 0.85) {
            Invoke-Kill -Pid $Pid -Name $Name -Rule "Composite:$($comp.N)" -Conf $comp.Conf
        }
    }
}

# ============================================================================
# RESPONSE ENGINE (kill gate)
# ============================================================================
function Invoke-Kill { param([int]$Pid,[string]$Name,[string]$Rule,[double]$Conf)
    if ($Pid -le 4 -or $Pid -eq $PID) { return }
    if ($Conf -lt 0.85) { return }
    Log-Event -Type "response" -Rule $Rule -Evidence "KILL: $Name (PID $Pid)" -Reasoning "Kill authorized at conf $Conf" -Conf $Conf -Tier "Response" -PName $Name -PId $Pid
    try {
        (Get-Process -Id $Pid -ErrorAction Stop).Kill()
        Write-Host "[KILL] $Name (PID $Pid) - $Rule (conf=$Conf)" -ForegroundColor Red
    } catch {
        Write-Host "[KILL FAILED] $Name (PID $Pid) - $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

# ============================================================================
# MAIN SCAN ENGINES
# ============================================================================
function Invoke-ProcessScan {
    foreach ($pid in $Script:ProcessAncestry.Keys) {
        $i = $Script:ProcessAncestry[$pid]
        if (-not $i -or $pid -le 4 -or $pid -eq $PID) { continue }
        $n=$i.N; $cl=$i.CL; $p=$i.P; $pp=$i.PP

        $dets = @(
            (Test-Destructive -CL $cl -Pid $pid -N $n),
            (Test-CredentialAccess -CL $cl -Pid $pid -N $n -Path $p),
            (Test-Evasion -CL $cl -Pid $pid -N $n),
            (Test-Persistence -CL $cl -Pid $pid -N $n),
            (Test-Execution -CL $cl -Pid $pid -N $n),
            (Test-Escalation -CL $cl -Pid $pid -N $n),
            (Test-LateralMovement -CL $cl -Pid $pid -N $n),
            (Test-Genealogy -Pid $pid -Name $n -PPid $pp),
            (Test-UnsignedStaged -Pid $pid -Name $n -Path $p)
        )

        foreach ($d in $dets) {
            if (-not $d) { continue }
            $dk = "$($d.Rule)|$pid"
            if (Is-Dup -K $dk) { continue }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning -Conf $d.Conf -Tier $d.Tier -PName $n -PId $pid
            Add-Signal -Pid $pid -Cat $d.Cat -Conf $d.Conf
            $color = if ($d.Tier -eq "Tier1Behavioral") {"Yellow"} else {"Cyan"}
            Write-Host "[$($d.Tier)] $($d.Rule): $n (PID $pid)" -ForegroundColor $color
            if ($d.Tier -eq "Tier1Behavioral" -and $d.Conf -ge 0.85) {
                Invoke-Kill -Pid $pid -Name $n -Rule $d.Rule -Conf $d.Conf
            }
        }
        Invoke-Composite -Pid $pid -Name $n
    }
}

function Invoke-MemoryScan {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Id -gt 4 -and $_.Id -ne $PID -and -not ($Script:JitPaths | Where-Object { $_.Path -like $_ })
    })
    # Filter JIT processes by path
    $filtered = @()
    foreach ($p in $procs) {
        $isJit = $false
        foreach ($jp in $Script:JitPaths) { if ($p.Path -like $jp) { $isJit=$true; break } }
        if (-not $isJit) { $filtered += $p }
    }
    $sample = $filtered | Get-Random -Count ([Math]::Min(25, $filtered.Count)) -ErrorAction SilentlyContinue
    foreach ($p in $sample) {
        $d = Invoke-MemoryAnalysis -Pid $p.Id -Name $p.ProcessName -Path $p.Path
        if ($d) {
            $dk = "Mem|$($p.Id)"
            if (Is-Dup -K $dk -TTL 120) { continue }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning -Conf $d.Conf -Tier $d.Tier -PName $p.ProcessName -PId $p.Id
            Add-Signal -Pid $p.Id -Cat $d.Cat -Conf $d.Conf
            Write-Host "[Tier1] $($d.Rule): $($d.Evidence)" -ForegroundColor Yellow
            if ($d.Conf -ge 0.85) { Invoke-Kill -Pid $p.Id -Name $p.ProcessName -Rule $d.Rule -Conf $d.Conf }
            Invoke-Composite -Pid $p.Id -Name $p.ProcessName
        }
    }
}

# ============================================================================
# STARTUP & MAIN LOOP
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host " ================================================" -ForegroundColor Green
    Write-Host "  Windows Sentinel v$Script:Version" -ForegroundColor Green
    Write-Host "  Behavioral EDR - assumes attacker reads source" -ForegroundColor Green
    Write-Host " ================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Detection: Memory | Behavior | Network | Beaconing | Files" -ForegroundColor Gray
    Write-Host "             Clipboard | DLL | Screen/Cam | DNS | Genealogy" -ForegroundColor Gray
    Write-Host "             Self-Protection | Lateral | Hash Reputation" -ForegroundColor Gray
    Write-Host "  Correlation: 120s window, 13 composite rules" -ForegroundColor Gray
    Write-Host ""

    $checks = @()
    if ($Script:IsElevated) { $checks += @{S="[OK] Elevated"; C="Green"} }
    else { $checks += @{S="[DEGRADED] Standard user"; C="Yellow"} }
    try { Initialize-Log; $checks += @{S="[OK] Log: $($Script:LogPath)"; C="Green"} } catch { $checks += @{S="[FAIL] Log"; C="Red"} }
    try { $null = Get-CimInstance Win32_Process -Property ProcessId -ErrorAction Stop | Select-Object -First 1; $checks += @{S="[OK] Process (WMI)"; C="Green"} } catch { $checks += @{S="[FAIL] Process"; C="Red"} }
    $fw = Initialize-FileMonitor
    if ($fw) { $checks += @{S="[OK] FileWatcher: $Script:MonitorPath"; C="Green"} } else { $checks += @{S="[DEGRADED] FileWatcher"; C="Yellow"} }
    $checks += @{S="[OK] Hash Reputation (CIRCL + MalwareBazaar)"; C="Green"}
    $checks += @{S="[ARMED] Active Response ENABLED"; C="Red"}

    foreach ($c in $checks) { Write-Host "  $($c.S)" -ForegroundColor $c.C }
    Write-Host ""
    Write-Host "  Processes will be KILLED on high-confidence behavioral match." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Ctrl+C to stop." -ForegroundColor Gray
    Write-Host ""

    Initialize-SelfProtection
    Initialize-ModuleBaseline
    Log-Event -Type "system" -Rule "Startup" -Evidence "Sentinel v$Script:Version Elevated=$Script:IsElevated" `
        -Reasoning "Initialization complete" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID
}

function Start-Sentinel {
    Show-Banner
    $cycle = 0
    try {
        while ($true) {
            $t0 = Get-Date; $cycle++
            try {
                Update-Ancestry
                Invoke-ProcessScan
                Invoke-NetworkAnalysis -Conns (Get-Connections)
                Invoke-FileAnalysis

                if ($cycle % 9 -eq 0) { Invoke-MemoryScan }           # ~45s
                if ($cycle % 4 -eq 0) { Test-ClipboardAnomaly }       # ~20s
                if ($cycle % 6 -eq 0) { Test-DnsAnomaly }             # ~30s
                if ($cycle % 12 -eq 0) { Test-ModuleInjection }       # ~60s
                if ($cycle % 60 -eq 0) { Test-WmiPersistence }        # ~5min
                if ($cycle % 6 -eq 0) { Test-SelfIntegrity }          # ~30s
                if ($cycle % 4 -eq 0) {                               # ~20s
                    $surveil = Test-SurveillanceAccess
                    foreach ($s in $surveil) {
                        Log-Event -Type "detection" -Rule $s.Rule -Evidence $s.Evidence -Reasoning $s.Reasoning -Conf $s.Conf -Tier $s.Tier -PName $s.PName -PId $s.PId
                        Add-Signal -Pid $s.PId -Cat $s.Cat -Conf $s.Conf
                        Write-Host "[$($s.Tier)] $($s.Rule): $($s.Evidence)" -ForegroundColor Cyan
                    }
                }
            } catch { Write-Verbose "Cycle $cycle error: $_" }

            # Prune stale beacon data
            if ($cycle % 20 -eq 0) {
                $now = Get-Date
                $stale = @($Script:BeaconTracker.Keys | Where-Object { $Script:BeaconTracker[$_].T.Count -eq 0 -or ($now - $Script:BeaconTracker[$_].T[-1]).TotalMinutes -gt 15 })
                foreach ($k in $stale) { $Script:BeaconTracker.Remove($k) }
                # Prune dead PIDs from correlation
                $deadPids = @($Script:Correlation.Keys | Where-Object { -not $Script:ProcessAncestry.ContainsKey($_) })
                foreach ($k in $deadPids) { $Script:Correlation.Remove($k) }
            }

            $ms = [Math]::Max(100, ($Script:ScanIntervalSeconds*1000) - ((Get-Date)-$t0).TotalMilliseconds)
            Start-Sleep -Milliseconds $ms
        }
    } finally {
        Write-Host "`nSentinel shutting down..." -ForegroundColor Yellow
        if ($Script:FileWatcher) { $Script:FileWatcher.EnableRaisingEvents=$false; $Script:FileWatcher.Dispose() }
        Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue
        Log-Event -Type "system" -Rule "Shutdown" -Evidence "Stopped after $cycle cycles" -Reasoning "Clean shutdown" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID
        Write-Host "Sentinel stopped. $cycle cycles." -ForegroundColor Green
    }
}

# ============================================================================
# PERSISTENCE (scheduled task, same as AV.ps1)
# ============================================================================
function Install-Startup {
    $scriptPath = $PSCommandPath
    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Log-Event -Type "system" -Rule "Persistence" -Evidence "Already installed as scheduled task" -Reasoning "Skipping" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID
        return
    }

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description "Windows Sentinel EDR" -Force -ErrorAction Stop | Out-Null
        Write-Host "  [OK] Installed startup task (PowerShell)" -ForegroundColor Green
        return
    } catch {
        Write-Host "  [WARN] PS task registration failed, trying schtasks..." -ForegroundColor Yellow
    }

    # Method 2: schtasks fallback
    try {
        $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$scriptPath\`"`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
        $null = cmd /c $cmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Installed startup task (schtasks)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] All persistence methods failed" -ForegroundColor Yellow
        }
    } catch {}
}

function Uninstall-Sentinel {
    Write-Host "Uninstalling Windows Sentinel..." -ForegroundColor Yellow

    # Remove scheduled task
    try { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { schtasks /Delete /TN $Script:TaskName /F 2>&1 | Out-Null } catch {}
    Write-Host "  [OK] Removed scheduled task" -ForegroundColor Green

    # Kill other running instances
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like "*Sentinel*" } |
            ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "  [OK] Stopped instance PID:$($_.ProcessId)" -ForegroundColor Green
            }
    } catch {}

    Write-Host "  Data at $env:ProgramData\WindowsSentinel can be deleted manually." -ForegroundColor Gray
    Write-Host "Uninstall complete." -ForegroundColor Green
    exit 0
}

# ============================================================================
# ENTRY POINT
# ============================================================================
if ($Uninstall) { Uninstall-Sentinel }
Install-Startup
Start-Sentinel
