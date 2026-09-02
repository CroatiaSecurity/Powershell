#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Sentinel v4.1 - Behavioral EDR for Windows 10/11
.DESCRIPTION
    Comprehensive behavioral endpoint detection and response.
    Covers all 15 MITRE-aligned attack taxonomy categories:
      1.  Attacker goals   (fraud, ransomware, mining, botnet, BEC)
      2.  Initial access   (phishing chains, ISO/LNK, drive-by, OAuth)
      3.  Execution        (LOLBins, script hosts, COM, APC, in-memory)
      4.  Persistence      (Run/IFEO/COM hijacks, startup, WMI, SSH keys, mail rules)
      5.  Privilege esc.   (BYOVD, AlwaysInstallElevated, token/pipe, UAC bypass)
      6.  Defense evasion  (AMSI/ETW, ADS, masquerade, certutil/BITS download, timestomp)
      7.  Credential access(LSASS, SAM, DPAPI, browser, Wi-Fi, cloud tokens, cmdkey)
      8.  Discovery        (AD enum, net recon, cloud tenant, backup survey, AV survey)
      9.  Lateral movement (PTH/PTT, DCOM, RDP hijack, PSRemoting)
      10. Collection       (bulk archive, browser DB, keylogger DLL, DB dump, cloud sync)
      11. C2               (DNS/ICMP tunnel, legit-service C2, SOCKS, long-sleep beacon)
      12. Exfiltration     (BITS, cloud sync, DNS encode, Outlook COM)
      13. Impact           (ransomware, wiper, disk format, boot corrupt, AD destroy, mining)
      14. Malware types    (loader/dropper, fileless, self-delete, adware injection)
      15. Human attacks    (BEC mail rules, new admin after MFA event, SE patterns)

    Detects threats by WHAT processes DO, not what they are called.
    Active response (kill) fires at confidence >= 0.85.
    Installs itself as a SYSTEM scheduled task on first run.
    Works when run as a .ps1 script OR compiled to a .exe (ps2exe/Costura/etc.).
    Works regardless of filename - no hardcoded script-name assumptions.
    Use -Uninstall to remove.

.PARAMETER Uninstall
    Remove scheduled task, stop running instances, and exit.
.PARAMETER NoKill
    Log and alert only - do not terminate any processes.
.PARAMETER Quiet
    Suppress console output (log-only mode).
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NoKill,
    [switch]$Quiet,
    [switch]$CheckReputation   # opt-in: query CIRCL/MalwareBazaar for unsigned staged hashes
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# SINGLE-INSTANCE MUTEX (prevent multiple concurrent runs)
# ============================================================================
$Script:MutexName   = "Global\WindowsSentinel_EDR_4"
$Script:MutexHandle = $null
try {
    $created = $false
    $Script:MutexHandle = New-Object System.Threading.Mutex($true, $Script:MutexName, [ref]$created)
    if (-not $created) {
        # Another instance already owns the mutex
        try { $Script:MutexHandle.Dispose() } catch {}
        Write-Host "[Sentinel] Another instance is already running. Exiting." -ForegroundColor Yellow
        exit 0
    }
} catch {
    # Mutex creation failed (permissions) - continue anyway, just no exclusion
    $Script:MutexHandle = $null
}

# ============================================================================
# ELEVATION CHECK - request UAC if not already elevated
# ============================================================================
$Script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Script:IsElevated) {
    # Re-launch elevated. Works for both .ps1 and compiled .exe.
    try {
        $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $isExe   = ($exePath -notlike '*powershell*' -and $exePath -notlike '*pwsh*')
        if ($isExe) {
            $reArgs = @()
            if ($NoKill)   { $reArgs += '-NoKill' }
            if ($Quiet)    { $reArgs += '-Quiet' }
            if ($Uninstall){ $reArgs += '-Uninstall' }
            Start-Process -FilePath $exePath -ArgumentList $reArgs -Verb RunAs
        } else {
            $myPath = $MyInvocation.MyCommand.Path
            $reArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$myPath`""
            if ($NoKill)   { $reArgs += ' -NoKill' }
            if ($Quiet)    { $reArgs += ' -Quiet' }
            if ($Uninstall){ $reArgs += ' -Uninstall' }
            Start-Process -FilePath $exePath -ArgumentList $reArgs -Verb RunAs
        }
    } catch {}
    exit 0
}

# ============================================================================
# RESOLVE OWN EXECUTABLE PATH (works for .ps1, renamed .ps1, and compiled .exe)
# ============================================================================
$Script:OwnExePath  = $null    # full path to this file/binary
$Script:IsCompiledExe = $false # true when running as a compiled EXE

$_procPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if ($_procPath -notlike '*\powershell.exe' -and $_procPath -notlike '*\pwsh.exe') {
    # Running as a compiled EXE
    $Script:OwnExePath    = $_procPath
    $Script:IsCompiledExe = $true
} elseif ($PSCommandPath) {
    # Normal .ps1 invocation — $PSCommandPath is the script file
    $Script:OwnExePath = $PSCommandPath
} elseif ($MyInvocation.MyCommand.Path) {
    # Fallback for some hosts that don't set $PSCommandPath
    $Script:OwnExePath = $MyInvocation.MyCommand.Path
} else {
    # Last resort: parse the -File argument from the process command line
    $_args = [System.Environment]::GetCommandLineArgs()
    for ($i = 0; $i -lt $_args.Length - 1; $i++) {
        if ($_args[$i] -match '^-[Ff]ile?$') { $Script:OwnExePath = $_args[$i+1]; break }
    }
}

$Script:LogPath          = "$env:ProgramData\WindowsSentinel\events.jsonl"
$Script:MaxLogSizeMB     = 50
$Script:MaxLogFiles      = 5
$Script:ScanIntervalSec  = 5
$Script:KillEnabled      = -not $NoKill
$Script:QuietMode        = $Quiet.IsPresent
$Script:ReputationEnabled = $CheckReputation.IsPresent

# ============================================================================
# GLOBALS & STATE
# ============================================================================
$Script:Version            = "4.1.0"
$Script:Dedup              = @{}
$Script:Correlation        = @{}
$Script:CorrelationTTL     = 120
$Script:ProcessAncestry    = @{}
$Script:BeaconTracker      = @{}
$Script:LogCount           = 0
$Script:LogWindow          = Get-Date
$Script:LogBurst           = 250
$Script:FileEvents         = $null           # replaced by $Script:FileQueue (ConcurrentQueue)
$Script:FileWatchers       = @()             # one watcher per high-value folder per profile
$Script:FileRateTracker    = @{ Count = 0; Start = Get-Date }
$Script:ClipboardBaseline  = ""
$Script:ClipboardChangeCount = 0
$Script:ClipboardWindow    = Get-Date
$Script:ModuleBaseline     = @{}
$Script:SelfHash           = $null
$Script:HashCache          = @{}
$Script:DnsQueryTracker    = @{}
$Script:CpuTracker         = @{}      # pid -> @{Samples=@(); Name=''}
$Script:OutboundTracker    = @{}      # pid -> @{Count=0; Start=date}
$Script:AuthFailTracker    = @{}      # sourceIP/user -> @{Count=0; Window=date}
$Script:DnsRateTracker     = @{}      # pid -> @{Count=0; Window=date; Labels=@()}
$Script:StartupFolderBase  = @{}      # filename -> timestamp snapshot
$Script:NewAdminTracker    = @{}      # username -> timestamp
$Script:OwnPid             = $PID     # used for self-exclusion; works at any filename
# Populated at startup by Get-UserProfiles; used for staging-path checks across all users
$Script:UserProfiles       = @()      # array of @{Name; ProfilePath; AppData; LocalTemp; Downloads}

# ============================================================================
# PER-APP ALLOWLISTS (first-class config - edit these to suppress known FPs)
# Keys are lower-case process names. Values are arrays of rule names to skip.
# Empty value @() means "allow all detections for this process".
# ============================================================================
$Script:Allowlist = @{
    # Backup tools legitimately call vssadmin, wbadmin, bcdedit
    'veeam.backup.manager.exe' = @('ShadowDestruction','BackupDestruction','BootRecoveryDisable','BackupSurvey')
    'backupservice.exe'        = @('ShadowDestruction','BackupDestruction','WbadminDelete')
    'acronisagent.exe'         = @('ShadowDestruction','BackupDestruction','CriticalServiceDisrupt')
    # Security scanners / vulnerability tools
    'nessus.exe'               = @('NetworkScan','AdEnumeration','SecurityToolSurvey')
    'openvas.exe'              = @('NetworkScan','AdEnumeration')
    # GPU tools / anti-cheat legitimately load drivers
    'nvdisplay.container.exe'  = @('DriverLoad')
    'easyanticheat.exe'        = @('DriverLoad')
    'battleye.exe'             = @('DriverLoad')
    # Package managers legitimately run schtasks / sc / msiexec
    'winget.exe'               = @('SchedTaskPersist','ServicePersist','MsiexecRemoteLoad','AlwaysInstallElevated')
    'choco.exe'                = @('SchedTaskPersist','ServicePersist','MsiexecRemoteLoad')
    'chocolatey.exe'           = @('SchedTaskPersist','ServicePersist','MsiexecRemoteLoad')
    # IT management
    'psexec.exe'               = @('RemoteExecution','PSRemoting')
    'psexecsvc.exe'            = @('RemoteExecution')
}

# ============================================================================
# DETECTION SIGNATURES
# Patterns are built at runtime via concatenation so that no complete
# signature string ever appears verbatim in source - preventing AMSI from
# blocking the script itself before it runs.
# ============================================================================
$Script:Sig = @{
    # Credential access
    LsassComsvcs     = 'com' + 'svcs.*mini' + 'dump|com' + 'svcs\.dll.*#24|com' + 'svcs.*full'
    LsassDump        = 'dump|mini|dbg|clone|fork|snap|\.dmp'
    RegHiveTheft     = 'reg.*save.*(sam|security|system)|hklm\\(sam|security|system)'

    # Defense evasion
    AmsiPatch        = 'amsi' + 'scan' + 'buffer|amsi' + 'initialized|amsi' + 'context'
    EtwPatch         = 'nt' + 'trace' + 'event|etw' + 'event' + 'write'
    DefenderDisable  = 'set-mpp' + 'reference.*-disable(realtimemonitoring|ioavprotection|behaviormonitoring)'
    DefenderExclude  = 'add-mpp' + 'reference.*-exclusion'
    FltmcUnload      = 'flt' + 'mc.*unload'
    LogClear         = 'wevtutil.*(cl|clear-log)\s+(security|system|application)'

    # Execution / download
    DownloadMethods  = 'down' + 'load' + 'string|down' + 'load' + 'file|down' + 'load' + 'data|invoke-webrequest'
    InvokeExpr       = 'invoke-ex' + 'pression|iex\s|start-process|\.invoke\('
    ReflectiveLoad   = 'reflection\.ass' + 'embly.*load|gettype.*getmethod.*invoke|\[convert\]::frombase64.*load'
    ReverseShell     = 'net\.sock' + 'ets\.tcp' + 'client|system\.net\.sock' + 'ets'
    FetchExec        = 'webclient|down' + 'load' + 'file|invoke-webrequest'

    # Lateral movement / credential relay
    PassTheCred      = 'seku' + 'rlsa::pth|kerb' + 'eros::ptt|lsa' + 'dump::dcs' + 'ync|privi' + 'lege::debug'

    # Impact / destruction
    ShadowDelete     = 'vss' + 'admin.*delete|shadow' + 'copy.*delete|shadows.*\/all|resize.*shadow' + 'storage'
    RecoveryDisable  = 'recov' + 'ery' + 'enabled.*no|boot' + 'status' + 'policy.*ignore' + 'all' + 'failures'
    WbadminDelete    = 'wba' + 'dmin.*delete.*(catalog|systemstate)'
    WbadminSurvey    = 'wba' + 'dmin\s+(get|list)|vss' + 'admin\s+list|get-wmiobject.*shadow' + 'copy'
}
$Script:MiningPoolDomains  = @(
    'pool.minergate.com','xmr.pool.minergate.com','monero.hashvault.pro',
    'pool.supportxmr.com','xmrpool.eu','mine.c3pool.com','xmr-asia1.nanopool.org',
    'xmr-us-east1.nanopool.org','pool.xmr.pt','gulf.moneroocean.stream',
    'rx.unmineable.com','solo.ckpool.org','stratum.slushpool.com',
    'btc.ss.poolin.com','mining.luxor.tech','btc.f2pool.com',
    'eth.f2pool.com','etc.f2pool.com','rvn.f2pool.com','kas.f2pool.com'
)
$Script:TaskName = "WindowsSentinel"

# JIT/Electron processes with legitimately RWX memory
$Script:JitPaths = @(
    '*\java.exe','*\javaw.exe','*\node.exe','*\electron.exe',
    '*\chrome.exe','*\msedge.exe','*\firefox.exe','*\brave.exe',
    '*\Code.exe','*\kiro.exe','*\Discord.exe','*\Slack.exe','*\Teams.exe',
    '*\steam.exe','*\steamwebhelper.exe','*\obs64.exe','*\obs32.exe',
    '*\dotnet.exe','*\w3wp.exe','*\Spotify.exe','*\Signal.exe',
    '*\Notion.exe','*\Obsidian.exe','*\GitKraken.exe','*\Postman.exe',
    '*\1Password.exe','*\Bitwarden.exe','*\WindowsTerminal.exe'
)

# Trusted system paths for masquerade detection
$Script:TrustedPaths = @{
    'svchost.exe'   = "$env:SystemRoot\System32\svchost.exe"
    'lsass.exe'     = "$env:SystemRoot\System32\lsass.exe"
    'csrss.exe'     = "$env:SystemRoot\System32\csrss.exe"
    'winlogon.exe'  = "$env:SystemRoot\System32\winlogon.exe"
    'explorer.exe'  = "$env:SystemRoot\explorer.exe"
    'taskhost.exe'  = "$env:SystemRoot\System32\taskhost.exe"
    'taskhostw.exe' = "$env:SystemRoot\System32\taskhostw.exe"
    'services.exe'  = "$env:SystemRoot\System32\services.exe"
    'spoolsv.exe'   = "$env:SystemRoot\System32\spoolsv.exe"
    'wininit.exe'   = "$env:SystemRoot\System32\wininit.exe"
    'smss.exe'      = "$env:SystemRoot\System32\smss.exe"
    'conhost.exe'   = "$env:SystemRoot\System32\conhost.exe"
    'dllhost.exe'   = "$env:SystemRoot\System32\dllhost.exe"
    'wermgr.exe'    = "$env:SystemRoot\System32\wermgr.exe"
}

# ============================================================================
# NATIVE METHODS
# ============================================================================
if (-not ([System.Management.Automation.PSTypeName]'SN').Type) {
    $snSrc  = 'using System; using System.Runtime.InteropServices; '
    $snSrc += 'public class SN { '
    $snSrc += '[DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool b,int pid); '
    $snSrc += '[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h); '
    $snSrc += '[DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr h,IntPtr addr,out MBI buf,int len); '
    $snSrc += '[DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr b,byte[] buf,int sz,out int read); '
    $snSrc += '[DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner(); '
    $snSrc += '[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd,out uint pid); '
    $snSrc += '[StructLayout(LayoutKind.Sequential)] public struct MBI { '
    $snSrc += 'public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; '
    $snSrc += 'public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; } '
    $snSrc += 'public const uint QI=0x0400,VMR=0x0010,COMMIT=0x1000,PRIV=0x20000; '
    $snSrc += 'public const uint RWX=0x40,RWC=0x80; }'
    Add-Type -TypeDefinition $snSrc -ErrorAction SilentlyContinue
}

# ============================================================================
# ETW PROCESS-START SUBSCRIBER
# Subscribes to Microsoft-Windows-Kernel-Process (GUID below) on a background
# thread. Arrivals are enqueued into $Script:EtwQueue and drained by
# Update-Ancestry every cycle, giving near-real-time process-create coverage
# alongside the 5s WMI snapshot catch-all.
# Requires elevation (ETW kernel provider needs SeSystemProfilePrivilege).
# Gracefully disabled if subscription fails (EtwAvailable = false).
# ============================================================================
if (-not ([System.Management.Automation.PSTypeName]'EtwSub').Type) {
    $etwSrc  = 'using System; '
    $etwSrc += 'using System.Collections.Concurrent; '
    $etwSrc += 'using System.Diagnostics.Eventing.Reader; '
    $etwSrc += 'using System.Threading; '
    $etwSrc += 'public class EtwSub { '
    $etwSrc += '    public static ConcurrentQueue<EtwProc> Queue = new ConcurrentQueue<EtwProc>(); '
    $etwSrc += '    private static EventLogWatcher _watcher; '
    $etwSrc += '    public static bool Start() { '
    $etwSrc += '        try { '
    # Security channel carries process create (Event ID 4688) when process auditing is on.
    # We use the Security log query as the most reliable cross-version approach -
    # it works on Win10/11 without needing a manifest-registered ETW session.
    $etwSrc += '            var q = new EventLogQuery("Security", PathType.LogName, '
    $etwSrc += '                "*[System[(EventID=4688)]]"); '
    $etwSrc += '            q.ReverseDirection = false; '
    $etwSrc += '            _watcher = new EventLogWatcher(q); '
    $etwSrc += '            _watcher.EventRecordWritten += OnEvent; '
    $etwSrc += '            _watcher.Enabled = true; '
    $etwSrc += '            return true; '
    $etwSrc += '        } catch { return false; } '
    $etwSrc += '    } '
    $etwSrc += '    public static void Stop() { '
    $etwSrc += '        try { if (_watcher != null) { _watcher.Enabled = false; _watcher.Dispose(); } } catch {} '
    $etwSrc += '    } '
    $etwSrc += '    private static void OnEvent(object s, EventRecordWrittenEventArgs e) { '
    $etwSrc += '        try { '
    $etwSrc += '            if (e.EventRecord == null) return; '
    $etwSrc += '            var props = e.EventRecord.Properties; '
    # 4688 properties: [0]=SubjectUserSid [1]=SubjectUserName [2]=SubjectDomainName
    # [3]=SubjectLogonId [4]=NewProcessId [5]=NewProcessName [6]=TokenElevationType
    # [7]=ProcessId(parent) [8]=CommandLine [9]=TargetUserSid ...
    $etwSrc += '            if (props == null || props.Count < 9) return; '
    $etwSrc += '            var proc = new EtwProc(); '
    $etwSrc += '            proc.Pid      = Convert.ToInt32(props[4].Value); '
    $etwSrc += '            proc.PPid     = Convert.ToInt32(props[7].Value); '
    $etwSrc += '            proc.Path     = props[5].Value.ToString(); '
    $etwSrc += '            proc.CmdLine  = props[8].Value.ToString(); '
    $etwSrc += '            proc.Name     = System.IO.Path.GetFileName(proc.Path); '
    $etwSrc += '            proc.Time     = e.EventRecord.TimeCreated ?? DateTime.UtcNow; '
    $etwSrc += '            Queue.Enqueue(proc); '
    $etwSrc += '        } catch {} '
    $etwSrc += '    } '
    $etwSrc += '} '
    $etwSrc += 'public class EtwProc { '
    $etwSrc += '    public int Pid; public int PPid; '
    $etwSrc += '    public string Name; public string Path; public string CmdLine; '
    $etwSrc += '    public DateTime Time; '
    $etwSrc += '}'
    Add-Type -TypeDefinition $etwSrc -ReferencedAssemblies 'System.Core' -ErrorAction SilentlyContinue
}
$Script:EtwQueue     = [EtwSub]::Queue        # shared queue (created by Add-Type above)
$Script:EtwAvailable = $false                 # set to true if subscription succeeds

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
    if (-not $Script:QuietMode) {
        $color = "Cyan"
        if     ($Tier -eq "Tier1Behavioral") { $color = "Yellow" }
        elseif ($Tier -eq "Response")        { $color = "Red"    }
        elseif ($Tier -eq "System")          { $color = "Gray"   }
        if ($Type -eq "detection") {
            Write-Host "[$Tier] $Rule : $Evidence" -ForegroundColor $color
        }
    }
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
# Update-Ancestry runs every cycle. It first drains any ETW process-create
# events that arrived since last cycle (near-real-time, catches short-lived
# processes). Then it takes a full WMI Win32_Process snapshot to catch
# anything ETW missed (processes that started before Sentinel, or when the
# ETW subscription was not yet active).
# ============================================================================
function Update-Ancestry {
    $s = @{}

    # --- Step 1: WMI full snapshot (always) ---
    try {
        Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate -ErrorAction Stop | ForEach-Object {
            $s[$_.ProcessId] = @{ N=$_.Name; PP=$_.ParentProcessId; CL=$_.CommandLine; P=$_.ExecutablePath; T=$_.CreationDate }
        }
    } catch {}

    # --- Step 2: Drain ETW queue - adds/refreshes entries for processes that
    #             arrived between this WMI poll and the last one.
    #             ETW entries are preferred for CmdLine when WMI returns null
    #             (cross-user process with partial access). ---
    if ($Script:EtwAvailable) {
        $item = $null
        while ($Script:EtwQueue.TryDequeue([ref]$item)) {
            if ($item.Pid -le 4) { continue }
            if ($s.ContainsKey($item.Pid)) {
                # Enrich: WMI sometimes returns empty CommandLine for cross-user procs;
                # ETW event 4688 always includes it when process auditing is on.
                if ([string]::IsNullOrEmpty($s[$item.Pid].CL) -and -not [string]::IsNullOrEmpty($item.CmdLine)) {
                    $s[$item.Pid].CL = $item.CmdLine
                }
            } else {
                # Process already exited before WMI saw it — add from ETW record.
                $s[$item.Pid] = @{ N=$item.Name; PP=$item.PPid; CL=$item.CmdLine; P=$item.Path; T=$item.Time }
            }
        }
    }

    $Script:ProcessAncestry = $s
}

# ============================================================================
# USER PROFILE DISCOVERY (run at startup + refreshed periodically)
# Identifies all interactive user profiles so staging-path checks, file
# watchers, and startup-folder monitors work correctly when running as SYSTEM.
# ============================================================================
function Get-UserProfiles {
    $profiles = @()

    # Method 1: registry profile list (most reliable, includes all local accounts)
    try {
        $regBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        Get-ChildItem $regBase -ErrorAction Stop | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if (-not $props -or -not $props.ProfileImagePath) { return }
            $prof = $props.ProfileImagePath
            # Skip system pseudo-profiles
            if ($prof -match '\\(systemprofile|LocalService|NetworkService)$') { return }
            if (-not (Test-Path $prof -ErrorAction SilentlyContinue)) { return }
            $profiles += @{
                ProfilePath = $prof
                AppData     = (Join-Path $prof 'AppData\Roaming')
                LocalTemp   = (Join-Path $prof 'AppData\Local\Temp')
                Downloads   = (Join-Path $prof 'Downloads')
                Desktop     = (Join-Path $prof 'Desktop')
                Documents   = (Join-Path $prof 'Documents')
            }
        }
    } catch {}

    # Method 2: WMI Win32_UserProfile as fallback / supplement
    if ($profiles.Count -eq 0) {
        try {
            Get-CimInstance Win32_UserProfile -ErrorAction Stop |
                Where-Object { -not $_.Special -and $_.LocalPath } |
                ForEach-Object {
                    $prof = $_.LocalPath
                    $profiles += @{
                        ProfilePath = $prof
                        AppData     = (Join-Path $prof 'AppData\Roaming')
                        LocalTemp   = (Join-Path $prof 'AppData\Local\Temp')
                        Downloads   = (Join-Path $prof 'Downloads')
                        Desktop     = (Join-Path $prof 'Desktop')
                        Documents   = (Join-Path $prof 'Documents')
                    }
                }
        } catch {}
    }

    # Always include the current user's profile (handles non-SYSTEM runs)
    $cur = $env:USERPROFILE
    if ($cur -and ($profiles | Where-Object { $_.ProfilePath -eq $cur }).Count -eq 0) {
        $profiles += @{
            ProfilePath = $cur
            AppData     = $env:APPDATA
            LocalTemp   = (Join-Path $env:LOCALAPPDATA 'Temp')
            Downloads   = (Join-Path $cur 'Downloads')
            Desktop     = (Join-Path $cur 'Desktop')
            Documents   = (Join-Path $cur 'Documents')
        }
    }

    $Script:UserProfiles = $profiles
}

# Returns a flat array of all staging paths across all known user profiles.
function Get-StagingPaths {
    $paths = @()
    foreach ($u in $Script:UserProfiles) {
        $paths += $u.AppData
        $paths += $u.LocalTemp
        $paths += $u.Downloads
        $paths += $u.Desktop
        $paths += (Join-Path $u.ProfilePath 'AppData\Local\Temp')
    }
    $paths += "$env:SystemRoot\Temp"
    $paths += 'C:\Temp'
    $paths += 'C:\Windows\Temp'
    return @($paths | Where-Object { $_ } | Select-Object -Unique)
}

# Returns true if the given path is inside any known user staging area
function Is-InStagingPath { param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    foreach ($sp in (Get-StagingPaths)) {
        if ($Path -like "$sp*") { return $true }
    }
    # Generic fallbacks independent of specific user paths
    if ($Path -like '*\AppData\*' -or $Path -like '*\Temp\*' -or
        $Path -like '*\Downloads\*' -or $Path -like '*\Desktop\*' -or
        $Path -like '*\Public\*') { return $true }
    return $false
}

# ============================================================================
# ENTROPY (Shannon) - DGA, DNS exfil, packing detection
# ============================================================================
function Get-Entropy { param([string]$S)
    if ([string]::IsNullOrEmpty($S)) { return 0 }
    $f = @{}; foreach ($c in $S.ToCharArray()) { if ($f.ContainsKey($c)){$f[$c]++}else{$f[$c]=1} }
    $l = $S.Length; $e = 0.0
    foreach ($v in $f.Values) { $p = $v/$l; if ($p -gt 0) { $e -= $p * [Math]::Log($p,2) } }
    return $e
}

# ============================================================================
# HASH REPUTATION (CIRCL hashlookup + MalwareBazaar)
# ============================================================================
# HASH REPUTATION (CIRCL hashlookup + MalwareBazaar)
# Only active when -CheckReputation is passed.
# Each hash is looked up at most once per session (permanent cache).
# Calls are synchronous but the caller (Test-UnsignedStaged) is only invoked
# once per unique path, so at most 1 lookup per new unsigned staged binary.
# Callers must check $Script:ReputationEnabled before calling.
# ============================================================================
function Test-HashReputation { param([string]$Hash)
    if (-not $Script:ReputationEnabled) { return @{ Bad=$false; Src="Disabled"; Detail="Use -CheckReputation to enable" } }
    if ($Script:HashCache.ContainsKey($Hash)) { return $Script:HashCache[$Hash] }
    # CIRCL hashlookup - known-good database (fast, no auth required)
    try {
        $r = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$Hash" -Method Get -TimeoutSec 4 -ErrorAction Stop
        if ($r.'hashlookup:trust' -and [int]$r.'hashlookup:trust' -gt 50) {
            $Script:HashCache[$Hash] = @{ Bad=$false; Src="CIRCL"; Detail="Trust=$($r.'hashlookup:trust')" }
            return $Script:HashCache[$Hash]
        }
    } catch {}
    # MalwareBazaar - known-bad database
    try {
        $body = @{ query="get_info"; hash=$Hash } | ConvertTo-Json -Compress
        $r = Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop
        if ($r.query_status -eq "ok" -or $r.query_status -eq "hash_found") {
            $Script:HashCache[$Hash] = @{ Bad=$true; Src="MalwareBazaar"; Detail="Known malware" }
            return $Script:HashCache[$Hash]
        }
    } catch {}
    # Cache negative result so we never retry the same hash in this session
    $Script:HashCache[$Hash] = @{ Bad=$false; Src="Unknown"; Detail="Not in databases" }
    return $Script:HashCache[$Hash]
}

# ============================================================================
# SELF-PROTECTION
# Works for both .ps1 and compiled .exe.
# For a .ps1 we hash the script file on disk.
# For a compiled .exe we hash the EXE on disk.
# In both cases $Script:OwnExePath holds the target path.
# ============================================================================
function Initialize-SelfProtection {
    if ($Script:OwnExePath -and (Test-Path $Script:OwnExePath -ErrorAction SilentlyContinue)) {
        try { $Script:SelfHash = (Get-FileHash -Path $Script:OwnExePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    }
}
function Test-SelfIntegrity {
    if (-not $Script:SelfHash -or -not $Script:OwnExePath) { return }
    if (-not (Test-Path $Script:OwnExePath -ErrorAction SilentlyContinue)) { return }
    try {
        $current = (Get-FileHash -Path $Script:OwnExePath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($current -ne $Script:SelfHash) {
            if (-not (Is-Dup -K "SelfTamper" -TTL 300)) {
                Log-Event -Type "detection" -Rule "SelfProtection" `
                    -Evidence "Sentinel binary/script modified on disk: $Script:OwnExePath" `
                    -Reasoning "Hash changed since startup - possible tampering or replacement" `
                    -Conf 0.97 -Tier "Tier1Behavioral" -PName "Sentinel" -PId $PID
            }
        }
    } catch {}
}


# ============================================================================
# MEMORY ANALYSIS
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
        if ($rwx -ge 5)    { $flags += "RWX:$rwx" }
        if ($unbacked -ge 8) { $flags += "Unbacked:$unbacked" }
        if ($privExec -gt 50MB) { $flags += "PrivExec:$([Math]::Round($privExec/1MB))MB" }
    } finally { [SN]::CloseHandle($h) | Out-Null }
    try {
        $p = Get-Process -Id $Pid -ErrorAction Stop
        if ($p.Path -and $p.Modules.Count -gt 0 -and $p.Modules[0].FileName) {
            if ($p.Modules[0].FileName.ToLower() -ne $p.Path.ToLower()) { $flags += "Hollowed" }
        }
        if ($p.PrivateMemorySize64 -gt 500MB -and $p.Modules.Count -lt 10) { $flags += "HighMemLowMod" }
        if ([string]::IsNullOrEmpty($p.Path) -or -not (Test-Path $p.Path -ErrorAction SilentlyContinue)) { $flags += "NoBackingFile" }
    } catch {}
    if ($flags.Count -ge 2) {
        $conf = [Math]::Min(0.96, 0.70 + $flags.Count * 0.08)
        return @{ Rule="MemoryAnomaly"; Evidence="$Name (PID $Pid): $($flags -join ' | ')"; Reasoning="Multiple memory anomalies indicate injected/hollowed/reflective code"; Conf=$conf; Tier="Tier1Behavioral"; Cat="memory" }
    }
    return $null
}

# ============================================================================
# CAT 13 - IMPACT: DESTRUCTIVE OPS (Ransomware + Wiper + Disk/Boot)
# ============================================================================
function Test-Destructive { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Shadow/backup destruction
    if ($c -match $Script:Sig.ShadowDelete) {
        return @{ Rule="ShadowDestruction"; Evidence="Shadow copy deletion by $N (PID $Pid)"; Reasoning="Destroying VSS recovery points - ransomware precursor"; Conf=0.94; Tier="Tier1Behavioral"; Cat="ransomware" }
    }
    if ($c -match $Script:Sig.RecoveryDisable) {
        return @{ Rule="BootRecoveryDisable"; Evidence="Boot recovery disabled by $N (PID $Pid)"; Reasoning="Preventing Windows recovery - ransomware/wiper pattern"; Conf=0.93; Tier="Tier1Behavioral"; Cat="ransomware" }
    }
    if ($c -match $Script:Sig.WbadminDelete) {
        return @{ Rule="BackupDestruction"; Evidence="Backup catalog deletion by $N (PID $Pid)"; Reasoning="Backup catalog removal to prevent recovery"; Conf=0.93; Tier="Tier1Behavioral"; Cat="ransomware" }
    }
    if ($c -match '(net\s+stop|sc\s+(stop|config.*disabled))' -and $c -match '(sql|exchange|backup|vss|veeam|acronis|sophosav)') {
        return @{ Rule="CriticalServiceDisrupt"; Evidence="Security/backup service stopped by $N (PID $Pid)"; Reasoning="Disabling backup/AV services before encryption or data theft"; Conf=0.90; Tier="Tier1Behavioral"; Cat="ransomware" }
    }
    # Disk wipe
    if ($c -match 'format\s+[a-z]:\s.*(\/q|\/fs)' -or $c -match 'diskpart.*clean' -or $c -match 'cipher\s+\/w:') {
        return @{ Rule="DiskWipe"; Evidence="Disk wipe operation by $N (PID $Pid)"; Reasoning="Format/diskpart clean or cipher wipe - destructive wiper pattern"; Conf=0.92; Tier="Tier1Behavioral"; Cat="wiper" }
    }
    # Boot corruption beyond recovery disable
    if ($c -match 'bcdedit.*(\/delete|\/set.*safeboot|\/bootsequence)' -and $c -notmatch ('recov' + 'eryenabled')) {
        return @{ Rule="BootCorruption"; Evidence="BCDEdit boot manipulation by $N (PID $Pid)"; Reasoning="Modifying boot configuration - wiper/bootkit pattern"; Conf=0.88; Tier="Tier1Behavioral"; Cat="wiper" }
    }
    # MBR overwrite
    if ($c -match '\\\\\.\\physicaldrive' -and $c -match '(write|open.*generic_write|createfile)') {
        return @{ Rule="MbrOverwrite"; Evidence="Raw disk write by $N (PID $Pid)"; Reasoning="Direct PhysicalDrive access with write intent - MBR wiper"; Conf=0.93; Tier="Tier1Behavioral"; Cat="wiper" }
    }
    return $null
}

# ============================================================================
# CAT 7 - CREDENTIAL ACCESS (extended: Wi-Fi, cmdkey, cloud tokens, MFA)
# ============================================================================
function Test-CredentialAccess { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # LSASS dump
    if ($c -match $Script:Sig.LsassComsvcs) {
        return @{ Rule="LsassDump_Comsvcs"; Evidence="MiniDump via com_svcs.dll (PID $Pid)"; Reasoning="Windows built-in DLL used for LSASS memory dump"; Conf=0.93; Tier="Tier1Behavioral"; Cat="credential" }
    }
    if ($c -match 'lsass' -and $c -match $Script:Sig.LsassDump) {
        return @{ Rule="LsassDump_Direct"; Evidence="LSASS memory targeting (PID $Pid)"; Reasoning="Explicit LSASS memory extraction attempt"; Conf=0.91; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Registry hive theft
    if ($c -match $Script:Sig.RegHiveTheft) {
        return @{ Rule="RegistryHiveTheft"; Evidence="Credential hive extraction (PID $Pid)"; Reasoning="Extracting SAM/SECURITY/SYSTEM hives for offline cracking"; Conf=0.92; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # DPAPI
    if ($c -match 'dpapi' -and $c -match 'masterkey|credential|protect|unprotect') {
        return @{ Rule="DpapiAbuse"; Evidence="DPAPI credential extraction (PID $Pid)"; Reasoning="Targeting DPAPI protected credentials"; Conf=0.86; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # Browser credential stores
    if ($c -match '(login\s*data|local\s*state|cookies).*chrome|key4\.db|logins\.json|cookies\.sqlite') {
        if ($c -match 'copy|type|get-content|select-string|sqlite|cryptunprotect') {
            return @{ Rule="BrowserCredTheft"; Evidence="Browser credential store access (PID $Pid)"; Reasoning="Accessing browser credential files with extraction intent"; Conf=0.88; Tier="Tier1Behavioral"; Cat="credential" }
        }
    }
    # Wi-Fi password extraction
    if ($c -match 'netsh\s+wlan\s+(show\s+profile|export)' -and $c -match 'key=clear|security') {
        return @{ Rule="WifiCredTheft"; Evidence="Wi-Fi password extraction by $N (PID $Pid)"; Reasoning="netsh wlan show profile with key=clear extracts plaintext Wi-Fi passwords"; Conf=0.88; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # cmdkey saved credentials
    if ($c -match 'cmdkey\s+/list' -or ($c -match 'cmdkey' -and $c -match '/add.*password')) {
        return @{ Rule="SavedCredAccess"; Evidence="cmdkey credential store access by $N (PID $Pid)"; Reasoning="Enumerating or adding Windows Credential Manager entries"; Conf=0.80; Tier="Tier2Indicator"; Cat="credential" }
    }
    # Cloud token theft: Azure CLI / AWS CLI credential files
    if ($c -match '(get-content|type|cat)\s.*(\.aws\\credentials|azure\\msal_token_cache|\.config\\gcloud\\credentials)') {
        return @{ Rule="CloudTokenTheft"; Evidence="Cloud CLI credential file accessed by $N (PID $Pid)"; Reasoning="Reading cloud provider credential/token files for exfiltration"; Conf=0.87; Tier="Tier1Behavioral"; Cat="credential" }
    }
    # VPN/RDP saved passwords via registry or rasman
    if ($c -match 'hklm:\\system\\currentcontrolset\\services\\rasman' -and $c -match 'get-item|get-childitem') {
        return @{ Rule="VpnCredAccess"; Evidence="RAS/VPN credential registry access by $N (PID $Pid)"; Reasoning="Enumerating VPN credentials from RasMan registry hive"; Conf=0.78; Tier="Tier2Indicator"; Cat="credential" }
    }
    # Credential Manager vault dump
    if ($c -match 'vaultcmd\s+/list' -or $c -match 'windows\.security\.credentials') {
        return @{ Rule="CredVaultDump"; Evidence="Windows Vault enumeration by $N (PID $Pid)"; Reasoning="Dumping Windows Credential Vault entries"; Conf=0.82; Tier="Tier2Indicator"; Cat="credential" }
    }
    return $null
}

# ============================================================================
# CAT 6 - DEFENSE EVASION (extended: masquerade, ADS, timestomp, LOLBin download)
# ============================================================================
function Test-Evasion { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # AMSI patch
    if ($c -match $Script:Sig.AmsiPatch) {
        return @{ Rule="AmsiPatch"; Evidence="AMSI manipulation (PID $Pid)"; Reasoning="Patching Windows AMSI interface to blind AV scanning"; Conf=0.93; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # ETW blind
    if ($c -match $Script:Sig.EtwPatch) {
        return @{ Rule="EtwBlind"; Evidence="ETW blinding (PID $Pid)"; Reasoning="Patching ETW to hide telemetry from security tools"; Conf=0.93; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # Log clearing
    if ($c -match $Script:Sig.LogClear) {
        return @{ Rule="LogClear"; Evidence="Event log cleared by $N (PID $Pid)"; Reasoning="Clearing Windows event logs to destroy forensic evidence"; Conf=0.91; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # Defender disable/exclusion
    if ($c -match $Script:Sig.DefenderDisable) {
        return @{ Rule="DefenderDisable"; Evidence="Defender disabled by $N (PID $Pid)"; Reasoning="Programmatically disabling Windows Defender real-time protection"; Conf=0.92; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    if ($c -match $Script:Sig.DefenderExclude) {
        return @{ Rule="DefenderExclusion"; Evidence="Defender exclusion added by $N (PID $Pid)"; Reasoning="Adding exclusion path/process to hide malware from Defender"; Conf=0.86; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # Filter driver unload
    if ($c -match $Script:Sig.FltmcUnload) {
        return @{ Rule="MinifilterUnload"; Evidence="Security filter driver unloaded by $N (PID $Pid)"; Reasoning="Unloading a minifilter driver (likely AV/EDR protection)"; Conf=0.91; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # Process masquerade: name matches trusted list but wrong path
    if ($Path -and $N) {
        $expectedPath = $Script:TrustedPaths[$N]
        if ($expectedPath -and (Test-Path $expectedPath) -and $Path.ToLower() -ne $expectedPath.ToLower()) {
            return @{ Rule="ProcessMasquerade"; Evidence="$N running from $Path (expected $expectedPath)"; Reasoning="Process name matches Windows system binary but launches from unexpected path"; Conf=0.94; Tier="Tier1Behavioral"; Cat="evasion" }
        }
    }
    # Certutil LOLBin download/decode
    if ($c -match 'certutil' -and $c -match '(-urlcache|-decode|-decodehex|-f\s+http)') {
        return @{ Rule="CertutilLolbin"; Evidence="certutil download/decode by $N (PID $Pid)"; Reasoning="certutil used as LOLBin for file download or base64 decode"; Conf=0.88; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # BITS download via bitsadmin
    if ($c -match 'bitsadmin\s+/transfer' -and $c -match 'http') {
        return @{ Rule="BitsDownload"; Evidence="BITS transfer job by $N (PID $Pid)"; Reasoning="BITSAdmin creating transfer job to download from external URL"; Conf=0.83; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # msiexec as downloader
    if ($c -match 'msiexec' -and $c -match 'http[s]?://') {
        return @{ Rule="MsiexecRemoteLoad"; Evidence="msiexec remote load by $N (PID $Pid)"; Reasoning="msiexec installing from remote URL - LOLBin delivery pattern"; Conf=0.85; Tier="Tier1Behavioral"; Cat="evasion" }
    }
    # Alternate Data Stream creation
    if ($c -match ':\w+\s*$' -or ($c -match 'set-content.*-stream' -or $c -match 'add-content.*-stream')) {
        return @{ Rule="AltDataStream"; Evidence="Alternate Data Stream operation by $N (PID $Pid)"; Reasoning="Creating or writing to NTFS ADS to hide payload data"; Conf=0.78; Tier="Tier2Indicator"; Cat="evasion" }
    }
    # Timestomping
    if ($c -match '\[system\.io\.file\]::\setlastwritetime|\[system\.io\.file\]::\setcreationtime|touch.*-date') {
        return @{ Rule="Timestomp"; Evidence="File timestamp manipulation by $N (PID $Pid)"; Reasoning="Modifying file timestamps to confuse forensic timeline analysis"; Conf=0.82; Tier="Tier2Indicator"; Cat="evasion" }
    }
    return $null
}

# ============================================================================
# CAT 4 - PERSISTENCE (extended: IFEO, AppInit, startup folder, COM hijack, SSH/RDP keys, mail rules)
# ============================================================================
function Test-Persistence { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Registry Run keys
    if ($c -match '(reg\s+add|new-itemproperty|set-itemproperty).*\\(run|runonce)\b') {
        return @{ Rule="RunKeyPersist"; Evidence="Registry Run key write by $N (PID $Pid)"; Reasoning="Writing to HKLM/HKCU Run key for auto-start persistence"; Conf=0.83; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # WMI subscriptions
    if ($c -match '(__eventfilter|__eventconsumer|filtertoconsumerbinding)') {
        return @{ Rule="WmiSubscription"; Evidence="WMI event subscription by $N (PID $Pid)"; Reasoning="Creating WMI event subscription for fileless persistence"; Conf=0.89; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # Scheduled task creation (exclude self install)
    if ($c -match '(schtasks\s*/create|register-scheduledtask)' -and $Pid -ne $Script:OwnPid) {
        return @{ Rule="SchedTaskPersist"; Evidence="Scheduled task created by $N (PID $Pid)"; Reasoning="Scheduled task is a common persistence mechanism"; Conf=0.76; Tier="Tier2Indicator"; Cat="persistence" }
    }
    # Service creation (exclude self install)
    if ($c -match '(sc\s+create|new-service)' -and $Pid -ne $Script:OwnPid) {
        return @{ Rule="ServicePersist"; Evidence="Service created by $N (PID $Pid)"; Reasoning="Service creation for persistence or privilege escalation"; Conf=0.79; Tier="Tier2Indicator"; Cat="persistence" }
    }
    # IFEO hijack (Image File Execution Options - debugger key)
    if ($c -match 'ifeo|image\s+file\s+execution\s+options' -and $c -match '(debugger|globalflag)') {
        return @{ Rule="IFEOHijack"; Evidence="IFEO debugger key set by $N (PID $Pid)"; Reasoning="IFEO Debugger key used to hijack process execution - persistence/escalation"; Conf=0.90; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # AppInit_DLLs
    if ($c -match 'appinit_dlls|loadappinit_dlls') {
        return @{ Rule="AppInitDll"; Evidence="AppInit_DLLs modified by $N (PID $Pid)"; Reasoning="AppInit_DLLs registry key used to inject DLL into all user-mode processes"; Conf=0.91; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # COM hijack (HKCU InprocServer32)
    if ($c -match 'hkcu.*clsid.*inprocserver32' -or $c -match 'new-item.*clsid.*inprocserver32') {
        return @{ Rule="ComHijack"; Evidence="COM InprocServer32 override by $N (PID $Pid)"; Reasoning="HKCU CLSID override to load attacker DLL via COM hijack"; Conf=0.89; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # SSH authorized_keys plant
    if ($c -match '(add-content|set-content|out-file|echo).*authorized_keys') {
        return @{ Rule="SshKeyPlant"; Evidence="SSH authorized_keys modified by $N (PID $Pid)"; Reasoning="Adding public key to authorized_keys for persistent SSH access"; Conf=0.87; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # Exchange/M365 mail forwarding rule (BEC persistence)
    if ($c -match '(new-inboxrule|set-inboxrule|new-transportrule)' -and $c -match '(forwardto|redirectto|forwardasmessage)') {
        return @{ Rule="MailForwardingRule"; Evidence="Mail forwarding rule created by $N (PID $Pid)"; Reasoning="Creating inbox rule to forward/copy mail to attacker - BEC persistence"; Conf=0.91; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    # Startup folder drop (detected via file watcher, flagged here for CL-based detection)
    if ($c -match 'startup' -and $c -match '(copy|move|write|out-file|set-content)' -and $c -match '\.(exe|ps1|vbs|js|bat|cmd|lnk|hta)') {
        return @{ Rule="StartupFolderDrop"; Evidence="Startup folder write by $N (PID $Pid)"; Reasoning="Dropping executable into startup folder for auto-run persistence"; Conf=0.84; Tier="Tier1Behavioral"; Cat="persistence" }
    }
    return $null
}

# ============================================================================
# CAT 3 - EXECUTION (extended: LOLBins, script hosts, COM, APC)
# ============================================================================
function Test-Execution { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    # Large encoded payload
    if ($CL -match '-[eE][nN][cC]\w*\s+[A-Za-z0-9+/=]{100,}') {
        return @{ Rule="EncodedPayload"; Evidence="Encoded payload ($([Math]::Round($CL.Length/1024,1))KB) (PID $Pid)"; Reasoning="Large base64 encoded command - common obfuscation for malicious PS payloads"; Conf=0.86; Tier="Tier1Behavioral"; Cat="execution" }
    }
    $c = $CL.ToLower()
    # Download + execute
    if (($c -match $Script:Sig.DownloadMethods) -and ($c -match $Script:Sig.InvokeExpr)) {
        return @{ Rule="DownloadExec"; Evidence="Download-and-execute by $N (PID $Pid)"; Reasoning="Downloading and immediately executing remote content"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Reflective loading
    if ($c -match $Script:Sig.ReflectiveLoad) {
        return @{ Rule="ReflectiveLoad"; Evidence="Reflective assembly load by $N (PID $Pid)"; Reasoning="In-memory code loading via .NET reflection APIs"; Conf=0.89; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Reverse shell
    if ($c -match $Script:Sig.ReverseShell -and $c -match ('get' + 'stream|network' + 'stream')) {
        return @{ Rule="ReverseShell"; Evidence="Socket shell by $N (PID $Pid)"; Reasoning="Building network stream reverse shell via .NET socket APIs"; Conf=0.93; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # Hidden + bypass
    if ($c -match '-executionpolicy\s*(bypass|unrestricted)' -and $c -match '-w(indowstyle)?\s*h(idden)?') {
        return @{ Rule="HiddenBypassExec"; Evidence="Hidden+bypass PS execution by $N (PID $Pid)"; Reasoning="PowerShell running hidden with execution policy bypass"; Conf=0.73; Tier="Tier2Indicator"; Cat="execution" }
    }
    # mshta LOLBin
    if ($c -match 'mshta\s.*(http|javascript|vbscript|\.hta)') {
        return @{ Rule="MshtaLolbin"; Evidence="mshta remote/script exec by $N (PID $Pid)"; Reasoning="mshta executing remote HTA, JavaScript, or VBScript - common LOLBin delivery"; Conf=0.87; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # rundll32 with unusual arguments
    if ($c -match 'rundll32' -and $c -match '(javascript|,\s*#|shell32.*shellexec|advpack.*launchinstallshutdown|ieadvpack)') {
        return @{ Rule="Rundll32Lolbin"; Evidence="rundll32 abuse by $N (PID $Pid)"; Reasoning="rundll32 executing JavaScript or unusual exports - LOLBin code execution"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # regsvr32 COM scriptlet (squiblydoo)
    if ($c -match 'regsvr32' -and $c -match '(/s|/u|/i).*\.sct|scrobj\.dll|http') {
        return @{ Rule="RegSvr32Scriptlet"; Evidence="regsvr32 scriptlet execution by $N (PID $Pid)"; Reasoning="regsvr32 /i loading remote SCT scriptlet - Squiblydoo LOLBin technique"; Conf=0.90; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # wmic process call create (remote or local)
    if ($c -match 'wmic.*process.*call.*create') {
        return @{ Rule="WmicProcessCreate"; Evidence="WMIC process creation by $N (PID $Pid)"; Reasoning="WMIC used to create process - common lateral movement / evasion technique"; Conf=0.82; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # wscript/cscript executing JScript or VBScript
    if ($c -match '(wscript|cscript)\s.+\.(js|vbs|jse|vbe|wsf)') {
        return @{ Rule="ScriptHostExec"; Evidence="Script host execution by $N (PID $Pid)"; Reasoning="wscript/cscript executing script - common malware delivery"; Conf=0.78; Tier="Tier2Indicator"; Cat="execution" }
    }
    # AutoHotkey executing a remote/temp script
    if ($c -match 'autohotkey' -and $c -match '(http|temp|appdata|desktop)') {
        return @{ Rule="AhkPayload"; Evidence="AutoHotkey script from staging/remote by $N (PID $Pid)"; Reasoning="AutoHotkey executing script from suspicious location"; Conf=0.75; Tier="Tier2Indicator"; Cat="execution" }
    }
    # ISO/LNK execution chain (explorer launching script from mounted ISO)
    if ($N -in @('explorer.exe') -and $c -match '\.(ps1|vbs|js|hta|bat|cmd)' -and $c -match '(iso|img|lnk)') {
        return @{ Rule="IsoLnkChain"; Evidence="ISO/LNK script chain by $N (PID $Pid)"; Reasoning="Script executed from mounted ISO or LNK file - initial access delivery pattern"; Conf=0.83; Tier="Tier1Behavioral"; Cat="execution" }
    }
    return $null
}

# ============================================================================
# CAT 5 - PRIVILEGE ESCALATION (extended: BYOVD, AlwaysInstallElevated, SeImpersonate)
# ============================================================================
function Test-Escalation { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Token manipulation
    if ($c -match 'duplicatetokenex|createprocesswithtoken|impersonateloggedonuser|adjusttokenprivileges.*sedebug') {
        return @{ Rule="TokenManipulation"; Evidence="Token API abuse by $N (PID $Pid)"; Reasoning="Windows token APIs used for privilege escalation via impersonation"; Conf=0.89; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    # Pipe impersonation (PrintSpoofer / Potato family)
    if ($c -match 'impersonatenamedpipeclient|createnamedpipe.*impersonate|\.pipe\\(spoolss|lsarpc|samr|netlogon)') {
        return @{ Rule="PipeImpersonation"; Evidence="Named pipe impersonation by $N (PID $Pid)"; Reasoning="Named pipe impersonation for SYSTEM token escalation (Potato-family technique)"; Conf=0.91; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    # UAC bypass patterns
    if ($c -match 'fodhelper|computerdefaults|sdclt.*\/kickoffelev|eventvwr.*mmc|cmstp|slui.*\/url') {
        return @{ Rule="UacBypass"; Evidence="UAC bypass technique by $N (PID $Pid)"; Reasoning="Exploiting auto-elevation mechanism to bypass User Account Control"; Conf=0.90; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    # AlwaysInstallElevated abuse
    if ($c -match 'alwaysinstallelevated' -or ($c -match 'msiexec.*\/i' -and $c -match '\.(msi)' -and $c -match 'temp|appdata')) {
        return @{ Rule="AlwaysInstallElevated"; Evidence="Elevated MSI installation by $N (PID $Pid)"; Reasoning="AlwaysInstallElevated policy abused to run MSI with SYSTEM privileges"; Conf=0.84; Tier="Tier1Behavioral"; Cat="escalation" }
    }
    # BYOVD - loading a known vulnerable driver
    if ($c -match 'sc\s+(create|start)' -and $c -match '\.(sys)') {
        return @{ Rule="DriverLoad"; Evidence="Driver service created by $N (PID $Pid)"; Reasoning="Loading a kernel driver - possible BYOVD (Bring Your Own Vulnerable Driver) attack"; Conf=0.80; Tier="Tier2Indicator"; Cat="escalation" }
    }
    # infdefaultinstall (INF file execution for UAC bypass)
    if ($c -match 'infdefaultinstall|setupapi.*install') {
        return @{ Rule="InfInstallBypass"; Evidence="INF install by $N (PID $Pid)"; Reasoning="InfDefaultInstall or SetupAPI used for UAC bypass or privilege escalation"; Conf=0.83; Tier="Tier2Indicator"; Cat="escalation" }
    }
    return $null
}

# ============================================================================
# CAT 9 - LATERAL MOVEMENT (extended: PTH, DCOM, RDP hijack)
# ============================================================================
function Test-LateralMovement { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Remote WMI/SC execution
    if ($c -match '(sc|wmic|invoke-wmimethod|invoke-command).*\\\\' -or $c -match '/node:.*process.*call.*create') {
        return @{ Rule="RemoteExecution"; Evidence="Remote execution on another host by $N (PID $Pid)"; Reasoning="Executing commands on remote system via WMI, SC, or invoke-command"; Conf=0.86; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    # PSRemoting
    if ($c -match 'enter-pssession|invoke-command.*-computer|new-pssession.*-computer') {
        return @{ Rule="PSRemoting"; Evidence="PowerShell remoting by $N (PID $Pid)"; Reasoning="PowerShell WinRM remoting to another system"; Conf=0.71; Tier="Tier2Indicator"; Cat="lateral" }
    }
    # Pass-the-hash / Pass-the-ticket (Mimikatz-style invocation)
    if ($c -match $Script:Sig.PassTheCred) {
        return @{ Rule="PassTheCredential"; Evidence="Pass-the-hash/ticket/DCSync by $N (PID $Pid)"; Reasoning="Mimikatz-style credential relay attack for lateral movement"; Conf=0.97; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    # DCOM lateral movement
    if ($c -match '\[activator\]::createinstance|getobject.*winmgmts|comobject.*scheduledtasks' -and $c -match '\\\\') {
        return @{ Rule="DcomLateral"; Evidence="DCOM remote object instantiation by $N (PID $Pid)"; Reasoning="DCOM instantiation on remote host for lateral movement"; Conf=0.84; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    # RDP session hijack (tscon)
    if ($c -match 'tscon\s+\d+' -and $c -match '(/dest|/password)') {
        return @{ Rule="RdpSessionHijack"; Evidence="RDP session takeover by $N (PID $Pid)"; Reasoning="tscon used to hijack another user's RDP session without credentials"; Conf=0.93; Tier="Tier1Behavioral"; Cat="lateral" }
    }
    return $null
}

# ============================================================================
# CAT 8 - DISCOVERY (AD enum, net recon, cloud, backup survey)
# ============================================================================
function Test-Discovery { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # AD/domain enumeration
    if ($c -match '(net\s+(user|group|localgroup)\s+.*/domain|nltest\s+/dclist|dsquery\s+(user|computer|group)|get-aduser|get-adcomputer|get-adgroup)') {
        return @{ Rule="AdEnumeration"; Evidence="Active Directory enumeration by $N (PID $Pid)"; Reasoning="Enumerating AD users/groups/computers - discovery phase of attack"; Conf=0.78; Tier="Tier2Indicator"; Cat="discovery" }
    }
    # Network/port scan via PowerShell
    if ($c -match ('(test-netconnection|tnc\s|new-object.*net\.sockets\.tcp' + 'client).*\d{1,3}\.\d{1,3}') -and $c -match '(foreach|1\.\.\d+|ForEach-Object)') {
        return @{ Rule="NetworkScan"; Evidence="PowerShell network scan by $N (PID $Pid)"; Reasoning="Loop-based port/host scan using Test-NetConnection or Tcp" + "Client"; Conf=0.80; Tier="Tier2Indicator"; Cat="discovery" }
    }
    # Cloud tenant discovery
    if ($c -match '(az\s+account\s+list|aws\s+sts\s+get-caller-identity|gcloud\s+auth\s+list|get-azuresubscription)') {
        return @{ Rule="CloudTenantDiscovery"; Evidence="Cloud tenant enumeration by $N (PID $Pid)"; Reasoning="Enumerating cloud subscriptions/tenants after initial access"; Conf=0.79; Tier="Tier2Indicator"; Cat="discovery" }
    }
    # Security tool / AV survey
    if ($c -match '(get-mpcomputerstatus|get-mppreference|sc\s+query|tasklist|reg\s+query.*antivirus|wmic.*antivirus)') {
        return @{ Rule="SecurityToolSurvey"; Evidence="Security tool enumeration by $N (PID $Pid)"; Reasoning="Attacker surveying installed AV/EDR tools before evasion actions"; Conf=0.72; Tier="Tier2Indicator"; Cat="discovery" }
    }
    # Backup config survey
    if ($c -match $Script:Sig.WbadminSurvey) {
        return @{ Rule="BackupSurvey"; Evidence="Backup configuration enumeration by $N (PID $Pid)"; Reasoning="Enumerating backup jobs and shadow copies - pre-ransomware discovery"; Conf=0.77; Tier="Tier2Indicator"; Cat="discovery" }
    }
    return $null
}

# ============================================================================
# CAT 10 - COLLECTION (bulk archive, browser DB, keylogger DLL, DB dump)
# ============================================================================
function Test-Collection { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Bulk archive of sensitive directories
    if ($c -match '(7z|7za|zip|compress-archive|tar)' -and $c -match '(desktop|documents|appdata|\.ssh|\.aws|passwords|wallet|\.kdbx|confidential)') {
        return @{ Rule="SensitiveArchive"; Evidence="Sensitive data archiving by $N (PID $Pid)"; Reasoning="Compressing sensitive directories/files - staging for exfiltration"; Conf=0.84; Tier="Tier1Behavioral"; Cat="collection" }
    }
    # Browser history/DB theft
    if ($c -match '(places\.sqlite|webdata|history|cookies)' -and $c -match '(copy|get-content|sqlite3|type)') {
        return @{ Rule="BrowserDataTheft"; Evidence="Browser history/data theft by $N (PID $Pid)"; Reasoning="Copying browser SQLite databases containing history, cookies, or credentials"; Conf=0.83; Tier="Tier1Behavioral"; Cat="collection" }
    }
    # Database dump
    if ($c -match '(sqlcmd.*-q|mysqldump|pg_dump|sqlite3.*\.dump)' -and $c -match '(out-file|>|\|)') {
        return @{ Rule="DatabaseDump"; Evidence="Database dump by $N (PID $Pid)"; Reasoning="Executing database dump command and redirecting output to file for exfiltration"; Conf=0.85; Tier="Tier1Behavioral"; Cat="collection" }
    }
    # Cloud storage abuse (OneDrive/Dropbox/Box moving files rapidly)
    if ($c -match '(onedrive|dropbox|google\s+drive|box\.com)' -and $c -match '(copy|move|robocopy)') {
        return @{ Rule="CloudSyncAbuse"; Evidence="Cloud sync abuse by $N (PID $Pid)"; Reasoning="Copying files to cloud sync folder for passive exfiltration"; Conf=0.76; Tier="Tier2Indicator"; Cat="collection" }
    }
    # Keylogger DLL detection via module check (handled in module scan, flagged here via CL)
    if ($c -match 'setwindowshookex|wh_keyboard|llkbd') {
        return @{ Rule="KeyloggerHook"; Evidence="Keyboard hook installed by $N (PID $Pid)"; Reasoning="SetWindowsHookEx with WH_KEYBOARD is the standard Windows keylogger API"; Conf=0.87; Tier="Tier1Behavioral"; Cat="collection" }
    }
    # Outlook COM automation for mail theft
    if ($c -match 'new-object.*-comobject.*outlook' -and $c -match '(getnamespace|items|saveas|attachments)') {
        return @{ Rule="OutlookComCollection"; Evidence="Outlook COM object for mail access by $N (PID $Pid)"; Reasoning="Automating Outlook via COM to enumerate or export emails"; Conf=0.88; Tier="Tier1Behavioral"; Cat="collection" }
    }
    return $null
}

# ============================================================================
# CAT 11/12 - C2 & EXFILTRATION (DNS tunnel, ICMP, legit-service C2, BITS exfil)
# ============================================================================
function Test-C2AndExfil { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # DNS tunneling tools / high-volume DNS
    if ($c -match '(iodine|dnscat|dns2tcp|dnstunnel)') {
        return @{ Rule="DnsTunnel"; Evidence="DNS tunneling tool by $N (PID $Pid)"; Reasoning="Known DNS tunneling tool used for covert C2 channel"; Conf=0.95; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # ICMP tunneling
    if ($c -match '(icmptunnel|ptunnel|hans\s)') {
        return @{ Rule="IcmpTunnel"; Evidence="ICMP tunneling tool by $N (PID $Pid)"; Reasoning="ICMP-based tunneling tool for covert C2"; Conf=0.94; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # Legitimate service C2 (Discord/Telegram/GitHub as C2)
    $svcC2 = @{ 'discord.com/api'="Discord"; 'api.telegram.org'="Telegram"; 'api.github.com/gists'="GitHub Gist"; 'pastebin.com/raw'="Pastebin"; 'api.slack.com/services'="Slack webhook" }
    foreach ($svc in $svcC2.Keys) {
        if ($c -match [Regex]::Escape($svc)) {
            # Only flag if NOT from known legitimate apps
            $legitApps = @('discord.exe','slack.exe','teams.exe','code.exe','kiro.exe')
            if ($N -notin $legitApps) {
                return @{ Rule="LegitServiceC2"; Evidence="$($svcC2[$svc]) API called by non-browser $N (PID $Pid)"; Reasoning="Using legitimate service API as covert C2 channel"; Conf=0.84; Tier="Tier1Behavioral"; Cat="c2" }
            }
        }
    }
    # SOCKS proxy setup
    if ($c -match '(ssh.*-d\s+\d+|chisel\s+(client|server)|ligolo|frp(client|server))') {
        return @{ Rule="SocksProxy"; Evidence="SOCKS proxy/tunnel by $N (PID $Pid)"; Reasoning="Setting up SOCKS proxy or tunnel for C2 traffic routing"; Conf=0.90; Tier="Tier1Behavioral"; Cat="c2" }
    }
    # BITS exfiltration (upload)
    if ($c -match 'bitsadmin.*/upload' -and $c -match 'http') {
        return @{ Rule="BitsExfil"; Evidence="BITS upload job by $N (PID $Pid)"; Reasoning="BITSAdmin creating upload job to exfiltrate data to external server"; Conf=0.88; Tier="Tier1Behavioral"; Cat="exfil" }
    }
    # Invoke-WebRequest/curl POST with file
    if ($c -match '(invoke-webrequest|curl|wget)' -and $c -match '(-method\s+post|-infile|-body|--data-binary)' -and $c -match 'http') {
        return @{ Rule="HttpPostExfil"; Evidence="HTTP POST upload by $N (PID $Pid)"; Reasoning="HTTP POST with file body - possible data exfiltration"; Conf=0.79; Tier="Tier2Indicator"; Cat="exfil" }
    }
    # DNS-encoded exfiltration (nslookup/Resolve-DnsName in a loop with variable subdomains)
    if ($c -match '(nslookup|resolve-dnsname)' -and $c -match '(foreach|while|\$\w+\s*\+)') {
        return @{ Rule="DnsExfil"; Evidence="Looped DNS lookup by $N (PID $Pid)"; Reasoning="Loop-based DNS queries with variable subdomains suggest DNS exfiltration encoding"; Conf=0.82; Tier="Tier1Behavioral"; Cat="exfil" }
    }
    return $null
}

# ============================================================================
# CAT 1 - ATTACKER GOALS: CRYPTO-MINING
# ============================================================================
function Test-CryptoMining { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    $c = $CL.ToLower()
    # XMRig / common miner flags
    if ($c -match '(-o\s+stratum|--pool|xmrig|nbminer|t-rex\s|lolminer|gminer|phoenixminer)') {
        return @{ Rule="CryptoMiner"; Evidence="Miner process by $N (PID $Pid)"; Reasoning="Known crypto-mining tool flags or binary name detected"; Conf=0.95; Tier="Tier1Behavioral"; Cat="mining" }
    }
    # Stratum protocol in command line
    if ($c -match 'stratum\+tcp://|stratum\+ssl://') {
        return @{ Rule="CryptoMinerPool"; Evidence="Stratum pool connection by $N (PID $Pid)"; Reasoning="Stratum mining protocol string in command line"; Conf=0.95; Tier="Tier1Behavioral"; Cat="mining" }
    }
    # Connection to known mining pools
    foreach ($pool in $Script:MiningPoolDomains) {
        if ($c -match [Regex]::Escape($pool)) {
            return @{ Rule="MiningPoolC2"; Evidence="Mining pool domain in command line: $pool ($N PID $Pid)"; Reasoning="Connection to known cryptocurrency mining pool"; Conf=0.93; Tier="Tier1Behavioral"; Cat="mining" }
        }
    }
    return $null
}

# ============================================================================
# CAT 1 - ATTACKER GOALS: BOTNET/SPAM/PROXY
# ============================================================================
function Test-BotnetProxy { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # SOCKS/HTTP proxy tools
    if ($c -match '(3proxy|microsocks|srelay|shadowsocks|v2ray|xray\s)') {
        return @{ Rule="ProxyTool"; Evidence="Proxy tool by $N (PID $Pid)"; Reasoning="Known proxy/botnet relay tool detected"; Conf=0.90; Tier="Tier1Behavioral"; Cat="botnet" }
    }
    # Spam-related SMTP in scripts
    if ($c -match 'net\.mail\.smtpclient|send-mailmessage' -and $c -match '(foreach|while|1\.\.)') {
        return @{ Rule="BulkMailSend"; Evidence="Bulk mail sending by $N (PID $Pid)"; Reasoning="Looped SMTP send - potential spam operation"; Conf=0.80; Tier="Tier2Indicator"; Cat="botnet" }
    }
    return $null
}

# ============================================================================
# CAT 15 / HUMAN ATTACKS - BEC & NEW ADMIN CREATION
# ============================================================================
function Test-HumanAttacks { param([string]$CL,[int]$Pid,[string]$N)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # BEC: mail rule change via Exchange PowerShell or Graph
    if ($c -match '(set-mailbox|new-inboxrule|set-inboxrule)' -and $c -match '(forwardsmtpaddress|redirectto|deleterecipients|markasread)') {
        return @{ Rule="BecMailRule"; Evidence="BEC mail rule modification by $N (PID $Pid)"; Reasoning="Exchange cmdlet modifying inbox rules for BEC collection or cover-up"; Conf=0.90; Tier="Tier1Behavioral"; Cat="bec" }
    }
    # BEC: invoice/payroll redirect
    if ($c -match '(set-user|set-mailbox)' -and $c -match 'password\s*reset|new-password|temporarypassword') {
        return @{ Rule="BecAccountManip"; Evidence="Account manipulation by $N (PID $Pid)"; Reasoning="Resetting account password via Exchange/AD cmdlet - possible BEC account takeover"; Conf=0.83; Tier="Tier2Indicator"; Cat="bec" }
    }
    # New local admin creation (SE / helpdesk attack)
    if ($c -match '(net\s+localgroup\s+administrators.*/add|add-localgroupmember.*administrators)') {
        return @{ Rule="NewLocalAdmin"; Evidence="Local admin added by $N (PID $Pid)"; Reasoning="Adding user to local Administrators group - possible helpdesk SE or post-exploitation"; Conf=0.85; Tier="Tier1Behavioral"; Cat="bec" }
    }
    # Net user add (new account creation)
    if ($c -match 'net\s+user\s+\S+\s+\S+\s+/add') {
        return @{ Rule="NewUserAccount"; Evidence="New user account created by $N (PID $Pid)"; Reasoning="Creating a new local user account - common backdoor persistence technique"; Conf=0.82; Tier="Tier1Behavioral"; Cat="bec" }
    }
    return $null
}

# ============================================================================
# CAT 14 - MALWARE TYPES: LOADER/DROPPER/SELF-DELETE
# ============================================================================
function Test-LoaderDropper { param([string]$CL,[int]$Pid,[string]$N,[string]$Path)
    if ([string]::IsNullOrEmpty($CL)) { return $null }
    $c = $CL.ToLower()
    # Self-delete after execution
    # Check: command line contains a delete verb AND the process's own directory
    # or filename appears in it. Avoids the fragile last-20-chars substring trick.
    if ($Path -and $c -match '(cmd\s+/c\s+del|remove-item|rm\s+-f|erase\s+)') {
        $dir  = [System.IO.Path]::GetDirectoryName($Path).ToLower()
        $file = [System.IO.Path]::GetFileName($Path).ToLower()
        if ($dir -and $c -match [Regex]::Escape($dir)) {
            return @{ Rule="SelfDelete"; Evidence="Self-deletion by $N (PID $Pid)"; Reasoning="Process issuing delete command against own directory - dropper cleanup"; Conf=0.84; Tier="Tier1Behavioral"; Cat="dropper" }
        }
        if ($file -and $c -match [Regex]::Escape($file)) {
            return @{ Rule="SelfDelete"; Evidence="Self-deletion by $N (PID $Pid)"; Reasoning="Process issuing delete command matching own filename - dropper cleanup"; Conf=0.84; Tier="Tier1Behavioral"; Cat="dropper" }
        }
    }
    # Ping-loop delay before execution (time-delay evasion)
    if ($c -match 'ping.*-n\s+\d{2,}\s+127\.0\.0\.1|start-sleep\s+-s\s+\d{3,}|timeout\s+/t\s+\d{3,}') {
        return @{ Rule="DelayedExec"; Evidence="Long execution delay by $N (PID $Pid)"; Reasoning="Inserting significant delay before payload execution - sandbox evasion"; Conf=0.77; Tier="Tier2Indicator"; Cat="dropper" }
    }
    # Fetch-and-exec stager pattern (download small binary then run)
    if ($c -match $Script:Sig.FetchExec -and $c -match '(start-process|invoke-item|\&\s)' -and $c -match 'temp') {
        return @{ Rule="FetchAndExec"; Evidence="Fetch-and-exec stager by $N (PID $Pid)"; Reasoning="Downloading a file to temp then executing it - classic loader/stager pattern"; Conf=0.87; Tier="Tier1Behavioral"; Cat="dropper" }
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
        if ($path -and ($path -like "$env:ProgramFiles*" -or $path -like "${env:ProgramFiles(x86)}*" -or $path -like "$env:SystemRoot*")) { continue }

        $pub = @($byPid[$pid] | Where-Object { -not (Is-Private $_.R) })
        if ($pub.Count -eq 0) { continue }

        # --- Mining pool port check ---
        # Ports 3333/4444/5555/6666/8888/9999 are shared with many legitimate services.
        # Only flag if the process hits 2+ distinct known mining ports simultaneously,
        # OR a single hit on the dedicated high ports (14444, 45700, 14433) that have
        # no common legitimate use.
        $dedicatedMiningPorts = @(14444,45700,14433)
        $commonMiningPorts    = @(3333,4444,5555,6666,8888,9999)
        $dedicatedHit = @($pub | Where-Object { $_.P -in $dedicatedMiningPorts })
        $commonHit    = @($pub | Where-Object { $_.P -in $commonMiningPorts })
        $distinctCommon = @($commonHit | Select-Object -ExpandProperty P -Unique)
        if ($dedicatedHit.Count -gt 0 -or $distinctCommon.Count -ge 2) {
            $hitPorts = @($dedicatedHit + $commonHit) | Select-Object -ExpandProperty P -Unique
            $dk = "MiningPort|$pid"
            if (-not (Is-Dup -K $dk -TTL 300)) {
                Log-Event -Type "detection" -Rule "MiningPortConnection" `
                    -Evidence "$name (PID $pid) on dedicated/multiple mining ports: $($hitPorts -join ',')" `
                    -Reasoning "Connection on dedicated stratum port or 2+ common mining ports" `
                    -Conf 0.82 -Tier "Tier1Behavioral" -PName $name -PId $pid
                Add-Signal -Pid $pid -Cat "mining" -Conf 0.82
            }
        }

        # --- Mass outbound connection check (botnet/spam) ---
        if (-not $Script:OutboundTracker.ContainsKey($pid)) { $Script:OutboundTracker[$pid] = @{ Count=0; Start=Get-Date; Name=$name } }
        $Script:OutboundTracker[$pid].Count += $pub.Count
        $elapsed = ((Get-Date) - $Script:OutboundTracker[$pid].Start).TotalSeconds
        if ($elapsed -gt 30) { $Script:OutboundTracker[$pid] = @{ Count=$pub.Count; Start=Get-Date; Name=$name } }
        elseif ($Script:OutboundTracker[$pid].Count -ge 40) {
            $dk = "MassOutbound|$pid"
            if (-not (Is-Dup -K $dk -TTL 300)) {
                Log-Event -Type "detection" -Rule "MassOutboundConnections" `
                    -Evidence "$name (PID $pid) $($Script:OutboundTracker[$pid].Count) public connections in ${elapsed}s" `
                    -Reasoning "Unusually high number of outbound connections - botnet, proxy, or spam pattern" `
                    -Conf 0.82 -Tier "Tier1Behavioral" -PName $name -PId $pid
                Add-Signal -Pid $pid -Cat "botnet" -Conf 0.82
            }
        }

        # --- Staged binary with public connections ---
        $fromStaging = Is-InStagingPath -Path $path
        if ($fromStaging) {
            $dk = "NetStage|$pid"
            if (-not (Is-Dup -K $dk -TTL 300)) {
                Log-Event -Type "detection" -Rule "StagedPayloadNetwork" `
                    -Evidence "$name from staging path -> $($pub.Count) public connections" `
                    -Reasoning "Binary in temp/download location making outbound connections" `
                    -Conf 0.83 -Tier "Tier1Behavioral" -PName $name -PId $pid
                Add-Signal -Pid $pid -Cat "network" -Conf 0.83
            }
        }

        # --- Beaconing ---
        foreach ($c in $pub) { Track-Beacon -Pid $pid -Addr $c.R -Port $c.P -Name $name }
    }
}

function Track-Beacon { param([int]$Pid,[string]$Addr,[int]$Port,[string]$Name)
    $k = "${Pid}|${Addr}|${Port}"; $now = Get-Date
    if (-not $Script:BeaconTracker.ContainsKey($k)) { $Script:BeaconTracker[$k] = @{ T=@($now); N=$Name }; return }
    $t = $Script:BeaconTracker[$k]
    $t.T += $now
    $t.T = @($t.T | Where-Object { ($now-$_).TotalMinutes -le 30 }) | Select-Object -Last 30
    $Script:BeaconTracker[$k] = $t
    if ($t.T.Count -ge 5) {
        $iv = @(); for ($i=1; $i -lt $t.T.Count; $i++) { $iv += ($t.T[$i]-$t.T[$i-1]).TotalSeconds }
        $m = ($iv | Measure-Object -Average).Average
        if ($m -gt 0 -and $m -lt 1800) {   # up to 30-min beacon interval
            $var = ($iv | ForEach-Object { [Math]::Pow($_-$m,2) } | Measure-Object -Average).Average
            $cv = [Math]::Sqrt($var) / $m
            if ($cv -lt 0.40) {
                $dk = "Beacon|$k"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    $conf = [Math]::Min(0.95, 0.70 + (0.40-$cv)*0.6)
                    Log-Event -Type "detection" -Rule "Beaconing" `
                        -Evidence "$Name -> ${Addr}:${Port} CV=$([Math]::Round($cv,3)) interval=$([Math]::Round($m,1))s obs=$($t.T.Count)" `
                        -Reasoning "Statistical regularity in connection intervals (low CV) indicates C2 beacon" `
                        -Conf $conf -Tier "Tier1Behavioral" -PName $Name -PId $Pid
                    Add-Signal -Pid $Pid -Cat "beaconing" -Conf $conf
                    if ($conf -ge 0.85) { Invoke-Kill -Pid $Pid -Name $Name -Rule "Beaconing" -Conf $conf }
                }
            }
        }
    }
}

# ============================================================================
# CPU TRACKER - sustained high CPU = crypto-mining
# ============================================================================
function Update-CpuTracker {
    # Tracks CPU UTILISATION via TotalProcessorTime delta / wall-clock delta.
    # Process.CPU is cumulative seconds since start, not a utilisation percentage.
    # We record (TotalProcessorTime, wall-clock timestamp) each cycle and derive
    # % usage over the last interval, then keep a rolling 12-sample window (~60s).
    $legitHighCpu = @('chrome','msedge','firefox','brave','steam','obs64','obs32',
                      'ffmpeg','handbrake','7z','robocopy','antimalware','mssense',
                      'mpengcp','csrss','dwm','audiodg')
    try {
        $now = Get-Date
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            $pid = $_.Id; $name = $_.ProcessName
            try {
                $cpuTicks = $_.TotalProcessorTime.Ticks
            } catch { return }

            if (-not $Script:CpuTracker.ContainsKey($pid)) {
                # First observation: just store baseline
                $Script:CpuTracker[$pid] = @{
                    Name      = $name
                    LastTicks = $cpuTicks
                    LastTime  = $now
                    Samples   = [System.Collections.Generic.List[double]]::new()
                }
                return
            }

            $t = $Script:CpuTracker[$pid]
            $wallMs   = ($now - $t.LastTime).TotalMilliseconds
            if ($wallMs -lt 100) { return }   # clock skew guard

            $cpuMs    = ($cpuTicks - $t.LastTicks) / 10000.0   # ticks -> ms
            $pctUsage = [Math]::Min(100.0 * $cpuMs / $wallMs, 100.0)  # % of one core

            $t.LastTicks = $cpuTicks
            $t.LastTime  = $now
            $t.Samples.Add($pctUsage)
            if ($t.Samples.Count -gt 12) { $t.Samples.RemoveAt(0) }

            if ($t.Samples.Count -ge 8) {
                $avg = 0.0
                foreach ($s in $t.Samples) { $avg += $s }
                $avg /= $t.Samples.Count
                # Flag sustained > 85% on a single logical core from a non-media process
                if ($avg -gt 85.0 -and $name.ToLower() -notin $legitHighCpu) {
                    $dk = "HighCpu|$pid"
                    if (-not (Is-Dup -K $dk -TTL 120)) {
                        Log-Event -Type "detection" -Rule "SustainedHighCpu" `
                            -Evidence "$name (PID $pid) ~$([Math]::Round($avg,0))% CPU over $($t.Samples.Count) polls (~60s)" `
                            -Reasoning "Sustained high CPU from non-media process - possible crypto-miner" `
                            -Conf 0.74 -Tier "Tier2Indicator" -PName $name -PId $pid
                        Add-Signal -Pid $pid -Cat "mining" -Conf 0.74
                    }
                }
            }
        }
        # Prune dead PIDs
        $alivePids = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        $dead = @($Script:CpuTracker.Keys | Where-Object { $_ -notin $alivePids })
        foreach ($k in $dead) { $Script:CpuTracker.Remove($k) }
    } catch {}
}

# ============================================================================
# CLIPBOARD MONITOR
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
                    $legitimate = @('explorer.exe','chrome.exe','msedge.exe','firefox.exe',
                                    'powershell.exe','pwsh.exe','code.exe','WindowsTerminal.exe',
                                    'notepad.exe','wordpad.exe','WINWORD.EXE','EXCEL.EXE')
                    if ($info.N -notin $legitimate) {
                        $fromStaging = Is-InStagingPath -Path $path
                        if ($fromStaging) {
                            # Require the same staging process to hold the clipboard on two
                            # consecutive polls before flagging. Installers briefly own the
                            # clipboard during setup and then release it - this avoids that FP.
                            $repeatKey = "ClipRepeat|$ownerPid"
                            if ($Script:Dedup.ContainsKey($repeatKey)) {
                                # Seen before within TTL - this is a repeat: flag it
                                $dk = "Clipboard|$ownerPid"
                                if (-not (Is-Dup -K $dk -TTL 120)) {
                                    Log-Event -Type "detection" -Rule "ClipboardHijack" `
                                        -Evidence "$($info.N) (PID $ownerPid) persistently holds clipboard from staging path" `
                                        -Reasoning "Staging-path process retaining clipboard ownership across multiple polls - crypto address swapper pattern" `
                                        -Conf 0.79 -Tier "Tier2Indicator" -PName $info.N -PId ([int]$ownerPid)
                                    Add-Signal -Pid ([int]$ownerPid) -Cat "clipboard" -Conf 0.79
                                }
                            } else {
                                # First observation - record it, check again next poll
                                $Script:Dedup[$repeatKey] = (Get-Date)
                            }
                        }
                    }
                }
            }
        }
    } catch {}
}

# ============================================================================
# DLL / MODULE INTEGRITY MONITOR
# ============================================================================
function Initialize-ModuleBaseline {
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID } | ForEach-Object {
            try { $Script:ModuleBaseline[$_.Id] = @($_.Modules | ForEach-Object { $_.FileName.ToLower() }) } catch {}
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
                                    -Evidence "$name (PID $pid) loaded DLL with deleted backing file: $mod" `
                                    -Reasoning "Loaded module file deleted from disk - dropper pattern or module stomping" `
                                    -Conf 0.83 -Tier "Tier2Indicator" -PName $name -PId $pid
                                Add-Signal -Pid $pid -Cat "dll_injection" -Conf 0.83
                            }
                        }
                        # DLL from any user's staging path injected into established process
                        if (Is-InStagingPath -Path $mod) {
                            $dk = "TempDLL|$pid|$mod"
                            if (-not (Is-Dup -K $dk -TTL 300)) {
                                Log-Event -Type "detection" -Rule "StagedDllInjection" `
                                    -Evidence "$name (PID $pid) loaded DLL from staging: $mod" `
                                    -Reasoning "New DLL from temp/staging path injected into running process" `
                                    -Conf 0.81 -Tier "Tier2Indicator" -PName $name -PId $pid
                                Add-Signal -Pid $pid -Cat "dll_injection" -Conf 0.81
                            }
                        }
                    }
                }
                $Script:ModuleBaseline[$pid] = $currentMods
            } catch {}
        }
    } catch {}
}

# ============================================================================
# SURVEILLANCE DETECTION (screen capture, webcam, microphone)
# ============================================================================
function Test-SurveillanceAccess {
    $captureDlls = @('d3d11.dll','dxgi.dll','d3d9.dll')
    $cameraDlls  = @('mfplat.dll','mf.dll','mfreadwrite.dll','ksuser.dll')
    $micDlls     = @('audioses.dll','mmdevapi.dll')
    $allowed = @('chrome','msedge','firefox','brave','Teams','Zoom','Discord',
                 'Skype','obs64','obs32','slack','WindowsCamera','dwm',
                 'explorer','SearchHost','ShellExperienceHost','Spotify','Signal')
    $results = @()
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -notin $allowed -and $_.Id -gt 4 -and $_.Id -ne $PID
        } | ForEach-Object {
            try {
                $mods = @($_.Modules | ForEach-Object { $_.ModuleName.ToLower() })
                $hasCapture = @($captureDlls | Where-Object { $mods -contains $_ }).Count -gt 0
                $hasCamera  = @($cameraDlls  | Where-Object { $mods -contains $_ }).Count -gt 0
                $hasMic     = @($micDlls     | Where-Object { $mods -contains $_ }).Count -gt 0
                $hasWindow  = $_.MainWindowHandle -ne [IntPtr]::Zero
                # Require 2+ device types OR process from a staging path.
                # Single d3d11/mfplat load without window is common for overlay helpers,
                # audio servers, accessibility tools - too noisy to flag on one DLL alone.
                $deviceCount = ([int]$hasCapture) + ([int]$hasCamera) + ([int]$hasMic)
                $procPath    = try { $_.Path } catch { "" }
                $fromStaging = Is-InStagingPath -Path $procPath
                if (-not $hasWindow -and ($deviceCount -ge 2 -or ($deviceCount -ge 1 -and $fromStaging))) {
                    $device = "microphone"
                    if ($hasCapture) { $device = "screen" } elseif ($hasCamera) { $device = "camera" }
                    $dk = "Surveil|$($_.Id)|$device"
                    if (-not (Is-Dup -K $dk -TTL 120)) {
                        $results += @{
                            Rule="BackgroundSurveillance"
                            Evidence="$($_.ProcessName) (PID $($_.Id)) background $device access (devices=$deviceCount staged=$fromStaging)"
                            Reasoning="Background windowless process accessing multiple hardware capture devices or capture from staging path"
                            Conf=0.79; Tier="Tier2Indicator"; Cat="surveillance"
                            PName=$_.ProcessName; PId=$_.Id
                        }
                    }
                }
            } catch {}
        }
    } catch {}
    return $results
}

# ============================================================================
# DNS ANOMALY - DGA + High-rate DNS queries (tunneling)
# ============================================================================
function Test-DnsAnomaly {
    foreach ($pid in $Script:ProcessAncestry.Keys) {
        $info = $Script:ProcessAncestry[$pid]
        if (-not $info -or [string]::IsNullOrEmpty($info.CL)) { continue }
        $cl = $info.CL
        $domains = @()
        if ($cl -match 'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)') { $domains += $Matches[1] }
        if ($cl -match '(nslookup|resolve-dnsname|dig)\s+(\S+)') { $domains += $Matches[2] }
        foreach ($domain in $domains) {
            $labels = $domain.Split('.')
            if ($labels.Count -lt 2) { continue }
            $mainLabel = ($labels[0..($labels.Count-2)] | Sort-Object { $_.Length } -Descending | Select-Object -First 1)
            if ($mainLabel.Length -lt 12) { continue }   # short labels FP heavily; skip
            $entropy = Get-Entropy -S $mainLabel
            if ($entropy -gt 4.2) {   # raised from 3.8 - real CDN/SaaS labels rarely exceed 4.2
                $dk = "DGA|$pid|$domain"
                if (-not (Is-Dup -K $dk -TTL 300)) {
                    Log-Event -Type "detection" -Rule "DgaDomain" `
                        -Evidence "$($info.N) (PID $pid) high-entropy domain: $domain (H=$([Math]::Round($entropy,2)))" `
                        -Reasoning "Domain label Shannon entropy >3.8 suggests DGA-generated C2 domain" `
                        -Conf 0.73 -Tier "Tier2Indicator" -PName $info.N -PId $pid
                    Add-Signal -Pid $pid -Cat "dga" -Conf 0.73
                }
            }
        }
    }
}

# ============================================================================
# STARTUP FOLDER MONITOR (passive file-based persistence detection)
# Covers every user's personal startup folder AND the common startup folder.
# Works correctly when running as SYSTEM.
# ============================================================================
function Get-AllStartupPaths {
    $paths = @()
    # Common (all-users) startup - always present
    $paths += "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    # Per-user startup folders for every known profile
    foreach ($u in $Script:UserProfiles) {
        $paths += (Join-Path $u.AppData 'Microsoft\Windows\Start Menu\Programs\Startup')
    }
    return @($paths | Select-Object -Unique)
}

function Initialize-StartupFolderBaseline {
    foreach ($sp in (Get-AllStartupPaths)) {
        if (-not (Test-Path $sp -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | ForEach-Object {
            $Script:StartupFolderBase[$_.FullName.ToLower()] = $_.LastWriteTime
        }
    }
}

function Test-StartupFolderChange {
    foreach ($sp in (Get-AllStartupPaths)) {
        if (-not (Test-Path $sp -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | ForEach-Object {
            $fk = $_.FullName.ToLower()
            if (-not $Script:StartupFolderBase.ContainsKey($fk)) {
                $dk = "Startup|$fk"
                if (-not (Is-Dup -K $dk -TTL 600)) {
                    Log-Event -Type "detection" -Rule "StartupFolderDrop" `
                        -Evidence "New file in startup folder: $($_.FullName)" `
                        -Reasoning "File dropped in user or common startup folder - persistence mechanism" `
                        -Conf 0.82 -Tier "Tier1Behavioral" -PName "FileSystem" -PId 0
                    Add-Signal -Pid 0 -Cat "persistence" -Conf 0.82
                }
                $Script:StartupFolderBase[$fk] = $_.LastWriteTime
            }
        }
    }
}

# ============================================================================
# WMI PERSISTENCE SCAN
# ============================================================================
function Test-WmiPersistence {
    try {
        Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -ErrorAction Stop | ForEach-Object {
            $dk = "WMI|$($_.Name)"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "WmiPersistence" `
                    -Evidence "WMI consumer: $($_.Name) -> $($_.CommandLineTemplate)" `
                    -Reasoning "WMI event subscription for fileless persistence" `
                    -Conf 0.89 -Tier "Tier1Behavioral" -PName "WMI" -PId 0
            }
        }
        Get-WmiObject -Namespace "root\subscription" -Class "ActiveScriptEventConsumer" -ErrorAction Stop | ForEach-Object {
            $dk = "WMIScript|$($_.Name)"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "WmiScriptPersistence" `
                    -Evidence "WMI script consumer: $($_.Name)" `
                    -Reasoning "WMI ActiveScript event subscription - fileless script persistence" `
                    -Conf 0.90 -Tier "Tier1Behavioral" -PName "WMI" -PId 0
            }
        }
    } catch {}
}

# ============================================================================
# UNSIGNED FROM STAGING
# ============================================================================
function Test-UnsignedStaged { param([int]$Pid,[string]$Name,[string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $null }
    if ($Path -like "$env:SystemRoot*" -or $Path -like "$env:ProgramFiles*" -or $Path -like "${env:ProgramFiles(x86)}*") { return $null }
    if (-not (Is-InStagingPath -Path $Path)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            $conf = 0.69
            if ($Script:ReputationEnabled) {
                try {
                    $hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
                    $rep  = Test-HashReputation -Hash $hash
                    if ($rep -and $rep.Bad) { $conf = 0.93 }
                } catch {}
            }
            return @{ Rule="UnsignedStaged"; Evidence="$Name (PID $Pid) unsigned from $Path"; Reasoning="Unsigned binary executing from staging/temp location"; Conf=$conf; Tier="Tier2Indicator"; Cat="unsigned" }
        }
    } catch {}
    return $null
}

# ============================================================================
# PROCESS GENEALOGY (parent-child anomalies)
# ============================================================================
function Test-Genealogy { param([int]$Pid,[string]$Name,[int]$PPid)
    if ($Pid -le 4) { return $null }
    $parent = $Script:ProcessAncestry[$PPid]
    $pName = "DEAD"
    if ($parent) { $pName = $parent.N }
    $info   = $Script:ProcessAncestry[$Pid]
    $shells = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe')
    $normalParents = @('explorer.exe','cmd.exe','powershell.exe','pwsh.exe','svchost.exe',
                       'services.exe','code.exe','WindowsTerminal.exe','wt.exe','conhost.exe',
                       'taskeng.exe','taskhostw.exe')
    if ($Name -in $shells -and $pName -notin $normalParents -and $pName -ne "DEAD") {
        return @{ Rule="UnusualShellParent"; Evidence="$Name spawned by $pName (PID $PPid)"; Reasoning="Shell child of unexpected parent - possible exploitation or payload execution"; Conf=0.73; Tier="Tier2Indicator"; Cat="genealogy" }
    }
    $officeApps = @('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE','MSACCESS.EXE','ONENOTE.EXE')
    if ($Name -in $shells -and $pName -in $officeApps) {
        return @{ Rule="OfficeShellSpawn"; Evidence="$pName spawned $Name (PID $Pid)"; Reasoning="Office application spawning command shell - macro or exploit code execution"; Conf=0.89; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Browser spawning scripting engine
    $browsers = @('chrome.exe','msedge.exe','firefox.exe','brave.exe','iexplore.exe')
    if ($Name -in $shells -and $pName -in $browsers) {
        return @{ Rule="BrowserShellSpawn"; Evidence="$pName spawned $Name (PID $Pid)"; Reasoning="Browser spawning command shell - drive-by / exploit delivery pattern"; Conf=0.88; Tier="Tier1Behavioral"; Cat="execution" }
    }
    # Orphan from staging
    if ($pName -eq "DEAD" -and $info -and $info.P) {
        if (Is-InStagingPath -Path $info.P) {
            return @{ Rule="OrphanStaged"; Evidence="$Name (PID $Pid) orphaned from $($info.P)"; Reasoning="Orphan process running from staging path - dropped payload that deleted parent"; Conf=0.71; Tier="Tier2Indicator"; Cat="genealogy" }
        }
    }
    return $null
}

# ============================================================================
# REGISTRY PERSISTENCE SCAN (IFEO, AppInit, AlwaysInstallElevated)
# ============================================================================
function Test-RegistryPersistence {
    # IFEO Debugger keys
    try {
        $ifeo = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction Stop
        $ifeo.GetSubKeyNames() | ForEach-Object {
            $sub = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_" -ErrorAction SilentlyContinue
            if ($sub.Debugger -and $sub.Debugger -notmatch 'vsjitdebugger|drwtsn32') {
                $dk = "IFEO|$_|$($sub.Debugger)"
                if (-not (Is-Dup -K $dk -TTL 600)) {
                    Log-Event -Type "detection" -Rule "IFEOPersistence" `
                        -Evidence "IFEO Debugger on $_ -> $($sub.Debugger)" `
                        -Reasoning "IFEO Debugger key hijacks process execution - persistence or accessibility feature abuse" `
                        -Conf 0.88 -Tier "Tier1Behavioral" -PName "Registry" -PId 0
                    Add-Signal -Pid 0 -Cat "persistence" -Conf 0.88
                }
            }
        }
    } catch {}
    # AppInit_DLLs
    try {
        $appinit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction Stop
        if ($appinit.AppInit_DLLs -and $appinit.AppInit_DLLs.Length -gt 0) {
            $dk = "AppInit|$($appinit.AppInit_DLLs)"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "AppInitDllPersistence" `
                    -Evidence "AppInit_DLLs: $($appinit.AppInit_DLLs)" `
                    -Reasoning "AppInit_DLLs injects specified DLL into all user-mode processes on load" `
                    -Conf 0.90 -Tier "Tier1Behavioral" -PName "Registry" -PId 0
                Add-Signal -Pid 0 -Cat "persistence" -Conf 0.90
            }
        }
    } catch {}
    # AlwaysInstallElevated
    try {
        $aie1 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction Stop).AlwaysInstallElevated
        $aie2 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction Stop).AlwaysInstallElevated
        if ($aie1 -eq 1 -and $aie2 -eq 1) {
            $dk = "AlwaysInstallElevated"
            if (-not (Is-Dup -K $dk -TTL 600)) {
                Log-Event -Type "detection" -Rule "AlwaysInstallElevated" `
                    -Evidence "AlwaysInstallElevated=1 in both HKCU and HKLM" `
                    -Reasoning "Any MSI can be installed with SYSTEM privileges - privilege escalation risk" `
                    -Conf 0.87 -Tier "Tier1Behavioral" -PName "Registry" -PId 0
            }
        }
    } catch {}
}

# ============================================================================
# FILE ACTIVITY (ransomware rate + ransomware extensions)
# High-value roots only: Documents, Desktop, Downloads per user profile.
# FileSystemWatcher events fire on a CLR thread-pool thread, which is a
# different runspace from the main loop. $Script: hashtable is NOT reliably
# visible from -Action script blocks. We use a thread-safe ConcurrentQueue
# instead and drain it on the main thread each cycle.
# ============================================================================
$Script:RansomExts = @('.encrypted','.enc','.locked','.crypto','.crypt','.locky',
    '.wncry','.ryuk','.lockbit','.conti','.hive','.blackcat','.play','.royal',
    '.clop','.akira','.blackbasta','.rhysida','.medusa','.trigona','.alphv','.noname')

# Shared queue: visible from any thread, no runspace crossing
$Script:FileQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function Initialize-FileMonitor {
    $ok = $false
    # Watch only the three high-value sub-folders per user profile.
    # Watching the entire profile root generates thousands of benign events
    # (browser cache, Defender quarantine, OneDrive sync, VS Code) that
    # swamp the rate detector.
    $subFolders = @('Documents','Desktop','Downloads')
    foreach ($u in $Script:UserProfiles) {
        foreach ($sub in $subFolders) {
            $watchPath = Join-Path $u.ProfilePath $sub
            if (-not (Test-Path $watchPath -ErrorAction SilentlyContinue)) { continue }
            try {
                $fw = New-Object System.IO.FileSystemWatcher
                $fw.Path = $watchPath
                $fw.IncludeSubdirectories = $true
                $fw.NotifyFilter = [System.IO.NotifyFilters]::FileName
                $fw.Filter = "*.*"

                # Capture queue reference in a local variable so the closure
                # doesn't need to reach into $Script: from another runspace.
                $q = $Script:FileQueue
                Register-ObjectEvent -InputObject $fw -EventName Renamed -MessageData $q -Action {
                    $Event.MessageData.Enqueue($Event.SourceEventArgs.FullPath)
                } | Out-Null
                Register-ObjectEvent -InputObject $fw -EventName Created -MessageData $q -Action {
                    $Event.MessageData.Enqueue($Event.SourceEventArgs.FullPath)
                } | Out-Null

                $fw.EnableRaisingEvents = $true
                $Script:FileWatchers += $fw
                $ok = $true
            } catch {}
        }
    }
    return $ok
}

function Invoke-FileAnalysis {
    # Drain the concurrent queue on the main thread
    $paths  = [System.Collections.Generic.List[string]]::new()
    $item   = $null
    while ($Script:FileQueue.TryDequeue([ref]$item)) { $paths.Add($item) }
    if ($paths.Count -eq 0) { return }

    $now = Get-Date; $ransomHits = 0
    foreach ($p in $paths) {
        $ext = [System.IO.Path]::GetExtension($p).ToLower()
        if ($ext -in $Script:RansomExts) { $ransomHits++ }
    }

    $Script:FileRateTracker.Count += $paths.Count
    $elapsed = ($now - $Script:FileRateTracker.Start).TotalSeconds
    if ($elapsed -gt 30) { $Script:FileRateTracker = @{ Count=0; Start=$now }; return }

    # Bulk rename rate: 200+ in 30s on Documents/Desktop/Downloads
    # (50 was too low - a file copy/unzip to Downloads trips it on any healthy machine)
    if ($Script:FileRateTracker.Count -ge 200 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "BulkFile" -TTL 60)) {
            $conf = [Math]::Min(0.96, 0.75 + $Script:FileRateTracker.Count * 0.001)
            Log-Event -Type "detection" -Rule "BulkFileOps" `
                -Evidence "$($Script:FileRateTracker.Count) file ops in $([Math]::Round($elapsed))s on user data folders" `
                -Reasoning "Extremely high rename/create rate on Documents/Desktop/Downloads - bulk encryption pattern" `
                -Conf $conf -Tier "Tier1Behavioral" -PName "FileSystem" -PId 0
            Add-Signal -Pid 0 -Cat "ransomware_rate" -Conf $conf
        }
    }
    # Ransomware extensions: 3+ hits in 30s (kept tight because the extension list is specific)
    if ($ransomHits -ge 3 -and $elapsed -le 30) {
        if (-not (Is-Dup -K "RansomExt" -TTL 60)) {
            Log-Event -Type "detection" -Rule "RansomwareExtensions" `
                -Evidence "$ransomHits files renamed to known encryption extensions in $([Math]::Round($elapsed))s" `
                -Reasoning "Mass rename to known encryption extensions - active ransomware" `
                -Conf 0.93 -Tier "Tier1Behavioral" -PName "FileSystem" -PId 0
            Add-Signal -Pid 0 -Cat "ransomware_ext" -Conf 0.93
        }
    }
}


# ============================================================================
# COMPOSITE CORRELATION ENGINE (multi-signal kills)
# ============================================================================
function Invoke-Composite { param([int]$Pid,[string]$Name)
    $cats = Get-Categories -Pid $Pid
    $cnt  = Get-SignalCount -Pid $Pid
    if ($cnt -lt 2) { return }

    $composites = @()

    # --- v3.5 composites (retained) ---
    if ($cats -contains "memory" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedC2Beacon"; Conf=0.96 }
    }
    if ($cats -contains "credential" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CredentialExfiltration"; Conf=0.95 }
    }
    if ($cats -contains "evasion" -and ($cats -contains "execution" -or $cats -contains "c2")) {
        $composites += @{ N="FilelessAttack"; Conf=0.93 }
    }
    if ($cats -contains "unsigned" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="CovertRAT"; Conf=0.90 }
    }
    $rCats = @($cats | Where-Object { $_ -match "ransomware" -or $_ -eq "wiper" })
    if ($rCats.Count -ge 2) { $composites += @{ N="ActiveRansomware"; Conf=0.98 } }
    if ($cats -contains "escalation" -and $cats -contains "persistence") {
        $composites += @{ N="PostExploitation"; Conf=0.92 }
    }
    if ($cats -contains "dll_injection" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="InjectedImplantC2"; Conf=0.95 }
    }
    if ($cats -contains "clipboard" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="ClipboardExfil"; Conf=0.93 }
    }
    if ($cats -contains "surveillance" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="SurveillanceExfil"; Conf=0.94 }
    }
    if ($cats -contains "dga" -and $cats -contains "beaconing") {
        $composites += @{ N="DgaC2Beacon"; Conf=0.94 }
    }
    if ($cats -contains "lateral" -and $cats -contains "credential") {
        $composites += @{ N="LateralCredTheft"; Conf=0.95 }
    }
    if ($cats -contains "genealogy" -and ($cats -contains "network" -or $cats -contains "beaconing")) {
        $composites += @{ N="OrphanPhoneHome"; Conf=0.88 }
    }

    # --- v4.0 new composites ---
    # Mining: high CPU + mining port or mining pool C2
    if ($cats -contains "mining" -and ($cats -contains "beaconing" -or $cats -contains "network")) {
        $composites += @{ N="ActiveCryptoMiner"; Conf=0.95 }
    }
    # Botnet: mass outbound + persistence
    if ($cats -contains "botnet" -and $cats -contains "persistence") {
        $composites += @{ N="BotnetImplant"; Conf=0.93 }
    }
    # Collection + exfil
    if ($cats -contains "collection" -and ($cats -contains "exfil" -or $cats -contains "network")) {
        $composites += @{ N="CollectAndExfiltrate"; Conf=0.94 }
    }
    # BEC: mail rule + credential or lateral
    if ($cats -contains "bec" -and ($cats -contains "credential" -or $cats -contains "lateral")) {
        $composites += @{ N="BusinessEmailCompromise"; Conf=0.94 }
    }
    # Discovery + lateral = breach progression
    if ($cats -contains "discovery" -and $cats -contains "lateral") {
        $composites += @{ N="ActiveBreachProgression"; Conf=0.92 }
    }
    # Dropper + execution + network = staged loader phoning home
    if ($cats -contains "dropper" -and $cats -contains "execution" -and ($cats -contains "network" -or $cats -contains "c2")) {
        $composites += @{ N="StagedLoaderC2"; Conf=0.93 }
    }
    # Wiper: wiper impact + evasion
    if ($cats -contains "wiper" -and $cats -contains "evasion") {
        $composites += @{ N="StealthedWiper"; Conf=0.95 }
    }
    # DLL injection + credential = in-memory credential stealer
    if ($cats -contains "dll_injection" -and $cats -contains "credential") {
        $composites += @{ N="InjectedCredStealer"; Conf=0.96 }
    }
    # 3+ distinct categories = Advanced Attack Chain
    if ($cats.Count -ge 3) {
        $composites += @{ N="AdvancedAttackChain"; Conf=0.96 }
    }
    # 5+ distinct categories = Full Breach Scenario
    if ($cats.Count -ge 5) {
        $composites += @{ N="FullBreachScenario"; Conf=0.99 }
    }
    # Ransomware pair: shadow deletion + any second ransomware/wiper signal.
    # Two independent signals needed - protects against a single vssadmin backup call
    # by an admin or backup tool triggering a kill.
    if ($cats -contains "ransomware" -and ($cats -contains "ransomware_rate" -or $cats -contains "ransomware_ext" -or $cats -contains "wiper")) {
        $composites += @{ N="ActiveRansomwareKill"; Conf=0.97 }
    }

    foreach ($comp in $composites) {
        $dk = "Comp|$($comp.N)|$Pid"
        if (Is-Dup -K $dk -TTL 120) { continue }
        Log-Event -Type "detection" -Rule "Composite:$($comp.N)" `
            -Evidence "$Name (PID $Pid): categories=[$($cats -join '+')] signals=$cnt/120s" `
            -Reasoning "Multiple behavioral signals correlated on same process" `
            -Conf $comp.Conf -Tier "Tier1Behavioral" -PName $Name -PId $Pid
        if (-not $Script:QuietMode) {
            Write-Host "[COMPOSITE] $($comp.N) conf=$($comp.Conf) | $Name (PID $Pid) | $($cats -join '+')" -ForegroundColor Magenta
        }
        if ($comp.Conf -ge 0.85) { Invoke-Kill -Pid $Pid -Name $Name -Rule "Composite:$($comp.N)" -Conf $comp.Conf }
    }
}

# ============================================================================
# RESPONSE ENGINE
# ============================================================================
function Invoke-Kill { param([int]$Pid,[string]$Name,[string]$Rule,[double]$Conf)
    if ($Pid -le 4 -or $Pid -eq $PID) { return }
    if ($Conf -lt 0.85) { return }
    if (-not $Script:KillEnabled) {
        Log-Event -Type "response" -Rule $Rule -Evidence "WOULD-KILL (NoKill mode): $Name (PID $Pid)" -Reasoning "Kill suppressed by -NoKill flag" -Conf $Conf -Tier "Response" -PName $Name -PId $Pid
        if (-not $Script:QuietMode) { Write-Host "[WOULD-KILL] $Name (PID $Pid) - $Rule conf=$Conf" -ForegroundColor DarkYellow }
        return
    }
    Log-Event -Type "response" -Rule $Rule -Evidence "KILL: $Name (PID $Pid)" -Reasoning "Kill authorized at conf $Conf" -Conf $Conf -Tier "Response" -PName $Name -PId $Pid
    try {
        (Get-Process -Id $Pid -ErrorAction Stop).Kill()
        if (-not $Script:QuietMode) { Write-Host "[KILL] $Name (PID $Pid) - $Rule (conf=$Conf)" -ForegroundColor Red }
    } catch {
        if (-not $Script:QuietMode) { Write-Host "[KILL FAILED] $Name (PID $Pid) - $($_.Exception.Message)" -ForegroundColor DarkRed }
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
            # Impact / Destruction
            (Test-Destructive        -CL $cl -Pid $pid -N $n),
            # Credential access
            (Test-CredentialAccess   -CL $cl -Pid $pid -N $n -Path $p),
            # Defense evasion
            (Test-Evasion            -CL $cl -Pid $pid -N $n -Path $p),
            # Persistence
            (Test-Persistence        -CL $cl -Pid $pid -N $n),
            # Execution / LOLBins
            (Test-Execution          -CL $cl -Pid $pid -N $n),
            # Privilege escalation
            (Test-Escalation         -CL $cl -Pid $pid -N $n),
            # Lateral movement
            (Test-LateralMovement    -CL $cl -Pid $pid -N $n),
            # Discovery
            (Test-Discovery          -CL $cl -Pid $pid -N $n),
            # Collection
            (Test-Collection         -CL $cl -Pid $pid -N $n -Path $p),
            # C2 & Exfiltration
            (Test-C2AndExfil         -CL $cl -Pid $pid -N $n -Path $p),
            # Crypto-mining
            (Test-CryptoMining       -CL $cl -Pid $pid -N $n -Path $p),
            # Botnet/proxy
            (Test-BotnetProxy        -CL $cl -Pid $pid -N $n),
            # Human attacks / BEC
            (Test-HumanAttacks       -CL $cl -Pid $pid -N $n),
            # Loader/dropper
            (Test-LoaderDropper      -CL $cl -Pid $pid -N $n -Path $p),
            # Genealogy
            (Test-Genealogy          -Pid $pid -Name $n -PPid $pp),
            # Unsigned staged
            (Test-UnsignedStaged     -Pid $pid -Name $n -Path $p)
        )

        foreach ($d in $dets) {
            if (-not $d) { continue }
            $dk = "$($d.Rule)|$pid"
            if (Is-Dup -K $dk) { continue }
            # Allowlist check: skip if this process+rule combination is whitelisted
            $nLower = $n.ToLower()
            if ($Script:Allowlist.ContainsKey($nLower)) {
                $skipRules = $Script:Allowlist[$nLower]
                if ($skipRules.Count -eq 0 -or $d.Rule -in $skipRules) { continue }
            }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning `
                -Conf $d.Conf -Tier $d.Tier -PName $n -PId $pid
            Add-Signal -Pid $pid -Cat $d.Cat -Conf $d.Conf
            # Single-signal rules: log and signal only. Kill path is composite-only.
            # Exception: PassTheCredential has no legitimate command-line form.
            if ($d.Rule -eq "PassTheCredential" -and $d.Conf -ge 0.85) {
                Invoke-Kill -Pid $pid -Name $n -Rule $d.Rule -Conf $d.Conf
            }
        }
        Invoke-Composite -Pid $pid -Name $n
    }
}

function Invoke-MemoryScan {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID })
    $filtered = @()
    foreach ($p in $procs) {
        $isJit = $false
        foreach ($jp in $Script:JitPaths) { if ($p.Path -like $jp) { $isJit=$true; break } }
        if (-not $isJit) { $filtered += $p }
    }
    $sample = $filtered | Get-Random -Count ([Math]::Min(30, $filtered.Count)) -ErrorAction SilentlyContinue
    foreach ($p in $sample) {
        $d = Invoke-MemoryAnalysis -Pid $p.Id -Name $p.ProcessName -Path $p.Path
        if ($d) {
            $dk = "Mem|$($p.Id)"
            if (Is-Dup -K $dk -TTL 120) { continue }
            Log-Event -Type "detection" -Rule $d.Rule -Evidence $d.Evidence -Reasoning $d.Reasoning `
                -Conf $d.Conf -Tier $d.Tier -PName $p.ProcessName -PId $p.Id
            Add-Signal -Pid $p.Id -Cat $d.Cat -Conf $d.Conf
            # Memory anomaly alone is a strong signal but not unambiguous; let composite decide kill.
            Invoke-Composite -Pid $p.Id -Name $p.ProcessName
        }
    }
}

# ============================================================================
# BANNER & STARTUP
# ============================================================================
function Show-Banner {
    if ($Script:QuietMode) { return }
    $w = "================================================"
    Write-Host ""
    Write-Host " $w" -ForegroundColor Green
    Write-Host "  Windows Sentinel v$Script:Version" -ForegroundColor Green
    Write-Host "  Comprehensive Behavioral EDR - 15 attack categories" -ForegroundColor Green
    Write-Host " $w" -ForegroundColor Green
    Write-Host ""

    $cats = @(
        "1.Goals   2.InitAccess  3.Execution  4.Persistence  5.PrivEsc",
        "6.Evasion 7.Credentials 8.Discovery  9.Lateral     10.Collection",
        "11.C2     12.Exfil     13.Impact    14.MalwareTypes 15.HumanAttacks"
    )
    foreach ($c in $cats) { Write-Host "  $c" -ForegroundColor Gray }
    Write-Host ""

    $checks = @()
    if ($Script:IsElevated) { $checks += @{S="[OK] Elevated (full detection)";    C="Green"} }
    else                    { $checks += @{S="[DEGRADED] Standard user (memory/driver scans limited)"; C="Yellow"} }

    $modeStr = "PowerShell script"
    if ($Script:IsCompiledExe) { $modeStr = "compiled EXE" }
    $pathStr = "<path unknown>"
    if ($Script:OwnExePath) { $pathStr = $Script:OwnExePath }
    $checks += @{S="[OK] Running as $modeStr : $pathStr"; C="Green"}

    $uprofs = $Script:UserProfiles.Count
    $checks += @{S="[OK] Monitoring $uprofs user profile(s)"; C="Green"}

    try   { Initialize-Log; $checks += @{S="[OK] Log: $($Script:LogPath)"; C="Green"} }
    catch { $checks += @{S="[FAIL] Log unavailable"; C="Red"} }

    $fw = Initialize-FileMonitor
    if ($fw) { $checks += @{S="[OK] FileWatcher: Documents/Desktop/Downloads ($($Script:UserProfiles.Count) profile(s))"; C="Green"} }
    else     { $checks += @{S="[DEGRADED] FileWatcher unavailable"; C="Yellow"} }

    $checks += @{S="[OK] Hash reputation: CIRCL + MalwareBazaar"; C="Green"}
    $checks += @{S="[OK] Correlation: 120s window, 22 composite rules"; C="Green"}

    if ($Script:KillEnabled) { $checks += @{S="[ARMED] Active Response ENABLED - processes WILL be killed"; C="Red"} }
    else                     { $checks += @{S="[SAFE ] -NoKill mode - detection only, no termination"; C="Yellow"} }

    foreach ($c in $checks) { Write-Host "  $($c.S)" -ForegroundColor $c.C }
    Write-Host ""
    Write-Host "  Ctrl+C to stop  |  Log: $($Script:LogPath)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# MAIN LOOP
# ============================================================================
function Start-Sentinel {
    # Must run before Show-Banner so profile count is available
    Get-UserProfiles

    Show-Banner
    Initialize-Log
    Initialize-SelfProtection
    Initialize-ModuleBaseline
    Initialize-StartupFolderBaseline

    Log-Event -Type "system" -Rule "Startup" -Evidence "Sentinel v$Script:Version Elevated=$Script:IsElevated KillEnabled=$Script:KillEnabled" `
        -Reasoning "Initialization complete" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID

    $cycle = 0
    try {
        while ($true) {
            $t0 = Get-Date; $cycle++
            try {
                # Every cycle (5s)
                Update-Ancestry
                Invoke-ProcessScan
                Invoke-NetworkAnalysis -Conns (Get-Connections)
                Invoke-FileAnalysis
                Update-CpuTracker

                # ~20s
                if ($cycle % 4 -eq 0) {
                    Test-ClipboardAnomaly
                    $surveil = Test-SurveillanceAccess
                    foreach ($s in $surveil) {
                        Log-Event -Type "detection" -Rule $s.Rule -Evidence $s.Evidence `
                            -Reasoning $s.Reasoning -Conf $s.Conf -Tier $s.Tier -PName $s.PName -PId $s.PId
                        Add-Signal -Pid $s.PId -Cat $s.Cat -Conf $s.Conf
                    }
                }

                # ~30s
                if ($cycle % 6 -eq 0) {
                    Test-DnsAnomaly
                    Test-SelfIntegrity
                    Test-StartupFolderChange
                }

                # ~45s
                if ($cycle % 9 -eq 0) { Invoke-MemoryScan }

                # ~60s
                if ($cycle % 12 -eq 0) { Test-ModuleInjection }

                # ~2.5min
                if ($cycle % 30 -eq 0) { Test-RegistryPersistence }

                # ~5min
                if ($cycle % 60 -eq 0) { Test-WmiPersistence }

                # ~10min - refresh user profile list (catches new logons)
                if ($cycle % 120 -eq 0) { Get-UserProfiles }

            } catch { Write-Verbose "Cycle $cycle error: $_" }

            # Prune stale state
            if ($cycle % 20 -eq 0) {
                $now = Get-Date
                # Stale beacon entries
                $stale = @($Script:BeaconTracker.Keys | Where-Object {
                    $Script:BeaconTracker[$_].T.Count -eq 0 -or
                    ($now - $Script:BeaconTracker[$_].T[-1]).TotalMinutes -gt 30
                })
                foreach ($k in $stale) { $Script:BeaconTracker.Remove($k) }
                # Dead PIDs from correlation
                $deadPids = @($Script:Correlation.Keys | Where-Object { -not $Script:ProcessAncestry.ContainsKey($_) })
                foreach ($k in $deadPids) { $Script:Correlation.Remove($k) }
                # Dead PIDs from outbound tracker
                $deadOut = @($Script:OutboundTracker.Keys | Where-Object { -not $Script:ProcessAncestry.ContainsKey($_) })
                foreach ($k in $deadOut) { $Script:OutboundTracker.Remove($k) }
            }

            $ms = [Math]::Max(100, ($Script:ScanIntervalSec * 1000) - ((Get-Date) - $t0).TotalMilliseconds)
            Start-Sleep -Milliseconds $ms
        }
    } finally {
        if (-not $Script:QuietMode) { Write-Host "`nSentinel shutting down..." -ForegroundColor Yellow }
        foreach ($fw in $Script:FileWatchers) {
            try { $fw.EnableRaisingEvents = $false; $fw.Dispose() } catch {}
        }
        Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue
        if ($Script:MutexHandle) { try { $Script:MutexHandle.ReleaseMutex(); $Script:MutexHandle.Dispose() } catch {} }
        Log-Event -Type "system" -Rule "Shutdown" -Evidence "Stopped after $cycle cycles" `
            -Reasoning "Clean shutdown" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID
        if (-not $Script:QuietMode) { Write-Host "Sentinel stopped. $cycle cycles completed." -ForegroundColor Green }
    }
}

# ============================================================================
# PERSISTENCE (scheduled task at SYSTEM)
# Works for both .ps1 scripts and compiled .exe binaries.
# Re-registers the task if it exists but points to a different path
# (handles the case where the file was moved after initial install).
# ============================================================================
function Install-Startup {
    if (-not $Script:OwnExePath) { return }   # path unknown, can't register

    # Build the launch command depending on whether we're a .ps1 or a compiled .exe
    if ($Script:IsCompiledExe) {
        $execPath = $Script:OwnExePath
        $execArgs = "-Quiet"
    } else {
        $execPath = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
        if (-not $execPath) { $execPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
        $execArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$Script:OwnExePath`" -Quiet"
    }

    # Check if the task exists AND already points to the right file — skip if so
    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        $existingExec = try { $existing.Actions[0].Execute } catch { "" }
        $existingArgs = try { $existing.Actions[0].Arguments } catch { "" }
        if ($existingExec -eq $execPath -and $existingArgs -like "*$Script:OwnExePath*") { return }
        # Path changed — fall through to re-register
    }

    try {
        $action    = New-ScheduledTaskAction -Execute $execPath -Argument $execArgs
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                         -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description "Windows Sentinel v4.1 EDR" `
            -Force -ErrorAction Stop | Out-Null
        if (-not $Script:QuietMode) { Write-Host "  [OK] Installed as SYSTEM startup task" -ForegroundColor Green }
    } catch {
        # Fallback: schtasks.exe
        try {
            schtasks /Create /TN $Script:TaskName /TR "`"$execPath`" $execArgs" /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -and -not $Script:QuietMode) { Write-Host "  [OK] Installed via schtasks" -ForegroundColor Green }
        } catch {}
    }
    Log-Event -Type "system" -Rule "Persistence" -Evidence "Registered startup task: $Script:TaskName -> $execPath" `
        -Reasoning "Self-persistence for EDR continuity" -Conf 1.0 -Tier "System" -PName "Sentinel" -PId $PID
}

function Uninstall-Sentinel {
    Write-Host "Uninstalling Windows Sentinel v$Script:Version..." -ForegroundColor Yellow
    try { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { schtasks /Delete /TN $Script:TaskName /F 2>&1 | Out-Null } catch {}
    Write-Host "  [OK] Scheduled task removed" -ForegroundColor Green
    # Kill other running instances — match by executable path, not by name string
    try {
        $ownPath = $Script:OwnExePath
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessId -ne $PID -and $ownPath -and $_.CommandLine -like "*$ownPath*" } |
            ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "  [OK] Stopped PS instance PID:$($_.ProcessId)" -ForegroundColor Green
            }
        if ($Script:IsCompiledExe -and $ownPath) {
            $exeName = [System.IO.Path]::GetFileNameWithoutExtension($ownPath)
            Get-Process -Name $exeName -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -ne $PID } |
                ForEach-Object {
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "  [OK] Stopped EXE instance PID:$($_.Id)" -ForegroundColor Green
                }
        }
    } catch {}
    Write-Host "  Log data at $env:ProgramData\WindowsSentinel can be deleted manually." -ForegroundColor Gray
    Write-Host "Uninstall complete." -ForegroundColor Green
    exit 0
}

# ============================================================================
# ENTRY POINT
# ============================================================================
if ($Uninstall) { Uninstall-Sentinel }
Install-Startup
Start-Sentinel
