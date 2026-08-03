<#
.SYNOPSIS
  Baseline-Guard.ps1 - embed safe baseline, detect changes (firewall, services, autoruns, ASR, Defender), quarantine suspicious files, optionally restore.
.DESCRIPTION
  - Embeds a baseline database (hashtables/lists) inside script.
  - Produces an HTML/text report and backups of modified settings.
  - By default only reports. Pass -AutoFix to apply changes.
.PARAMETER AutoFix
  When present, the script will attempt to remediate deviations automatically.
.EXAMPLE
  .\Baseline-Guard.ps1
  .\Baseline-Guard.ps1 -AutoFix
#>

param(
    [switch]$AutoFix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator. Exiting."
        exit 1
    }
}

# ---------------------------
# Embedded baseline database
# ---------------------------
# This is a conservative, small, example baseline. Expand to match your org's policy.
$Baseline = @{
    "WindowsDefender" = @{
        "RealtimeMonitoring" = $true
        "CloudProtection"    = $true
        "PuaProtection"      = "Audit"   # Allowed: Off/Block/Audit
        "ScanSchedule"       = "Daily"   # descriptive only
    }
    "ASR" = @{
        # ASR rules and their expected state (1 = enabled, 0 = disabled)
        "DONT_EXECUTE_LICENSED_BINARIES" = 1
        "BLOCK_OFFICE_MACROS" = 1
        "BLOCK_USBTODRIVE" = 1
    }
    "FirewallRules" = @{
        # Example: keep only essential inbound rules named here (others are suspicious)
        "AllowedInbound" = @(
            # allow these rule names (exact match) inbound
            "Core Networking - DHCP-In",
            "Core Networking - DNS (TCP-In)",
            "Core Networking - DNS (UDP-In)"
        )
        # Allowed outbound rules (names)
        "AllowedOutbound" = @(
            "Core Networking - DNS (UDP-Out)",
            "System - HTTP Out (approved-app)"  # example, add real ones if needed
        )
    }
    "Services" = @{
        # Expected service start types: 'Automatic', 'Manual', 'Disabled'
        "WinDefend" = "Automatic"
        "MpsSvc"    = "Automatic"  # Windows Firewall
        "EventLog"  = "Automatic"
        # Conservative: do not interfere with many services; list the critical ones to check
    }
    "TrustedAutorunsPaths" = @(
        "$Env:ProgramFiles",
        "$Env:ProgramFiles(x86)",
        "$Env:Windir\System32",
        "$Env:Windir\SysWOW64"
    )
    "TrustedSignerThumbprints" = @(
        # Example: Microsoft Code Signing (short list). Add thumbprints your org trusts.
    )
    "TrustedScheduledTasks" = @(
        # Task paths that are considered safe (e.g. '\Microsoft\Windows\Defrag\ScheduledDefrag')
        '\Microsoft\Windows\Defrag\ScheduledDefrag',
        '\Microsoft\Windows\Defender\Windows Defender Scheduled Scan'
    )
}

# ---------------------------
# Paths and env
# ---------------------------
$BaseDir = "C:\BaselineGuard"
$QuarantineDir = Join-Path $BaseDir "Quarantine"
$BackupsDir = Join-Path $BaseDir "Backups"
$ReportDir = Join-Path $BaseDir "Reports"
$Now = (Get-Date).ToString("yyyyMMdd_HHmmss")
$ReportFile = Join-Path $ReportDir "BaselineGuard_Report_$Now.html"
$LogFile = Join-Path $ReportDir "BaselineGuard_Log_$Now.txt"

# Ensure directories
New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null
New-Item -Path $BackupsDir -ItemType Directory -Force | Out-Null
New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null

# Helper logger
$Global:Log = New-Object System.Collections.Generic.List[string]
function Log-Write { param($s) $Global:Log.Add("$(Get-Date -Format o) `t $s"); Write-Host $s }

# ---------------------------
# Backup helpers
# ---------------------------
function Backup-RegistryKey {
    param($KeyPath, $BackupName)
    try {
        $file = Join-Path $BackupsDir ($BackupName + "_" + $Now + ".reg")
        reg export $KeyPath $file /y | Out-Null
        Log-Write "Exported registry $KeyPath -> $file"
        return $file
    } catch {
        Log-Write "Failed to export registry $KeyPath : $_"
        return $null
    }
}

function Backup-FirewallRules {
    $file = Join-Path $BackupsDir ("firewall_rules_$Now.wfw")
    # Use netsh advfirewall (available on Windows) to export
    try {
        netsh advfirewall export $file | Out-Null
        Log-Write "Exported firewall config to $file"
        return $file
    } catch {
        Log-Write "Failed to export firewall rules: $_"
        return $null
    }
}

function Backup-ScheduledTasks {
    $file = Join-Path $BackupsDir ("scheduled_tasks_$Now.xml")
    try {
        # Export tasks enumerated under TaskScheduler library root
        $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath
        $tasks | Out-File (Join-Path $BackupsDir ("scheduled_tasks_list_$Now.txt")) -Encoding UTF8
        Log-Write "Saved scheduled task list."
    } catch {
        Log-Write "Failed to save scheduled task list: $_"
    }
}

# ---------------------------
# Quarantine helper
# ---------------------------
function Quarantine-File {
    param($Path, $Reason)
    try {
        if (-not (Test-Path $Path)) { Log-Write "Quarantine skipped: not found $Path"; return $false }
        $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
        $dest = Join-Path $QuarantineDir ("$($hash.Substring(0,16))_" + (Split-Path $Path -Leaf))
        Copy-Item -Path $Path -Destination $dest -ErrorAction Stop
        # Optionally remove original after copy (only if AutoFix)
        if ($AutoFix) {
            try { Remove-Item -Path $Path -Force -ErrorAction Stop; Log-Write "Removed original file: $Path" } catch { Log-Write "Failed to remove original file: $Path - $_" }
        }
        Log-Write "Quarantined $Path -> $dest ; Reason: $Reason"
        return $dest
    } catch {
        Log-Write "Quarantine failed for $Path : $_"
        return $false
    }
}

# ---------------------------
# Scanners & Restorers
# ---------------------------

# 1) Windows Defender / Security Center checks
function Check-WindowsDefender {
    $result = [ordered]@{}
    try {
        # Uses Get-MpPreference if Defender module available
        if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
            $prefs = Get-MpPreference
            $result.RealtimeEnabled = -not $prefs.DisableRealtimeMonitoring
            $result.CloudEnabled = -not $prefs.DisableBlockAtFirstSeen
            $result.PuaProtection = if ($prefs.PuaProtection) { $prefs.PuaProtection } else { "Unknown" }
            $result.PathToScan = $prefs.ExclusionPath
        } else {
            $result.Info = "Get-MpPreference not available; Windows Defender module missing or running older OS."
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Enforce-WindowsDefender {
    Log-Write "Backing up Defender policy where possible..."
    Backup-RegistryKey "HKLM\SOFTWARE\Microsoft\Windows Defender" "DefenderBackup"
    if (-not (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue)) {
        Log-Write "Set-MpPreference not available; cannot programmatically enable Defender preferences on this system."
        return
    }
    $target = $Baseline.WindowsDefender
    if ($AutoFix) {
        try {
            if ($target.RealtimeMonitoring) { Set-MpPreference -DisableRealtimeMonitoring $false; Log-Write "Enabled Defender realtime monitoring." }
            if ($target.CloudProtection)    { Set-MpPreference -DisableBlockAtFirstSeen $false; Log-Write "Enabled cloud protection." }
            if ($target.PuaProtection -and ($target.PuaProtection -ne "Audit")) {
                # translate to Set-MpPreference flags if needed
            }
        } catch {
            Log-Write "Failed to set Defender prefs: $_"
        }
    } else {
        Log-Write "AutoFix not set - skipping changes to Defender prefs."
    }
}

# 2) ASR rules check (requires Get-MpPreference / Get-MpThreat)
function Check-ASR {
    $out = [ordered]@{}
    if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
        $prefs = Get-MpPreference
        # MpPreference contains AttackSurfaceReductionRules_Actions or similar depending on OS version
        $asr = @{}
        try {
            $map = $prefs.ASROptions
            # many PowerShell versions don't expose ASR easily; attempt to parse relevant properties
            foreach ($k in $Baseline.ASR.Keys) {
                $asr[$k] = "Unknown"
            }
        } catch {
            foreach ($k in $Baseline.ASR.Keys) { $asr[$k] = "Unavailable" }
        }
        $out.ASR = $asr
    } else {
        $out.Error = "Get-MpPreference not available."
    }
    return $out
}

function Enforce-ASR {
    Log-Write "ASR enforcement: best-effort. Backing up preferences..."
    Backup-RegistryKey "HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ASRBackup"
    if (-not (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue)) {
        Log-Write "Set-MpPreference missing; cannot set ASR via this system."
        return
    }
    if ($AutoFix) {
        foreach ($k in $Baseline.ASR.Keys) {
            try {
                # This mapping depends on installed PowerShell module and Windows build.
                # Use PowerShell cmdlets or registry edits as agent of last resort.
                Log-Write "Would set ASR rule $k to $($Baseline.ASR[$k]) - implementation may vary by OS."
            } catch {
                Log-Write "Failed set ASR $k : $_"
            }
        }
    } else {
        Log-Write "AutoFix not set - skipping ASR modifications."
    }
}

# 3) Firewall scan and optional restore
function Check-Firewall {
    $res = [ordered]@{}
    try {
        $inbound = Get-NetFirewallRule -Direction Inbound -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Select-Object -Property Name,DisplayName,Enabled,Action,Profile
        $outbound = Get-NetFirewallRule -Direction Outbound -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Select-Object -Property Name,DisplayName,Enabled,Action,Profile
        $res.Inbound = $inbound
        $res.Outbound = $outbound
        # identify inbound rules not on allowlist
        $allowed = $Baseline.FirewallRules.AllowedInbound
        $suspiciousInbound = $inbound | Where-Object { ($allowed -notcontains $_.DisplayName) -and ($_.Action -eq 'Allow') }
        $res.SuspiciousInbound = $suspiciousInbound
        $allowedOut = $Baseline.FirewallRules.AllowedOutbound
        $suspiciousOutbound = $outbound | Where-Object { ($allowedOut -notcontains $_.DisplayName) -and ($_.Action -eq 'Allow') }
        $res.SuspiciousOutbound = $suspiciousOutbound
    } catch {
        $res.Error = $_.Exception.Message
    }
    return $res
}

function Enforce-Firewall {
    $backup = Backup-FirewallRules
    if ($AutoFix) {
        $fw = Check-Firewall
        if ($fw.SuspiciousInbound) {
            foreach ($r in $fw.SuspiciousInbound) {
                try {
                    # disable rule (safer than delete); user can review backup
                    Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop
                    Log-Write "Disabled inbound firewall rule: $($r.DisplayName)"
                } catch {
                    Log-Write "Failed disabling firewall rule $($r.DisplayName): $_"
                }
            }
        }
        if ($fw.SuspiciousOutbound) {
            foreach ($r in $fw.SuspiciousOutbound) {
                try {
                    Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop
                    Log-Write "Disabled outbound firewall rule: $($r.DisplayName)"
                } catch {
                    Log-Write "Failed disabling outbound rule $($r.DisplayName): $_"
                }
            }
        }
    } else {
        Log-Write "AutoFix not set - skipping firewall modifications. Backup at $backup"
    }
}

# 4) Services scan & restore
function Check-Services {
    $res = @()
    foreach ($svcName in $Baseline.Services.Keys) {
        try {
            $s = Get-Service -Name $svcName -ErrorAction Stop
            $expected = $Baseline.Services[$svcName]
            $res += [PSCustomObject]@{
                Name = $svcName
                Status = $s.Status
                StartType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'").StartMode
                ExpectedStartType = $expected
            }
        } catch {
            $res += [PSCustomObject]@{
                Name = $svcName
                Error = $_.Exception.Message
                StartType = "Missing"
                ExpectedStartType = $Baseline.Services[$svcName]
            }
        }
    }
    return $res
}

function Enforce-Services {
    $svcs = Check-Services
    foreach ($s in $svcs) {
        if ($s.Error) { Log-Write "Service $($s.Name) error: $($s.Error)"; continue }
        if ($s.StartType -ne $s.ExpectedStartType) {
            Log-Write "Service $($s.Name) start type mismatch: current=$($s.StartType) expected=$($s.ExpectedStartType)"
            if ($AutoFix) {
                try {
                    $mode = $s.ExpectedStartType
                    # Set start mode via sc.exe or Set-Service where appropriate
                    if ($mode -eq 'Automatic') { Set-Service -Name $s.Name -StartupType Automatic -ErrorAction Stop; Log-Write "Set $($s.Name) startup to Automatic" }
                    elseif ($mode -eq 'Manual') { Set-Service -Name $s.Name -StartupType Manual -ErrorAction Stop; Log-Write "Set $($s.Name) startup to Manual" }
                    elseif ($mode -eq 'Disabled') { Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop; Log-Write "Set $($s.Name) startup to Disabled" }
                } catch {
                    Log-Write "Failed to set start type for $($s.Name): $_"
                }
            }
        }
    }
}

# 5) Autoruns & suspicious file scanning
function Get-Autoruns {
    # search common autorun locations: Run registry keys, Scheduled Tasks, Services, Startup folders
    $autoruns = @()

    # Registry Run keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $runKeys) {
        try {
            $vals = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
            if ($vals) {
                foreach ($p in $vals.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' }) {
                    $autoruns += [PSCustomObject]@{ Source = $k; Name = $p.Name; Command = $p.Value }
                }
            }
        } catch {}
    }

    # Startup folders
    $paths = @(
        "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$Env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $autoruns += [PSCustomObject]@{ Source = $p; Name = $_.Name; Command = $_.FullName }
            }
        }
    }

    # Scheduled tasks
    try {
        Get-ScheduledTask | ForEach-Object {
            $autoruns += [PSCustomObject]@{ Source = 'ScheduledTask'; Name = $_.TaskName; Command = ($_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).TaskName; Path = $_.TaskPath }
        }
    } catch {}

    return $autoruns
}

function Scan-UnsignedExecutables {
    # Look for exe/ps1/hta/vbs in non-trusted paths and check if they are signed
    $suspicious = @()
    $pathsToScan = @(
        "$Env:Windir\Temp",
        "$Env:UserProfile\AppData\Local\Temp",
        "$Env:UserProfile\AppData\Roaming",
        "$Env:ProgramData"
    )
    # also check autorun locations specifically
    $autoruns = Get-Autoruns
    $pathsToScan += ($autoruns | ForEach-Object { $_.Command }) | Where-Object { $_ -and ($_ -match '\\') } | Select-Object -Unique

    foreach ($p in $pathsToScan | Select-Object -Unique) {
        if (-not $p) { continue }
        # if it's command string rather than folder, extract exe path
        $file = $null
        if (Test-Path $p -PathType Container) {
            $files = Get-ChildItem -Path $p -Include *.exe,*.ps1,*.vbs,*.hta,*.js -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | Select-Object -First 200
            foreach ($f in $files) { $file = $f.FullName; goto ProcessFile }
        } elseif (Test-Path $p -PathType Leaf) {
            $file = $p
        } else {
            # try to extract quoted path from command
            if ($p -match '"([^"]+)"') { $cand = $Matches[1]; if (Test-Path $cand) { $file = $cand } }
            elseif ($p -match "([A-Za-z]:\\[^ ]+\.(exe|ps1|vbs|hta|js))") { $file = $Matches[1] }
        }

        ProcessFile:
        if ($file) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $file -ErrorAction SilentlyContinue
                if (($sig -eq $null) -or $sig.Status -ne 'Valid') {
                    # also exclude files in trusted paths baseline
                    $trusted = $false
                    foreach ($tp in $Baseline.TrustedAutorunsPaths) {
                        $expanded = [Environment]::ExpandEnvironmentVariables($tp)
                        if ($file.StartsWith($expanded, [System.StringComparison]::InvariantCultureIgnoreCase)) { $trusted = $true; break }
                    }
                    if (-not $trusted) {
                        $suspicious += [PSCustomObject]@{
                            File = $file
                            Signature = if ($sig) { $sig.Status } else { 'NoSignature' }
                            Size = (Get-Item $file).Length
                        }
                    }
                }
            } catch {
                # ignore
            }
        }
    }
    return $suspicious | Sort-Object -Property Size -Descending
}

# 6) Scheduled tasks suspicious check
function Check-ScheduledTasks {
    $res = @()
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -ne '\Microsoft\Windows\' } -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $fullPath = "$($t.TaskPath)$($t.TaskName)"
            if ($Baseline.TrustedScheduledTasks -notcontains $fullPath) {
                $res += [PSCustomObject]@{
                    TaskName = $t.TaskName
                    TaskPath = $t.TaskPath
                    Actions = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue)
                }
            }
        }
    } catch {
        Log-Write "Scheduled tasks check failed: $_"
    }
    return $res
}

function Enforce-ScheduledTasks {
    $susp = Check-ScheduledTasks
    if ($AutoFix) {
        foreach ($t in $susp) {
            try {
                # disable task first
                $full = Join-Path $t.TaskPath $t.TaskName
                Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
                Log-Write "Disabled suspicious scheduled task: $($t.TaskName) at $($t.TaskPath)"
                # optionally export xml to backups then delete
                try {
                    $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
                    if ($xml) { $xml | Out-File (Join-Path $BackupsDir ("task_$($t.TaskName)_$Now.xml")) -Encoding UTF8 }
                } catch {}
                # delete
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                Log-Write "Unregistered suspicious scheduled task: $($t.TaskName)"
            } catch {
                Log-Write "Failed to remediate scheduled task $($t.TaskName) : $_"
            }
        }
    } else {
        Log-Write "AutoFix not set - suspicious scheduled tasks will not be changed."
    }
}

# 7) Quick Windows Defender scan (if available)
function Run-DefenderQuickScan {
    if (Get-Command -Name Start-MpScan -ErrorAction SilentlyContinue) {
        try {
            Log-Write "Starting quick Windows Defender scan..."
            Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
            Log-Write "Requested quick scan (asynchronous). Check Windows Security for results."
        } catch {
            Log-Write "Failed to start Defender quick scan: $_"
        }
    } else {
        Log-Write "Start-MpScan not available on this system."
    }
}

# ---------------------------
# Orchestration
# ---------------------------
Ensure-Admin

Log-Write "Starting Baseline-Guard run. AutoFix=$AutoFix"
Log-Write "Base dir: $BaseDir"

# Backups
Backup-FirewallRules
Backup-RegistryKey "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" "PoliciesBackup"
Backup-ScheduledTasks

# Run checks
$report = [ordered]@{}
$report.Timestamp = $Now
$report.Computer = $env:COMPUTERNAME

Log-Write "Checking Windows Defender settings..."
$report.Defender = Check-WindowsDefender
Enforce-WindowsDefender

Log-Write "Checking ASR rules..."
$report.ASR = Check-ASR
Enforce-ASR

Log-Write "Checking firewall rules..."
$report.Firewall = Check-Firewall
Enforce-Firewall

Log-Write "Checking critical services..."
$report.Services = Check-Services
Enforce-Services

Log-Write "Enumerating autoruns..."
$report.Autoruns = Get-Autoruns

Log-Write "Scanning for unsigned/unknown executables in risky locations..."
$report.SuspiciousFiles = Scan-UnsignedExecutables

Log-Write "Checking scheduled tasks..."
$report.ScheduledTasks = Check-ScheduledTasks
Enforce-ScheduledTasks

# Quarantine suspicious files if AutoFix
if ($AutoFix -and $report.SuspiciousFiles) {
    foreach ($s in $report.SuspiciousFiles) {
        Quarantine-File -Path $s.File -Reason "Unsigned or outside trusted paths"
    }
} else {
    Log-Write "AutoFix not set or no suspicious files - no quarantining performed."
}

# Optionally start Defender scan
if ($AutoFix) { Run-DefenderQuickScan }

# ---------------------------
# Output / report
# ---------------------------
# Save log
$Global:Log | Out-File -FilePath $LogFile -Encoding UTF8
Log-Write "Wrote action log to $LogFile"

# Create simple HTML report
function To-HtmlSafe {
    param($obj)
    return ($obj | Out-String) -replace '<','&lt;' -replace '>','&gt;'
}

$html = @()
$html += "<html><head><meta charset='utf-8'><title>Baseline Guard Report - $Now</title></head><body>"
$html += "<h1>Baseline Guard Report - $Now</h1>"
$html += "<h2>Computer: $($report.Computer)</h2>"
$html += "<h3>Summary Log</h3><pre>" + (Get-Content -Path $LogFile -Raw) + "</pre>"

$html += "<h3>Windows Defender</h3><pre>" + (To-HtmlSafe $report.Defender) + "</pre>"
$html += "<h3>ASR (best-effort)</h3><pre>" + (To-HtmlSafe $report.ASR) + "</pre>"

$html += "<h3>Suspicious Firewall Inbound Rules</h3><pre>"
if ($report.Firewall.SuspiciousInbound -and $report.Firewall.SuspiciousInbound.Count -gt 0) {
    foreach ($r in $report.Firewall.SuspiciousInbound) { $html += (To-HtmlSafe $r) }
} else { $html += "None found" }
$html += "</pre>"

$html += "<h3>Suspicious Files</h3><pre>"
if ($report.SuspiciousFiles -and $report.SuspiciousFiles.Count -gt 0) {
    foreach ($f in $report.SuspiciousFiles) { $html += (To-HtmlSafe $f) + "`n" }
} else { $html += "None found" }
$html += "</pre>"

$html += "<h3>Suspicious Scheduled Tasks</h3><pre>"
if ($report.ScheduledTasks -and $report.ScheduledTasks.Count -gt 0) {
    foreach ($t in $report.ScheduledTasks) { $html += (To-HtmlSafe $t) + "`n" }
} else { $html += "None found" }
$html += "</pre>"

$html += "<h3>Autoruns</h3><pre>" + (To-HtmlSafe $report.Autoruns | Out-String) + "</pre>"

$html += "</body></html>"

$html -join "`n" | Out-File -FilePath $ReportFile -Encoding UTF8
Log-Write "Saved HTML report to $ReportFile"

Write-Host ""
Write-Host "Run completed. Report: $ReportFile"
Write-Host "Action log: $LogFile"
Write-Host "Quarantine location: $QuarantineDir (if any files were quarantined)"
Write-Host ""
Write-Host "WARNING: Review backups in $BackupsDir and quarantined files before permanent deletion."

# exit
exit 0
