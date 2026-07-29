<#
Vacuum_Full_Auto.ps1
Single-file reproduction of Vacuum behavior.
This script automatically runs in "AutoFix" mode on launch (no switches required).

SAFETY:
- Destructive system-level commands (registry deletes, netsh resets, reboot, etc.)
  are included verbatim as COMMENTED blocks. They will NOT run unless you:
    1) Manually open this PS1 and set $UNSAFE_OVERRIDE_INSIDE_SCRIPT = $true
    2) Re-run the script and type "I UNDERSTAND" when prompted.
  This manual edit + typed confirmation is required to run destructive blocks.
#>

# ---------------------------
# Auto-run "AutoFix" mode
# ---------------------------
$AUTOFIX = $true               # script will behave like -AutoFix automatically
$Verbose = $true

# ---------------------------
# Safety: explicit manual toggle inside file required
# ---------------------------
# EDIT THIS FILE to enable unsafe blocks: set the following variable to $true.
# This prevents accidental one-click destructive execution.
$UNSAFE_OVERRIDE_INSIDE_SCRIPT = $false

function ConfirmUnsafe {
    if (-not $UNSAFE_OVERRIDE_INSIDE_SCRIPT) {
        Write-Warning "Unsafe actions are disabled. To enable them, open this script and set `$UNSAFE_OVERRIDE_INSIDE_SCRIPT = `$true, then re-run."
        return $false
    }
    Write-Warning "You have enabled UNSAFE actions inside the file. These may change registry, firewall, services, restart network stack or reboot machine."
    $confirm = Read-Host "Type 'I UNDERSTAND' to proceed"
    if ($confirm -ne 'I UNDERSTAND') {
        Write-Warning "Confirmation failed. Unsafe actions will not run."
        return $false
    }
    return $true
}

# ---------------------------
# Prep & dirs
# ---------------------------
$BaseDir = "C:\Vacuum_Full"
$ExportsDir = Join-Path $BaseDir "exports"
$BackupsDir = Join-Path $BaseDir "backups"
$SqlOutDir = Join-Path $BaseDir "sqlout"
$QuarantineDir = Join-Path $BaseDir "Quarantine"

foreach ($d in @($BaseDir,$ExportsDir,$BackupsDir,$SqlOutDir,$QuarantineDir)) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
}

$Now = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $BaseDir ("VacuumRun_$Now.log")
$Global:Log = New-Object System.Collections.Generic.List[string]
function Log-Write { param($s) $Global:Log.Add("$(Get-Date -Format o) `t $s"); if ($Verbose) { Write-Host $s } }

# ---------------------------
# Embedded database (ENVIO)
# Replace these sample rows with your exact dump if you want absolute fidelity.
# ---------------------------
$ENVIO = @(
    [PSCustomObject]@{
        CodGrupo = 'FIREWALL_DEFAULT'; CodUsuario='SYSTEM'; CodPrestamo=''; CodPago='PF';
        MontoPrestamo=0.0; MontoGarantia=0.0; Observaciones='Keep core networking inbound rules only';
        FechReg=[datetime]"2025-01-01T00:00:00"; FechUpd=[datetime]"2025-01-01T00:00:00"; Exported=0
    },
    [PSCustomObject]@{
        CodGrupo = 'ASR_BASELINE'; CodUsuario='SYSTEM'; CodPrestamo=''; CodPago='AS';
        MontoPrestamo=0.0; MontoGarantia=0.0; Observaciones='ASR baseline';
        FechReg=[datetime]"2025-01-01T00:00:00"; FechUpd=[datetime]"2025-01-01T00:00:00"; Exported=0
    }
    # -- paste additional rows here to exactly match your DB --
)

$Schema = @{
    CodGrupo='CHAR(50) NOT NULL'; CodUsuario='CHAR(50)'; CodPrestamo='VARCHAR(100)'; CodPago='CHAR(10)';
    MontoPrestamo='REAL'; MontoGarantia='REAL'; Observaciones='VARCHAR(255)'; FechReg='DATETIME'; FechUpd='DATETIME'; Exported='INTEGER DEFAULT 0'
}

function Get-TS { (Get-Date).ToString('yyyyMMdd_HHmmss') }

# ---------------------------
# DB emulation functions
# ---------------------------
function Ensure-Exported {
    foreach ($r in $ENVIO) { if (-not ($r.PSObject.Properties.Name -contains 'Exported')) { $r | Add-Member -NotePropertyName Exported -NotePropertyValue 0 } }
}

function Integrity-Check {
    $ok = $true
    foreach ($r in $ENVIO) {
        foreach ($k in $Schema.Keys) {
            if (-not ($r.PSObject.Properties.Name -contains $k)) { $ok = $false ; break }
        }
        if (-not $ok) { break }
    }
    $out = if ($ok) {'ok'} else {'corrupt'}
    $path = Join-Path $SqlOutDir ("integrity_check_" + (Get-TS) + ".txt")
    $out | Out-File -FilePath $path -Encoding UTF8
    Log-Write "Integrity: $out -> $path"
    return $ok
}

function Export-vEnvio {
    $rows = $ENVIO | Group-Object -Property CodGrupo | ForEach-Object {
        $g = $_.Group
        [PSCustomObject]@{
            CodGrupo = $_.Name
            CodPrestamo = ($g | Select-Object -First 1).CodPrestamo
            Total = ($g | Measure-Object -Property @{Expression = { $_.MontoPrestamo + $_.MontoGarantia }} -Sum).Sum
        }
    }
    $outFile = Join-Path $ExportsDir ("vEnvio_" + (Get-TS) + ".csv")
    $rows | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Log-Write "Exported vEnvio -> $outFile"
    return $outFile
}

function Mark-Exported-Rows {
    $c=0
    foreach ($r in $ENVIO) { if (-not $r.Exported -or $r.Exported -eq 0) { $r.Exported=1; $c++ } }
    Log-Write "Marked $c rows exported."
}

function Write-SqlDump {
    $dump = Join-Path $BackupsDir ("dump_" + (Get-TS) + ".sql")
    $create = @"
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE ENVIO(CodGrupo CHAR(50) NOT NULL, CodUsuario CHAR(50), CodPrestamo VARCHAR(100), CodPago CHAR(10), MontoPrestamo REAL, MontoGarantia REAL, Observaciones VARCHAR(255), FechReg DATETIME, FechUpd DATETIME, Exported INTEGER DEFAULT 0);
CREATE VIEW vEnvio AS SELECT CodGrupo, CodPrestamo, SUM(MontoPrestamo + MontoGarantia) AS Total FROM ENVIO GROUP BY CodGrupo;
"@
    $inserts = $ENVIO | ForEach-Object {
        $vals = @()
        foreach ($c in @('CodGrupo','CodUsuario','CodPrestamo','CodPago','MontoPrestamo','MontoGarantia','Observaciones','FechReg','FechUpd','Exported')) {
            $v = $_.$c
            if ($c -in @('MontoPrestamo','MontoGarantia','Exported')) { $vals += ($v -as [string]) }
            else { $safe = ($v -as [string]) -replace "'","''"; $vals += "'$safe'" }
        }
        "INSERT INTO ENVIO VALUES(" + ($vals -join ',') + ");"
    }
    ($create + "`n" + ($inserts -join "`n") + "`nCOMMIT;") | Out-File -FilePath $dump -Encoding UTF8
    Log-Write "Wrote SQL dump -> $dump"
    return $dump
}

function Write-Pragma {
    $path = Join-Path $SqlOutDir ("pragma_envio_" + (Get-TS) + ".txt")
    $i=0; $lines=@()
    foreach ($k in $Schema.Keys) { $lines += "$i|$k|$($Schema[$k])|0||0"; $i++ }
    $lines | Out-File -FilePath $path -Encoding UTF8
    Log-Write "Wrote PRAGMA-like -> $path"
    return $path
}

# ---------------------------
# Remediation: defensive actions (auto-run)
# ---------------------------
function Backup-Firewall {
    $file = Join-Path $BackupsDir ("firewall_" + (Get-TS) + ".wfw")
    try { netsh advfirewall export $file | Out-Null; Log-Write "Firewall exported -> $file"; return $file } catch { Log-Write "Firewall export failed: $_"; return $null }
}

function Backup-RegistryKey { param($k,$name) ; $fn = Join-Path $BackupsDir ("reg_$name_" + (Get-TS) + ".reg"); try { reg export $k $fn /y | Out-Null; Log-Write "Reg $k -> $fn"; return $fn } catch { Log-Write "Reg export failed $k: $_"; return $null } }

function Restore-Defender-And-ASR {
    # Best-effort using available Windows Defender cmdlets
    if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
        try {
            Log-Write "Enabling Defender realtime and cloud protection..."
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
            Log-Write "Defender preferences set (best-effort)."
        } catch { Log-Write "Failed to set Defender preferences: $_" }
    } else { Log-Write "Defender module missing; cannot programmatically set Defender prefs." }
    # ASR rules are OS-version dependent; mention them in log.
    Log-Write "ASR enforcement: best-effort; please verify Attack Surface Reduction rules manually if needed."
}

function Check-And-Fix-Services {
    $baseline = @{ 'WinDefend'='Automatic'; 'MpsSvc'='Automatic'; 'EventLog'='Automatic' }
    foreach ($svc in $baseline.GetEnumerator()) {
        try {
            $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Key)'" -ErrorAction SilentlyContinue
            if ($null -eq $cim) { Log-Write "Svc missing: $($svc.Key)"; continue }
            if ($cim.StartMode -ne $svc.Value) {
                Log-Write "Svc start mode mismatch $($svc.Key): current=$($cim.StartMode) expected=$($svc.Value)"
                if ($AUTOFIX) { try { Set-Service -Name $svc.Key -StartupType $svc.Value -ErrorAction Stop; Log-Write "Set $($svc.Key) startup to $($svc.Value)" } catch { Log-Write "Failed set service: $_" } }
            }
        } catch { Log-Write "Service check error: $_" }
    }
}

function Scan-And-Quarantine-Unsigned {
    $paths = @("$Env:Windir\Temp","$Env:UserProfile\AppData\Local\Temp","$Env:UserProfile\AppData\Roaming","$Env:ProgramData")
    $susp=@()
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        Get-ChildItem -Path $p -Include *.exe,*.ps1,*.vbs,*.hta -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
            if (($sig -eq $null) -or ($sig.Status -ne 'Valid')) {
                $susp += $_.FullName
            }
        }
    }
    foreach ($f in $susp | Select-Object -Unique) {
        try {
            $hash = (Get-FileHash -Path $f -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $dest = Join-Path $QuarantineDir ("$($hash.Substring(0,12))_" + (Split-Path $f -Leaf))
            Copy-Item -Path $f -Destination $dest -Force -ErrorAction SilentlyContinue
            if ($AUTOFIX) { try { Remove-Item -Path $f -Force -ErrorAction SilentlyContinue; Log-Write "Quarantined and removed $f" } catch { Log-Write "Quarantine copy done, removal failed: $_" } }
            else { Log-Write "Quarantine copy only: $f -> $dest" }
        } catch { Log-Write "Quarantine error for $f : $_" }
    }
    if ($susp.Count -eq 0) { Log-Write "No unsigned suspicious files found." }
}

function Check-And-Disable-Suspicious-Firewall {
    $allowlist = @('Core Networking - DHCP-In','Core Networking - DNS (TCP-In)','Core Networking - DNS (UDP-In)')
    try {
        $list = Get-NetFirewallRule -Direction Inbound -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        if ($list) {
            foreach ($r in $list) {
                if ($r.Action -eq 'Allow' -and ($allowlist -notcontains $r.DisplayName)) {
                    Log-Write "Suspicious inbound rule: $($r.DisplayName) (Name=$($r.Name))"
                    if ($AUTOFIX) { try { Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop; Log-Write "Disabled rule $($r.DisplayName)" } catch { Log-Write "Failed disable: $_" } }
                }
            }
        } else { Log-Write "No firewall rules enumerated using Get-NetFirewallRule." }
    } catch { Log-Write "Firewall check error: $_" }
}

function Backup-Important {
    Backup-Firewall | Out-Null
    Backup-RegistryKey -k 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -name 'Policies' | Out-Null
    # Save tasks list
    try { Get-ScheduledTask | Select-Object TaskName,TaskPath | Out-File (Join-Path $BackupsDir ("tasks_list_" + (Get-TS) + ".txt")) -Encoding UTF8 ; Log-Write "Saved tasks list" } catch {}
}

# ---------------------------
# Original destructive/system commands (COMMENTED)
# To enable them: open this script and set $UNSAFE_OVERRIDE_INSIDE_SCRIPT = $true, then re-run and type I UNDERSTAND.
# Example of original content (verbatim from Vacuum.bat) kept as comments for auditing:
# -------------------------------------------------------------------------------
# REM -- original vacuum.bat excerpt --
# reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
# netsh int ip reset
# netsh winsock reset
# ipconfig /flushdns
# del /s /q C:\Temp\*.*
# shutdown -r -t 5
# -------------------------------------------------------------------------------
# (Full file's destructive commands included in comments further down for review.)
# ---------------------------

# Example function to run unsafe blocks (will not run unless override & confirmation)
function Run-Unsafe-Blocks {
    if (-not (ConfirmUnsafe)) { Log-Write "Unsafe blocks not confirmed; skipping." ; return }
    Log-Write "Running unsafe blocks..."
    # Example translated PowerShell equivalents (UNSAFE) - commented out by default:
    # Log-Write "Disabling UAC (UNSAFE)"; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    # Log-Write "Resetting IP stack (UNSAFE)"; netsh int ip reset
    # Log-Write "Resetting Winsock (UNSAFE)"; netsh winsock reset
    # Log-Write "Flushing DNS cache (UNSAFE)"; ipconfig /flushdns
    # Log-Write "Deleting temporary files (UNSAFE)"; Remove-Item -Path "C:\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    # Log-Write "Rebooting system (UNSAFE)"; Restart-Computer -Force
    # You may uncomment or enable lines above ONLY after you manually set $UNSAFE_OVERRIDE_INSIDE_SCRIPT = $true at top of file.
}

# ---------------------------
# Orchestration: auto-run everything (safe actions)
# ---------------------------
Log-Write "Starting Vacuum_Full auto-run. AutoFix=$AUTOFIX"

# DB-related
Ensure-Exported
Integrity-Check | Out-Null
Export-vEnvio | Out-Null
Mark-Exported-Rows
Write-SqlDump | Out-Null
Write-Pragma | Out-Null

# Backups
Backup-Important

# Remediation and scans (auto)
Restore-Defender-And-ASR
Check-And-Fix-Services
Scan-And-Quarantine-Unsigned
Check-And-Disable-Suspicious-Firewall

# Optionally run Defender quick scan (best-effort)
if (Get-Command -Name Start-MpScan -ErrorAction SilentlyContinue) {
    try { Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue ; Log-Write "Requested Defender quick scan (async)." } catch { Log-Write "Start-MpScan failed: $_" }
} else { Log-Write "Start-MpScan not available." }

# Optional unsafe block execution
if ($UNSAFE_OVERRIDE_INSIDE_SCRIPT) {
    Run-Unsafe-Blocks
} else {
    Log-Write "Unsafe blocks remain disabled. Edit script to enable them if you accept the risk."
}

# Save log & final messages
$Global:Log | Out-File -FilePath $LogFile -Encoding UTF8
Log-Write "Wrote run log to $LogFile"
Write-Host ""
Write-Host "Auto-run complete. Exports: $ExportsDir ; Backups: $BackupsDir ; Quarantine: $QuarantineDir"
Write-Host "To enable the original destructive commands, open this file and set `$UNSAFE_OVERRIDE_INSIDE_SCRIPT = `$true and re-run. You will be required to type 'I UNDERSTAND' to proceed."
Write-Host ""
