# Antivirus.ps1 - Hardened & Corrected
# Lightweight PowerShell-based Antivirus Engine
# Includes async queue, watchers, process monitor, CIRCL/MalwareBazaar lookups,
# quarantine, backup, heuristic checks, and script integrity self-protection.

# ----------------------------------
# Configuration
# ----------------------------------
$Base         = "C:\ProgramData\Antivirus"
$Quarantine   = Join-Path $Base "Quarantine"
$Backup       = Join-Path $Base "Backup"
$LogFile      = Join-Path $Base "antivirus.log"
$MaxQueueSize = 20000
$WorkerCount  = 4
$SelfCheckIntervalSeconds = 30

$MalwareBazaarAuthKey = ""   # optional
$CirclLookupBase      = "https://hashlookup.circl.lu/lookup/sha256"
$MalwareBazaarAPI     = "https://mb-api.abuse.ch/api/v1/"

$ScanExtensions = @(
    '.exe','.dll','.sys','.drv','.ocx','.cpl','.scr',
    '.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.js',
    '.wsf','.wsh','.ps1xml','.pssc','.winmd'
)

$MonitorPaths = @("C:\","D:\")

$Exclusions = @(
    "$Base*",
    "C:\Windows\*",
    "C:\Program Files*",
    "C:\Program Files (x86)*"
)

# ----------------------------------
# Init Folders
# ----------------------------------
New-Item -ItemType Directory -Path $Base -Force | Out-Null
New-Item -ItemType Directory -Path $Quarantine -Force | Out-Null
New-Item -ItemType Directory -Path $Backup -Force | Out-Null

# ----------------------------------
# Logging
# ----------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"

    try {
        Add-Content -Path $LogFile -Value $line -ErrorAction Stop
    } catch {
        Write-Host $line
    }
}

# ----------------------------------
# Utilities
# ----------------------------------
function Safe-GetFileHash([string]$Path) {
    try {
        if (-not (Test-Path $Path)) { return $null }
        return (Get-FileHash -Path $Path -Algorithm SHA256 -EA Stop).Hash.ToLower()
    } catch {
        Write-Log "Failed to hash $($Path): $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Matches-Exclusion([string]$Path) {
    foreach ($ex in $Exclusions) {
        if ($Path -like $ex) { return $true }
    }
    return $false
}

function Is-ScanCandidate([string]$Path) {
    $ext = [IO.Path]::GetExtension($Path)
    if (-not $ext) { return $false }
    return ($ScanExtensions -contains $ext.ToLower())
}

function Quarantine-File([string]$Path,[string]$Reason) {
    try {
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $name = [IO.Path]::GetFileName($Path)
        $qfile = Join-Path $Quarantine "${ts}_$name"

        Copy-Item $Path (Join-Path $Backup "${ts}_$name") -Force -EA SilentlyContinue
        Move-Item $Path $qfile -Force -EA Stop

        Write-Log "Quarantined $($Path) -> $($qfile) : $($Reason)" 'WARN'
        return $qfile
    } catch {
        Write-Log "Failed to quarantine $($Path): $($_.Exception.Message)" 'ERROR'
        return $null
    }
}

# ----------------------------------
# Online Lookups
# ----------------------------------
function Query-CIRCL([string]$sha256) {
    try {
        return Invoke-RestMethod "$CirclLookupBase/$sha256" -UseBasicParsing -Method GET -TimeoutSec 10
    } catch {
        Write-Log "CIRCL lookup failed for $($sha256): $($_.Exception.Message)" 'DEBUG'
        return $null
    }
}

function Query-MalwareBazaar([string]$sha256) {
    try {
        $body = @{ query = 'get_info'; sha256_hash = $sha256 }
        if ($MalwareBazaarAuthKey) { $body.api_key = $MalwareBazaarAuthKey }

        return Invoke-RestMethod -Uri $MalwareBazaarAPI -Method POST -Body $body -TimeoutSec 15
    } catch {
        Write-Log "MalwareBazaar lookup failed for $($sha256): $($_.Exception.Message)" 'DEBUG'
        return $null
    }
}

# ----------------------------------
# Scan File
# ----------------------------------
function Scan-File([string]$Path) {
    try {
        if (-not (Test-Path $Path)) { return }
        if (Matches-Exclusion $Path) { return }
        if (-not (Is-ScanCandidate $Path)) { return }

        $sha256 = Safe-GetFileHash $Path
        if (-not $sha256) { return }

        # Check if signed
        $signed = $false
        try {
            if ((Get-AuthenticodeSignature $Path).Status -eq 'Valid') { $signed = $true }
        } catch {}

        if ($signed) {
            Write-Log "Allowed (signed): $($Path)" 'INFO'
            return
        }

        # CIRCL
        $circl = Query-CIRCL $sha256
        if ($circl -and $circl.count -gt 0) {
            Quarantine-File $Path "CIRCL match"
            return
        }

        # MalwareBazaar
        $mb = Query-MalwareBazaar $sha256
        if ($mb.query_status -eq 'ok') {
            Quarantine-File $Path "MalwareBazaar match"
            return
        }

        # Heuristic: large unsigned EXE/DLL
        $fi = Get-Item $Path -EA SilentlyContinue
        if ($fi.Length -gt 10MB -and $Path -match '\.(exe|dll|sys|drv|ocx|cpl|scr)$') {
            Quarantine-File $Path "Heuristic large unsigned binary"
            return
        }

        Write-Log "No threat found: $($Path)" 'INFO'
    } catch {
        Write-Log "Error scanning $($Path): $($_.Exception.Message)" 'ERROR'
    }
}

# ----------------------------------
# Async Queue & Workers
# ----------------------------------
Add-Type -AssemblyName System.Collections.Concurrent
$Queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function Enqueue-Path([string]$p) {
    if ($Queue.Count -ge $MaxQueueSize) {
        Write-Log "Queue full, dropping $($p)" 'WARN'
        return
    }
    $Queue.Enqueue($p)
}

function Start-Worker {
    $sb = {
        param($Queue,$ScanScript)
        while ($true) {
            $item = $null
            if ($Queue.TryDequeue([ref]$item)) {
                & $ScanScript $item
            } else {
                Start-Sleep -Milliseconds 200
            }
        }
    }

    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $ps.AddScript($sb).AddArgument($Queue).AddArgument((Get-Command Scan-File).ScriptBlock)
    $ps.BeginInvoke() | Out-Null
}

# Start workers
for ($i=1; $i -le $WorkerCount; $i++) { Start-Worker }
Write-Log "Started $WorkerCount workers" 'INFO'

# ----------------------------------
# FileSystem Watchers
# ----------------------------------
function Start-Watchers {
    foreach ($p in $MonitorPaths) {
        if (-not (Test-Path $p)) { Write-Log "Missing path: $($p)" 'WARN'; continue }

        try {
            $fsw = New-Object IO.FileSystemWatcher $p
            $fsw.IncludeSubdirectories = $true
            $fsw.NotifyFilter = [IO.NotifyFilters]'FileName,LastWrite,Size'

            Register-ObjectEvent $fsw Created -Action {
                $f = $Event.SourceEventArgs.FullPath
                if (-not (Matches-Exclusion $f)) { Enqueue-Path $f }
            } | Out-Null

            Register-ObjectEvent $fsw Changed -Action {
                $f = $Event.SourceEventArgs.FullPath
                if (-not (Matches-Exclusion $f)) { Enqueue-Path $f }
            } | Out-Null

            Register-ObjectEvent $fsw Renamed -Action {
                $f = $Event.SourceEventArgs.FullPath
                if (-not (Matches-Exclusion $f)) { Enqueue-Path $f }
            } | Out-Null

            $fsw.EnableRaisingEvents = $true
            Write-Log "Watcher active for: $($p)" 'INFO'
        } catch {
            Write-Log "Failed to start watcher for $($p): $($_.Exception.Message)" 'ERROR'
        }
    }
}

# ----------------------------------
# Process Monitor
# ----------------------------------
function Start-ProcessMonitor {
    try {
        Register-WmiEvent `
            -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" `
            -SourceIdentifier "ProcMon" `
            -Action {
                $p = $Event.SourceEventArgs.NewEvent.TargetInstance
                $path = $p.ExecutablePath
                if ($path -and (Is-ScanCandidate $path) -and -not (Matches-Exclusion $path)) {
                    Enqueue-Path $path
                }
            } | Out-Null

        Write-Log "Process monitor started" 'INFO'
    } catch {
        Write-Log "Process monitor failed: $($_.Exception.Message)" 'ERROR'
    }
}

# ----------------------------------
# Self-Protection
# ----------------------------------
$ScriptPath = $MyInvocation.MyCommand.Path
$OriginalHash = Safe-GetFileHash $ScriptPath

function Self-Check {
    try {
        $h = Safe-GetFileHash $ScriptPath
        if ($h -and $h -ne $OriginalHash) {
            Write-Log "Script tampered! Attempting restore..." 'WARN'

            $name = Split-Path $ScriptPath -Leaf
            $bak = Get-ChildItem $Backup -Filter "*_$name" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

            if ($bak) {
                Copy-Item $bak.FullName $ScriptPath -Force
                Write-Log "Restored script from backup." 'WARN'
            }
        }
    } catch {
        Write-Log "Self-check error: $($_.Exception.Message)" 'ERROR'
    }
}

$SelfTimer = New-Object System.Timers.Timer ($SelfCheckIntervalSeconds * 1000)
$SelfTimer.AutoReset = $true
$SelfTimer.add_Elapsed({ Self-Check })
$SelfTimer.Enabled = $true

# ----------------------------------
# Initial Scan
# ----------------------------------
function Seed-InitialScan {
    Write-Log "Starting initial scan..." 'INFO'
    foreach ($p in $MonitorPaths) {
        try {
            Get-ChildItem -Path $p -Recurse -Force -EA SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object {
                    $fp = $_.FullName
                    if (Is-ScanCandidate $fp -and -not (Matches-Exclusion $fp)) {
                        Enqueue-Path $fp
                    }
                }
        } catch {
            Write-Log "Initial scan error in $($p): $($_.Exception.Message)" 'WARN'
        }
    }
}

# ----------------------------------
# START
# ----------------------------------
Start-Watchers
Start-ProcessMonitor
Seed-InitialScan

Write-Log "Antivirus started." 'INFO'
Write-Host "Antivirus running. Ctrl+C to stop. Logs at $LogFile"

while ($true) {
    Start-Sleep -Milliseconds 500
}
