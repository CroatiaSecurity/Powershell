# Antivirus.ps1 – 2025 Hardened Edition
# Original author: Gorstak | Hardening & stability fixes: community 2025

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"

# Allowed system accounts (expanded – these never get touched)
$AllowedSIDs = @(
    'S-1-5-18', # LOCAL SYSTEM
    'S-1-5-19', # LOCAL SERVICE
    'S-1-5-20', # NETWORK SERVICE
    'S-1-3-0',  # Creator Owner
    'S-1-5-32-544' # Administrators (optional – remove if you want to block even admin drops)
)

# Never kill these processes – expanded list for 2025
$ProtectedProcessNames = @(
    'System','smss','csrss','wininit','winlogon','services','lsass','svchost','explorer',
    'dwm','sihost','SearchIndexer','SearchUI','ShellExperienceHost','RuntimeBroker',
    'SecurityHealthService','MsMpEng','NisSrv','wdnisdrv','conhost','fontdrvhost'
)

# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup -Force | Out-Null

# ========================== LOGGING ==========================
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
}

function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid" | Out-File $BlockedLog -Append -Encoding ASCII
    Log "BLOCKED $type → $file (PID $pid)"

    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($proc -and $ProtectedNames -contains $proc.ProcessName) {
        Log "Skipping termination of protected process: $($proc.ProcessName)"
        return
    }
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
}

# ========================== FAST ALLOW ==========================
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }
    # 1. Valid Microsoft/Authenticode signature = instant allow
    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -or $sig.Status -eq 'TrustedPublisher') { return $true }
    } catch {}

    # 2. CIRCL known-good hash database
    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()
        $r = Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 4 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}
    return $false
}

# ========================== QUARANTINE ==========================
function Do-Quarantine($file,$reason) {
    if (-not (Test-Path $file)) { return }
    $name = Split-Path $file -Leaf
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ("$name`_$ts.bak")
    $q    = Join-Path $Quarantine ("$name`_$ts")

    # Try to kill anything holding the file
    Get-Process | Where-Object {
        try { $_.Modules.FileName -contains $file } catch { $false }
    } | Where-Object { $ProtectedNames -notcontains $_.Name } | ForEach-Object {
        Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
    }

    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q -Force -ErrorAction Stop
        Log "QUARANTINED [$reason] → $q (backup: $bak)"
    } catch {
        Log "QUARANTINE FAILED [$reason] $file → $_"
    }
}

# ========================== DECISION ENGINE ==========================
$MonitoredExtensions = @('.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.jar','.msi','.cpl','.hta','.lnk')

function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    # Fast allow → skip everything else
    if (Test-FastAllow $file) {
        Log "ALLOWED (trusted signature/CIRCL) → $file"
        return
    }

    # Very small unsigned DLLs in risky folders = almost certainly malicious in 2025
    if ($ext -in '.dll','.winmd') {
        $size = (Get-Item $file).Length
        $pathLow = $file.ToLower()
        if ($size -lt 2MB -and ($pathLow -like '*\temp\*' -or $pathLow -like '*\appdata\*' -or $pathLow -like '*\downloads\*')) {
            Do-Quarantine $file "Suspicious tiny unsigned DLL in risky folder"
            return
        }
    }

    Log "ALLOWED (no reputation hit) → $file"
}

# ========================== REFLECTIVE / MANUAL-MAP SCANNER (2025 fix) ==========================
Log "[+] Starting 2025 reflective/manual-map detector"
Start-Job -Name "ReflectiveScanner" -ScriptBlock {
    $log = "$using:Base\reflective_hits.log"
    while ($true) {
        Start-Sleep -Seconds 15
        Get-Process | Where-Object { $_.WorkingSet64 -gt 30MB } | ForEach-Object {
            $p = $_
            $sus = $false

            # Process has no path on-disk image → hollowed or reflective
            if ([string]::IsNullOrWhiteSpace($p.Path) -or $p.Path -match 'unknown') { $sus = $true }

            # Has modules with empty FileName/ModuleName → manually mapped
            if ($p.Modules | Where-Object { [string]::IsNullOrWhiteSpace($_.FileName)) { $sus = $true }

            if ($sus -and $using:ProtectedNames -notcontains $p.ProcessName) {
                "$([DateTime]::Now) | REFLECTIVE/MANUAL-MAP → $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
} | Out-Null

# ========================== MAIN EXECUTION ==========================
Log "=== Gorstak Antivirus 2025 Hardened Edition starting ==="

# Initial scan of risky folders
@("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}

# FileSystemWatcher on risky folders
$WatchFolders = "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA\Temp"
foreach ($f in $WatchFolders) {
    if (-not (Test-Path $f)) { continue }
    $w = New-Object IO.FileSystemWatcher $f, "*.*" -Property @{
        IncludeSubdirectories = $true
        NotifyFilter = 'FileName,LastWrite'
    }
    Register-ObjectEvent $w Created -Action {
        $path = $Event.SourceEventArgs.FullPath
        $ext  = [IO.Path]::GetExtension($path).ToLower()
        if ($using:MonitoredExtensions -contains $ext) {
            Start-Sleep -Milliseconds 800
            Decide-And-Act $path
        }
    } | Out-Null
    $w.EnableRaisingEvents = $true
}

# Process creation hook (still useful for classic droppers)
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e   = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID  = $e.ProcessId

    if (Test-FastAllow $Path) { return }
    Deny-Execution $Path $PID "EXE"
    Decide-And-Act $Path
} | Out-Null

# Main loop – periodic sweep
Log "All detectors active – entering main loop"
while ($true) {
    Get-Process | ForEach-Object {
        try {
            $exe = $_.MainModule.FileName
            if ($exe -and (Test-Path $exe)) { Decide-And-Act $exe }
        } catch {}
    }
    Start-Sleep -Seconds 45
}