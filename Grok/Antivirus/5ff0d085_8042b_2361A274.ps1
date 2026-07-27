# Antivirus.ps1
# Author: Gorstak

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"
$Database   = Join-Path $Base "scanned_files.txt"

$MonitoredExtensions = @('.com', '.exe', '.exif', '.dll', '.winmd', '.scr', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.cpl', '.hta', '.lnk')

$ProtectedProcessNames = @(
    'System','smss','csrss','wininit','winlogon','services','lsass','svchost',
    'explorer','dwm','SearchIndexer','SearchUI','ShellExperienceHost',
    'RuntimeBroker','SecurityHealthService','MsMpEng','NisSrv','conhost'
)

$RiskyPaths = @('\temp','\downloads','\appdata\local\temp','\public','\windows\temp','\appdata\roaming','\desktop')

$AllowedSIDs = @('S-1-2-0', 'S-1-5-20')

# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup -Force | Out-Null

# ----------------------- Logging -----------------------
function Log {
    param([string]$msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
}

# ----------------------- Quarantine -----------------------
function Do-Quarantine {
    param([string]$file, [string]$reason)

    if (-not (Test-Path $file)) { return }

    $name = Split-Path $file -Leaf
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup "$name`_$ts.bak"
    $q    = Join-Path $Quarantine "$name`_$ts"

    # Try to kill non-protected processes holding the file
    Get-Process | Where-Object {
        try { $_.Modules.FileName -contains $file } catch { $false }
    } | Where-Object { $ProtectedProcessNames -notcontains $_.Name } |
    ForEach-Object { Stop-Process $_.Id -Force -ErrorAction SilentlyContinue }

    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q -Force -ErrorAction Stop
        Log "QUARANTINED [$reason] -> $q (backup: $bak)"
    } catch {
        Log "QUARANTINE FAILED [$reason] $file - $($_.Exception.Message)"
    }
}

# ----------------------- Fast Allow -----------------------
function Test-FastAllow {
    param([string]$filePath)

    if (-not (Test-Path $filePath)) { return $false }

    # Check signature
    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -or $sig.Status -eq 'TrustedPublisher') {
            return $true
        }
    } catch {}

    # CIRCL hash lookup
    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()
        $r = Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}

    return $false
}

# ----------------------- Suspicious small unsigned DLL -----------------------
function Is-SuspiciousUnsignedDll {
    param([string]$file)

    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin @('.dll','.winmd')) { return $false }

    try {
        $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $false }
    } catch { return $false }

    $size = (Get-Item $file -ErrorAction SilentlyContinue).Length
    $pathLower = $file.ToLower()

    foreach ($rp in $RiskyPaths) {
        if ($pathLower -like "*$rp*" -and $size -lt 3MB) {
            return $true
        }
    }

    return $false
}

# ----------------------- Main decision logic -----------------------
function Decide-And-Act {
    param([string]$file)

    if (-not (Test-Path $file -PathType Leaf)) { return }

    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    if (Test-FastAllow $file) {
        Log "ALLOWED (trusted signature or CIRCL) -> $file"
        return
    }

    if (Is-SuspiciousUnsignedDll $file) {
        Do-Quarantine $file "Suspicious small unsigned DLL in risky path"
        return
    }

    Log "ALLOWED (no strong reputation hit) -> $file"
}

# ----------------------- Reflective / Manual Map Detector -----------------------
Log "Starting reflective / manual-map detector"
Start-Job -Name "ReflectiveScanner" -ScriptBlock {
    $log = "$using:Base\reflective_hits.log"
    $protected = $using:ProtectedProcessNames

    while ($true) {
        Start-Sleep -Seconds 15
        Get-Process | Where-Object { $_.WorkingSet64 -gt 30MB } | ForEach-Object {
            $p = $_
            $sus = $false

            if ([string]::IsNullOrWhiteSpace($p.Path)) { $sus = $true }
            if ($p.Modules | Where-Object { [string]::IsNullOrWhiteSpace($_.FileName) }) { $sus = $true }

            if ($sus -and $protected -notcontains $p.ProcessName) {
                "$(Get-Date) | REFLECTIVE/MANUAL-MAP -> $($p.Name) ($($p.Id)) Path='$($p.Path)'" |
                    Out-File $log -Append -Encoding ASCII
                Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
} | Out-Null

# ----------------------- Initial scan -----------------------
Log "Performing initial scan of risky folders"
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") |
ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { Decide-And-Act $_.FullName }
    }
}

# ----------------------- Real-time FileSystemWatcher -----------------------
$WatchFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:LOCALAPPDATA\Packages",          # UWP / modern apps
    "C:\Temp",                              # common drop location
    "C:\Users\Public\Downloads"             # sometimes used by installers
    # Add company-specific shared folders if needed, e.g. "\\server\IT-Drop"
)

foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }

    $w = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{
        IncludeSubdirectories = $true
        NotifyFilter          = 'FileName,LastWrite'
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

Log "FileSystemWatcher real-time monitoring started"

# ----------------------- WMI Process Start Hook -----------------------
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e    = $Event.SourceEventArgs.NewEvent
    $path = $e.ProcessName
    $pid  = $e.ProcessId

    if (Test-FastAllow $path) { return }
    Decide-And-Act $path

    # Optional: aggressive kill (comment out if too noisy)
    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($proc -and $using:ProtectedProcessNames -notcontains $proc.ProcessName) {
       Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
} | Out-Null

Log "WMI process creation hook registered"

# ----------------------- Main loop (periodic sweep) -----------------------
Log "=== Antivirus started - entering main loop ==="

try {
    while ($true) {
        Get-Process | ForEach-Object {
            try {
                $exe = $_.MainModule.FileName
                if ($exe -and (Test-Path $exe)) {
                    Decide-And-Act $exe
                }
            } catch {}
        }
        Start-Sleep -Seconds 60
    }
}
finally {
    Log "Script is exiting / was terminated"
}