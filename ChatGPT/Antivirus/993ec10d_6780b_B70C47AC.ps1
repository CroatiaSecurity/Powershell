# =====================================================================
#  Antivirus.ps1 - Real-time file scanner with quarantine and process kill
#  ASCII only, no unicode
# =====================================================================

$Base        = "$env:ProgramData\Antivirus"
$Quarantine  = Join-Path $Base "Quarantine"
$Backup      = Join-Path $Base "Backup"
$LogFile     = Join-Path $Base "antivirus.log"

New-Item -ItemType Directory -Path $Base -Force | Out-Null
New-Item -ItemType Directory -Path $Quarantine -Force | Out-Null
New-Item -ItemType Directory -Path $Backup -Force | Out-Null

# =====================================================================
# Logging
# =====================================================================

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
}

# =====================================================================
# Whitelisted extensions (common unsigned harmless files)
# =====================================================================

$AllowedExtensions = @(
    ".tmp",".log",".txt",".png",".jpg",".jpeg",".gif",
    ".bmp",".json",".dat",".dmp",".crx",".crx3",".ini",".db"
)

# =====================================================================
# Check if file is locked
# =====================================================================

function Is-Locked($file) {
    try {
        $stream = [System.IO.File]::Open($file,'Open','ReadWrite')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

# =====================================================================
# Kill processes that have the file open
# =====================================================================

$ProtectedProcessNames = @(
    "explorer","csrss","wininit","winlogon","services",
    "lsass","smss","System","svchost","dwm","winver",
    "SearchApp","fontdrvhost","Registry"
)

function Kill-ProcessesUsingFile($file) {
    Write-Host "Checking processes locking file: $file"

    $procs = Get-Process -ErrorAction SilentlyContinue

    foreach ($p in $procs) {

        # Ignore protected Windows processes
        if ($ProtectedProcessNames -contains $p.Name) { continue }

        try {
            $handles = (Get-Process -Id $p.Id `
               -Module -ErrorAction SilentlyContinue).FileName

            if ($handles -contains $file) {

                Write-Host "   -> Process $($p.Name) (PID $($p.Id)) holds file."

                try {
                    Write-Host "   -> Trying graceful close..."
                    $p.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 500
                } catch {}

                if (!$p.HasExited) {
                    Write-Host "   -> Force killing process."
                    try {
                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Host "   -> Failed to kill $($p.Name)."
                    }
                }

                Log "Killed process $($p.Name) for file $file"
            }
        } catch {}
    }
}

# =====================================================================
# Check digital signature
# =====================================================================

function Check-DigitalSignature($file) {
    Write-Host "Checking signature: $file"

    try {
        $sig = Get-AuthenticodeSignature -FilePath $file
        if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match "Microsoft Corporation") {
            Write-Host "   -> Trusted Microsoft signed"
            return $true
        }
    } catch {}

    Write-Host "   -> Not trusted"
    return $false
}

# =====================================================================
# Move file to quarantine
# =====================================================================

function Move-ToQuarantine($file) {

    # Kill processes using the file
    Kill-ProcessesUsingFile $file

    if (Is-Locked $file) {
        Write-Host "   -> File is still locked. Skipping."
        Log "Skipping locked file $file"
        return
    }

    Write-Host "Quarantining: $file"

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Write-Host "   -> Backup: $bak"
    Write-Host "   -> Quarantine: $q"

    try {
        Copy-Item $file $bak -Force
        Move-Item $file $q -Force
        Log "Quarantined $file"
    } catch {
        Log "ERROR moving $file : $_"
    }
}

# =====================================================================
# Scan a single file
# =====================================================================

function Scan-File($file) {

    if (!(Test-Path $file)) { return }

    Write-Host "Scanning: $file"

    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($AllowedExtensions -contains $ext) {
        Write-Host "   -> Extension whitelisted, skipping."
        return
    }

    # Check digital signature
    $trusted = Check-DigitalSignature $file
    if ($trusted) {
        Write-Host "   -> File trusted"
        return
    }

    # Not trusted -> quarantine
    Write-Host "   -> File untrusted, quarantining"
    Move-ToQuarantine $file
}

# =====================================================================
# Scan a folder recursively
# =====================================================================

function Scan-Folder($path) {

    Write-Host "Starting folder scan: $path"

    if (!(Test-Path $path)) { return }

    $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue

    foreach ($f in $files) {
        Scan-File $f.FullName
    }

    Write-Host "Folder scan complete."
}

# =====================================================================
# Real-time monitoring loop
# =====================================================================

function Start-Monitor {

    Write-Host "Real-time monitor started."
    Log "Monitor started"

    while ($true) {
        try {
            Scan-Folder "$env:TEMP"
            Scan-Folder "C:\Windows\Temp"
        } catch {
            Log "Error in monitor: $_"
        }

        Start-Sleep -Seconds 10
    }
}

# =====================================================================
# Script start
# =====================================================================

Write-Host "Antivirus started."
Log "Antivirus launched"

Scan-Folder "$env:TEMP"
Scan-Folder "C:\Windows\Temp"

# Enable real-time scanning
# Uncomment if desired:
# Start-Monitor
