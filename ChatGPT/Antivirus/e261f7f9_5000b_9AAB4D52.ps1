# =====================================================================
#  Simple Antivirus / Integrity Monitor
#  Rewritten with full console output (ASCII only)
# =====================================================================

$Base      = "$env:ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"

# Create folders
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
# Check digital signature
# =====================================================================

function Check-DigitalSignature($file) {
    Write-Host "Checking signature: $file"
    try {
        $sig = Get-AuthenticodeSignature -FilePath $file
        if ($sig.Status -eq "Valid") {
            if ($sig.SignerCertificate.Subject -match "Microsoft Corporation") {
                Write-Host "   -> Microsoft signed"
                return $true
            }
            Write-Host "   -> Signed but not trusted"
            return $false
        }
    } catch {
        Write-Host "   -> Error reading signature"
    }
    Write-Host "   -> Not signed"
    return $false
}

# =====================================================================
# Quarantine file
# =====================================================================

function Move-ToQuarantine($file) {
    Write-Host "Quarantining: $file"

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Write-Host "   -> Backup copy: $bak"
    Write-Host "   -> Quarantine path: $q"

    try {
        Copy-Item $file $bak -Force
        Move-Item $file $q -Force
        Log "Quarantined $file"
    } catch {
        Log "ERROR: Failed to quarantine $file : $_"
    }
}

# =====================================================================
# Restore from quarantine
# =====================================================================

function Restore-FromQuarantine($src, $dest) {
    Write-Host "Restoring: $src to $dest"

    try {
        Move-Item $src $dest -Force
        Log "Restored $src"
    } catch {
        Log "ERROR: Failed to restore $src : $_"
    }
}

# =====================================================================
# Scan a single file
# =====================================================================

function Scan-File($file) {

    if (!(Test-Path $file)) {
        Write-Host "File not found: $file"
        return
    }

    Write-Host "Scanning: $file"

    # 1. Signature check
    $trusted = Check-DigitalSignature $file

    if ($trusted) {
        Write-Host "   -> File trusted"
        return
    }

    # 2. Unknown or unsigned -> quarantine
    Write-Host "   -> File NOT trusted, sending to quarantine"
    Move-ToQuarantine $file
}

# =====================================================================
# Scan folder recursively
# =====================================================================

function Scan-Folder($path) {
    Write-Host "Starting folder scan: $path"

    if (!(Test-Path $path)) {
        Write-Host "Folder not found: $path"
        return
    }

    $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue

    foreach ($f in $files) {
        Scan-File $f.FullName
    }

    Write-Host "Folder scan complete."
}

# =====================================================================
# Continuous monitoring loop (optional)
# =====================================================================

function Start-Monitor {
    Write-Host "Starting real-time monitor loop."
    Log "Monitor started"

    while ($true) {
        try {
            # Example: scan Windows temp every 10 seconds
            Scan-Folder "$env:TEMP"

            # Add other folders if needed:
            # Scan-Folder "C:\ProgramData"
            # Scan-Folder "C:\Windows\System32"

            Start-Sleep -Seconds 10
        } catch {
            Log "Error in monitoring loop: $_"
        }
    }
}

# =====================================================================
# Script entry point
# =====================================================================

Write-Host "Antivirus.ps1 started."
Log "Antivirus launched"

# Example one-time scans
Scan-Folder "C:\Windows\Temp"
Scan-Folder "$env:TEMP"

# Uncomment to enable continuous monitoring:
# Start-Monitor
