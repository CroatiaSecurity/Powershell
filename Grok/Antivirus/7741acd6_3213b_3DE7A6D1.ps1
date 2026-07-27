
# Antivirus.ps1
# Purpose: Basic antivirus script to scan for unsigned DLL files, quarantine them, and exclude whitelisted paths

# Define paths
$scriptPath = $PSCommandPath
$scriptDir = Split-Path -Parent $scriptPath
$quarantineDir = Join-Path $scriptDir "Quarantine"
$scanDir = "C:\Path\To\Scan" # Replace with the directory to scan
$logFile = Join-Path $scriptDir "AntivirusLog.txt"
$whitelist = @($scriptPath, $scriptDir, $quarantineDir)

# Create quarantine directory if it doesn't exist
if (-not (Test-Path $quarantineDir)) {
    New-Item -Path $quarantineDir -ItemType Directory | Out-Null
    Write-Output "$(Get-Date): Created quarantine directory at $quarantineDir" | Out-File -FilePath $logFile -Append
}

# Function to check if a file is digitally signed
function Test-FileSignature {
    param (
        [string]$FilePath
    )
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        return $signature.Status -eq "Valid"
    } catch {
        Write-Output "$(Get-Date): Error checking signature for $FilePath - $_" | Out-File -FilePath $logFile -Append
        return $false
    }
}

# Function to quarantine a file
function Quarantine-File {
    param (
        [string]$FilePath
    )
    $destPath = Join-Path $quarantineDir ([System.IO.Path]::GetFileName($FilePath))
    $counter = 1
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $extension = [System.IO.Path]::GetExtension($FilePath)
    while (Test-Path $destPath) {
        $destPath = Join-Path $quarantineDir "$baseName_$counter$extension"
        $counter++
    }
    try {
        Move-Item -Path $FilePath -Destination $destPath -Force -ErrorAction Stop
        Write-Output "$(Get-Date): Quarantined $FilePath to $destPath" | Out-File -FilePath $logFile -Append
        Write-Host "Quarantined: $FilePath"
    } catch {
        Write-Output "$(Get-Date): Failed to quarantine $FilePath - $_" | Out-File -FilePath $logFile -Append
        Write-Host "Failed to quarantine: $FilePath"
    }
}

# Main antivirus scan
Write-Host "Starting antivirus scan..."
Write-Output "$(Get-Date): Starting scan of $scanDir" | Out-File -FilePath $logFile -Append

# Scan for DLL files
$dllFiles = Get-ChildItem -Path $scanDir -Recurse -Include "*.dll" -File -ErrorAction SilentlyContinue

foreach ($file in $dllFiles) {
    # Skip whitelisted paths
    if ($whitelist -contains $file.FullName -or $file.FullName.StartsWith($quarantineDir)) {
        Write-Host "Skipping whitelisted file: $($file.FullName)"
        Write-Output "$(Get-Date): Skipped whitelisted file: $($file.FullName)" | Out-File -FilePath $logFile -Append
        continue
    }

    # Check if the DLL is unsigned
    if (-not (Test-FileSignature -FilePath $file.FullName)) {
        Write-Host "Unsigned DLL detected: $($file.FullName)"
        Quarantine-File -FilePath $file.FullName
    } else {
        Write-Host "Signed DLL, skipping: $($file.FullName)"
        Write-Output "$(Get-Date): Signed DLL, skipped: $($file.FullName)" | Out-File -FilePath $logFile -Append
    }
}

Write-Host "Antivirus scan completed."
Write-Output "$(Get-Date): Scan completed." | Out-File -FilePath $logFile -Append
