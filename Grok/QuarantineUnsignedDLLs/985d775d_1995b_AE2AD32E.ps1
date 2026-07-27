
# QuarantineUnsignedDLLs.ps1
# Purpose: Quarantine unsigned DLL files, excluding whitelisted paths (script, its files, and quarantine folder)

# Define paths
$scriptPath = $PSCommandPath
$scriptDir = Split-Path -Parent $scriptPath
$quarantineDir = Join-Path $scriptDir "Quarantine"
$targetDir = "C:\Path\To\Scan" # Replace with the directory to scan
$whitelist = @($scriptPath, $scriptDir, $quarantineDir)

# Create quarantine directory if it doesn't exist
if (-not (Test-Path $quarantineDir)) {
    New-Item -Path $quarantineDir -ItemType Directory | Out-Null
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
        return $false
    }
}

# Scan for DLL files
$dllFiles = Get-ChildItem -Path $targetDir -Recurse -Include "*.dll" -File

foreach ($file in $dllFiles) {
    # Skip whitelisted paths
    if ($whitelist -contains $file.FullName -or $file.FullName.StartsWith($quarantineDir)) {
        Write-Host "Skipping whitelisted file: $($file.FullName)"
        continue
    }

    # Check if the DLL is unsigned
    if (-not (Test-FileSignature -FilePath $file.FullName)) {
        Write-Host "Quarantining unsigned DLL: $($file.FullName)"
        $destPath = Join-Path $quarantineDir $file.Name
        # Avoid name conflicts in quarantine
        $counter = 1
        while (Test-Path $destPath) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $extension = [System.IO.Path]::GetExtension($file.Name)
            $destPath = Join-Path $quarantineDir "$baseName_$counter$extension"
            $counter++
        }
        Move-Item -Path $file.FullName -Destination $destPath -Force
    } else {
        Write-Host "Signed DLL, skipping: $($file.FullName)"
    }
}

Write-Host "Quarantine process completed."
