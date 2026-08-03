

# ExtractRegTweaks.ps1
# Extracts registry tweaks from a privacy.sexy batch script and writes them to a .reg file
# Excludes tweaks that explicitly break functionality (e.g., Phone Link, Sound Recorder, Microsoft Store, System Restore)

param (
    [Parameter(Mandatory=$true)]
    [string]$BatchFilePath, # Path to the input batch file (e.g., privacy-script.bat)
    [Parameter(Mandatory=$true)]
    [string]$OutputRegFile # Path to the output .reg file (e.g., privacy-script.reg)
)

# Ensure the batch file exists
if (-not (Test-Path $BatchFilePath)) {
    Write-Error "Batch file not found: $BatchFilePath"
    exit 1
}

# Read the batch file content
$batchContent = Get-Content -Path $BatchFilePath -Raw

# Initialize output for .reg file
$regContent = @"
Windows Registry Editor Version 5.00

; Generated from $BatchFilePath by ExtractRegTweaks.ps1
; https://privacy.sexy - v0.13.8 - Thu, 02 Oct 2025
; Excludes tweaks that break functionality (Phone Link, Sound Recorder, Microsoft Store, System Restore)
; WARNING: Script may be truncated; provide full script for complete tweaks

"@

# Flag to track if the script is truncated
$isTruncated = $batchContent -match "truncated \d+ characters"

# List of tweaks that break functionality (based on comments)
$breakingTweaks = @(
    "Disable app access to phone calls", # Breaks Phone Link
    "Disable app access to microphone", # Breaks Sound Recorder
    "Disable Microsoft Account Sign-in Assistant", # Breaks Microsoft Store and account sign-in
    "Disable Shadow Copy" # Breaks System Restore and Windows Backup
)

# Function to convert PowerShell reg add to .reg format
function Convert-ToRegFormat {
    param (
        [string]$Command,
        [string]$SectionComment
    )
    # Extract registry path, value name, type, and data
    if ($Command -match 'reg add\s+''([^'']+)''\s+/v\s+''([^'']+)''\s+/t\s+''([^'']+)''\s+/d\s+''([^'']+)''\s+/f') {
        $regPath = $Matches[1] -replace '\\', '\\'
        $valueName = $Matches[2]
        $regType = $Matches[3]
        $valueData = $Matches[4]

        # Convert PowerShell types to .reg types
        switch ($regType) {
            'REG_SZ' { $valueData = "`"$valueData`"" }
            'REG_DWORD' { $valueData = "dword:$($valueData.PadLeft(8, '0'))" }
            'REG_MULTI_SZ' {
                if ($valueData -eq '\0') {
                    return "; $SectionComment`n[-$regPath]`n"
                } else {
                    $valueData = $valueData -replace '\0', '\0'
                    $valueData = "`"$valueData`""
                }
            }
            default { return $null }
        }

        return "; $SectionComment`n[$regPath]`n`"$valueName`"=$valueData`n"
    }
    return $null
}

# Function to handle NTP settings (w32tm command)
function Add-NTPSettings {
    $ntpReg = @"
; Set NTP (time) server to pool.ntp.org
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters]
"NtpServer"="0.pool.ntp.org,0x1 1.pool.ntp.org,0x1 2.pool.ntp.org,0x1 3.pool.ntp.org,0x1"
"Type"="NTP"

"@
    return $ntpReg
}

# Parse the batch file line by line
$currentSection = ""
$skipSection = $false
$regTweaks = @()

foreach ($line in $batchContent -split "`n") {
    # Detect section headers
    if ($line -match '^echo --- (.+)$') {
        $currentSection = $Matches[1].Trim()
        $skipSection = $breakingTweaks -contains $currentSection
        continue
    }

    # Skip sections that break functionality
    if ($skipSection) { continue }

    # Extract reg add commands
    if ($line -match 'reg add\s+') {
        $regEntry = Convert-ToRegFormat -Command $line -SectionComment $currentSection
        if ($regEntry) {
            $regTweaks += $regEntry
        }
    }

    # Handle service disabling (registry-based)
    if ($line -match 'Set-ItemProperty.*HKLM:\\SYSTEM\\CurrentControlSet\\Services\\([^\\]+).*Start.*4') {
        $serviceName = $Matches[1]
        $regEntry = "; $currentSection`n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\$serviceName]`n`"Start`"=dword:00000004`n"
        $regTweaks += $regEntry
    }

    # Handle NTP settings
    if ($line -match 'w32tm /config /syncfromflags:manual /manualpeerlist:') {
        $regTweaks += Add-NTPSettings
    }
}

# Add note about truncation
if ($isTruncated) {
    $regContent += "; WARNING: Batch script is truncated. Missing tweaks may include app permissions (e.g., camera, contacts), telemetry settings, or other privacy policies.`n"
    $regContent += "; Common missing tweaks might include:`n"
    $regContent += "; - Disable telemetry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry=dword:00000000`n"
    $regContent += "; - Disable Cortana: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\AllowCortana=dword:00000000`n"
    $regContent += "; - Disable advertising ID: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled=dword:00000000`n"
    $regContent += "; Provide the full script to include all tweaks.`n`n"
}

# Combine unique tweaks and write to file
$regTweaks = $regTweaks | Select-Object -Unique
$regContent += ($regTweaks -join "`n")

try {
    Set-Content -Path $OutputRegFile -Value $regContent -Force
    Write-Host "Successfully wrote registry tweaks to $OutputRegFile"
}
catch {
    Write-Error "Failed to write to $OutputRegFile : $_"
    exit 1
}

