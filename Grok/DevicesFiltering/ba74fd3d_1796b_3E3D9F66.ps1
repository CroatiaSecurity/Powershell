# DevicesFiltering.ps1 by Gorstak
# PowerShell script to list devices and set permissions using SetACL.exe

# Ensure the script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

# Get the script's directory and path to SetACL.exe
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$setAclPath = Join-Path $scriptDir "SetACL.exe"

# Check if SetACL.exe exists in the script's folder
if (-not (Test-Path $setAclPath)) {
    Write-Error "SetACL.exe not found in the script's folder: $scriptDir"
    exit 1
}

# List all devices
Write-Host "Listing all devices..."
$devices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -ne $null } | Select-Object Name, DeviceID
$devices | Format-Table -AutoSize

# Define the Console Logon group
$consoleLogonGroup = "S-1-2-1"

# Iterate through each device and set permissions
foreach ($device in $devices) {
    $deviceId = $device.DeviceID
    Write-Host "Setting permissions for device: $($device.Name) ($deviceId)"

    # Use SetACL to grant full control to Console Logon group
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np" -ace "n:$consoleLogonGroup;p:full"

    # Remove inherited permissions
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np"

    # Remove all other permissions except Console Logon
    & $setAclPath -on $deviceId -ot reg -actn rstchldrn -rst "dacl,sacl"

    Write-Host "Permissions updated for $deviceId"
}

Write-Host "Permissions update completed for all devices."