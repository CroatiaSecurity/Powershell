# NetworkDebloat.ps1
# Author: Gorstak (gorstak.eu)
# Description: Disables unnecessary network adapter bindings (File/Printer Sharing, QoS,
#              LLTD) on all active adapters and blocks LDAP/LDAPS ports via firewall.
#              Installs as persistent scheduled task at logon.
#Requires -RunAsAdministrator

# Define paths and parameters
$taskName = "NetworkDebloatStartup"
$taskDescription = "Runs the NetworkDebloat script at user logon with system privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\NetworkDebloat.ps1"

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Output "Set execution policy to Bypass for current user."
}

# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled task as SYSTEM (cmdlet first, schtasks fallback)
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $installed = $false
    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force | Out-Null
        Write-Output "Scheduled task '$taskName' registered via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Output "Register-ScheduledTask failed: $_"
    }

    # Method 2: schtasks.exe fallback
    if (-not $installed) {
        try {
            $schtasksArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
            $cmd = "schtasks /Create /TN `"$taskName`" /TR `"powershell.exe $schtasksArgs`" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Scheduled task '$taskName' registered via schtasks.exe fallback."
            } else {
                Write-Output "schtasks fallback failed: $result"
            }
        } catch {
            Write-Output "schtasks fallback exception: $_"
        }
    }
} elseif (-not $isAdmin) {
    Write-Output "Skipping task registration: Admin privileges required"
}

# List of unwanted bindings
$componentsToDisable = @(
    "ms_server",     # File and Printer Sharing
    "ms_msclient",   # Client for Microsoft Networks
    "ms_pacer",      # QoS Packet Scheduler
    "ms_lltdio",     # Link Layer Mapper I/O Driver
    "ms_rspndr"      # Link Layer Responder
)

# Disable on all active adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    foreach ($component in $componentsToDisable) {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Block LDAP and LDAPS via firewall
$ldapPorts = @(389, 636)
foreach ($port in $ldapPorts) {
    New-NetFirewallRule -DisplayName "Block LDAP Port $port" -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction SilentlyContinue
}
