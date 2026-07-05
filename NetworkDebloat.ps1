# NetworkDebloat.ps1
# Author: Gorstak (gorstak.eu)
# Description: Disables unnecessary network adapter bindings (File/Printer Sharing, QoS,
#              LLTD) on all active adapters and blocks LDAP/LDAPS ports via firewall.
#              Installs as persistent scheduled task at startup.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "NetworkDebloatSetup"
$Script:InstallDir = "$env:ProgramData\NetworkDebloat"
$Script:ScriptName = "NetworkDebloat.ps1"

function Install-Persistence {
    # Create install directory
    if (-not (Test-Path $Script:InstallDir)) {
        New-Item -Path $Script:InstallDir -ItemType Directory -Force | Out-Null
    }

    # Copy script to install location
    $targetPath = Join-Path $Script:InstallDir $Script:ScriptName
    Copy-Item -Path $PSCommandPath -Destination $targetPath -Force

    # Register scheduled task (cmdlet first, schtasks fallback)
    $installed = $false
    $pwshArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Scheduled task '$($Script:TaskName)' registered via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Host "Register-ScheduledTask failed: $_"
    }

    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Scheduled task '$($Script:TaskName)' registered via schtasks.exe fallback."
            } else {
                Write-Host "schtasks fallback failed: $result"
            }
        } catch {
            Write-Host "schtasks fallback exception: $_"
        }
    }

    Write-Host "Persistence installed to: $targetPath"
}

function Uninstall-Persistence {
    Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $Script:InstallDir) {
        Remove-Item -Path $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Persistence removed for '$($Script:TaskName)'."
}

if ($Install) { Install-Persistence; return }
if ($Uninstall) { Uninstall-Persistence; return }

# Auto-install if not running from installed location
$installedPath = Join-Path $Script:InstallDir $Script:ScriptName
if ($PSCommandPath -and $PSCommandPath -ne $installedPath) {
    $existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        Install-Persistence
        return
    }
}

# ==============================
# Main Logic - Network Debloat
# ==============================

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
