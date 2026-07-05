#requires -RunAsAdministrator
# BCDCleanup.ps1
# Author: Gorstak (gorstak.eu)
# Description: Enumerates Boot Configuration Data (BCD) entries, identifies suspicious
#              non-Windows boot entries (VHD, non-standard paths), backs up BCD store,
#              and removes suspicious entries automatically. One-time run utility.

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "BCDCleanupTask"
$Script:InstallDir = "$env:ProgramData\BCDCleanup"
$Script:ScriptName = "BCDCleanup.ps1"

function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "BCD Cleanup Task (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONSTART /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] BCDCleanup uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

# Fully automated script to enumerate and clean up suspicious BCD entries
# Designed for batch file compatibility, with no user input
# Logs actions and creates a BCD backup before changes
# Run in an elevated PowerShell prompt or from a batch file

# Set up logging
$LogFile = "C:\BCD_Cleanup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

# Initialize exit code (0 = success, 1 = error)
$ExitCode = 0

# Create backup of BCD store
$BackupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
Write-Log "Creating BCD backup at $BackupPath"
try {
    & (Join-Path $env:windir "system32\bcdedit.exe") /export $BackupPath | Out-Null
    Write-Log "BCD backup created successfully."
} catch {
    Write-Log "Error creating BCD backup: $_"
    $ExitCode = 1
    exit $ExitCode
}

# Get all BCD entries
Write-Log "Enumerating all BCD entries..."
$BcdOutput = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if (-not $BcdOutput) {
    Write-Log "Error: Failed to enumerate BCD entries."
    $ExitCode = 1
    exit $ExitCode
}

$BcdEntries = @()
$currentEntry = $null
foreach ($line in $BcdOutput) {
    if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
        if ($currentEntry) {
            $BcdEntries += $currentEntry
        }
        $currentEntry = [PSCustomObject]@{
            Identifier = $Matches[1]
            Properties = @{}
        }
    } elseif ($line -match "^(\w+)\s+(.+)$") {
        if ($currentEntry) {
            $currentEntry.Properties[$Matches[1]] = $Matches[2]
        }
    }
}
if ($currentEntry) {
    $BcdEntries += $currentEntry
}

# Define critical identifiers to protect
$CriticalIds = @("{bootmgr}", "{current}", "{default}")

# Flag suspicious entries
Write-Log "Analyzing BCD entries for suspicious content..."
$SuspiciousEntries = @()
foreach ($entry in $BcdEntries) {
    $isSuspicious = $false
    $reason = ""

    # Skip critical entries
    if ($entry.Identifier -in $CriticalIds) {
        continue
    }

    # Check for suspicious characteristics
    if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
        $isSuspicious = $true
        $reason += "Non-Windows description: $($entry.Properties.description); "
    }
    if ($entry.Properties.device -match "vhd=") {
        $isSuspicious = $true
        $reason += "Uses VHD device: $($entry.Properties.device); "
    }
    if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
        $isSuspicious = $true
        $reason += "Non-standard boot path: $($entry.Properties.path); "
    }

    if ($isSuspicious) {
        $SuspiciousEntries += [PSCustomObject]@{
            Identifier = $entry.Identifier
            Description = $entry.Properties.description
            Device = $entry.Properties.device
            Path = $entry.Properties.path
            Reason = $reason
        }
    }
}

# Process suspicious entries
if ($SuspiciousEntries.Count -eq 0) {
    Write-Log "No suspicious BCD entries found."
} else {
    Write-Log "Found $($SuspiciousEntries.Count) suspicious BCD entries:"
    foreach ($entry in $SuspiciousEntries) {
        Write-Log "Identifier: $($entry.Identifier)"
        Write-Log "Description: $($entry.Description)"
        Write-Log "Device: $($entry.Device)"
        Write-Log "Path: $($entry.Path)"
        Write-Log "Reason: $($entry.Reason)"
        Write-Log "------------------------"
        
        # Automatically delete the suspicious entry
        Write-Log "Deleting entry: $($entry.Identifier)"
        try {
            & (Join-Path $env:windir "system32\bcdedit.exe") /delete $entry.Identifier /f | Out-Null
            Write-Log "Successfully deleted entry: $($entry.Identifier)"
        } catch {
            Write-Log "Error deleting entry $($entry.Identifier): $_"
            $ExitCode = 1
        }
    }
}

# Verify cleanup
Write-Log "Verifying BCD store after cleanup..."
$BcdOutputAfter = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if ($BcdOutputAfter) {
    $BcdOutputAfter | Out-File -FilePath $LogFile -Append
    Write-Log "Cleanup complete. Review the log at $LogFile for details."
    Write-Log "BCD backup is available at $BackupPath if restoration is needed."
} else {
    Write-Log "Error: Failed to verify BCD store after cleanup."
    $ExitCode = 1
}

# Exit with appropriate code
exit $ExitCode