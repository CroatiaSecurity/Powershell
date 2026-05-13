#requires -RunAsAdministrator

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