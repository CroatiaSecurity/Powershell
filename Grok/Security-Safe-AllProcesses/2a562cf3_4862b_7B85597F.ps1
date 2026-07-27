

# Security-Safe-AllProcesses.ps1
# Run as Administrator (intended for SYSTEM account). Logs to C:\Temp\SecurityLog.txt.
# Applies to all process exes, excludes specific processes and system paths.

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "C:\Temp\SecurityLog.txt"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry
}

# Function to apply permissions with rollback
function Set-FilePermissions {
    param([string]$Path, [string]$ProcessName)

    Write-Log "Processing $Path for $ProcessName"
    
    # Skip system-critical paths
    if ($Path -like "C:\Windows\System32*" -or $Path -like "C:\Windows\SysWOW64*") {
        Write-Log "Skipping system path: $Path"
        return $false
    }

    # Backup current ACL
    $backupFile = "C:\Temp\AclBackup_$($ProcessName)_$(Get-Date -Format 'yyyyMMddHHmmss').acl"
    $backupAcl = & icacls "$Path" /save "$backupFile" 2>&1
    Write-Log "ACL backup: $backupAcl"
    
    # Test access
    $canAccess = Test-Path $Path -ErrorAction SilentlyContinue
    if (-not $canAccess) {
        Write-Log "Cannot access $Path. Skipping."
        return $false
    }

    # Take ownership
    $takeownResult = & takeown /f "$Path" /A 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "takeown failed: $takeownResult"
        return $false
    }
    Write-Log "takeown success: $takeownResult"

    # Reset permissions
    $resetResult = & icacls "$Path" /reset 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "icacls /reset failed: $resetResult"
        return $false
    }
    Write-Log "icacls /reset success: $resetResult"

    # Remove inheritance
    $inheritResult = & icacls "$Path" /inheritance:r 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "icacls /inheritance:r failed: $inheritResult"
        # Rollback
        & icacls "$Path" /restore "$backupFile" 2>&1
        Write-Log "Restored original ACL due to failure."
        return $false
    }
    Write-Log "icacls /inheritance:r success: $inheritResult"

    # Grant S-1-2-1
    $grantResult = & icacls "$Path" /grant:r "*S-1-2-1":F 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "icacls /grant failed: $grantResult"
        # Rollback
        & icacls "$Path" /restore "$backupFile" 2>&1
        Write-Log "Restored original ACL due to failure."
        return $false
    }
    Write-Log "icacls /grant success: $grantResult"

    # Verify final permissions
    $finalPerms = & icacls "$Path" 2>&1
    Write-Log "Final permissions: $finalPerms"
    return $true
}

# WMI query for all process starts
$query = "SELECT * FROM Win32_ProcessStartTrace"

# Excluded processes
$excludedProcesses = @("brave.exe", "svchost.exe", "explorer.exe")  # Add more as needed

# Action block
$action = {
    $eventArgs = $Event.SourceEventArgs.NewEvent
    $processName = $eventArgs.ProcessName
    $pid = $eventArgs.ProcessID

    Write-Log "Event triggered: $processName (PID: $pid)"

    # Skip excluded processes
    if ($excludedProcesses -contains $processName.ToLower()) {
        Write-Log "Skipping excluded process: $processName"
        return
    }

    try {
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $path = $process.MainModule.FileName
            if ($path) {
                Write-Log "Path resolved: $path"
                $success = Set-FilePermissions -Path $path -ProcessName $processName
                if ($success) {
                    Write-Log "Permissions updated for $path"
                } else {
                    Write-Log "Failed to update permissions for $path"
                }
            } else {
                Write-Log "Failed to get MainModule.FileName for PID $pid"
            }
        } else {
            Write-Log "Get-Process failed for PID $pid"
        }
    } catch {
        Write-Log "Error in action block for PID $pid`: $_"
    }
}

# Register WMI event (single-run test)
try {
    Write-Log "Registering WMI event for all processes..."
    Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
    Write-Log "WMI event registered."
} catch {
    Write-Log "Failed to register WMI event: $_"
    exit
}

# Run for a short time to test (30 seconds)
Write-Log "Monitoring for all processes. Will stop after 30 seconds."
$timeout = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $timeout) {
    Start-Sleep -Seconds 1
}

# Cleanup
Write-Log "Test complete. Unregistering WMI event."
Unregister-Event -SourceIdentifier "ProcessStartMonitor" -ErrorAction SilentlyContinue
Write-Log "Script stopped."

