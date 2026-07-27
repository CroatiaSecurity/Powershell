

# Midas-Debug-Fixed.ps1
# Run as Administrator (intended for SYSTEM). Logs to C:\Temp\SecurityLog.txt.
# Applies to all process exes, excludes specific processes and system paths.

# Ensure single instance
$currentScript = $PSCommandPath
if (-not $currentScript) {
    Write-Host "Error: Could not determine script path."
    exit 1
}
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running (PID: $($existingProcess.Id)). Exiting."
    exit 1
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $sid, Path: $currentScript"

# Ensure execution policy
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Log "Set execution policy to Bypass for current process."
    } catch {
        Write-Log "Failed to set execution policy: $_"
        exit 1
    }
}

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "C:\Temp\SecurityLog.txt"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
    try {
        Add-Content -Path $logPath -Value $logEntry -ErrorAction Stop
        Write-Host $logEntry
    } catch {
        Write-Host "Failed to write to log: $_"
    }
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

# Check WMI health
try {
    $wmiTest = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    Write-Log "WMI health check: OK (Computer: $($wmiTest.Name))"
} catch {
    Write-Log "WMI health check failed: $_"
    exit 1
}

# WMI query for all process starts
$query = "SELECT * FROM Win32_ProcessStartTrace"

# Excluded processes
$excludedProcesses = @("brave.exe", "svchost.exe", "explorer.exe")  # Add more as needed
$processedPaths = @{}  # Track processed paths to avoid duplicates

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
                # Skip if already processed
                if ($processedPaths[$path]) {
                    Write-Log "Skipping already processed path: $path"
                    return
                }
                $processedPaths[$path] = $true
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

# Register WMI event
try {
    Write-Log "Registering WMI event for all processes..."
    Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
    Write-Log "WMI event registered."
} catch {
    Write-Log "Failed to register WMI event: $_"
    exit 1
}

# Run for a test (60 seconds)
Write-Log "Monitoring for all processes. Will stop after 60 seconds."
$timeout = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $timeout) {
    Start-Sleep -Seconds 1
}

# Cleanup
Write-Log "Test complete. Unregistering WMI event."
Unregister-Event -SourceIdentifier "ProcessStartMonitor" -ErrorAction SilentlyContinue
Remove-Job -Name "ProcessStartMonitor" -ErrorAction SilentlyContinue
Write-Log "Script stopped."

