# Midas.ps1 by Gorstak

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunMidasAtLogon"
    )

    # Define paths
    $scriptSource = $PSCommandPath
    if (-not $scriptSource) {
        Write-Output "Error: Could not determine script path. Ensure the script is run from a file."
        exit 1
    }
    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script to ${targetPath}: $_"
        exit 1
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
        exit 1
    }
}

# Run the function
Register-SystemLogonScript

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