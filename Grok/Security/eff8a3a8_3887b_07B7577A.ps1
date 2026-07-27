# Security.ps1 by Gorstak
# This script must be run as Administrator to change file ownership and permissions.
# It monitors process starts using WMI events and applies the specified ownership and permission changes to the executable file of each new process.
# Note: This may fail on system-protected files and could disrupt system functionality if applied broadly. Use with caution.

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunSecurityAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        # Fallback to determine script path
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Output "Error: Could not determine script path."
            return
        }
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
        Write-Output "Failed to copy script: $_"
        return
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
    }
}

# Run the function
Register-SystemLogonScript

# Define the WMI query for process start events
$query = "SELECT * FROM Win32_ProcessStartTrace"

# Define the action block to execute on each event
$action = {
    $eventArgs = $Event.SourceEventArgs.NewEvent
    $processName = $eventArgs.ProcessName
    $pid = $eventArgs.ProcessID

    try {
        # Get the full path of the executable
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $path = $process.MainModule.FileName
            if ($path) {
                Write-Host "Detected new process: $processName (PID: $pid) at $path"
                
                # Apply the commands
                # Take ownership to Administrators group
                & takeown /f "$path" /A
                
                # Reset permissions to default
                & icacls "$path" /reset
                
                # Remove inheritance
                & icacls "$path" /inheritance:r
                
                # Grant full control only to S-1-2-1 (Console Logon group), replacing existing grants
                & icacls "$path" /grant:r "*S-1-2-1":F
                
                Write-Host "Permissions updated for $path"
            }
        }
    } catch {
        Write-Host "Error processing PID $pid: $_"
    }
}

# Register the WMI event
Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action

# Keep the script running to listen for events (press Ctrl+C to stop)
Write-Host "Monitoring for new process executions. Press Ctrl+C to stop."
while ($true) {
    Start-Sleep -Seconds 1
}