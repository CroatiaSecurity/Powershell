
# Midas.ps1 by Gorstak (with logging)
# Run as Administrator. Logs to default temp folder ($env:TEMP\SecurityLog.txt)

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = Join-Path $env:TEMP "SecurityLog.txt"
    $logDir = Split-Path $logPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry  # Also to console for initial run
}

function Register-SystemLogonScript {
    param ([string]$TaskName = "RunMidasAtLogon")

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Log "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # Run as current user with admin privileges
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon for $currentUser with elevated privileges."
    } catch {
        Write-Log "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript
Write-Log "Script setup complete. Starting WMI monitoring..."

# Define the WMI query for process start events
$query = "SELECT * FROM Win32_ProcessStartTrace"

# Define the action block
$action = {
    $eventArgs = $Event.SourceEventArgs.NewEvent
    $processName = $eventArgs.ProcessName
    $pid = $eventArgs.ProcessID

    Write-Log "Event triggered: Process '$processName' (PID: $pid)"

    try {
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $path = $process.MainModule.FileName
            if ($path) {
                Write-Log "Full path resolved: $path"

                # Check if the path belongs to Program Files or the Current User directory
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $currentUserPath = "C:\Users\$($currentUser.Split('\')[1])"  # Get user profile path dynamically

                $programFilesPath = "C:\Program Files"
                $programFilesX86Path = "C:\Program Files (x86)"

                if ($path.StartsWith($programFilesPath) -or $path.StartsWith($programFilesX86Path) -or $path.StartsWith($currentUserPath)) {
                    Write-Log "Path is valid for modification: $path"
                    
                    # Run commands and capture output
                    $takeownOut = & takeown /f "$path" /A 2>&1
                    Write-Log "takeown output: $takeownOut"
                    
                    $resetOut = & icacls "$path" /reset 2>&1
                    Write-Log "icacls /reset output: $resetOut"
                    
                    $inheritOut = & icacls "$path" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output: $inheritOut"
                    
                    $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
                    Write-Log "icacls /grant output: $grantOut"
                    
                    # Verify final perms
                    $finalPerms = & icacls "$path" 2>&1
                    Write-Log "Final perms for $path`: $finalPerms"
                } else {
                    Write-Log "Skipping file $path. It is not located in Program Files or the Current User directory."
                }
            } else {
                Write-Log "Failed to get MainModule.FileName for PID $pid"
            }
        } else {
            Write-Log "Get-Process failed for PID $pid (process may have exited)"
        }
    } catch {
        Write-Log "Error in action block for PID $pid`: $_"
    }
}

# Register the WMI event
try {
    Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
    Write-Log "WMI event registered successfully."
} catch {
    Write-Log "Failed to register WMI event: $_"
}

# Keep running
Write-Log "Monitoring started. Press Ctrl+C to stop."
while ($true) {
    Start-Sleep -Seconds 1
}
