
# Midas.ps1 (Debug Version)
# Run as Administrator. Logs to $env:TEMP\SecurityLog.txt

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: Script must be run as Administrator. Exiting."
    exit
}

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = Join-Path $env:TEMP "SecurityLog.txt"
    $logDir = Split-Path $logPath -Parent
    try {
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Host "Created log directory: $logDir"
        }
        Add-Content -Path $logPath -Value $logEntry -ErrorAction Stop
        Write-Host $logEntry
    } catch {
        Write-Host "Failed to write to log ($logPath): $_"
    }
}

# Function to create scheduled task (commented out for debugging)
<#
function Register-SystemLogonScript {
    param ([string]$TaskName = "RunMidasAtLogon")
    Write-Log "Attempting to register scheduled task: $TaskName"
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
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created for $currentUser with elevated privileges."
    } catch {
        Write-Log "Failed to register task: $_"
    }
}
#>

# Check WMI service
$wmiService = Get-Service -Name Winmgmt
if ($wmiService.Status -ne "Running") {
    Write-Log "Error: WMI service (Winmgmt) is not running. Status: $($wmiService.Status)"
    exit
}
Write-Log "WMI service is running."

# Run the scheduled task function (uncomment to enable)
# Register-SystemLogonScript
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
            Write-Log "Process found: $processName (PID: $pid)"
            $path = $process.MainModule.FileName
            if ($path) {
                Write-Log "Full path resolved: $path"

                # Get current user profile path
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $currentUserPath = "C:\Users\$($currentUser.Split('\')[1])"
                if (-not $currentUser) {
                    Write-Log "Warning: Could not determine current user. Skipping user path checks."
                    $currentUserPath = ""
                }

                $programFilesPath = "C:\Program Files"
                $programFilesX86Path = "C:\Program Files (x86)"

                if ($path -and ($path.StartsWith($programFilesPath) -or $path.StartsWith($programFilesX86Path) -or ($currentUserPath -and $path.StartsWith($currentUserPath)))) {
                    Write-Log "Path is valid for modification: $path"
                    
                    # Run permission commands
                    try {
                        $takeownOut = & takeown /f "$path" /A 2>&1
                        Write-Log "takeown output: $takeownOut"
                    } catch {
                        Write-Log "takeown failed: $_"
                    }

                    try {
                        $resetOut = & icacls "$path" /reset 2>&1
                        Write-Log "icacls /reset output: $resetOut"
                    } catch {
                        Write-Log "icacls /reset failed: $_"
                    }

                    try {
                        $inheritOut = & icacls "$path" /inheritance:r 2>&1
                        Write-Log "icacls /inheritance:r output: $inheritOut"
                    } catch {
                        Write-Log "icacls /inheritance:r failed: $_"
                    }

                    try {
                        $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
                        Write-Log "icacls /grant output: $grantOut"
                    } catch {
                        Write-Log "icacls /grant failed: $_"
                    }

                    try {
                        $finalPerms = & icacls "$path" 2>&1
                        Write-Log "Final perms for $path`: $finalPerms"
                    } catch {
                        Write-Log "Failed to verify perms: $_"
                    }
                } else {
                    Write-Log "Skipping file $path. Not in Program Files or user directory."
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
    Write-Log "Attempting to register WMI event..."
    Unregister-WmiEvent -SourceIdentifier "ProcessStartMonitor" -ErrorAction SilentlyContinue
    Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
    Write-Log "WMI event registered successfully."
} catch {
    Write-Log "Failed to register WMI event: $_"
    exit
}

# Keep running
Write-Log "Monitoring started. Press Ctrl+C to stop."
while ($true) {
    Start-Sleep -Seconds 1
}
