
# Midas.ps1 by Gorstak
# Run as Administrator. Logs to $env:TEMP\MidasLog.txt

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = Join-Path $env:TEMP "MidasLog.txt"
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

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Define task variables
$taskName = "MidasMonitor"
$taskDescription = "Midas process monitoring task"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Log "Set execution policy to Bypass for current user."
}

# --- Ensure script copies itself to Bin folder ---
try {
    $scriptDir  = "C:\Windows\Setup\Scripts\Bin"
    $scriptPath = Join-Path $scriptDir "Midas.ps1"
    $currentPath = $MyInvocation.MyCommand.Path

    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
        Write-Log "Created script directory: $scriptDir"
    }

    # Always copy/update itself
    Copy-Item -Path $currentPath -Destination $scriptPath -Force -ErrorAction Stop
    Write-Log "Copied script to: $scriptPath"
}
catch {
    Write-Log "Failed to copy script: $_"
}

# Register scheduled task as SYSTEM
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
    Write-Log "Scheduled task '$taskName' registered to run as SYSTEM."
} elseif (-not $isAdmin) {
    Write-Log "Skipping task registration: Admin privileges required"
}

function Sanitize-Folders {
    $targetRoots = @("C:\Program Files", "C:\Program Files (x86)", "C:\Users")
    
    foreach ($root in $targetRoots) {
        if (-not (Test-Path $root)) {
            Write-Log "Root path does not exist: $root"
            continue
        }

        Write-Log "Sanitizing folder: $root"

        try {
            # Process all files recursively
            Get-ChildItem -Path $root -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $filePath = $_.FullName
                try {
                    Write-Log "Processing file: $filePath"

                    $takeownOut = & takeown /f "$filePath" /A 2>&1
                    Write-Log "takeown output for $filePath:`n$takeownOut"

                    $resetOut = & icacls "$filePath" /reset 2>&1
                    Write-Log "icacls /reset output for $filePath:`n$resetOut"

                    $inheritOut = & icacls "$filePath" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output for $filePath:`n$inheritOut"

                    $grantOut = & icacls "$filePath" /grant:r "*S-1-5-32-545:F" /T 2>&1  # Users group SID
                    Write-Log "icacls /grant output for $filePath:`n$grantOut"

                    $finalPerms = & icacls "$filePath" 2>&1
                    Write-Log "Final permissions for $filePath:`n$finalPerms"
                } catch {
                    Write-Log "Error sanitizing $filePath: $_"
                }
            }
            Write-Log "Sanitization complete for: $root"
        } catch {
            Write-Log "Error processing folder $root: $_"
        }
    }
}

function Start-WmiMonitoring {
    Write-Log "Starting WMI monitoring..."

    # Clean up any existing event subscription
    try {
        Unregister-Event -SourceIdentifier "ProcessStartMonitor" -ErrorAction SilentlyContinue
        Write-Log "Cleaned up existing WMI event subscription."
    } catch {
        # Ignore if not registered
    }

    $query = "SELECT * FROM Win32_ProcessStartTrace"

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

                    $programFilesPath = "C:\Program Files"
                    $programFilesX86Path = "C:\Program Files (x86)"
                    $usersRoot = "C:\Users"

                    $isInTargetPath = $path.StartsWith($programFilesPath) -or $path.StartsWith($programFilesX86Path) -or $path.StartsWith($usersRoot)

                    if ($isInTargetPath) {
                        Write-Log "Path is valid for modification: $path"

                        $takeownOut = & takeown /f "$path" /A 2>&1
                        Write-Log "takeown output: $takeownOut"

                        $resetOut = & icacls "$path" /reset 2>&1
                        Write-Log "icacls /reset output: $resetOut"

                        $inheritOut = & icacls "$path" /inheritance:r 2>&1
                        Write-Log "icacls /inheritance:r output: $inheritOut"

                        $grantOut = & icacls "$path" /grant:r "*S-1-5-32-545:F" 2>&1  # Users group SID
                        Write-Log "icacls /grant output: $grantOut"

                        $finalPerms = & icacls "$path" 2>&1
                        Write-Log "Final perms for $path`: $finalPerms"
                    } else {
                        Write-Log "Skipping file $path. Not under target folders."
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

    try {
        Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
        Write-Log "WMI event registered successfully."
    } catch {
        Write-Log "Failed to register WMI event: $_"
        return
    }

    Write-Log "Monitoring started. Press Ctrl+C to stop."
    
    try {
        # Wait for user interrupt with proper cleanup
        while ($true) {
            Start-Sleep -Seconds 1
        }
    } finally {
        # Clean up on exit
        try {
            Unregister-Event -SourceIdentifier "ProcessStartMonitor" -ErrorAction SilentlyContinue
            Write-Log "WMI event unregistered."
        } catch {
            Write-Log "Error unregistering WMI event: $_"
        }
    }
}

# Main execution
Write-Log "Starting Midas script..."

# Run sanitization for all target folders
Sanitize-Folders

# Start WMI monitoring
Start-WmiMonitoring

Write-Log "Midas script completed."
