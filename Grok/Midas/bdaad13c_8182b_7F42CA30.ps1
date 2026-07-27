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

function Sanitize-DesktopFolders {
    $usersRoot = "C:\Users"
    $desktopPaths = Get-ChildItem -Path $usersRoot -Directory -Force | ForEach-Object {
        $desktop = Join-Path $_.FullName "Desktop"
        if (Test-Path $desktop) { $desktop }
    }

    foreach ($desktopPath in $desktopPaths) {
        Write-Log "Sanitizing Desktop folder: $desktopPath"

        try {
            $takeownOut = & takeown /f "$desktopPath" /r /d Y /A 2>&1
            Write-Log "takeown output:`n$takeownOut"

            $resetOut = & icacls "$desktopPath" /reset /T 2>&1
            Write-Log "icacls /reset output:`n$resetOut"

            $inheritOut = & icacls "$desktopPath" /inheritance:r /T 2>&1
            Write-Log "icacls /inheritance:r output:`n$inheritOut"

            $grantOut = & icacls "$desktopPath" /grant:r "*S-1-2-1:F" /T 2>&1  # Changed to Users group SID
            Write-Log "icacls /grant output:`n$grantOut"

            Write-Log "Sanitization complete for: $desktopPath"
        } catch {
            Write-Log "Error sanitizing $desktopPath: $_"
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
                    $desktopTargets = @()

                    # Build all known desktop paths
                    Get-ChildItem -Path $usersRoot -Directory -Force | ForEach-Object {
                        $desktopPath = Join-Path $_.FullName "Desktop"
                        if (Test-Path $desktopPath) {
                            $desktopTargets += $desktopPath
                        }
                    }

                    $isInTargetPath = $false

                    if ($path.StartsWith($programFilesPath) -or $path.StartsWith($programFilesX86Path)) {
                        $isInTargetPath = $true
                    } else {
                        foreach ($desktop in $desktopTargets) {
                            if ($path.StartsWith($desktop)) {
                                $isInTargetPath = $true
                                break
                            }
                        }
                    }

                    if ($isInTargetPath) {
                        Write-Log "Path is valid for modification: $path"

                        $takeownOut = & takeown /f "$path" /A 2>&1
                        Write-Log "takeown output: $takeownOut"

                        $resetOut = & icacls "$path" /reset 2>&1
                        Write-Log "icacls /reset output: $resetOut"

                        $inheritOut = & icacls "$path" /inheritance:r 2>&1
                        Write-Log "icacls /inheritance:r output: $inheritOut"

                        $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1  # Changed to Users group SID
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

# Run desktop sanitization
Sanitize-DesktopFolders

# Start WMI monitoring
Start-WmiMonitoring

Write-Log "Midas script completed."