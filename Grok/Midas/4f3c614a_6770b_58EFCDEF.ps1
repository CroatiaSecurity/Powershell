# Midas.ps1 by Gorstak (with logging)
# Run as Administrator. Logs to C:\Temp\SecurityLog.txt

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Log "Set execution policy to Bypass for current user."
}
 
# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Log "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Log "Copied/Updated script to: $scriptPath"
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

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "C:\Temp\SecurityLog.txt"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry
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

            $grantOut = & icacls "$desktopPath" /grant:r "*S-1-2-1:F" /T 2>&1
            Write-Log "icacls /grant output:`n$grantOut"

            Write-Log "Sanitization complete for: $desktopPath"
        } catch {
            Write-Log "Error sanitizing $desktopPath: $_"
        }
    }
}

function Start-WmiMonitoring {
    Write-Log "Starting WMI monitoring..."

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

                        $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
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
    }

    Write-Log "Monitoring started. Press Ctrl+C to stop."
    while ($true) {
        Start-Sleep -Seconds 1
    }
}

Register-SystemLogonScript
Sanitize-DesktopFolders
Start-WmiMonitoring
