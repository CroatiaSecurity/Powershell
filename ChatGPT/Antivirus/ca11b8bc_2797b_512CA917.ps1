# Antivirus.ps1
# Author: Gorstak

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "$env:windir\Temp\AntivirusLog.txt"
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry
}

# Set up FileSystemWatcher for each local/removable/network drive
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
foreach ($drive in $drives) {
    try {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $drive.DeviceID + "\"  # ensure proper format like C:\
        $fileWatcher.Filter = "*.*"                # watch everything, filter later
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true
        $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        $action = {
            param($sender, $e)
            try {
                $path = $e.FullPath -replace '/', '\'

                # Only react to exe and dll
                if ($path -notmatch '\.(?i:(exe|dll))$') { return }

                if ($e.ChangeType -in "Created", "Changed") {
                    Write-Log "Detected file change: $path (ChangeType: $($e.ChangeType))"

                    $takeownOut = & takeown /f "$path" /A 2>&1
                    Write-Log "takeown output: $takeownOut"
                
                    $resetOut = & icacls "$path" /reset 2>&1
                    Write-Log "icacls /reset output: $resetOut"
                
                    $inheritOut = & icacls "$path" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output: $inheritOut"
                
                    $finalPerms = & icacls "$path" 2>&1
                    Write-Log "Final perms for $path`: $finalPerms"

                    Start-Sleep -Milliseconds 500
                }
            } catch {
                Write-Log "Watcher error for $path`: $($_.Exception.Message)"
            }
        }

        Register-ObjectEvent -InputObject $fileWatcher -EventName Created -SourceIdentifier "FileCreated_$($drive.DeviceID)" -Action $action -ErrorAction Stop
        Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -SourceIdentifier "FileChanged_$($drive.DeviceID)" -Action $action -ErrorAction Stop
        Write-Log "FileSystemWatcher set up for $($drive.DeviceID)"
    } catch {
        Write-Log "Failed to set up watcher for $($drive.DeviceID)`: $($_.Exception.Message)"
    }
}

# Keep running
Write-Log "Monitoring started. Press Ctrl+C to stop."
Start-Job -ScriptBlock {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
