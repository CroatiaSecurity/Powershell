# Simple Antivirus (Permission Removal Mode) by Gorstak

# Define paths
$logFile = Join-Path $env:TEMP "antivirus_log.txt"
$scannedFiles = @{} # Initialize empty hash table

# Logging Function with Rotation (10MB)
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host $logEntry
    if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -ge 10MB)) {
        $archiveName = "$env:TEMP\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
    }
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

Write-Log "Script initialized. User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        Write-Log "Signature for ${filePath}: $($signature.Status) - $($signature.StatusMessage)"
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error hashing $filePath: $($_.Exception.Message)"
        return $null
    }
}

# Remove all permissions from file
function Strip-Permissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /inheritance:r /remove:g *S-1-1-0 Administrators SYSTEM Users Everyone | Out-Null
        Write-Log "Removed all permissions from $filePath"
        return $true
    } catch {
        Write-Log "Failed to strip permissions from ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Stop processes using DLL (same as original, kept aggressive)
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)"
        try {
            $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
            foreach ($process in $processes) {
                taskkill /PID $process.Id /F | Out-Null
                Write-Log "Force-killed process $($process.Name) (PID: $($process.Id))"
            }
        } catch {
            Write-Log "Fallback kill failed for ${filePath}: $($_.Exception.Message)"
        }
    }
}

# Remove Unsigned DLLs (Drive + System32)
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan..."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction Stop
            foreach ($dll in $dllFiles) {
                try {
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if ($fileHash) {
                        if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            if (-not $scannedFiles[$fileHash.Hash]) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Strip-Permissions -filePath $dll.FullName
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            if (-not $isValid) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Strip-Permissions -filePath $dll.FullName
                            }
                        }
                    }
                } catch {
                    Write-Log "Error processing $($dll.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Scan failed for $root: $($_.Exception.Message)"
        }
    }

    # Explicit System32 Scan
    Write-Log "Starting explicit System32 scan..."
    try {
        $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Filter *.dll -File -ErrorAction Stop
        foreach ($dll in $system32Files) {
            try {
                $fileHash = Calculate-FileHash -filePath $dll.FullName
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Strip-Permissions -filePath $dll.FullName
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $scannedFiles[$fileHash.Hash] = $isValid
                        if (-not $isValid) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Strip-Permissions -filePath $dll.FullName
                        }
                    }
                }
            } catch {
                Write-Log "Error processing System32 $($dll.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "System32 scan failed: $($_.Exception.Message)"
    }
}

# File System Watcher
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
foreach ($drive in $drives) {
    $monitorPath = $drive.DeviceID + "\"
    try {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $monitorPath
        $fileWatcher.Filter = "*.dll"
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true
        $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        $action = {
            param($sender, $e)
            try {
                if ($e.ChangeType -in "Created", "Changed") {
                    Write-Log "Detected change: $($e.FullPath)"
                    $fileHash = Calculate-FileHash -filePath $e.FullPath
                    if ($fileHash) {
                        if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            if (-not $scannedFiles[$fileHash.Hash]) {
                                Stop-ProcessUsingDLL -filePath $e.FullPath
                                Strip-Permissions -filePath $e.FullPath
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            if (-not $isValid) {
                                Stop-ProcessUsingDLL -filePath $e.FullPath
                                Strip-Permissions -filePath $e.FullPath
                            }
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
            } catch {
                Write-Log "Watcher error for $($e.FullPath): $($_.Exception.Message)"
            }
        }

        Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action
        Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action
        Write-Log "Watcher set up for $monitorPath"
    } catch {
        Write-Log "Failed watcher for $monitorPath: $($_.Exception.Message)"
    }
}

# Initial scan
Remove-UnsignedDLLs
Write-Log "Initial scan done. Monitoring started."

# Keep script alive
Write-Host "Antivirus running (permission-removal mode). Press [Ctrl] + [C] to stop."
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Log "Main loop crashed: $($_.Exception.Message)"
}
