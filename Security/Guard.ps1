# Guard.ps1
# Author: Gorstak (gorstak.eu)
# Description: DLL integrity monitor and quarantine engine. Scans Program Files and AppData
#              for unsigned DLLs, quarantines them, stops processes using malicious modules,
#              and monitors for new DLL creation via FileSystemWatcher. Persistent via
#              scheduled task with cmdlet-first, schtasks fallback.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "GuardProtection"
$Script:InstallDir = "$env:ProgramData\Guard"
$Script:ScriptName = "Guard.ps1"

function Install-Persistence {
    # Create install directory
    if (-not (Test-Path $Script:InstallDir)) {
        New-Item -Path $Script:InstallDir -ItemType Directory -Force | Out-Null
    }

    # Copy script to install location
    $targetPath = Join-Path $Script:InstallDir $Script:ScriptName
    Copy-Item -Path $PSCommandPath -Destination $targetPath -Force

    # Register scheduled task (cmdlet first, schtasks fallback)
    $installed = $false
    $pwshArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Scheduled task '$($Script:TaskName)' registered via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Host "Register-ScheduledTask failed: $_"
    }

    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Scheduled task '$($Script:TaskName)' registered via schtasks.exe fallback."
                $installed = $true
            } else {
                Write-Host "schtasks fallback failed: $result"
            }
        } catch {
            Write-Host "schtasks fallback exception: $_"
        }
    }

    Write-Host "Persistence installed to: $targetPath"
}

function Uninstall-Persistence {
    try { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    & schtasks.exe /Delete /TN "$($Script:TaskName)" /F 2>$null | Out-Null
    if (Test-Path $Script:InstallDir) {
        Remove-Item -Path $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Persistence removed for '$($Script:TaskName)'."
}

if ($Install) { Install-Persistence; return }
if ($Uninstall) { Uninstall-Persistence; return }

# Auto-install if not running from installed location
$installedPath = Join-Path $Script:InstallDir $Script:ScriptName
if ($PSCommandPath -and $PSCommandPath -ne $installedPath) {
    $existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        Install-Persistence
        return
    }
}

# ==============================
# Main Logic - DLL Integrity Monitor
# ==============================

$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{} # Initialize empty hash table

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created folder: $quarantineFolder"
    }
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
        Write-Host "Rotated log to: $archiveName"
    }
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
}

Write-Log "Script initialized. User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Load or Reset Scanned Files Database
if (Test-Path $localDatabase) {
    try {
        $scannedFiles.Clear()
        $lines = Get-Content $localDatabase -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]$matches[2]
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    $scannedFiles.Clear()
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-Log "Created new database: $localDatabase"
}

# Take Ownership and Modify Permissions (Aggressive)
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /reset | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d | Out-Null
        Write-Log "Forcibly set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        Write-Log "Signature status for ${filePath}: $($signature.Status) - $($signature.StatusMessage)"
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error processing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

# Quarantine File (Crash-Proof)
function Quarantine-File {
    param ([string]$filePath)
    try {
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Failed to quarantine ${filePath}: $($_.Exception.Message)"
    }
}

# Stop Processes Using DLL (Aggressive)
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
                Write-Log "Force-killed process $($process.Name) (PID: $($process.Id)) using taskkill"
            }
        } catch {
            Write-Log "Fallback process kill failed for ${filePath}: $($_.Exception.Message)"
        }
    }
}

# Remove Unsigned DLLs (Target Specific Folders)
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan in Program Files and AppData folders."
    
    $targetFolders = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )
    
    foreach ($folder in $targetFolders) {
        if (Test-Path $folder) {
            Write-Log "Scanning folder: $folder"
            try {
                $dllFiles = Get-ChildItem -Path $folder -Filter *.dll -Recurse -File -Exclude @($quarantineFolder) -ErrorAction Stop
                foreach ($dll in $dllFiles) {
                    try {
                        $fileHash = Calculate-FileHash -filePath $dll.FullName
                        if ($fileHash) {
                            if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                                Write-Log "Skipping already scanned file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                                if (-not $scannedFiles[$fileHash.Hash]) {
                                    if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                        Stop-ProcessUsingDLL -filePath $dll.FullName
                                        Quarantine-File -filePath $dll.FullName
                                    }
                                }
                            } else {
                                $isValid = $fileHash.Status -eq "Valid"
                                $scannedFiles[$fileHash.Hash] = $isValid
                                "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                                Write-Log "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                                if (-not $isValid) {
                                    if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                        Stop-ProcessUsingDLL -filePath $dll.FullName
                                        Quarantine-File -filePath $dll.FullName
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log "Error processing file $($dll.FullName): $($_.Exception.Message)"
                    }
                }
            } catch {
                Write-Log "Scan failed for folder ${folder}: $($_.Exception.Message)"
            }
        } else {
            Write-Log "Folder not found: $folder"
        }
    }
}

# File System Watcher (Throttled and Crash-Proof)
$targetFolders = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
)

foreach ($monitorPath in $targetFolders) {
    if (Test-Path $monitorPath) {
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
                    if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$quarantineFolder*") {
                        Write-Log "Detected file change: $($e.FullPath)"
                        $fileHash = Calculate-FileHash -filePath $e.FullPath
                        if ($fileHash) {
                            if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                                Write-Log "Skipping already scanned file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                                if (-not $scannedFiles[$fileHash.Hash]) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            } else {
                                $isValid = $fileHash.Status -eq "Valid"
                                $scannedFiles[$fileHash.Hash] = $isValid
                                "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                                Write-Log "Added new file to database: $($e.FullPath) (Valid: $isValid)"
                                if (-not $isValid) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            }
                        }
                        Start-Sleep -Milliseconds 500
                    }
                } catch {
                    Write-Log "Watcher error for $($e.FullPath): $($_.Exception.Message)"
                }
            }

            Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action -ErrorAction Stop
            Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action -ErrorAction Stop
            Write-Log "FileSystemWatcher set up for $monitorPath"
        } catch {
            Write-Log "Failed to set up watcher for ${monitorPath}: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Monitor path not found: $monitorPath"
    }
}

# Initial scan
Remove-UnsignedDLLs
Write-Log "Initial scan completed. Monitoring started."

# Enter blocking loop (running from installed location via scheduled task)
Write-Host "Guard running. Press [Ctrl] + [C] to stop."
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $logFile for details."
}
