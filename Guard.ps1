# Guard.ps1
# Author: Gorstak
 
# Define paths and parameters
$taskName = "GuardStartup"
$taskDescription = "Runs the Guard script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts\Bin"
$scriptPath = "$scriptDir\Guard.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{} # Initialize empty hash table
 
# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"
 
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
 
# Initial log with diagnostics
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
 
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
 
# Load or Reset Scanned Files Database
if (Test-Path $localDatabase) {
    try {
        $scannedFiles.Clear() # Reset hash table before loading
        $lines = Get-Content $localDatabase -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]$matches[2]
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear() # Reset on failure
    }
} else {
    $scannedFiles.Clear() # Ensure reset if no database
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
    
    # Define target folders
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
                                $isValid = $fileHash.Status -eq "Valid" # Only "Valid" is safe
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
                        Start-Sleep -Milliseconds 500 # Throttle to prevent event flood
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
 
# Keep script running with crash protection
Write-Host "Antivirus running. Press [Ctrl] + [C] to stop."
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $logFile for details."
}
