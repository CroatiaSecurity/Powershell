# Antivirus
# Author: Gorstak

# === CONFIGURATION ===
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts\Bin"
$scriptPath = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

# Whitelist for known-good Microsoft system DLLs that are catalog-signed (not embedded-signed)
$knownGoodUnsigned = @(
    "C:\Windows\System32\msctf.dll",
    "C:\Windows\System32\msutb.dll",
    "C:\Windows\System32\input.dll",
    "C:\Windows\System32\coreuicomponents.dll",
    "C:\Windows\System32\ctfmon.exe",
    "C:\Windows\System32\dwrite.dll",
    "C:\Windows\System32\windows.storage.dll",
    "C:\Windows\System32\win32u.dll",
    "C:\Windows\SysWOW64\msctf.dll",
    "C:\Windows\SysWOW64\msutb.dll"
    # Add more if you discover others
) | ForEach-Object { $_.ToLower() }

# Folders we completely skip scanning (too many false positives + protected by Windows anyway)
$excludeFolders = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\servicing",
    "C:\Windows\InfusedApps"
)

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

# === NEW: Helper to check if file should be skipped ===
function Test-SkipFile {
    param ([string]$fullPath)
    $lowerPath = $fullPath.ToLower()

    # 1. Explicit whitelist
    if ($knownGoodUnsigned -contains $lowerPath) {
        Write-Log "SKIP: Known-good system file (whitelist): $fullPath"
        return $true
    }

    # 2. Exclude entire protected folders
    foreach ($folder in $excludeFolders) {
        if ($lowerPath.StartsWith($folder.ToLower() + "\")) {
            Write-Log "SKIP: File in excluded system folder: $fullPath"
            return $true
        }
    }

    return $false
}

# === MODIFIED Remove-UnsignedDLLs (now safe) ===
function Remove-UnsignedDLLs {
    Write-Log "Starting safe unsigned DLL scan (system folders excluded)."

    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2,3,4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"

        try {
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue
            foreach ($dll in $dllFiles) {
                # Skip whitelisted/excluded files early
                if (Test-SkipFile -fullPath $dll.FullName) { continue }

                try {
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if (-not $fileHash) { continue }

                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            Write-Log "Previously flagged - quarantining: $($dll.FullName)"
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                        continue
                    }

                    # Main decision: Valid embedded signature = trust
                    $isValid = $fileHash.Status -eq "Valid"
                    $scannedFiles[$fileHash.Hash] = $isValid
                    "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8

                    if (-not $isValid) {
                        Write-Log "UNSIGNED/INVALID DLL DETECTED: $($dll.FullName) → Quarantining"
                        if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Quarantine-File -filePath $dll.FullName
                        }
                    }
                }
                catch {
                    Write-Log "Error processing $($dll.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch { Write-Log "Scan error on $root : $($_.Exception.Message)" }
    }

    Write-Log "Full system scan completed (safe mode)."
}

# === MODIFIED FileSystemWatcher action (also respects whitelist) ===
$action = {
    param($sender, $e)
    try {
        if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$using:quarantineFolder*") {
            $fullPath = $e.FullPath

            if ($using:Test-SkipFile -fullPath $fullPath) { return }

            Write-Log "Watcher → New/Changed DLL: $fullPath"
            $fileHash = Calculate-FileHash -filePath $fullPath
            if (-not $fileHash) { return }

            if ($using:scannedFiles.ContainsKey($fileHash.Hash)) {
                if (-not $using:scannedFiles[$fileHash.Hash]) {
                    if (Set-FileOwnershipAndPermissions -filePath $fullPath) {
                        Stop-ProcessUsingDLL -filePath $fullPath
                        Quarantine-File -filePath $fullPath
                    }
                }
                return
            }

            $isValid = $fileHash.Status -eq "Valid"
            $using:scannedFiles[$fileHash.Hash] = $isValid
            "$($fileHash.Hash),$isValid" | Out-File -FilePath $using:localDatabase -Append -Encoding UTF8

            if (-not $isValid) {
                Write-Log "WATCHER QUARANTINE: $fullPath"
                if (Set-FileOwnershipAndPermissions -filePath $fullPath) {
                    Stop-ProcessUsingDLL -filePath $fullPath
                    Quarantine-File -filePath $fullPath
                }
            }

            Start-Sleep -Milliseconds 500
        }
    }
    catch { Write-Log "Watcher error: $($_.Exception.Message)" }
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