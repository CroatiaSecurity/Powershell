
# GShield.ps1 by Gorstak (Enhanced with Stability Improvements from 1.ps1)

# Hide the PowerShell console window
$null = Add-Type @"
using System;
using System.Runtime.InteropServices;
public class HideConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static void Hide() {
        IntPtr hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);
    }
}
"@
[HideConsoleWindow]::Hide()

# Global variables for resource management
$global:FileWatchers = @()
$global:EventSubscriptions = @()

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Define paths and parameters
$quarantineFolder = "C:\Quarantine"
$logFileAntivirus = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$logFileES = "$env:TEMP\SessionTerminator.log"
$logFileGSecurity = "$env:TEMP\GSecurity.log"
$scannedFiles = @{}
$checkIntervalSeconds = 60

# Firewall rules
$script:registryContent = @"
; Firewall

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services]
"fDenyTSConnections"=dword:00000001
"fAllowTSConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Terminal Server]
"fDenyTSConnections"=dword:00000001
"fAllowTSConnections"=dword:00000000
"@

# Ensure execution policy allows script
try {
    if ((Get-ExecutionPolicy) -eq "Restricted") {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    }
} catch {
    Write-Output "Failed to set execution policy: $_"
    exit 1
}

# Enhanced Logging Function for Antivirus with Rotation
function Write-Log {
    param (
        [string]$message,
        [string]$EntryType = "Info"
    )
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$EntryType] $message"
        Write-Host "Logging: $logEntry"

        if (-not (Test-Path $quarantineFolder)) {
            New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "Created folder: $quarantineFolder"
        }

        if ((Test-Path $logFileAntivirus) -and ((Get-Item $logFileAntivirus -ErrorAction SilentlyContinue).Length -ge 10MB)) {
            $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            Rename-Item -Path $logFileAntivirus -NewName $archiveName -ErrorAction Stop
            Write-Host "Rotated log to: $archiveName"
        }

        $logEntry | Out-File -FilePath $logFileAntivirus -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "CRITICAL LOGGING FAILURE: $($_.Exception.Message)"
    }
}

# Logging Function for GSecurity
function Write-GSecurityLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$EntryType] $Message"

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Add-Content -Path $logFileGSecurity -Value $logEntry
    }

    if ($Host.Name -match "ConsoleHost") {
        switch ($EntryType) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor White }
        }
    }
}

# Logging Function for ES
function Write-ESLog {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFileES -Append
}

# Logging Function for Terminate-Rootkits
function Write-RootkitLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Terminate-Rootkits")) {
            New-EventLog -LogName Application -Source "Terminate-Rootkits"
        }
        Write-EventLog -LogName Application -Source "Terminate-Rootkits" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

# Register System Logon Script
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )
    try {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Log "Error: Could not determine script path. Ensure the script is run from a file." -EntryType "Error"
            exit 1
        }
        $targetFolder = "C:\Windows\Setup\Scripts\Bin"
        $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

        if (-not (Test-Path $targetFolder)) {
            New-Item -Path $targetFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log "Created folder: $targetFolder"
        }

        if (-not (Test-Path $targetPath) -or (Get-Item $targetPath).LastWriteTime -lt (Get-Item $scriptSource).LastWriteTime) {
            Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
            Write-Log "Copied/Updated script to: $targetPath"
        }

        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $existingTask -and $isAdmin) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description "Runs GShield at system logon"
            Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force -ErrorAction Stop
            Write-Log "Scheduled task '$TaskName' registered to run as SYSTEM."
        } elseif (-not $isAdmin) {
            Write-Log "Skipping task registration: Admin privileges required" -EntryType "Warning"
        }
    } catch {
        Write-Log "Failed to register task: $($_.Exception.Message)" -EntryType "Error"
        exit 1
    }
}

# Load or Reset Scanned Files Database
try {
    if (-not (Test-Path $localDatabase)) {
        Write-Log "Scanned files database not found!" -EntryType "Warning"
        New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
        Write-Log "Created new database: $localDatabase"
    } else {
        $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
        if ($null -ne $lines) {
            foreach ($line in $lines) {
                try {
                    if ($line -match "^[a-fA-F0-9]{64},(True|False)$") {
                        $parts = $line.Split(",")
                        $hash = $parts[0].ToLower()
                        $status = [bool]::Parse($parts[1])
                        $scannedFiles[$hash] = $status
                    } else {
                        Write-Log "Invalid entry in scanned_files.txt: $line" -EntryType "Warning"
                    }
                } catch {
                    Write-Log "Error processing database entry: $line - $($_.Exception.Message)" -EntryType "Error"
                }
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    }
} catch {
    Write-Log "Failed to load database: $($_.Exception.Message)" -EntryType "Error"
    $scannedFiles.Clear()
}

# Take Ownership and Modify Permissions
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        if (-not (Test-Path $filePath)) {
            Write-Log "File not found: $filePath" -EntryType "Warning"
            return $false
        }

        takeown /F $filePath /A 2>&1 | Out-Null
        if (-not $?) {
            Write-Log "takeown failed for $filePath" -EntryType "Warning"
            return $false
        }

        $acl = Get-Acl -Path $filePath -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
        Write-Log "Set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)" -EntryType "Error"
        return $false
    }
}

# Calculate File Hash and Signature with Timeout
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        if (-not (Test-Path $filePath)) {
            Write-Log "File not found for hashing: $filePath" -EntryType "Warning"
            return $null
        }

        $hashJob = Start-Job -ScriptBlock {
            param($path)
            $hash = Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop
            $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            return @{
                Hash = $hash.Hash.ToLower()
                Status = $signature.Status
                StatusMessage = $signature.StatusMessage
            }
        } -ArgumentList $filePath

        $result = $hashJob | Wait-Job -Timeout 30
        if (-not $result) {
            $hashJob | Stop-Job -ErrorAction SilentlyContinue
            Write-Log "Timeout calculating hash for $filePath" -EntryType "Warning"
            return $null
        }

        $output = Receive-Job -Job $hashJob
        Remove-Job -Job $hashJob -Force

        return [PSCustomObject]@{
            Hash = $output.Hash
            Status = $output.Status
            StatusMessage = $output.StatusMessage
        }
    } catch {
        Write-Log "Error processing file ${filePath}: $($_.Exception.Message)" -EntryType "Error"
        return $null
    }
}

# Quarantine File with Unique Naming
function Quarantine-File {
    param ([string]$filePath)
    try {
        if (-not (Test-Path $filePath)) {
            Write-Log "File not found for quarantine: $filePath" -EntryType "Warning"
            return
        }

        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        if (Test-Path $quarantinePath) {
            $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath "$([System.IO.Path]::GetFileNameWithoutExtension($filePath))_$(Get-Date -Format 'yyyyMMddHHmmss')$([System.IO.Path]::GetExtension($filePath))"
        }

        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Error quarantining file ${filePath}: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Stop Processes Using DLL
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { 
            try {
                ($_.Modules | Where-Object { $_.FileName -eq $filePath }) -ne $null
            } catch {
                $false
            }
        }

        foreach ($process in $processes) {
            try {
                if ($process.Id -ne $PID) {
                    Stop-Process -Id $process.Id -Force -ErrorAction Stop
                    Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
                }
            } catch {
                Write-Log "Failed to stop process $($process.Name) (PID: $($process.Id)): $($_.Exception.Message)" -EntryType "Warning"
            }
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Remove Unsigned DLLs with Timeout
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan."
    try {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
        foreach ($drive in $drives) {
            try {
                $root = $drive.DeviceID + "\"
                Write-Log "Scanning drive: $root"

                $dllFiles = @()
                $scanJob = Start-Job -ScriptBlock {
                    param($path)
                    Get-ChildItem -Path $path -Filter *.dll -Recurse -File -Exclude @($using:quarantineFolder, "C:\Windows\System32\config") -ErrorAction SilentlyContinue
                } -ArgumentList $root

                $result = $scanJob | Wait-Job -Timeout 300
                if ($result) {
                    $dllFiles = Receive-Job -Job $scanJob
                } else {
                    $scanJob | Stop-Job -ErrorAction SilentlyContinue
                    Write-Log "Timeout scanning drive $root" -EntryType "Warning"
                }
                Remove-Job -Job $scanJob -Force

                foreach ($dll in $dllFiles) {
                    try {
                        $fileHash = Calculate-FileHash -filePath $dll.FullName
                        if ($fileHash) {
                            $alreadyScanned = $scannedFiles[$fileHash.Hash] -eq $true
                            if ($alreadyScanned) {
                                Write-Log "Skipping already scanned valid file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                            } elseif ($scannedFiles.ContainsKey($fileHash.Hash)) {
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
                        Write-Log "Error processing file $($dll.FullName): $($_.Exception.Message)" -EntryType "Error"
                    }
                }
            } catch {
                Write-Log "Error scanning drive $($drive.DeviceID): $($_.Exception.Message)" -EntryType "Error"
            }
        }

        Write-Log "Starting explicit System32 scan."
        try {
            $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Filter *.dll -File -ErrorAction SilentlyContinue
            foreach ($dll in $system32Files) {
                try {
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if ($fileHash) {
                        $alreadyScanned = $scannedFiles[$fileHash.Hash] -eq $true
                        if ($alreadyScanned) {
                            Write-Log "Skipping already scanned valid System32 file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                        } elseif ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            Write-Log "Skipping already scanned System32 file: $($dll.FullName) (Hash: $($fileHash.Hash))"
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
                            Write-Log "Scanned new System32 file: $($dll.FullName) (Valid: $isValid)"
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error processing System32 file $($dll.FullName): $($_.Exception.Message)" -EntryType "Error"
                }
            }
        } catch {
            Write-Log "System32 scan failed: $($_.Exception.Message)" -EntryType "Error"
        }
    } catch {
        Write-Log "Critical error in Remove-UnsignedDLLs: $($_.Exception.Message)" -EntryType "Error"
    }
    Write-Log "Unsigned DLL scan completed."
}

# File System Watcher with Resource Management
function Start-FileSystemWatcher {
    try {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
        foreach ($drive in $drives) {
            try {
                $monitorPath = $drive.DeviceID + "\"
                $fileWatcher = New-Object System.IO.FileSystemWatcher
                $fileWatcher.Path = $monitorPath
                $fileWatcher.Filter = "*.dll"
                $fileWatcher.IncludeSubdirectories = $true
                $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite'

                $action = {
                    param($sender, $e)
                    try {
                        if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$($using:quarantineFolder)*") {
                            Write-Log "Detected file change: $($e.FullPath)"
                            $fileHash = Calculate-FileHash -filePath $e.FullPath
                            if ($fileHash) {
                                $alreadyScanned = $scannedFiles[$fileHash.Hash] -eq $true
                                if ($alreadyScanned) {
                                    Write-Log "Skipping already scanned valid file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                                } elseif ($scannedFiles.ContainsKey($fileHash.Hash)) {
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
                        }
                    } catch {
                        Write-Log "Error processing file event $($e.FullPath): $($_.Exception.Message)" -EntryType "Error"
                    }
                }

                $fileWatcher.EnableRaisingEvents = $true
                $subCreated = Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action
                $subChanged = Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action

                $global:FileWatchers += $fileWatcher
                $global:EventSubscriptions += $subCreated
                $global:EventSubscriptions += $subChanged

                Write-Log "Started monitoring drive: $monitorPath"
            } catch {
                Write-Log "Failed to initialize watcher for drive $($drive.DeviceID): $($_.Exception.Message)" -EntryType "Error"
            }
        }
    } catch {
        Write-Log "Critical error initializing file watchers: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Cleanup function for proper shutdown
function Cleanup-Resources {
    try {
        Write-Log "Starting resource cleanup..."

        foreach ($watcher in $global:FileWatchers) {
            try {
                $watcher.EnableRaisingEvents = $false
                $watcher.Dispose()
            } catch {
                Write-Log "Error disposing watcher: $($_.Exception.Message)" -EntryType "Warning"
            }
        }

        foreach ($sub in $global:EventSubscriptions) {
            try {
                $sub | Unregister-Event -ErrorAction SilentlyContinue
                $sub.Dispose()
            } catch {
                Write-Log "Error unregistering event: $($_.Exception.Message)" -EntryType "Warning"
            }
        }

        $global:FileWatchers = @()
        $global:EventSubscriptions = @()

        Write-Log "Resource cleanup completed."
    } catch {
        Write-Log "Error during cleanup: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Terminate Rootkits
function Terminate-Rootkits {
    try {
        $connections = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
        }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($pid in $lanProcIds) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $exePath = $proc.Path

                if ($exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    if ($signature.Status -ne 'Valid') {
                        Write-RootkitLog "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-RootkitLog "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-RootkitLog "Path unknown for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-RootkitLog "Error processing PID $pid`: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-RootkitLog "Error during detection: $($_.ToString())" -EntryType "Error"
    }
}

# Disable Network Briefly
function Disable-Network-Briefly {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        foreach ($adapter in $adapters) {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-GSecurityLog "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-GSecurityLog "Failed to toggle network adapters: $_" "Error"
    }
}

# Kill Process and Parent
function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-GSecurityLog "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-GSecurityLog "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-GSecurityLog "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

# ProcessLOGOUT Killer
function Start-ProcessKiller {
    while ($true) {
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-GSecurityLog "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-GSecurityLog "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
}

# XSS Watcher
function Start-XSSWatcher {
    while ($true) {
        $conns = Get-NetTCPConnection -State Established
        foreach ($conn in $conns) {
            $remoteIP = $conn.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-Network-Briefly
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -Force -ErrorAction SilentlyContinue
                    Write-GSecurityLog "XSS detected, blocked $($hostEntry.HostName) and disabled network." "Error"
                }
            } catch {}
        }
        Start-Sleep -Seconds 3
    }
}

# Kill Listeners
function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit")
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

# Terminate Non-Console Sessions
function Terminate-NonConsoleSessions {
    try {
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" }
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-ESLog "Listing all sessions:"
        $sessions | ForEach-Object { Write-ESLog $_ }

        foreach ($session in $sessionList) {
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                if ($sessionName -notin @("console")) {
                    Write-ESLog "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-ESLog "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-ESLog "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-ESLog "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-ESLog "Error processing sessions: $_"
    }
}

# Detect InProc Controls
function Detect-InProcControls {
    $basePath = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
    $hkcrBasePath = "HKCR:\WOW6432Node\CLSID"
    $allPaths = @()
    $allPaths += Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }
    $allPaths += Get-ChildItem -Path $hkcrBasePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }

    foreach ($path in $allPaths) {
        $inProcPath = Join-Path $path.PSPath "InProcServer32"
        $inProcHandlerPath = Join-Path $path.PSPath "InprocHandler32"
        $value = $null

        if (Test-Path $inProcPath) {
            $value = (Get-ItemProperty -Path $inProcPath -ErrorAction SilentlyContinue)."(default)"
        } elseif (Test-Path $inProcHandlerPath) {
            $value = (Get-ItemProperty -Path $inProcHandlerPath -ErrorAction SilentlyContinue)."(default)"
        }

        if ($value -and (Test-Path $value)) {
            Write-Log "Detected InProc control at $path.PSPath with value $value"
            return $true, $path.PSPath, $value
        }
    }
    return $false, $null, $null
}

# Remove InProc Controls
function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Log "Removed InProc control registry entry at $path"
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Log "Removed file: $value"
            }
        } catch {
            Write-Log "Error removing $path : $($_.Exception.Message)" -EntryType "Error"
        }
    }
}

# Enable LSASS as Protected Process Light
function Enable-LsassPPL {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "RunAsPPL"
        $regValue = 1

        if (-not (Test-Path $regPath)) {
            Write-Log "LSA registry path not found." -EntryType "Error"
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -ErrorAction Stop
        Write-Log "LSASS configured to run as Protected Process Light (PPL). Reboot required."
    } catch {
        Write-Log "Failed to enable LSASS PPL: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Clear Cached Credentials
function Clear-CachedCredentials {
    try {
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Log "Cleared cached credentials from Credential Manager using cmdkey."
        } else {
            Write-Log "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials." -EntryType "Warning"
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Log "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required." -EntryType "Warning"
            } catch {
                Write-Log "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager." -EntryType "Error"
                return
            }
        }
    } catch {
        Write-Log "Failed to clear cached credentials: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Disable Credential Caching
function Disable-CredentialCaching {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "CachedLogonsCount"
        $regValue = 0

        if (-not (Test-Path $regPath)) {
            Write-Log "Winlogon registry path not found." -EntryType "Error"
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -ErrorAction Stop
        Write-Log "Disabled cached logon credentials. Set CachedLogonsCount to 0."
    } catch {
        Write-Log "Failed to disable credential caching: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Enable Auditing for Credential Access
function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Log "Enabled auditing for credential validation events."
        } else {
            Write-Log "Failed to enable auditing: $auditPolicy" -EntryType "Error"
        }
    } catch {
        Write-Log "Failed to enable auditing: $($_.Exception.Message)" -EntryType "Error"
    }
}

# Apply Firewall Rules
function Apply-FirewallRules {
    try {
        $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
        $script:registryContent | Out-File -FilePath $tempRegFile -Encoding Unicode
        reg import $tempRegFile 2>&1 | Out-Null
        Write-GSecurityLog "Firewall rules applied from registry content at $(Get-Date)." "Information"
        Remove-Item $tempRegFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-GSecurityLog "Error applying firewall rules: $($_.Exception.Message)" "Error"
    }
}

# Monitor Firewall Rule Changes
function Start-FirewallMonitor {
    Write-GSecurityLog "Starting firewall rule monitoring..." "Information"
    try {
        $query = "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4947"
        Register-WmiEvent -Query $query -SourceIdentifier "FirewallRuleChange" -Action {
            Write-GSecurityLog "Detected firewall rule change at $(Get-Date)" "Warning"
            Apply-FirewallRules
        }
        Write-GSecurityLog "Firewall monitoring started. Running in background..." "Information"
    } catch {
        Write-GSecurityLog "Failed to start firewall monitoring: $($_.Exception.Message)" "Error"
    }
}

# Register shutdown handler
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Write-Log "Script is shutting down..."
    Cleanup-Resources
    Write-Log "Script shutdown complete."
} -MaxTriggerCount 1

# Initial log with diagnostics
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
Write-GSecurityLog "GSecurity component initialized." "Information"
Write-ESLog "ES component initialized."
Write-RootkitLog "Terminate-Rootkits component initialized."

# Initial Scans and Protections
if ($isAdmin) {
    Register-SystemLogonScript
    Enable-LsassPPL
    Clear-CachedCredentials
    Disable-CredentialCaching
    Enable-CredentialAuditing
    Remove-UnsignedDLLs
    Apply-FirewallRules
    Terminate-Rootkits
} else {
    Write-Log "Administrative privileges required for LSASS PPL, credential management, DLL scanning, firewall rule application, and rootkit termination." -EntryType "Error"
}

# Start Background Jobs
Start-Job -ScriptBlock {
    . $using:PSCommandPath
    Apply-FirewallRules
    Start-FirewallMonitor
} -Name "FirewallTasks"

Start-Job -ScriptBlock {
    . $using:PSCommandPath
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Terminate-NonConsoleSessions
        Terminate-Rootkits
        $detected, $path, $value = Detect-InProcControls
        if ($detected) {
            Remove-InProcControls -path $path -value $value
        } else {
            Write-Log "No InProc controls detected. Checking again in $using:checkIntervalSeconds seconds..."
        }
        Start-Sleep -Seconds 5
    }
} -Name "GShieldSecurityTasks"

# Initialize monitoring
Start-FileSystemWatcher

# Keep script running with resource monitoring
Write-Log "Initial scan completed. Monitoring started."
Write-Host "GShield running. Press [Ctrl] + [C] to stop."
Write-Host "Check logs at $logFileAntivirus, $logFileGSecurity, and $logFileES"
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
try {
    while ($true) {
        Start-Sleep -Seconds 10
        $memoryUsage = [System.GC]::GetTotalMemory($false) / 1MB
        if ($memoryUsage -gt 500) {
            [System.GC]::Collect()
            Write-Log "Performed garbage collection. Memory usage was $($memoryUsage.ToString('0.00')) MB"
        }
    }
} finally {
    Cleanup-Resources
}
