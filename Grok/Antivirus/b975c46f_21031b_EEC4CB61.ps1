# Antivirus.ps1 by Gorstak

$ErrorActionPreference = 'SilentlyContinue'

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGSecurityAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Output "Error: Could not determine script path."
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script: $_"
        return
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

function Disable-Network-Briefly {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 3
    foreach ($adapter in $adapters) {
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Log "Network briefly disabled"
}

function Add-XSSFirewallRule {
    param ([string]$url)
    try {
        $uri = [System.Uri]::new($url)
        $domain = $uri.Host
        $ruleName = "Block_XSS_$domain"

        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $domain `
                -Protocol TCP `
                -Profile Any `
                -Description "Blocked due to potential XSS in URL"
            Write-Log "Domain blocked via firewall: $domain"
        }
    } catch {
        Write-Log "Could not block: $url" -EntryType "Warning"
    }
}

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
                        Write-Log "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-Log "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-Log "Path unknown for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-Log "Error processing PID $pid`: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-Log "Error during rootkit detection: $($_.ToString())" -EntryType "Error"
    }
}

# Register the scheduled task
Register-SystemLogonScript

# Define paths
$programData = [Environment]::GetFolderPath("CommonApplicationData")
$baseDir = Join-Path $programData "GShield"
$scriptDir = Join-Path $baseDir "Bin"
$scriptPath = Join-Path $scriptDir "Antivirus.ps1"
$quarantineFolder = Join-Path $baseDir "Quarantine"
$backupFolder = Join-Path $baseDir "Backup"
$logFile = Join-Path $baseDir "antivirus_log.txt"
$localDatabase = Join-Path $baseDir "scanned_files.txt"
$configFile = Join-Path $baseDir "config.json"
$virusTotalApiKey = "24ebf7780f869017f4bf596d11d6d38dc6dd37ec5a52494b3f0c65f3bdd2c929"
$scannedFiles = @{}
$maxRetries = 3
$retryDelaySeconds = 5

# Whitelist for system-critical files, browser DLLs, and gaming apps
$whitelistPatterns = @(
    # System critical
    "*\Windows\System32\*",
    "*\Windows\SysWOW64\*",
    "*\Windows\WinSxS\*",
    "*\Program Files\Windows Defender\*",
    # Browser DLLs
    "*\Google\Chrome\Application\*",
    "*\Mozilla Firefox\*",
    "*\Microsoft\Edge\Application\*",
    "*\Opera\*",
    # Gaming apps
    "*\Steam\*",
    "*\Epic Games\*",
    "*\Origin\*",
    "*\Ubisoft\*",
    "*\Battle.net\*"
)

# Configuration defaults
$configDefaults = @{
    MaxFilesPerDrive = 100
    ScanIntervalSeconds = 3600
    MaxLogSizeMB = 10
}

# Ensure directories exist
foreach ($dir in @($baseDir, $scriptDir, $quarantineFolder, $backupFolder)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

# Save or load configuration
if (-not (Test-Path $configFile)) {
    $configDefaults | ConvertTo-Json | Set-Content $configFile
}
$config = Get-Content $configFile -Raw | ConvertFrom-Json

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host $logEntry
    try {
        if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge ($config.MaxLogSizeMB * 1MB))) {
            $archiveName = Join-Path $baseDir "antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            Rename-Item -Path $logFile -NewName $archiveName -ErrorAction SilentlyContinue
            Write-Log "Rotated log to $archiveName"
        }
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log: $($_.Exception.Message)"
    }
}

# Copy script if needed
if (-not (Test-Path $scriptPath)) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
    Write-Log "Copied script to: $scriptPath"
}

# Load Scanned Files Database
if (Test-Path $localDatabase) {
    $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($line -match "^([0-9a-f]{64}),(true|false)$") {
            $scannedFiles[$matches[1]] = [bool]$matches[2]
        }
    }
    Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
}

# Initialize FileSystemWatcher
function Start-FileSystemWatcher {
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    $watchers = @()
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Setting up FileSystemWatcher for drive: $root"
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            $action = {
                param ($source, $event)
                $filePath = $event.FullPath
                if (Is-Whitelisted -filePath $filePath) {
                    & $using:scriptPath Write-Log "Skipping whitelisted file: $filePath"
                    return
                }
                try {
                    $hash = & $using:scriptPath Calculate-FileHash -filePath $filePath
                    if ($using:scannedFiles.ContainsKey($hash)) { return }
                    $isMalicious = & $using:scriptPath Scan-FileWithVirusTotal -fileHash $hash
                    $using:scannedFiles[$hash] = -not $isMalicious
                    Add-Content -Path $using:localDatabase -Value "$hash,$(-not $isMalicious)"
                    if ($isMalicious) {
                        & $using:scriptPath Stop-ProcessUsingDLL -filePath $filePath
                        & $using:scriptPath Backup-And-Quarantine -filePath $filePath
                        & $using:scriptPath Show-Notification -message "Malicious file quarantined: $filePath"
                    }
                } catch {
                    & $using:scriptPath Write-Log "Error processing $filePath : $($_.Exception.Message)"
                }
            }
            Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action -SourceIdentifier "FileCreated_$($drive.DeviceID)" | Out-Null
            Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action -SourceIdentifier "FileChanged_$($drive.DeviceID)" | Out-Null
            $watchers += $watcher
            Write-Log "FileSystemWatcher initialized for $root"
        } catch {
            Write-Log "Error setting up FileSystemWatcher for $root : $($_.Exception.Message)"
        }
    }
    return $watchers
}

function Remove-UnsignedDLLs {
    param ([int]$maxFiles = $config.MaxFilesPerDrive)
    Write-Log "Starting unsigned file scan across all drives."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    if (-not $drives) {
        Write-Log "No drives detected for scanning."
        return
    }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
            if (-not $files) {
                Write-Log "No files found on drive $root"
                continue
            }
            $limitedFiles = $files | Select-Object -First $maxFiles
            foreach ($file in $limitedFiles) {
                if (Is-Whitelisted -filePath $file.FullName) {
                    Write-Log "Skipping whitelisted file: $($file.FullName)"
                    continue
                }
                try {
                    $cert = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
                    if ($cert.Status -ne 'Valid') {
                        Write-Log "Found unsigned file: $($file.FullName)"
                        Stop-ProcessUsingDLL -filePath $file.FullName
                        Backup-And-Quarantine -filePath $file.FullName
                        Show-Notification -message "Unsigned file quarantined: $($file.FullName)"
                    }
                } catch {
                    Write-Log "Error processing $($file.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Drive scan error on $root: $($_.Exception.Message)"
        }
    }
}

function Scan-AllFilesWithVirusTotal {
    Write-Log "Starting VirusTotal scan across all drives."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    if (-not $drives) {
        Write-Log "No drives detected for scanning."
        return
    }
    $jobs = @()
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
        if (-not $files) {
            Write-Log "No files found on $root"
            continue
        }
        foreach ($file in $files) {
            if (Is-Whitelisted -filePath $file.FullName) {
                Write-Log "Skipping whitelisted file: $($file.FullName)"
                continue
            }
            $jobs += Start-Job -ScriptBlock {
                param ($filePath, $scannedFiles, $localDatabase, $virusTotalApiKey)
                try {
                    $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                    if ($scannedFiles.ContainsKey($hash.Hash.ToLower())) { return }
                    $isMalicious = $null
                    for ($i = 0; $i -lt $using:maxRetries; $i++) {
                        try {
                            $url = "https://www.virustotal.com/api/v3/files/$($hash.Hash.ToLower())"
                            $headers = @{ "x-apikey" = $virusTotalApiKey }
                            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 30
                            if ($response.data.attributes) {
                                $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
                                $isMalicious = $maliciousCount -gt 3
                                break
                            }
                        } catch {
                            if ($i -lt ($using:maxRetries - 1)) {
                                Start-Sleep -Seconds $using:retryDelaySeconds
                                continue
                            }
                        }
                    }
                    if ($null -ne $isMalicious) {
                        $scannedFiles[$hash.Hash.ToLower()] = -not $isMalicious
                        Add-Content -Path $localDatabase -Value "$($hash.Hash.ToLower()),$(-not $isMalicious)"
                        if ($isMalicious) {
                            & $using:scriptPath Stop-ProcessUsingDLL -filePath $filePath
                            & $using:scriptPath Backup-And-Quarantine -filePath $filePath
                            & $using:scriptPath Show-Notification -message "Malicious file quarantined: $filePath"
                        }
                    }
                } catch {
                    & $using:scriptPath Write-Log "Error processing $filePath : $($_.Exception.Message)"
                }
            } -ArgumentList $file.FullName, $scannedFiles, $localDatabase, $virusTotalApiKey
        }
    }
    $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    Write-Log "Finished VirusTotal scan."
}

function Scan-FileWithVirusTotal {
    param ([string]$fileHash)
    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $url = "https://www.virustotal.com/api/v3/files/$fileHash"
            $headers = @{ "x-apikey" = $virusTotalApiKey }
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 30
            if ($response.data.attributes) {
                $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
                Write-Log "VirusTotal result for ${fileHash}: $maliciousCount malicious detections."
                return $maliciousCount -gt 3
            }
        } catch {
            Write-Log "Error scanning ${fileHash}: $($_.Exception.Message)"
            if ($i -lt ($maxRetries - 1)) {
                Start-Sleep -Seconds $retryDelaySeconds
                continue
            }
        }
    }
    return $false
}

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    } catch {
        Write-Log "Error hashing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

function Backup-And-Quarantine {
    param ([string]$filePath)
    try {
        # Take ownership
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        takeown /F $filePath /A | Out-Null
        Write-Log "Took ownership of file: $filePath"

        # Remove all permissions
        $acl = Get-Acl -Path $filePath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        Set-Acl -Path $filePath -AclObject $acl
        Write-Log "Removed all permissions from file: $filePath"

        # Backup
        $backupPath = Join-Path -Path $backupFolder -ChildPath ("$(Split-Path $filePath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
        Copy-Item -Path $filePath -Destination $backupPath -Force -ErrorAction Stop
        Write-Log "Backed up file: $filePath to $backupPath"

        # Quarantine
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Failed to backup/quarantine ${filePath}: $($_.Exception.Message)"
    }
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            # Stop the process
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"

            # Find and stop parent process
            try {
                $parent = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -ExpandProperty ParentProcessId
                if ($parent -and $parent -ne 0) {
                    Stop-Process -Id $parent -Force -ErrorAction Stop
                    $parentProcess = Get-Process -Id $parent -ErrorAction SilentlyContinue
                    if ($parentProcess) {
                        Write-Log "Stopped parent process $($parentProcess.Name) (PID: $parent) of process using $filePath"
                    }
                }
            } catch {
                Write-Log "Error stopping parent process for PID $($process.Id): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)"
    }
}

function Is-Whitelisted {
    param ([string]$filePath)
    foreach ($pattern in $whitelistPatterns) {
        if ($filePath -like $pattern) {
            return $true
        }
    }
    return $false
}

function Show-Notification {
    param ([string]$message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $notify = New-Object System.Windows.Forms.NotifyIcon
        $notify.Icon = [System.Drawing.SystemIcons]::Warning
        $notify.Visible = $true
        $notify.ShowBalloonTip(5000, "GShield Antivirus", $message, [System.Windows.Forms.ToolTipIcon]::Warning)
        Start-Sleep -Seconds 5
        $notify.Dispose()
    } catch {
        Write-Log "Failed to show notification: $($_.Exception.Message)"
    }
}

# Main execution
try {
    Write-Log "Starting antivirus scan with FileSystemWatcher"
    $watchers = Start-FileSystemWatcher
    Remove-UnsignedDLLs
    Scan-AllFilesWithVirusTotal
    Write-Log "Antivirus scan completed successfully. FileSystemWatcher is running."
    # Keep script running to maintain FileSystemWatcher
    while ($true) {
        Start-Sleep -Seconds $config.ScanIntervalSeconds
        Write-Log "Periodic VirusTotal scan initiated"
        Scan-AllFilesWithVirusTotal
    }
} catch {
    Write-Log "Error during scan: $($_.Exception.Message)"
} finally {
    # Cleanup watchers on script termination
    Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "FileCreated_*" -or $_.SourceIdentifier -like "FileChanged_*" } | Unregister-Event
    Get-Job | Remove-Job -Force
}