# Antivirus.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunAntivirusAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        # Fallback to determine script path
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

# Run the function
Register-SystemLogonScript

$ErrorActionPreference = 'SilentlyContinue'

# Define paths
$programData = [Environment]::GetFolderPath("CommonApplicationData")
$baseDir = Join-Path $programData "Antivirus"
$scriptDir = Join-Path $baseDir "Bin"
$scriptPath = Join-Path $scriptDir "Antivirus.ps1"
$quarantineFolder = Join-Path $baseDir "Quarantine"
$backupFolder = Join-Path $baseDir "Backup"
$logFile = Join-Path $baseDir "antivirus_log.txt"
$localDatabase = Join-Path $baseDir "scanned_files.txt"
$configFile = Join-Path $baseDir "config.json"
$lockFile = Join-Path $baseDir "antivirus.lock"
$virusTotalApiKey = "bb66071b32ed9b7d1f79f704e2772a2ce4d857e7cc0564ebabe41828def4f57b"
$scannedFiles = @{}
$maxRetries = 3
$retryDelaySeconds = 15 # Increased to manage API rate limits
$maxConcurrentScans = 4 # VirusTotal free API limit: 4 requests/minute
$eventQueue = New-Object 'System.Collections.Queue'
$maxQueueSize = 100
$maxFileSizeMB = 32 # VirusTotal free API upload limit: 32 MB

# Whitelist for system-critical files, browser DLLs, gaming apps, and problematic directories
$whitelistPatterns = @(
    "*\Antivirus\Bin\Antivirus.ps1*",
    "*\Antivirus\Quarantine\*",
    "*\Windows\System32\*",
    "*\Windows\SysWOW64\*",
    "*\Windows\WinSxS\*",
    "*\Program Files\Windows Defender\*",
    "*\Google\Chrome\Application\*",
    "*\Mozilla Firefox\*",
    "*\Microsoft\Edge\Application\*",
    "*\Opera\*",
    "*\Steam\*",
    "*\Epic Games\*",
    "*\Origin\*",
    "*\Ubisoft\*",
    "*\Battle.net\*",
    "*\Users\Admin\AppData\Local\Temp\*",
    "*\Users\Admin\AppData\Local\Microsoft\Windows\ActionCenterCache\*"
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

# Check for lock file to prevent multiple instances
if (Test-Path $lockFile) {
    $lockContent = Get-Content $lockFile -ErrorAction SilentlyContinue
    if ($lockContent -and (Get-Process -Id $lockContent -ErrorAction SilentlyContinue)) {
        Write-Host "Another instance of the antivirus script is already running (PID: $lockContent). Exiting."
        exit
    } else {
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    }
}
# Create lock file with current process ID
$pid = [System.Diagnostics.Process]::GetCurrentProcess().Id
Set-Content -Path $lockFile -Value $pid -Force
Write-Log "Created lock file with PID: $pid"

# Save or load configuration
if (-not (Test-Path $configFile)) {
    $configDefaults | ConvertTo-Json | Set-Content $configFile
}
$config = Get-Content $configFile -Raw | ConvertFrom-Json

# Logging Function with Rotation
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    try {
        if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge ($config.MaxLogSizeMB * 1MB))) {
            $archiveName = Join-Path $baseDir "antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            Rename-Item -Path $logFile -NewName $archiveName -ErrorAction SilentlyContinue
            Write-Host "Rotated log to $archiveName"
        }
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Host ("Failed to write to log: {0}" -f $_.Exception.Message)
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

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        if (-not (Test-Path $filePath -PathType Leaf)) {
            Write-Log "Skipping ${filePath}: Not a valid file."
            return $null
        }
        $fileInfo = Get-Item $filePath -ErrorAction Stop
        if ($fileInfo.Length -eq 0) {
            Write-Log "Skipping ${filePath}: Zero-byte file."
            return $null
        }
        if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
            Write-Log "Skipping ${filePath}: File size exceeds $maxFileSizeMB MB."
            return $null
        }
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    } catch {
        Write-Log ("Error hashing ${filePath}: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Upload-FileToVirusTotal {
    param ([string]$filePath, [string]$fileHash)
    try {
        $fileInfo = Get-Item $filePath -ErrorAction Stop
        if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
            Write-Log "Cannot upload ${filePath}: File size exceeds $maxFileSizeMB MB."
            return $false
        }
        $url = "https://www.virustotal.com/api/v3/files"
        $headers = @{ "x-apikey" = $virusTotalApiKey }
        
        # Create a multipart form-data request
        $boundary = [System.Guid]::NewGuid().ToString()
        $contentType = "multipart/form-data; boundary=$boundary"
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $fileName = [System.IO.Path]::GetFileName($filePath)
        
        # Construct the multipart form-data body
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream",
            "",
            [System.Text.Encoding]::UTF8.GetString($fileBytes),
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"

        Write-Log "Uploading file ${filePath} to VirusTotal."
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ContentType $contentType -Body $body -ErrorAction Stop
        $analysisId = $response.data.id
        Write-Log "File ${filePath} uploaded. Analysis ID: $analysisId"
        
        $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
        for ($i = 0; $i -lt $maxRetries; $i++) {
            Start-Sleep -Seconds $retryDelaySeconds
            try {
                $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
                if ($analysisResponse.data.attributes.status -eq "completed") {
                    $maliciousCount = $analysisResponse.data.attributes.stats.malicious
                    Write-Log "VirusTotal analysis for ${fileHash}: $maliciousCount malicious detections."
                    return $maliciousCount -gt 3
                }
            } catch {
                Write-Log ("Error checking analysis status for ${fileHash}: {0}" -f $_.Exception.Message)
            }
        }
        Write-Log "Analysis for ${fileHash} did not complete in time."
        return $false
    } catch {
        Write-Log ("Failed to upload ${filePath}: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Scan-FileWithVirusTotal {
    param ([string]$fileHash, [string]$filePath)
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
            if ($_.Exception.Response.StatusCode -eq 404) {
                Write-Log "File hash ${fileHash} not found in VirusTotal database. Attempting to upload."
                return Upload-FileToVirusTotal -filePath $filePath -fileHash $fileHash
            }
            Write-Log ("Error scanning ${fileHash}: {0}" -f $_.Exception.Message)
            if ($i -lt ($maxRetries - 1)) {
                Start-Sleep -Seconds $retryDelaySeconds
                continue
            }
        }
    }
    return $false
}

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
                if ($eventQueue.Count -ge $maxQueueSize) {
                    $eventQueue.Dequeue() | Out-Null
                }
                $eventQueue.Enqueue($filePath)
            }
            Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action -SourceIdentifier "FileCreated_$($drive.DeviceID)" | Out-Null
            Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action -SourceIdentifier "FileChanged_$($drive.DeviceID)" | Out-Null
            $watchers += $watcher
            Write-Log "FileSystemWatcher initialized for $root"
        } catch {
            Write-Log ("Error setting up FileSystemWatcher for {0}: {1}" -f $root, $_.Exception.Message)
        }
    }
    return $watchers
}

function Remove-UnsignedDLLs {
    param ([int]$maxFiles = $config.MaxFilesPerDrive)
    Write-Log "Starting unsigned DLL scan across all drives."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    if (-not $drives) {
        Write-Log "No drives detected for scanning."
        return
    }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $files = Get-ChildItem -Path $root -Recurse -File -Include *.dll -ErrorAction SilentlyContinue
            if (-not $files) {
                Write-Log "No DLL files found on drive $root"
                continue
            }
            $limitedFiles = $files | Select-Object -First $maxFiles
            foreach ($file in $limitedFiles) {
                if ($file.Extension -ne ".dll") {
                    Write-Log "Skipping non-DLL file: $($file.FullName)"
                    continue
                }
                if (Is-Whitelisted -filePath $file.FullName) {
                    Write-Log "Skipping whitelisted file: $($file.FullName)"
                    continue
                }
                try {
                    $cert = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
                    if ($cert.Status -ne 'Valid') {
                        Write-Log "Found unsigned DLL: $($file.FullName)"
                        Stop-ProcessUsingDLL -filePath $file.FullName
                        Backup-And-Quarantine -filePath $file.FullName
                        Show-Notification -message "Unsigned DLL quarantined: $($file.FullName)"
                    }
                } catch {
                    Write-Log ("Error processing {0}: {1}" -f $file.FullName, $_.Exception.Message)
                }
            }
        } catch {
            Write-Log ("Drive scan error on {0}: {1}" -f $root, $_.Exception.Message)
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
    $semaphore = New-Object System.Threading.Semaphore($maxConcurrentScans, $maxConcurrentScans)
    $jobs = @()
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
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
                    param ($filePath, $localDatabase, $virusTotalApiKey, $semaphore, $logFile, $backupFolder, $quarantineFolder, $maxRetries, $retryDelaySeconds, $maxFileSizeMB)
                    
                    function Write-Log {
                        param ([string]$Message)
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        $logEntry = "[$timestamp] $Message"
                        Write-Host $logEntry
                        try {
                            Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
                        } catch {
                            Write-Host ("Failed to write to log: {0}" -f $_.Exception.Message)
                        }
                    }
                    
                    function Calculate-FileHash {
                        param ([string]$filePath)
                        try {
                            if (-not (Test-Path $filePath -PathType Leaf)) {
                                Write-Log "Skipping ${filePath}: Not a valid file."
                                return $null
                            }
                            $fileInfo = Get-Item $filePath -ErrorAction Stop
                            if ($fileInfo.Length -eq 0) {
                                Write-Log "Skipping ${filePath}: Zero-byte file."
                                return $null
                            }
                            if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                                Write-Log "Skipping ${filePath}: File size exceeds $maxFileSizeMB MB."
                                return $null
                            }
                            $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                            return $hash.Hash.ToLower()
                        } catch {
                            Write-Log ("Error hashing ${filePath}: {0}" -f $_.Exception.Message)
                            return $null
                        }
                    }
                    
                    function Upload-FileToVirusTotal {
                        param ([string]$filePath, [string]$fileHash)
                        try {
                            $fileInfo = Get-Item $filePath -ErrorAction Stop
                            if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                                Write-Log "Cannot upload ${filePath}: File size exceeds $maxFileSizeMB MB."
                                return $false
                            }
                            $url = "https://www.virustotal.com/api/v3/files"
                            $headers = @{ "x-apikey" = $virusTotalApiKey }
                            
                            # Create a multipart form-data request
                            $boundary = [System.Guid]::NewGuid().ToString()
                            $contentType = "multipart/form-data; boundary=$boundary"
                            $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                            $fileName = [System.IO.Path]::GetFileName($filePath)
                            
                            # Construct the multipart form-data body
                            $bodyLines = @(
                                "--$boundary",
                                "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                                "Content-Type: application/octet-stream",
                                "",
                                [System.Text.Encoding]::UTF8.GetString($fileBytes),
                                "--$boundary--"
                            )
                            $body = $bodyLines -join "`r`n"

                            Write-Log "Uploading file ${filePath} to VirusTotal."
                            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ContentType $contentType -Body $body -ErrorAction Stop
                            $analysisId = $response.data.id
                            Write-Log "File ${filePath} uploaded. Analysis ID: $analysisId"
                            
                            $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
                            for ($i = 0; $i -lt $maxRetries; $i++) {
                                Start-Sleep -Seconds $retryDelaySeconds
                                try {
                                    $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
                                    if ($analysisResponse.data.attributes.status -eq "completed") {
                                        $maliciousCount = $analysisResponse.data.attributes.stats.malicious
                                        Write-Log "VirusTotal analysis for ${fileHash}: $maliciousCount malicious detections."
                                        return $maliciousCount -gt 3
                                    }
                                } catch {
                                    Write-Log ("Error checking analysis status for ${fileHash}: {0}" -f $_.Exception.Message)
                                }
                            }
                            Write-Log "Analysis for ${fileHash} did not complete in time."
                            return $false
                        } catch {
                            Write-Log ("Failed to upload ${filePath}: {0}" -f $_.Exception.Message)
                            return $false
                        }
                    }
                    
                    function Scan-FileWithVirusTotal {
                        param ([string]$fileHash, [string]$filePath)
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
                                if ($_.Exception.Response.StatusCode -eq 404) {
                                    Write-Log "File hash ${fileHash} not found in VirusTotal database. Attempting to upload."
                                    return Upload-FileToVirusTotal -filePath $filePath -fileHash $fileHash
                                }
                                Write-Log ("Error scanning ${fileHash}: {0}" -f $_.Exception.Message)
                                if ($i -lt ($maxRetries - 1)) {
                                    Start-Sleep -Seconds $retryDelaySeconds
                                    continue
                                }
                            }
                        }
                        return $false
                    }
                    
                    function Stop-ProcessUsingDLL {
                        param ([string]$filePath)
                        try {
                            $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
                            foreach ($process in $processes) {
                                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                                Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using ${filePath}"
                                try {
                                    $parent = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -ExpandProperty ParentProcessId
                                    if ($parent -and $parent -ne 0) {
                                        Stop-Process -Id $parent -Force -ErrorAction Stop
                                        $parentProcess = Get-Process -Id $parent -ErrorAction SilentlyContinue
                                        if ($parentProcess) {
                                            Write-Log "Stopped parent process $($parentProcess.Name) (PID: $parent) of process using ${filePath}"
                                        }
                                    }
                                } catch {
                                    Write-Log ("Error stopping parent process for PID $($process.Id): {0}" -f $_.Exception.Message)
                                }
                            }
                        } catch {
                            Write-Log ("Error stopping processes for ${filePath}: {0}" -f $_.Exception.Message)
                        }
                    }
                    
                    function Backup-And-Quarantine {
                        param ([string]$filePath)
                        try {
                            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                            if (-not $isAdmin) {
                                Write-Log "Insufficient permissions to process ${filePath}"
                                return
                            }
                            # Check for file locks
                            try {
                                $handle = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
                                $handle.Close()
                            } catch {
                                Write-Log "File ${filePath} is locked by another process."
                                return
                            }
                            takeown /F $filePath /A | Out-Null
                            Write-Log "Took ownership of file: ${filePath}"
                            $acl = Get-Acl -Path $filePath
                            $acl.SetAccessRuleProtection($true, $false)
                            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
                            $acl.AddAccessRule($adminRule)
                            Set-Acl -Path $filePath -AclObject $acl
                            Start-Sleep -Milliseconds 500
                            Write-Log "Removed all permissions and granted Administrators full control for file: ${filePath}"
                            $backupPath = Join-Path -Path $backupFolder -ChildPath ("$(Split-Path $filePath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                            Copy-Item -Path $filePath -Destination $backupPath -Force -ErrorAction Stop
                            Write-Log "Backed up file: ${filePath} to $backupPath"
                            $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
                            Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
                            Write-Log "Quarantined file: ${filePath} to $quarantinePath"
                        } catch {
                            Write-Log ("Failed to backup/quarantine ${filePath}: {0}" -f $_.Exception.Message)
                        }
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
                            Write-Log ("Failed to show notification: {0}" -f $_.Exception.Message)
                        }
                    }
                    
                    try {
                        $semaphore.WaitOne()
                        $hash = Calculate-FileHash -filePath $filePath
                        if (-not $hash) { return }
                        if (Test-Path $localDatabase) {
                            $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
                            $scannedFiles = @{}
                            foreach ($line in $lines) {
                                if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                                    $scannedFiles[$matches[1]] = [bool]$matches[2]
                                }
                            }
                        }
                        if ($scannedFiles.ContainsKey($hash)) { return }
                        $isMalicious = Scan-FileWithVirusTotal -fileHash $hash -filePath $filePath
                        Add-Content -Path $localDatabase -Value "$hash,$(-not $isMalicious)"
                        if ($isMalicious) {
                            Stop-ProcessUsingDLL -filePath $filePath
                            Backup-And-Quarantine -filePath $filePath
                            Show-Notification -message "Malicious file quarantined: $filePath"
                        }
                    } catch {
                        Write-Log ("Error processing ${filePath}: {0}" -f $_.Exception.Message)
                    } finally {
                        $semaphore.Release()
                    }
                } -ArgumentList $file.FullName, $localDatabase, $virusTotalApiKey, $semaphore, $logFile, $backupFolder, $quarantineFolder, $maxRetries, $retryDelaySeconds, $maxFileSizeMB
            }
        } catch {
            Write-Log ("Error scanning drive {0}: {1}" -f $root, $_.Exception.Message)
        }
    }
    $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    Write-Log "Finished VirusTotal scan."
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using ${filePath}"
            try {
                $parent = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -ExpandProperty ParentProcessId
                if ($parent -and $parent -ne 0) {
                    Stop-Process -Id $parent -Force -ErrorAction Stop
                    $parentProcess = Get-Process -Id $parent -ErrorAction SilentlyContinue
                    if ($parentProcess) {
                        Write-Log "Stopped parent process $($parentProcess.Name) (PID: $parent) of process using ${filePath}"
                    }
                }
            } catch {
                Write-Log ("Error stopping parent process for PID $($process.Id): {0}" -f $_.Exception.Message)
            }
        }
    } catch {
        Write-Log ("Error stopping processes for ${filePath}: {0}" -f $_.Exception.Message)
    }
}

function Backup-And-Quarantine {
    param ([string]$filePath)
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log "Insufficient permissions to process ${filePath}"
            return
        }
        # Check for file locks
        try {
            $handle = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
            $handle.Close()
        } catch {
            Write-Log "File ${filePath} is locked by another process."
            return
        }
        takeown /F $filePath /A | Out-Null
        Write-Log "Took ownership of file: ${filePath}"
        $acl = Get-Acl -Path $filePath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $filePath -AclObject $acl
        Start-Sleep -Milliseconds 500
        Write-Log "Removed all permissions and granted Administrators full control for file: ${filePath}"
        $backupPath = Join-Path -Path $backupFolder -ChildPath ("$(Split-Path $filePath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
        Copy-Item -Path $filePath -Destination $backupPath -Force -ErrorAction Stop
        Write-Log "Backed up file: ${filePath} to $backupPath"
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: ${filePath} to $quarantinePath"
    } catch {
        Write-Log ("Failed to backup/quarantine ${filePath}: {0}" -f $_.Exception.Message)
    }
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
        Write-Log ("Failed to show notification: {0}" -f $_.Exception.Message)
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

# Main execution
try {
    Write-Log "Starting antivirus scan in background job"
    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Script requires administrative privileges"
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
        exit
    }
    # Check for existing jobs
    $existingJob = Get-Job | Where-Object { $_.Name -eq "AntivirusMainJob" -and $_.State -eq "Running" }
    if ($existingJob) {
        Write-Log "An antivirus job (ID: $($existingJob.Id)) is already running. Exiting."
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
        exit
    }
    # Start the main execution as a background job
    $job = Start-Job -Name "AntivirusMainJob" -ScriptBlock {
        param ($logFile, $localDatabase, $virusTotalApiKey, $maxRetries, $retryDelaySeconds, $maxConcurrentScans, $whitelistPatterns, $config, $backupFolder, $quarantineFolder, $maxFileSizeMB, $eventQueue, $maxQueueSize, $lockFile)
        
        function Write-Log {
            param ([string]$Message)
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] $Message"
            Write-Host $logEntry
            try {
                if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge ($config.MaxLogSizeMB * 1MB))) {
                    $archiveName = Join-Path (Split-Path $logFile -Parent) "antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                    Rename-Item -Path $logFile -NewName $archiveName -ErrorAction SilentlyContinue
                    Write-Host "Rotated log to $archiveName"
                }
                Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
            } catch {
                Write-Host ("Failed to write to log: {0}" -f $_.Exception.Message)
            }
        }
        
        function Calculate-FileHash {
            param ([string]$filePath)
            try {
                if (-not (Test-Path $filePath -PathType Leaf)) {
                    Write-Log "Skipping ${filePath}: Not a valid file."
                    return $null
                }
                $fileInfo = Get-Item $filePath -ErrorAction Stop
                if ($fileInfo.Length -eq 0) {
                    Write-Log "Skipping ${filePath}: Zero-byte file."
                    return $null
                }
                if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                    Write-Log "Skipping ${filePath}: File size exceeds $maxFileSizeMB MB."
                    return $null
                }
                $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                return $hash.Hash.ToLower()
            } catch {
                Write-Log ("Error hashing ${filePath}: {0}" -f $_.Exception.Message)
                return $null
            }
        }
        
        function Upload-FileToVirusTotal {
            param ([string]$filePath, [string]$fileHash)
            try {
                $fileInfo = Get-Item $filePath -ErrorAction Stop
                if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                    Write-Log "Cannot upload ${filePath}: File size exceeds $maxFileSizeMB MB."
                    return $false
                }
                $url = "https://www.virustotal.com/api/v3/files"
                $headers = @{ "x-apikey" = $virusTotalApiKey }
                
                # Create a multipart form-data request
                $boundary = [System.Guid]::NewGuid().ToString()
                $contentType = "multipart/form-data; boundary=$boundary"
                $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                $fileName = [System.IO.Path]::GetFileName($filePath)
                
                # Construct the multipart form-data body
                $bodyLines = @(
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                    "Content-Type: application/octet-stream",
                    "",
                    [System.Text.Encoding]::UTF8.GetString($fileBytes),
                    "--$boundary--"
                )
                $body = $bodyLines -join "`r`n"

                Write-Log "Uploading file ${filePath} to VirusTotal."
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ContentType $contentType -Body $body -ErrorAction Stop
                $analysisId = $response.data.id
                Write-Log "File ${filePath} uploaded. Analysis ID: $analysisId"
                
                $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
                for ($i = 0; $i -lt $maxRetries; $i++) {
                    Start-Sleep -Seconds $retryDelaySeconds
                    try {
                        $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
                        if ($analysisResponse.data.attributes.status -eq "completed") {
                            $maliciousCount = $analysisResponse.data.attributes.stats.malicious
                            Write-Log "VirusTotal analysis for ${fileHash}: $maliciousCount malicious detections."
                            return $maliciousCount -gt 3
                        }
                    } catch {
                        Write-Log ("Error checking analysis status for ${fileHash}: {0}" -f $_.Exception.Message)
                    }
                }
                Write-Log "Analysis for ${fileHash} did not complete in time."
                return $false
            } catch {
                Write-Log ("Failed to upload ${filePath}: {0}" -f $_.Exception.Message)
                return $false
            }
        }
        
        function Scan-FileWithVirusTotal {
            param ([string]$fileHash, [string]$filePath)
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
                    if ($_.Exception.Response.StatusCode -eq 404) {
                        Write-Log "File hash ${fileHash} not found in VirusTotal database. Attempting to upload."
                        return Upload-FileToVirusTotal -filePath $filePath -fileHash $fileHash
                    }
                    Write-Log ("Error scanning ${fileHash}: {0}" -f $_.Exception.Message)
                    if ($i -lt ($maxRetries - 1)) {
                        Start-Sleep -Seconds $retryDelaySeconds
                        continue
                    }
                }
            }
            return $false
        }
        
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
                        if ($eventQueue.Count -ge $maxQueueSize) {
                            $eventQueue.Dequeue() | Out-Null
                        }
                        $eventQueue.Enqueue($filePath)
                    }
                    Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action -SourceIdentifier "FileCreated_$($drive.DeviceID)" | Out-Null
                    Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action -SourceIdentifier "FileChanged_$($drive.DeviceID)" | Out-Null
                    $watchers += $watcher
                    Write-Log "FileSystemWatcher initialized for $root"
                } catch {
                    Write-Log ("Error setting up FileSystemWatcher for {0}: {1}" -f $root, $_.Exception.Message)
                }
            }
            return $watchers
        }
        
        function Remove-UnsignedDLLs {
            param ([int]$maxFiles = $config.MaxFilesPerDrive)
            Write-Log "Starting unsigned DLL scan across all drives."
            $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
            if (-not $drives) {
                Write-Log "No drives detected for scanning."
                return
            }
            foreach ($drive in $drives) {
                $root = $drive.DeviceID + "\"
                Write-Log "Scanning drive: $root"
                try {
                    $files = Get-ChildItem -Path $root -Recurse -File -Include *.dll -ErrorAction SilentlyContinue
                    if (-not $files) {
                        Write-Log "No DLL files found on drive $root"
                        continue
                    }
                    $limitedFiles = $files | Select-Object -First $maxFiles
                    foreach ($file in $limitedFiles) {
                        if ($file.Extension -ne ".dll") {
                            Write-Log "Skipping non-DLL file: $($file.FullName)"
                            continue
                        }
                        if (Is-Whitelisted -filePath $file.FullName) {
                            Write-Log "Skipping whitelisted file: $($file.FullName)"
                            continue
                        }
                        try {
                            $cert = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
                            if ($cert.Status -ne 'Valid') {
                                Write-Log "Found unsigned DLL: $($file.FullName)"
                                Stop-ProcessUsingDLL -filePath $file.FullName
                                Backup-And-Quarantine -filePath $file.FullName
                                Show-Notification -message "Unsigned DLL quarantined: $($file.FullName)"
                            }
                        } catch {
                            Write-Log ("Error processing {0}: {1}" -f $file.FullName, $_.Exception.Message)
                        }
                    }
                } catch {
                    Write-Log ("Drive scan error on {0}: {1}" -f $root, $_.Exception.Message)
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
            $semaphore = New-Object System.Threading.Semaphore($maxConcurrentScans, $maxConcurrentScans)
            $jobs = @()
            foreach ($drive in $drives) {
                $root = $drive.DeviceID + "\"
                Write-Log "Scanning drive: $root"
                try {
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
                            param ($filePath, $localDatabase, $virusTotalApiKey, $semaphore, $logFile, $backupFolder, $quarantineFolder, $maxRetries, $retryDelaySeconds, $maxFileSizeMB)
                            
                            function Write-Log {
                                param ([string]$Message)
                                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                $logEntry = "[$timestamp] $Message"
                                Write-Host $logEntry
                                try {
                                    Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
                                } catch {
                                    Write-Host ("Failed to write to log: {0}" -f $_.Exception.Message)
                                }
                            }
                            
                            function Calculate-FileHash {
                                param ([string]$filePath)
                                try {
                                    if (-not (Test-Path $filePath -PathType Leaf)) {
                                        Write-Log "Skipping ${filePath}: Not a valid file."
                                        return $null
                                    }
                                    $fileInfo = Get-Item $filePath -ErrorAction Stop
                                    if ($fileInfo.Length -eq 0) {
                                        Write-Log "Skipping ${filePath}: Zero-byte file."
                                        return $null
                                    }
                                    if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                                        Write-Log "Skipping ${filePath}: File size exceeds $maxFileSizeMB MB."
                                        return $null
                                    }
                                    $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                                    return $hash.Hash.ToLower()
                                } catch {
                                    Write-Log ("Error hashing ${filePath}: {0}" -f $_.Exception.Message)
                                    return $null
                                }
                            }
                            
                            function Upload-FileToVirusTotal {
                                param ([string]$filePath, [string]$fileHash)
                                try {
                                    $fileInfo = Get-Item $filePath -ErrorAction Stop
                                    if ($fileInfo.Length -gt ($maxFileSizeMB * 1MB)) {
                                        Write-Log "Cannot upload ${filePath}: File size exceeds $maxFileSizeMB MB."
                                        return $false
                                    }
                                    $url = "https://www.virustotal.com/api/v3/files"
                                    $headers = @{ "x-apikey" = $virusTotalApiKey }
                                    
                                    # Create a multipart form-data request
                                    $boundary = [System.Guid]::NewGuid().ToString()
                                    $contentType = "multipart/form-data; boundary=$boundary"
                                    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                                    $fileName = [System.IO.Path]::GetFileName($filePath)
                                    
                                    # Construct the multipart form-data body
                                    $bodyLines = @(
                                        "--$boundary",
                                        "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                                        "Content-Type: application/octet-stream",
                                        "",
                                        [System.Text.Encoding]::UTF8.GetString($fileBytes),
                                        "--$boundary--"
                                    )
                                    $body = $bodyLines -join "`r`n"

                                    Write-Log "Uploading file ${filePath} to VirusTotal."
                                    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ContentType $contentType -Body $body -ErrorAction Stop
                                    $analysisId = $response.data.id
                                    Write-Log "File ${filePath} uploaded. Analysis ID: $analysisId"
                                    
                                    $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
                                    for ($i = 0; $i -lt $maxRetries; $i++) {
                                        Start-Sleep -Seconds $retryDelaySeconds
                                        try {
                                            $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
                                            if ($analysisResponse.data.attributes.status -eq "completed") {
                                                $maliciousCount = $analysisResponse.data.attributes.stats.malicious
                                                Write-Log "VirusTotal analysis for ${fileHash}: $maliciousCount malicious detections."
                                                return $maliciousCount -gt 3
                                            }
                                        } catch {
                                            Write-Log ("Error checking analysis status for ${fileHash}: {0}" -f $_.Exception.Message)
                                        }
                                    }
                                    Write-Log "Analysis for ${fileHash} did not complete in time."
                                    return $false
                                } catch {
                                    Write-Log ("Failed to upload ${filePath}: {0}" -f $_.Exception.Message)
                                    return $false
                                }
                            }
                            
                            function Scan-FileWithVirusTotal {
                                param ([string]$fileHash, [string]$filePath)
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
                                        if ($_.Exception.Response.StatusCode -eq 404) {
                                            Write-Log "File hash ${fileHash} not found in VirusTotal database. Attempting to upload."
                                            return Upload-FileToVirusTotal -filePath $filePath -fileHash $fileHash
                                        }
                                        Write-Log ("Error scanning ${fileHash}: {0}" -f $_.Exception.Message)
                                        if ($i -lt ($maxRetries - 1)) {
                                            Start-Sleep -Seconds $retryDelaySeconds
                                            continue
                                        }
                                    }
                                }
                                return $false
                            }
                            
                            function Stop-ProcessUsingDLL {
                                param ([string]$filePath)
                                try {
                                    $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
                                    foreach ($process in $processes) {
                                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                                        Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using ${filePath}"
                                        try {
                                            $parent = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -ExpandProperty ParentProcessId
                                            if ($parent -and $parent -ne 0) {
                                                Stop-Process -Id $parent -Force -ErrorAction Stop
                                                $parentProcess = Get-Process -Id $parent -ErrorAction SilentlyContinue
                                                if ($parentProcess) {
                                                    Write-Log "Stopped parent process $($parentProcess.Name) (PID: $parent) of process using ${filePath}"
                                                }
                                            }
                                        } catch {
                                            Write-Log ("Error stopping parent process for PID $($process.Id): {0}" -f $_.Exception.Message)
                                        }
                                    }
                                } catch {
                                    Write-Log ("Error stopping processes for ${filePath}: {0}" -f $_.Exception.Message)
                                }
                            }
                            
                            function Backup-And-Quarantine {
                                param ([string]$filePath)
                                try {
                                    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                                    if (-not $isAdmin) {
                                        Write-Log "Insufficient permissions to process ${filePath}"
                                        return
                                    }
                                    # Check for file locks
                                    try {
                                        $handle = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
                                        $handle.Close()
                                    } catch {
                                        Write-Log "File ${filePath} is locked by another process."
                                        return
                                    }
                                    takeown /F $filePath /A | Out-Null
                                    Write-Log "Took ownership of file: ${filePath}"
                                    $acl = Get-Acl -Path $filePath
                                    $acl.SetAccessRuleProtection($true, $false)
                                    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                                    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
                                    $acl.AddAccessRule($adminRule)
                                    Set-Acl -Path $filePath -AclObject $acl
                                    Start-Sleep -Milliseconds 500
                                    Write-Log "Removed all permissions and granted Administrators full control for file: ${filePath}"
                                    $backupPath = Join-Path -Path $backupFolder -ChildPath ("$(Split-Path $filePath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                                    Copy-Item -Path $filePath -Destination $backupPath -Force -ErrorAction Stop
                                    Write-Log "Backed up file: ${filePath} to $backupPath"
                                    $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
                                    Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
                                    Write-Log "Quarantined file: ${filePath} to $quarantinePath"
                                } catch {
                                    Write-Log ("Failed to backup/quarantine ${filePath}: {0}" -f $_.Exception.Message)
                                }
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
                                    Write-Log ("Failed to show notification: {0}" -f $_.Exception.Message)
                                }
                            }
                            
                            try {
                                $semaphore.WaitOne()
                                $hash = Calculate-FileHash -filePath $filePath
                                if (-not $hash) { return }
                                if (Test-Path $localDatabase) {
                                    $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
                                    $scannedFiles = @{}
                                    foreach ($line in $lines) {
                                        if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                                            $scannedFiles[$matches[1]] = [bool]$matches[2]
                                        }
                                    }
                                }
                                if ($scannedFiles.ContainsKey($hash)) { return }
                                $isMalicious = Scan-FileWithVirusTotal -fileHash $hash -filePath $filePath
                                Add-Content -Path $localDatabase -Value "$hash,$(-not $isMalicious)"
                                if ($isMalicious) {
                                    Stop-ProcessUsingDLL -filePath $filePath
                                    Backup-And-Quarantine -filePath $filePath
                                    Show-Notification -message "Malicious file quarantined: $filePath"
                                }
                            } catch {
                                Write-Log ("Error processing ${filePath}: {0}" -f $_.Exception.Message)
                            } finally {
                                $semaphore.Release()
                            }
                        } -ArgumentList $file.FullName, $localDatabase, $virusTotalApiKey, $semaphore, $logFile, $backupFolder, $quarantineFolder, $maxRetries, $retryDelaySeconds, $maxFileSizeMB
                    }
                } catch {
                    Write-Log ("Error scanning drive {0}: {1}" -f $root, $_.Exception.Message)
                }
            }
            $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            Write-Log "Finished VirusTotal scan."
        }
        
        function Stop-ProcessUsingDLL {
            param ([string]$filePath)
            try {
                $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
                foreach ($process in $processes) {
                    Stop-Process -Id $process.Id -Force -ErrorAction Stop
                    Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using ${filePath}"
                    try {
                        $parent = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -ExpandProperty ParentProcessId
                        if ($parent -and $parent -ne 0) {
                            Stop-Process -Id $parent -Force -ErrorAction Stop
                            $parentProcess = Get-Process -Id $parent -ErrorAction SilentlyContinue
                            if ($parentProcess) {
                                Write-Log "Stopped parent process $($parentProcess.Name) (PID: $parent) of process using ${filePath}"
                            }
                        }
                    } catch {
                        Write-Log ("Error stopping parent process for PID $($process.Id): {0}" -f $_.Exception.Message)
                    }
                }
            } catch {
                Write-Log ("Error stopping processes for ${filePath}: {0}" -f $_.Exception.Message)
            }
        }
        
        function Backup-And-Quarantine {
            param ([string]$filePath)
            try {
                $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isAdmin) {
                    Write-Log "Insufficient permissions to process ${filePath}"
                    return
                }
                # Check for file locks
                try {
                    $handle = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
                    $handle.Close()
                } catch {
                    Write-Log "File ${filePath} is locked by another process."
                    return
                }
                takeown /F $filePath /A | Out-Null
                Write-Log "Took ownership of file: ${filePath}"
                $acl = Get-Acl -Path $filePath
                $acl.SetAccessRuleProtection($true, $false)
                $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
                $acl.AddAccessRule($adminRule)
                Set-Acl -Path $filePath -AclObject $acl
                Start-Sleep -Milliseconds 500
                Write-Log "Removed all permissions and granted Administrators full control for file: ${filePath}"
                $backupPath = Join-Path -Path $backupFolder -ChildPath ("$(Split-Path $filePath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                Copy-Item -Path $filePath -Destination $backupPath -Force -ErrorAction Stop
                Write-Log "Backed up file: ${filePath} to $backupPath"
                $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
                Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-Log "Quarantined file: ${filePath} to $quarantinePath"
            } catch {
                Write-Log ("Failed to backup/quarantine ${filePath}: {0}" -f $_.Exception.Message)
            }
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
                Write-Log ("Failed to show notification: {0}" -f $_.Exception.Message)
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
        
        try {
            # Start FileSystemWatcher
            $watchers = Start-FileSystemWatcher
            # Run initial scans
            Write-Log "Starting initial scans."
            Remove-UnsignedDLLs
            Scan-AllFilesWithVirusTotal
            Write-Log "Initial scans completed."
            # Process FileSystemWatcher events
            while ($true) {
                if ($eventQueue.Count -gt 0) {
                    $filePath = $eventQueue.Dequeue()
                    if (Is-Whitelisted -filePath $filePath) {
                        Write-Log "Skipping whitelisted file: ${filePath}"
                        continue
                    }
                    try {
                        $hash = Calculate-FileHash -filePath $filePath
                        if (-not $hash) { continue }
                        if (Test-Path $localDatabase) {
                            $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
                            $scannedFiles = @{}
                            foreach ($line in $lines) {
                                if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                                    $scannedFiles[$matches[1]] = [bool]$matches[2]
                                }
                            }
                        }
                        if ($scannedFiles.ContainsKey($hash)) { continue }
                        if ($filePath -like "*.dll") {
                            try {
                                $cert = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                                if ($cert.Status -ne 'Valid') {
                                    Write-Log "Found unsigned DLL: ${filePath}"
                                    Stop-ProcessUsingDLL -filePath $filePath
                                    Backup-And-Quarantine -filePath $filePath
                                    Show-Notification -message "Unsigned DLL quarantined: ${filePath}"
                                    Add-Content -Path $localDatabase -Value "$hash,$false"
                                    continue
                                }
                            } catch {
                                Write-Log ("Error processing DLL {0}: {1}" -f $filePath, $_.Exception.Message)
                            }
                        } else {
                            Write-Log "Skipping non-DLL file: ${filePath}"
                        }
                        $isMalicious = Scan-FileWithVirusTotal -fileHash $hash -filePath $filePath
                        $scannedFiles[$hash] = -not $isMalicious
                        Add-Content -Path $localDatabase -Value "$hash,$(-not $isMalicious)"
                        if ($isMalicious) {
                            Stop-ProcessUsingDLL -filePath $filePath
                            Backup-And-Quarantine -filePath $filePath
                            Show-Notification -message "Malicious file quarantined: ${filePath}"
                        }
                    } catch {
                        Write-Log ("Error processing ${filePath}: {0}" -f $_.Exception.Message)
                    }
                }
                Start-Sleep -Seconds $config.ScanIntervalSeconds
                Write-Log "Periodic VirusTotal scan initiated"
                Scan-AllFilesWithVirusTotal
            }
        } catch {
            Write-Log ("Error during scan: {0}" -f $_.Exception.Message)
        } finally {
            Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "FileCreated_*" -or $_.SourceIdentifier -like "FileChanged_*" } | Unregister-Event
            Get-Job | Remove-Job -Force
            Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned up lock file and event subscribers."
        }
    } -ArgumentList $logFile, $localDatabase, $virusTotalApiKey, $maxRetries, $retryDelaySeconds, $maxConcurrentScans, $whitelistPatterns, $config, $backupFolder, $quarantineFolder, $maxFileSizeMB, $eventQueue, $maxQueueSize, $lockFile
    
    Write-Log "Antivirus script started as a background job with ID $($job.Id)."
    Write-Log "Logs are being written to $logFile."
} catch {
    Write-Log ("Error starting background job: {0}" -f $_.Exception.Message)
} finally {
    Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
}
# Exit immediately to allow the calling batch script to continue
exit