
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

# GShield.ps1 by Gorstak

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
$scannedFiles = @{} # Initialize empty hash table
$checkIntervalSeconds = 60 # Interval to check for custom controls in seconds
$stopFile = "C:\Quarantine\stop.txt" # Stop file for graceful exit

# Firewall rules
$script:registryContent = @"
# [Insert your firewall rules here]
"@

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

# Logging Function for Antivirus with Rotation
function Write-AntivirusLog {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
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
        Write-AntivirusLog "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-AntivirusLog "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    $scannedFiles.Clear()
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-AntivirusLog "Created new database: $localDatabase"
}

# Take Ownership and Modify Permissions
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /reset | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d | Out-Null
        Write-AntivirusLog "Set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-AntivirusLog "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-AntivirusLog "Error processing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

# Quarantine File
function Quarantine-File {
    param ([string]$filePath)
    try {
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-AntivirusLog "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-AntivirusLog "Failed to quarantine ${filePath}: $($_.Exception.Message)"
    }
}

# Stop Processes Using DLL
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-AntivirusLog "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        Write-AntivirusLog "Error stopping processes for ${filePath}: $($_.Exception.Message)"
        try {
            $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
            foreach ($process in $processes) {
                taskkill /PID $process.Id /F | Out-Null
                Write-AntivirusLog "Force-killed process $($process.Name) (PID: $($process.Id)) using taskkill"
            }
        } catch {
            Write-AntivirusLog "Fallback process kill failed for ${filePath}: $($_.Exception.Message)"
        }
    }
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    Write-AntivirusLog "Starting unsigned DLL scan."
    $scanPaths = @("C:\Windows\System32", "C:\Program Files")
    foreach ($path in $scanPaths) {
        Write-AntivirusLog "Scanning directory: $path"
        try {
            $dllFiles = Get-ChildItem -Path $path -Filter *.dll -Recurse -File -ErrorAction Stop
            $dllFiles | ForEach-Object -Begin { $batch = @() } -Process { $batch += $_ } -End {
                foreach ($dll in $batch) {
                    try {
                        $fileHash = Calculate-FileHash -filePath $dll.FullName
                        if ($fileHash) {
                            if ($scannedFiles.ContainsKey($fileHash.Hash)) {
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
                                if (-not $isValid) {
                                    if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                        Stop-ProcessUsingDLL -filePath $dll.FullName
                                        Quarantine-File -filePath $dll.FullName
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-AntivirusLog "Error processing file $($dll.FullName): $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-AntivirusLog "Scan failed for directory ${path}: $($_.Exception.Message)"
        }
    }
}

# File System Watcher
function Start-FileSystemWatcher {
    $monitorPaths = @("C:\Windows\System32", "C:\Program Files")
    foreach ($monitorPath in $monitorPaths) {
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
                    if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$using:quarantineFolder*") {
                        Write-AntivirusLog "Detected file change: $($e.FullPath)"
                        $fileHash = Calculate-FileHash -filePath $e.FullPath
                        if ($fileHash -and -not $scannedFiles.ContainsKey($fileHash.Hash)) {
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $using:localDatabase -Append -Encoding UTF8
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                    Stop-ProcessUsingDLL -filePath $e.FullPath
                                    Quarantine-File -filePath $e.FullPath
                                }
                            }
                        }
                    }
                } catch {
                    Write-AntivirusLog "Watcher error for $($e.FullPath): $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 2000
            }

            Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action -ErrorAction Stop
            Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action -ErrorAction Stop
            Write-AntivirusLog "FileSystemWatcher set up for $monitorPath"
        } catch {
            Write-AntivirusLog "Failed to set up watcher for ${monitorPath}: $($_.Exception.Message)"
        }
    }
}

# Stop FileSystemWatcher
function Stop-FileSystemWatcher {
    Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.IO.FileSystemWatcher] } | Unregister-Event -Force
    Write-AntivirusLog "Unregistered all FileSystemWatcher events."
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
        Write-GSecurityLog "Failed to toggle network adapters: $($_.Exception.Message)" "Error"
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

# Process Killer
function Start-ProcessKiller {
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
}

# XSS Watcher
function Start-XSSWatcher {
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
                        Write-ESLog "Failed to terminate session ID $sessionId : $($_.Exception.Message)"
                    }
                } else {
                    Write-ESLog "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-ESLog "Error processing sessions: $($_.Exception.Message)"
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
            Write-Host "Detected InProc control at $path.PSPath with value $value"
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
            Write-Host "Removed InProc control registry entry at $path"
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $($_.Exception.Message)"
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
            Write-Error "LSA registry path not found."
            return
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -ErrorAction Stop
        Write-Host "LSASS configured to run as Protected Process Light (PPL). Reboot required."
    } catch {
        Write-Error "Failed to enable LSASS PPL: $($_.Exception.Message)"
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
            Write-Host "Cleared cached credentials from Credential Manager using cmdkey."
        } else {
            Write-Warning "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials."
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Warning "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required."
            } catch {
                Write-Error "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager."
                return
            }
        }
    } catch {
        Write-Error "Failed to clear cached credentials: $($_.Exception.Message)"
    }
}

# Disable Credential Caching
function Disable-CredentialCaching {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "CachedLogonsCount"
        $regValue = 0
        if (-not (Test-Path $regPath)) {
            Write-Error "Winlogon registry path not found."
            return
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -ErrorAction Stop
        Write-Host "Disabled cached logon credentials. Set CachedLogonsCount to 0."
    } catch {
        Write-Error "Failed to disable credential caching: $($_.Exception.Message)"
    }
}

# Enable Auditing for Credential Access
function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        } else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    } catch {
        Write-Error "Failed to enable auditing: $($_.Exception.Message)"
    }
}

# Apply Firewall Rules
function Apply-FirewallRules {
    $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
    $script:registryContent | Out-File -FilePath $tempRegFile -Encoding Unicode
    try {
        reg import $tempRegFile 2>&1 | Out-Null
        Write-GSecurityLog "Firewall rules applied from registry content at $(Get-Date)." "Information"
    } catch {
        Write-GSecurityLog "Error applying firewall rules: $($_.Exception.Message)" "Error"
    }
    Remove-Item $tempRegFile -Force -ErrorAction SilentlyContinue
}

# Monitor Firewall Rule Changes
function Start-FirewallMonitor {
    Write-GSecurityLog "Starting firewall rule monitoring..." "Information"
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4947"
    Register-WmiEvent -Query $query -SourceIdentifier "FirewallRuleChange" -Action {
        Write-GSecurityLog "Detected firewall rule change at $(Get-Date)" "Warning"
        Apply-FirewallRules
    }
    Write-GSecurityLog "Firewall monitoring started. Running in background..." "Information"
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
                        Write-GSecurityLog "Terminating unsigned process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    }
                }
            } catch {
                Write-GSecurityLog "Error processing PID $pid: $($_.Exception.Message)" "Warning"
            }
        }
    } catch {
        Write-GSecurityLog "Error during rootkit detection: $($_.Exception.Message)" "Error"
    }
}

# Register System Logon Script
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )
    $targetPath = "%windir%\Setup\Scripts\unattend-04.ps1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-GSecurityLog "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-GSecurityLog "Failed to register task: $($_.Exception.Message)" "Error"
        exit 1
    }
}

# Clean Up Jobs
function Cleanup-Jobs {
    $completedJobs = Get-Job | Where-Object { $_.State -ne 'Running' }
    if ($completedJobs) {
        $completedJobs | Remove-Job -Force
        Write-AntivirusLog "Cleaned up $($completedJobs.Count) completed jobs."
    }
}

# Initial log with diagnostics
Write-AntivirusLog "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
Write-GSecurityLog "GSecurity component initialized." "Information"
Write-ESLog "ES component initialized."

# Initial Scans and Protections
if ($isAdmin) {
    Register-SystemLogonScript
    Enable-LsassPPL
    Clear-CachedCredentials
    Disable-CredentialCaching
    Enable-CredentialAuditing
    Remove-UnsignedDLLs
    Apply-FirewallRules
} else {
    Write-Error "Administrative privileges required for LSASS PPL, credential management, DLL scanning, and firewall rule application."
}

# Start Background Jobs
$job = Start-Job -ScriptBlock {
    . $using:PSCommandPath
    Apply-FirewallRules
    Start-FirewallMonitor
} -Name "FirewallTasks"

$job = Start-Job -ScriptBlock {
    . $using:PSCommandPath
    while (-not (Test-Path $using:stopFile)) {
        Kill-Listeners
        Terminate-Rootkits
        Start-ProcessKiller
        Start-XSSWatcher
        Terminate-NonConsoleSessions
        $detected, $path, $value = Detect-InProcControls
        if ($detected) {
            Remove-InProcControls -path $path -value $value
        }
        Start-Sleep -Seconds 60
    }
} -Name "ConsolidatedSecurityTasks"

Start-FileSystemWatcher

# Register Exit Handler
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Stop-FileSystemWatcher
    Get-Job | Remove-Job -Force
    Write-AntivirusLog "Script terminated gracefully."
}

# Main Loop
Write-Host "GShield running. Press [Ctrl] + [C] to stop or create $stopFile to exit gracefully."
Write-Host "Check logs at $logFileAntivirus, $logFileGSecurity, and $logFileES"
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
try {
    while (-not (Test-Path $stopFile)) {
        $cpuUsage = (Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -eq "pwsh" } | Measure-Object PercentProcessorTime -Sum).Sum
        if ($cpuUsage -gt 20) {
            Write-AntivirusLog "High CPU usage detected ($cpuUsage%). Pausing for 120 seconds."
            Start-Sleep -Seconds 120
        }
        Cleanup-Jobs
        Start-Sleep -Seconds 60
    }
    Stop-FileSystemWatcher
    Get-Job | Remove-Job -Force
    Write-AntivirusLog "Script stopped gracefully via stop file."
} catch {
    Write-AntivirusLog "Main loop crashed: $($_.Exception.Message)"
    Write-GSecurityLog "Main loop crashed: $($_.Exception.Message)" "Error"
    Write-ESLog "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check logs for details."
}
