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

# Requires administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Run PowerShell as Administrator."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
        Write-AntivirusLog "Set execution policy to Bypass for current user."
    } catch {
        Write-AntivirusLog "Error setting execution policy: $($_.Exception.Message)"
    }
}

# Define paths and parameters
$taskName = "GShieldStartup"
$taskDescription = "Runs the GShield script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\GShield.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

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

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Output "Error: Could not determine script path."
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

# Initial log with diagnostics
Write-AntivirusLog "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Register the scheduled task
Register-SystemLogonScript

function Write-RootkitLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GShield")) {
            New-EventLog -LogName Application -Source "GShield"
        }
        Write-EventLog -LogName Application -Source "GShield" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

# Define log file path
$logFile = "$env:TEMP\SessionTerminator.log"

# Function to log messages
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

# Function to list and terminate non-console sessions
function Terminate-NonConsoleSessions {
    try {
        # Run qwinsta to list sessions
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" } # Exclude active session marker
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-Log "Listing all sessions:"
        $sessions | ForEach-Object { Write-Log $_ }

        # Parse each session
        foreach ($session in $sessionList) {
            # Skip empty lines or headers
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                # Skip console session
                if ($sessionName -notin @("console")) {
                    Write-Log "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-Log "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-Log "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-Log "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-Log "Error processing sessions: $_"
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
if ($filePath -like "C:\Windows\Assembly\*" -or $filePath -like "C:\Windows\System32\drivers\*") {
    Write-AntivirusLog "Skipping ownership/permissions change for $filePath (GAC excluded)"
    return $false
}
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
    try {
        Write-AntivirusLog "Starting unsigned DLL scan."
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
        foreach ($drive in $drives) {
            $root = $drive.DeviceID + "\"
            Write-AntivirusLog "Scanning drive: $root"
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "C:\Windows\Assembly\*" -and $_.FullName -notlike "C:\Windows\System32\drivers\*" }
            foreach ($dll in $dllFiles) {
                $fileHash = Calculate-FileHash -filePath $dll.FullName
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        Write-AntivirusLog "Skipping already scanned file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                try {
                                    Kill-Process-And-ParentKill -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                } catch {
                                    Write-AntivirusLog "Error processing Stop-ProcessUsingDLL for $($dll.FullName): $($_.Exception.Message)"
                                }
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq 'Valid'
                        $scannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8
                        Write-AntivirusLog "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                        if (-not $isValid) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                try {
                                    Kill-Process-And-Parent -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                } catch {
                                    Write-AntivirusLog "Error processing Stop-ProcessUsingDLL for $($dll.FullName): $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Write-AntivirusLog "Error in Remove-UnsignedDLLs: $($_.Exception.Message)"
    }
}

# Function to enable LSASS as Protected Process Light (PPL)
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
    }
    catch {
        Write-Error "Failed to enable LSASS PPL: $_"
    }
}

# Function to clear cached credentials
function Clear-CachedCredentials {
    try {
        # Check if cmdkey is available
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            # Clear cached credentials using cmdkey
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Host "Cleared cached credentials from Credential Manager using cmdkey."
        }
        else {
            Write-Warning "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials."
            # Attempt to use COM object to access Credential Manager
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Warning "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required."
                # Note: WScript.Network does not directly support credential enumeration/deletion.
                # For full functionality, consider using a third-party module or manual cleanup.
            }
            catch {
                Write-Error "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager."
                return
            }
        }
    }
    catch {
        Write-Error "Failed to clear cached credentials: $_"
    }
}

# Function to disable credential caching
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
    }
    catch {
        Write-Error "Failed to disable credential caching: $_"
    }
}

# Function to enable auditing for credential access
function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        }
        else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    }
    catch {
        Write-Error "Failed to enable auditing: $_"
    }
}

# Import required module
Import-Module -Name Microsoft.PowerShell.Management

# Define base registry path for WOW6432Node CLSIDs
$basePath = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
$hkcrBasePath = "HKCR:\WOW6432Node\CLSID"

# Function to detect InProcServer32 and InprocHandler32 custom controls
function Detect-InProcControls {
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

# Function to remove InProc controls
function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            # Remove registry entry
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path"
            # Remove associated file if it exists
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $_"
        }
    }
}

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
        Write-Log "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-Log "Failed to toggle network adapters: $_" "Error"
    }
}

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Log "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Log "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

function Start-ProcessKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-Log "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
}

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
                    Write-Log "XSS detected, blocked $($hostEntry.HostName) and disabled network." "Error"
                }
            } catch {}
        }
        Start-Sleep -Seconds 3
    }
}

function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit") # Safe system processes
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore processes that no longer exist or access-denied
        }
    }
}

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
        Write-Log "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-Log "Failed to toggle network adapters: $_" "Error"
    }
}

function Start-ProcessKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-Log "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
}

    function Start-CrudeKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

# Initial scan
Remove-UnsignedDLLs
Enable-LsassPPL
Clear-CachedCredentials
Disable-CredentialCaching
Enable-CredentialAuditing
Write-AntivirusLog "Initial scan completed. Monitoring started."
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
Write-Host "Check Event Viewer (Security logs) for credential access auditing."

Start-Job -Name "GShield-Monitor" -ScriptBlock {

# File System Watcher
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
foreach ($drive in $drives) {
    $monitorPath = $drive.DeviceID + "\"
    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $monitorPath
    $fileWatcher.Filter = "*.dll"
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    $action = {
        param($sender, $e)
        try {
            if ($e.ChangeType -in "Created", "Changed") {
                Write-AntivirusLog "Detected file change: $($e.FullPath)"
                $fileHash = Calculate-FileHash -filePath $e.FullPath
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        Write-AntivirusLog "Skipping already scanned file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                Stop-ProcessUsingDLL -filePath $e.FullPath
                                Quarantine-File -filePath $e.FullPath
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq 'Valid'
                        $scannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                        Write-AntivirusLog "Added new file to database: $($e.FullPath) (Valid: $isValid)"
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
            Write-AntivirusLog "Error in FileSystemWatcher event: $($_.Exception.Message)"
        }
    }

    Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action
    Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action
}
 
   # --- Protection loop ---
    while ($true) {
        Start-CrudeKiller
	Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Terminate-NonConsoleSessions
	Terminate-Rootkits
	Start-Sleep -Seconds 10
    }
}