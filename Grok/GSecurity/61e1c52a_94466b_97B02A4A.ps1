# GSecurity.ps1
# Author: Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "GSecurity"
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
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at system startup under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

Register-SystemLogonScript

function Write-Log {
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
        Add-Content -Path "$env:TEMP\GSecurity.log" -Value $logEntry
    }

    if ($Host.Name -match "ConsoleHost") {
        switch ($EntryType) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor White }
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

function Detect-RootkitByNetstat {
    # Run netstat -ano and store the output
    $netstatOutput = netstat -ano | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }

    if (-not $netstatOutput) {
        Write-Warning "No network connections found via netstat -ano. Possible rootkit hiding activity."

        # Optionally: Log the suspicious event
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = "$env:TEMP\rootkit_suspected_$timestamp.log"
        "Netstat -ano returned no results. Possible rootkit activity." | Out-File -FilePath $logFile

        # Get all running processes (you could refine this)
        $processes = Get-Process | Where-Object { $_.Id -ne $PID }

        foreach ($proc in $processes) {
            try {
                # Comment this line if you want to observe first
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Output "Stopped process: $($proc.ProcessName) (PID: $($proc.Id))"
            } catch {
                Write-Warning "Could not stop process: $($proc.ProcessName) (PID: $($proc.Id))"
            }
        }
    } else {
        Write-Host "Netstat looks normal. Active connections detected."
    }
}

function Start-StealthKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}



function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

# Function to check and remove network bridges
function Remove-NetworkBridge {
    try {
        # Get all network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -or $_.Status -eq "Disconnected" }
        
        # Check for network bridge
        $bridge = Get-NetAdapter | Where-Object { $_.Name -like "*Network Bridge*" }
        
        if ($bridge) {
            Write-Host "Network Bridge detected. Attempting to remove..."
            # Remove the network bridge
            Remove-NetAdapter -Name $bridge.Name -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Network Bridge removed."
        }
        
        # Ensure no adapters are part of a bridge
        foreach ($adapter in $adapters) {
            $bindings = Get-NetAdapterBinding -Name $adapter.Name -ErrorAction SilentlyContinue
            foreach ($binding in $bindings) {
                if ($binding.DisplayName -like "*Bridge*") {
                    Write-Host "Bridge binding found on adapter: $($adapter.Name). Disabling..."
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $binding.ComponentID -ErrorAction SilentlyContinue
                    Write-Host "Bridge binding disabled on adapter: $($adapter.Name)"
                }
            }
        }
    }
    catch {
        Write-Host "Error occurred: $_"
    }
}

# Whitelist of critical system processes to protect
$protectedProcesses = @(
    "System", "smss", "csrss", "wininit", "services", "lsass", 
    "svchost", "dwm", "explorer", "taskhostw", "winlogon", 
    "conhost", "cmd", "powershell"
)

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*"
)

# Detect and terminate web servers
function Detect-And-Terminate-WebServers {
    $ports = @(80, 443, 8080)  # Common web server ports
    $connections = Get-NetTCPConnection | Where-Object { $ports -contains $_.LocalPort }
    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Web server detected: $($process.ProcessName) (PID: $($process.Id)) on Port $($connection.LocalPort)"
            Stop-Process -Id $process.Id -Force
            Write-Log "Web server process terminated: $($process.ProcessName)"
        }
    }
}

# Terminate suspicious web server services
function Detect-And-Terminate-WebServerServices {
    $webServices = @("w3svc", "apache2", "nginx")  # Known web server services
    foreach ($serviceName in $webServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Log "Web server service detected: $($serviceName)"
            Stop-Service -Name $serviceName -Force
            Write-Log "Web server service stopped: $($serviceName)"
        }
    }
}

# Detect and terminate screen overlays
function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object { 
        $_.MainWindowTitle -ne "" -and (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Log "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Log "Overlay process terminated: $($process.ProcessName)"
    }
}

# Detect and terminate keyloggers
function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

# Detect and terminate untrusted drivers
function Detect-And-Terminate-SuspiciousDrivers {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {
        ($_.DisplayName -notlike $trustedDriverVendors) -and $_.Started -eq $true
    }
    foreach ($driver in $drivers) {
        Write-Log "Suspicious driver detected: $($driver.DisplayName)"
        Stop-Service -Name $driver.Name -Force
        Write-Log "Suspicious driver stopped: $($driver.DisplayName)"
    }
}

# Constants
$logonGroup = "Console Logon"
$validGroups = @($logonGroup)
$consoleUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName
$quarantinePath = "C:\Quarantine"

# Create quarantine directory if it doesn't exist
if (-not (Test-Path $quarantinePath)) {
    New-Item -Path $quarantinePath -ItemType Directory | Out-Null
}

# Log function to log messages to a file in the Documents folder
function Write-Log {
    param (
        [string]$message
    )
    $logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\GShield_Log.txt")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logMessage = "$timestamp - $message"
    try {
        Add-Content -Path $logPath -Value $logMessage
    } catch {
        Write-Output "Error writing to log: $_"
    }
}

function Get-ProcessDetailsAndTerminate {
    param (
        [int]$ProcessId
    )

    try {
        # Get process details using the ProcessId
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $processName = $process.Name
        $processOwner = (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId").GetOwner().User

        # Log process details before termination
        Write-Log "Detected process to terminate: $processName (PID: $ProcessId), Owner: $processOwner"

        # Optionally, perform additional checks on the process (e.g., if it's not a system process)
        if ($processName -notin @("System", "svchost")) {
            Write-Log "Terminating process: $processName (PID: $ProcessId)"
            Stop-Process -Id $ProcessId -Force

            # Quarantine the process executable
            $processPath = $process.Path
            if ($processPath -and (Test-Path $processPath)) {
                $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($processPath))")
                try {
                    Move-Item -Path $processPath -Destination $dest -Force
                    Write-Log "Quarantined: $processPath to $dest"
                } catch {
                    Write-Log "Error quarantining $processPath: $_"
                }
            } else {
                Write-Log "No valid path found for quarantining process: $processName (PID: $ProcessId)"
            }
        } else {
            Write-Log "System process detected, skipping termination: $processName (PID: $ProcessId)"
        }
    } catch {
        Write-Log "Error retrieving details for process ID $ProcessId: $(${_}.Exception.Message)"
    }
}

# Function to check if the process is owned by the Console Logon group (SID: S-1-2-1)
function Is-ProcessFromConsoleLogonGroup {
    $consoleLogonSID = "S-1-2-1"  # Console Logon SID

    # Get all running processes
    $processes = Get-WmiObject Win32_Process

    foreach ($process in $processes) {
        try {
            # Get the SID of the process owner
            $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = '$($process.ProcessId)'").GetOwner()
            $processOwnerSID = (New-Object System.Security.Principal.NTAccount($owner.User)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            # Compare the SID of the process owner with the Console Logon SID
            if ($processOwnerSID -ne $consoleLogonSID) {
                # If the process is not from Console Logon group, terminate it
                Write-Log "Blocking non-console logon process: $($process.Name)"
                Stop-Process -Id $process.ProcessId -Force

                # Quarantine the process executable
                $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    $processPath = $proc.Path
                    if ($processPath -and (Test-Path $processPath)) {
                        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                        $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($processPath))")
                        try {
                            Move-Item -Path $processPath -Destination $dest -Force
                            Write-Log "Quarantined: $processPath to $dest"
                        } catch {
                            Write-Log "Error quarantining $processPath: $_"
                        }
                    } else {
                        Write-Log "No valid path found for quarantining process: $($process.Name) (PID: $($process.ProcessId))"
                    }
                }
            }
        } catch {
            Write-Log "Error retrieving owner for process $($process.ProcessId)."
        }
    }
}

# Function to check and block network connections that aren't from Console Logon group
function Block-NonConsoleLogonGroupNetwork {
    $consoleLogonSID = "S-1-2-1"  # Console Logon SID

    $networkProcesses = Get-NetTCPConnection
    foreach ($connection in $networkProcesses) {
        try {
            # Get the process owner SID
            $process = Get-Process -Id $connection.OwningProcess
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId = '$($process.Id)'").GetOwner()
            $processOwnerSID = (New-Object System.Security.Principal.NTAccount($owner.User)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            if ($processOwnerSID -ne $consoleLogonSID) {
                # Block network connection if process is not from Console Logon group
                Write-Log "Blocking network connection from non-console logon process: $($process.Name) on port $($connection.LocalPort)"
                Stop-Process -Id $process.Id -Force

                # Quarantine the process executable
                $processPath = $process.Path
                if ($processPath -and (Test-Path $processPath)) {
                    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                    $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($processPath))")
                    try {
                        Move-Item -Path $processPath -Destination $dest -Force
                        Write-Log "Quarantined: $processPath to $dest"
                    } catch {
                        Write-Log "Error quarantining $processPath: $_"
                    }
                } else {
                    Write-Log "No valid path found for quarantining process: $($process.Name) (PID: $($process.Id))"
                }
            }
        } catch {
            Write-Log "Error retrieving network connection owner for process $($connection.OwningProcess)."
        }
    }
}

# Ensure WMI and SharedAccess services are running
function Ensure-ServicesRunning {
    # Ensure WMI service is running
    $wmiService = Get-Service -Name "winmgmt" -ErrorAction SilentlyContinue
    if ($wmiService -and $wmiService.Status -ne "Running") {
        Start-Service -Name "winmgmt" -ErrorAction SilentlyContinue
        Write-Log "WMI service started."
    } elseif (-not $wmiService) {
        Write-Log "WMI service not found. Check system integrity."
    } else {
        Write-Log "WMI service is running."
    }

    # Ensure SharedAccess (Windows Firewall) service is running
    $sharedAccessService = Get-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
    if ($sharedAccessService -and $sharedAccessService.Status -ne "Running") {
        Start-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
        Write-Log "SharedAccess (Windows Firewall) service started."
    } elseif (-not $sharedAccessService) {
        Write-Log "SharedAccess service not found. Check system integrity."
    } else {
        Write-Log "SharedAccess service is running."
    }
}

# Remove suspicious dll's
function Monitor-LoadedDLLs {
    Write-Log "Monitoring all loaded DLLs system-wide."

    $processes = Get-Process | Where-Object { $_.ProcessName -ne "Idle" }

    foreach ($process in $processes) {
        try {
            $modules = $process.Modules
            foreach ($module in $modules) {
                try {
                    $cert = Get-AuthenticodeSignature $module.FileName
                    if ($cert.Status -ne "Valid") {
                        Write-Log "Quarantining suspicious DLL: $($module.FileName)"
                        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                        $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($module.FileName))")
                        Move-Item -Path $module.FileName -Destination $dest -Force -ErrorAction Stop
                    }
                } catch {
                    Write-Log "Error checking DLL $($module.FileName): $_"
                }
            }
        } catch {
            Write-Log "Skipping process $($process.ProcessName): $_"
        }
    }
}

# Function to monitor for suspicious screen overlays and trace their sources
function Monitor-Overlays {
    # Get a list of processes with visible windows (MainWindowHandle != 0), excluding whitelisted processes
    $windows = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 }

    foreach ($window in $windows) {
        Write-Log "Potential screen overlay or UI hijacker detected: $($window.ProcessName)"
        # Call the new function to get process details and terminate the process and parent
        Get-ProcessDetailsAndTerminate -ProcessId $window.Id
    }
}

# Function to detect potential keyloggers by monitoring keyboard hooks
function Detect-Keyloggers {
    Write-Log "Checking for keylogger behavior."
    $suspiciousProcesses = Get-WmiObject Win32_Process | Where-Object {
        ($_.CommandLine -match "SetWindowsHookEx" -or $_.CommandLine -match "GetAsyncKeyState")
    }
    foreach ($proc in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($proc.Name) - $($proc.CommandLine)"
    }
}

# Enhanced keylogger detection
function Monitor-Keyloggers {
    # Get processes that might be keyloggers based on behavior
    $suspiciousProcesses = Get-Process | Where-Object {
        ($_.Modules.ModuleName -match "hook|key|log|capture|sniff") -or
        ($_.Path -match "keylogger|hook|log|capture|sniff") -or
        (Get-Process -Id $_.Id -Module | Where-Object { $_.ModuleName -match "keylogger|hook|log|capture|sniff" })
    }

    foreach ($process in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($process.ProcessName)"
        Get-ProcessDetailsAndTerminate -ProcessId $process.Id
    }
}

# Function to prevent remote thread execution
function Prevent-RemoteThreadExecution {
    $remoteThreads = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "remote" }
    foreach ($thread in $remoteThreads) {
        Write-Log "Preventing remote thread execution for Process: $($thread.ProcessId)"
        Stop-Process -Id $thread.ProcessId -Force

        # Quarantine the process executable
        $proc = Get-Process -Id $thread.ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            $processPath = $proc.Path
            if ($processPath -and (Test-Path $processPath)) {
                $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($processPath))")
                try {
                    Move-Item -Path $processPath -Destination $dest -Force
                    Write-Log "Quarantined: $processPath to $dest"
                } catch {
                    Write-Log "Error quarantining $processPath: $_"
                }
            } else {
                Write-Log "No valid path found for quarantining process: $($thread.Name) (PID: $($thread.ProcessId))"
            }
        }
    }
}

# Function to detect and block remote logins
function Block-RemoteLogins {
    $remoteSessions = Get-CimInstance -Class Win32_ComputerSystem | Select-Object UserName
    if ($remoteSessions.UserName) {
        Write-Log "Remote login detected, logging off the user."
        Shutdown.exe /l
    }
}

# Function to detect and terminate rootkit-like behaviors
function Monitor-Rootkit {
    # Look for hidden processes, modules, or files
    $hiddenProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $null }

    foreach ($process in $hiddenProcesses) {
        Write-Log "Suspicious hidden process detected: $($process.ProcessName). Terminating process."
        Stop-Process -Name $process.ProcessName -Force

        # Quarantine the process executable (if path can be determined somehow, but since ExecutablePath is null, skip or find alternative)
        Write-Log "Skipping quarantine for hidden process $($process.ProcessName) due to null path."
    }

    $hiddenFiles = Get-ChildItem -Path "C:\Windows\System32" -Recurse | Where-Object { $_.Attributes -match "Hidden" }
    foreach ($file in $hiddenFiles) {
        Write-Log "Hidden file detected: $($file.FullName). Quarantining file."
        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
        $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($file.FullName))")
        Move-Item -Path $file.FullName -Destination $dest -Force
    }
}

# Function to scan memory for suspicious activity and terminate related processes
function Scan-MemoryForMalware {
    $suspiciousPatterns = @("malware", "inject", "hook")
    $memoryDump = Get-CimInstance -Query "SELECT * FROM Win32_Process"

    foreach ($process in $memoryDump) {
        $processName = $process.Name
        foreach ($pattern in $suspiciousPatterns) {
            if ($processName -match $pattern) {
                Write-Log "Suspicious memory pattern detected in process: $processName. Terminating process."
                Stop-Process -Name $processName -Force

                # Quarantine the process executable
                $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($proc) {
                    $processPath = $proc.Path
                    if ($processPath -and (Test-Path $processPath)) {
                        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
                        $dest = [System.IO.Path]::Combine($quarantinePath, "$timestamp`_$([System.IO.Path]::GetFileName($processPath))")
                        try {
                            Move-Item -Path $processPath -Destination $dest -Force
                            Write-Log "Quarantined: $processPath to $dest"
                        } catch {
                            Write-Log "Error quarantining $processPath: $_"
                        }
                    } else {
                        Write-Log "No valid path found for quarantining process: $processName"
                    }
                }
            }
        }
    }
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script requires administrative privileges. Please run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# Function to take ownership of a registry key
function Take-RegistryOwnership {
    param (
        [string]$RegPath
    )
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $acl = $regKey.GetAccessControl()
        $admin = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($admin)
        $regKey.SetAccessControl($acl)

        # Grant Full Control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        $regKey.SetAccessControl($acl)
        Write-Host "Ownership and Full Control granted for $RegPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to take ownership of $RegPath. Error: $_" -ForegroundColor Red
    } finally {
        if ($regKey) { $regKey.Close() }
    }
}

# Function to enable Echo Cancellation and Noise Suppression for all audio devices
function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    # Get all audio devices under the Render key
    $audioDevices = Get-ChildItem -Path $renderDevicesKey

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        # Check if the FxProperties key exists, if not, create it
        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        # Take ownership and set permissions for the FxProperties key
        Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', '')

        # Define the keys and values for AEC and Noise Suppression
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1  # 1 = Enable, 0 = Disable

        # Set Acoustic Echo Cancellation (AEC)
        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue -ErrorAction Stop
                Write-Host "Acoustic Echo Cancellation set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Acoustic Echo Cancellation for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Acoustic Echo Cancellation already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }

        # Set Noise Suppression
        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue -ErrorAction Stop
                Write-Host "Noise Suppression set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Noise Suppression for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Noise Suppression already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }
    }
}

# Run the function
Enable-AECAndNoiseSuppression

#requires -RunAsAdministrator

# Fully automated script to enumerate and clean up suspicious BCD entries
# Designed for batch file compatibility, with no user input
# Logs actions and creates a BCD backup before changes
# Run in an elevated PowerShell prompt or from a batch file

# Set up logging
$LogFile = "C:\BCD_Cleanup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

# Initialize exit code (0 = success, 1 = error)
$ExitCode = 0

# Create backup of BCD store
$BackupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd " #Added a space here because otherwise it would cause an error in the log file
Write-Log "Creating BCD backup at $BackupPath"
try {
    & (Join-Path $env:windir "system32\bcdedit.exe") /export $BackupPath | Out-Null
    Write-Log "BCD backup created successfully."
} catch {
    Write-Log "Error creating BCD backup: $_"
    $ExitCode = 1
    exit $ExitCode
}

# Get all BCD entries
Write-Log "Enumerating all BCD entries..."
$BcdOutput = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if (-not $BcdOutput) {
    Write-Log "Error: Failed to enumerate BCD entries."
    $ExitCode = 1
    exit $ExitCode
}

$BcdEntries = @()
$currentEntry = $null
foreach ($line in $BcdOutput) {
    if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
        if ($currentEntry) {
            $BcdEntries += $currentEntry
        }
        $currentEntry = [PSCustomObject]@{
            Identifier = $Matches[1]
            Properties = @{}
        }
    } elseif ($line -match "^(\w+)\s+(.+)$") {
        if ($currentEntry) {
            $currentEntry.Properties[$Matches[1]] = $Matches[2]
        }
    }
}
if ($currentEntry) {
    $BcdEntries += $currentEntry
}

# Define critical identifiers to protect
$CriticalIds = @("{bootmgr}", "{current}", "{default}")

# Flag suspicious entries
Write-Log "Analyzing BCD entries for suspicious content..."
$SuspiciousEntries = @()
foreach ($entry in $BcdEntries) {
    $isSuspicious = $false
    $reason = ""

    # Skip critical entries
    if ($entry.Identifier -in $CriticalIds) {
        continue
    }

    # Check for suspicious characteristics
    if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
        $isSuspicious = $true
        $reason += "Non-Windows description: $($entry.Properties.description); "
    }
    if ($entry.Properties.device -match "vhd=") {
        $isSuspicious = $true
        $reason += "Uses VHD device: $($entry.Properties.device); "
    }
    if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
        $isSuspicious = $true
        $reason += "Non-standard boot path: $($entry.Properties.path); "
    }

    if ($isSuspicious) {
        $SuspiciousEntries += [PSCustomObject]@{
            Identifier = $entry.Identifier
            Description = $entry.Properties.description
            Device = $entry.Properties.device
            Path = $entry.Properties.path
            Reason = $reason
        }
    }
}

# Process suspicious entries
if ($SuspiciousEntries.Count -eq 0) {
    Write-Log "No suspicious BCD entries found."
} else {
    Write-Log "Found $($SuspiciousEntries.Count) suspicious BCD entries:"
    foreach ($entry in $SuspiciousEntries) {
        Write-Log "Identifier: $($entry.Identifier)"
        Write-Log "Description: $($entry.Description)"
        Write-Log "Device: $($entry.Device)"
        Write-Log "Path: $($entry.Path)"
        Write-Log "Reason: $($entry.Reason)"
        Write-Log "------------------------"
        
        # Automatically delete the suspicious entry
        Write-Log "Deleting entry: $($entry.Identifier)"
        try {
            & (Join-Path $env:windir "system32\bcdedit.exe") /delete $entry.Identifier /f | Out-Null
            Write-Log "Successfully deleted entry: $($entry.Identifier)"
        } catch {
            Write-Log "Error deleting entry $($entry.Identifier): $_"
            $ExitCode = 1
        }
    }
}

# Verify cleanup
Write-Log "Verifying BCD store after cleanup..."
$BcdOutputAfter = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if ($BcdOutputAfter) {
    $BcdOutputAfter | Out-File -FilePath $LogFile -Append
    Write-Log "Cleanup complete. Review the log at $LogFile for details."
    Write-Log "BCD backup is available at $BackupPath if restoration is needed."
} else {
    Write-Log "Error: Failed to verify BCD store after cleanup."
    $ExitCode = 1
}

# Desired settings for WebRTC, remote desktop, and plugins
$desiredSettings = @{
    "media_stream" = 2
    "webrtc"       = 2
    "remote" = @{
        "enabled" = $false
        "support" = $false
    }
}

# Function to check and apply WebRTC, remote settings, and plugins
function Check-And-Apply-Settings {
    param (
        [string]$browserName,
        [string]$prefsPath
    )

    if (Test-Path $prefsPath) {
        $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
        $settingsChanged = $false
        
        # Check and apply WebRTC and remote desktop settings
        if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
            foreach ($key in $desiredSettings.Keys) {
                if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                    $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                    $settingsChanged = $true
                }
            }
        }

        # Check and apply remote desktop settings
        if ($prefsContent.remote) {
            foreach ($key in $desiredSettings["remote"].Keys) {
                if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                    $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                    $settingsChanged = $true
                }
            }
        }

        # Save the settings if changes were made
        if ($settingsChanged) {
            $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
            Write-Output "${browserName}: Settings updated for WebRTC and remote desktop."
        } else {
            Write-Output "${browserName}: No changes detected for WebRTC and remote desktop settings."
        }

        # Disable plugins (assuming this is done through the preferences as well)
        if ($prefsContent.plugins) {
            foreach ($plugin in $prefsContent.plugins) {
                $plugin.enabled = $false
            }
            Write-Output "${browserName}: Plugins have been disabled."
        } else {
            Write-Output "${browserName}: No plugins found to disable."
        }
    } else {
        Write-Output "${browserName}: Preferences file not found at $prefsPath."
    }
}

# Function to configure Firefox settings
function Configure-Firefox {
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory

        foreach ($profile in $firefoxProfiles) {
            Write-Output "Processing Firefox profile: $($profile.FullName)"
            $prefsJsPath = "$($profile.FullName)\prefs.js"
            $pluginRegPath = "$($profile.FullName)\pluginreg.dat"

            # Backup prefs.js and pluginreg.dat
            if (Test-Path $prefsJsPath) {
                Copy-Item -Path $prefsJsPath -Destination "$prefsJsPath.bak" -Force
                Write-Output "Backed up prefs.js for profile: $($profile.FullName)"
            }
            if (Test-Path $pluginRegPath) {
                Copy-Item -Path $pluginRegPath -Destination "$pluginRegPath.bak" -Force
                Write-Output "Backed up pluginreg.dat for profile: $($profile.FullName)"
            }

            # Modify prefs.js to disable WebRTC
            if (Test-Path $prefsJsPath) {
                $prefsJsContent = Get-Content -Path $prefsJsPath

                # Disable WebRTC
                if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                    Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                    Write-Output "Firefox profile ${profile.FullName}: WebRTC has been disabled."
                } else {
                    Write-Output "Firefox profile ${profile.FullName}: WebRTC already disabled."
                }
            }

            # Clear pluginreg.dat to disable plugins
            if (Test-Path $pluginRegPath) {
                Clear-Content -Path $pluginRegPath
                Write-Output "Firefox profile ${profile.FullName}: Plugins have been disabled."
            } else {
                Write-Output "Firefox profile ${profile.FullName}: No plugin registry found."
            }
        }
    } else {
        Write-Output "Mozilla Firefox is not installed or profile path not found."
    }
}

# Detect installed browsers and manage settings
$browsers = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
    "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
    "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable"
}

foreach ($browser in $browsers.GetEnumerator()) {
    if (Test-Path $browser.Value) {
        # Check and apply WebRTC and remote desktop settings
        Check-And-Apply-Settings -browserName $browser.Key -prefsPath $browser.Value
    } else {
        Write-Output "${browser.Key} is not installed or profile path not found."
    }
}

# Handle Firefox separately
if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
    Configure-Firefox
} else {
    Write-Output "Mozilla Firefox is not installed."
}

Write-Output "Script execution complete."

# Function to stop the Chrome Remote Desktop Host service
function Stop-CRDService {
    $serviceName = "chrome-remote-desktop-host"
    
    # Check if the service exists and stop it
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Stopping Chrome Remote Desktop Host service..."
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Host "Chrome Remote Desktop Host service stopped and disabled."
    } else {
        Write-Host "Chrome Remote Desktop Host service is not found."
    }
}

# Function to block CRD-related processes in Chrome-based browsers
function Block-CRDBrowsers {
    $browsers = @("chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "operagx.exe")
    
    foreach ($browser in $browsers) {
        $processes = Get-Process -Name $browser -ErrorAction SilentlyContinue
        if ($processes) {
            Write-Host "Terminating process: $browser"
            Stop-Process -Name $browser -Force
        }
    }
}

# Function to block CRD network ports (TCP 443)
function Block-CRDPorts {
    $ruleName = "Block CRD Ports"
    
    # Check if the firewall rule exists and remove it
    $existingRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleName }
    if ($existingRule) {
        Write-Host "Firewall rule already exists. Removing the rule..."
        Remove-NetFirewallRule -DisplayName $ruleName
    }

    # Create a new rule to block incoming TCP connections on port 443 (used by CRD)
    Write-Host "Creating firewall rule to block incoming TCP port 443..."
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-Host "Firewall rule created to block Chrome Remote Desktop connections."
}

# Main function to block CRD
function Disable-CRD {
    # Stop and disable CRD service
    Stop-CRDService

    # Block CRD-related processes in Chrome-based browsers
    Block-CRDBrowsers

    # Block incoming connections to the CRD ports
    Block-CRDPorts
}

# Execute the script
Disable-CRD

# Protect-LocalCredentials.ps1
# Enhances protection for local and non-domain credentials by securing LSASS and managing credential caching

# Requires administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Run PowerShell as Administrator."
    exit
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

# Main execution
Write-Host "Starting credential protection script..."

# Enable LSASS PPL
Enable-LsassPPL

# Clear cached credentials
Clear-CachedCredentials

# Disable credential caching
Disable-CredentialCaching

# Enable auditing
Enable-CredentialAuditing

Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
Write-Host "Check Event Viewer (Security logs) for credential access auditing."

param (
    [int]$CheckIntervalSeconds = 60  # Interval to check for custom controls in seconds
)

# Import required module
Import-Module -Name Microsoft.PowerShell.Management

function Register-SystemLogonScript {
    param ([string]$TaskName = "RunCCRAtLogon")

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Log "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Log "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript
Write-Log "Script setup complete. Starting WMI monitoring..."

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

# Main loop to run resident in memory
Start-Job -ScriptBlock {
while ($true) {
    $detected, $path, $value = Detect-InProcControls
    if ($detected) {
        Remove-InProcControls -path $path -value $value
    } else {
        Write-Host "No InProc controls detected. Checking again in $CheckIntervalSeconds seconds..."
    }
    Start-Sleep -Seconds $CheckIntervalSeconds
}
}

# ES.ps1 by Gorstak
# PowerShell script to list and terminate non-console sessions every 5 seconds as a background job
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunESAtLogon"
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

# Get current user's temp folder
$CurrentUser = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName
if ($CurrentUser) {
    $UserName = $CurrentUser.Split('\')[-1]
    $TempPath = [System.IO.Path]::GetTempPath()
} else {
    $TempPath = "C:\Windows\Temp"  # Fallback if no user is logged in
}
$LogPath = Join-Path $TempPath "GFocus.log"
$WhitelistPath = Join-Path $TempPath "GFocusWhitelist.txt"
if (!(Test-Path $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null }

# Quarantine folder
$QuarantinePath = "C:\Quarantine"
if (!(Test-Path $QuarantinePath)) { New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Host $Message -ForegroundColor Yellow
}

function Register-GFocusTask {
    $taskName = "GFocus"
    $taskPath = "\"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `\"D:\Gorstak\GSecurity-main\Iso\sources\`$OEM`$\$$\Setup\Scripts\Bin\GFocus.ps1`\""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Log "INFO: Registered scheduled task '$taskName' to run as SYSTEM on startup."
}

# Run setup if task doesn't exist
$task = Get-ScheduledTask -TaskName "GFocus" -ErrorAction SilentlyContinue
if (!$task) {
    Register-GFocusTask
}

# Config
$ScanIntervalMs = 1000  # Milliseconds between focus checks (1 second)

# Initialize whitelist from file or empty array
$DynamicFocusWhitelist = @()
if (Test-Path $WhitelistPath) {
    $DynamicFocusWhitelist = Get-Content -Path $WhitelistPath | Where-Object { $_ -and $_ -notmatch '^\s*$' }
    Write-Log "INFO: Loaded whitelist from $WhitelistPath with $($DynamicFocusWhitelist.Count) entries"
} else {
    Write-Log "INFO: No existing whitelist file found, starting empty."
}

# Critical system processes to avoid killing
$CriticalProcesses = @("svchost", "wininit", "csrss", "smss", "lsass", "winlogon", "services", "System", "explorer")

# Win32 API for foreground window
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
'@

function Get-ForegroundProcess {
    $procId = 0
    $hWnd = [Win32]::GetForegroundWindow()
    [Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId) | Out-Null
    if ($procId -ne 0) {
        try {
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            return $proc
        } catch {
            return $null
        }
    }
    return $null
}

# Get child processes
function Get-ChildProcesses {
    param($ParentId)
    $ChildProcs = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ParentId }
    $ChildNames = @()
    foreach ($Child in $ChildProcs) {
        $ChildName = $Child.Name -replace '\.exe$', ''
        if ($ChildName -and $ChildNames -notcontains $ChildName) {
            $ChildNames += $ChildName
        }
    }
    return $ChildNames
}

# Terminate non-whitelisted connections, kill processes, and quarantine executables
function Terminate-NonWhitelistedConnections {
    param($Whitelist)
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    foreach ($Conn in $NetConns) {
        $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        $ProcName = $Proc.Name -replace '\.exe$', ''
        if ($ProcName -and $Whitelist -notcontains $ProcName) {
            # Skip critical system processes
            if ($CriticalProcesses -contains $ProcName) {
                Write-Log "INFO: Skipped terminating critical process $ProcName (Proc: $($Conn.OwningProcess))"
                continue
            }

            # Terminate connection
            $TempRuleName = "GFocus_TempBlock_$($Conn.OwningProcess)_$(Get-Random)"
            try {
                netsh advfirewall firewall add rule name="$TempRuleName" dir=out program="$($Proc.Path)" action=block enable=yes | Out-Null
                Write-Log "INFO: Terminated connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
                Start-Sleep -Milliseconds 100
                netsh advfirewall firewall delete rule name="$TempRuleName" | Out-Null
            } catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log ("DEBUG: Failed to terminate connection for " + $ProcName + " : " + $ErrorMessage)
            }

            # Kill the process
            try {
                Stop-Process -Id $Conn.OwningProcess -Force -ErrorAction Stop
                Write-Log "INFO: Killed non-whitelisted process $ProcName (Proc: $($Conn.OwningProcess))"
            } catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log ("DEBUG: Failed to kill process " + $ProcName + " : " + $ErrorMessage)
            }

            # Quarantine the executable
            if ($Proc.Path -and (Test-Path $Proc.Path)) {
                try {
                    $QuarantineFile = Join-Path $QuarantinePath "$($ProcName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').exe"
                    if (Get-Process -Name $ProcName -ErrorAction SilentlyContinue) {
                        Write-Log "DEBUG: Skipping quarantine for $ProcName - process still running or file in use"
                    } else {
                        Move-Item -Path $Proc.Path -Destination $QuarantineFile -Force -ErrorAction Stop
                        Write-Log "INFO: Quarantined $ProcName to $QuarantineFile"
                    }
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Log ("DEBUG: Failed to quarantine " + $Proc.Path + " : " + $ErrorMessage)
                }
            }
        }
    }
}

Write-Log "=== GFocus Lockdown Started ==="
Write-Log "DEBUG: Starting with whitelist loaded from $WhitelistPath."

# Main loop: Monitor foreground apps, log, whitelist, terminate, and manage network rules
while ($true) {
    # Get active process
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        $ProcName = $ActiveProcess.Name -replace '\.exe$', ''
        $ProcId = $ActiveProcess.Id
        $ProcPath = $ActiveProcess.Path

        # Check if foreground process changed
        if ($LastForegroundProcess -eq $null -or $LastForegroundProcess.Id -ne $ProcId -or $LastForegroundProcess.Name -ne $ProcName) {
            Write-Log "DEBUG: New active process: $ProcName (ID: $ProcId, Path: $ProcPath)"
            $LastForegroundProcess = $ActiveProcess

            # Log and whitelist new foreground process
            if ($ProcName -and $DynamicFocusWhitelist -notcontains $ProcName) {
                $DynamicFocusWhitelist += $ProcName
                $DynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $WhitelistPath -Encoding UTF8
                Write-Log "INFO: New foreground app added to whitelist: $ProcName"
                # Log to file
                $LogEntry = "Foreground App: $ProcName (Path: $ProcPath, Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
                $LogEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8

                # Whitelist child processes
                $ChildProcesses = Get-ChildProcesses -ParentId $ProcId
                foreach ($Child in $ChildProcesses) {
                    if ($Child -and $DynamicFocusWhitelist -notcontains $Child) {
                        $DynamicFocusWhitelist += $Child
                        $DynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $WhitelistPath -Encoding UTF8
                        Write-Log "INFO: Child process added to whitelist: $Child (Parent: $ProcName)"
                    }
                }
            }
        }
    } else {
        Write-Log "DEBUG: No active process detected."
    }

    # Update firewall rules immediately based on current whitelist
    # Clear existing rules
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "GFocus_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
            Write-Log "DEBUG: Cleared old rule: $RuleName"
        }
    }

    # Allow whitelisted processes
    $RunningProcs = Get-Process | Where-Object { $DynamicFocusWhitelist -contains ($_.Name -replace '\.exe$', '') -and $_.Path }
    foreach ($Proc in $RunningProcs) {
        $ProcName = $Proc.Name -replace '\.exe$', ''
        # Outbound rule
        $RuleNameOut = "GFocus_Allow_Out_$($ProcName)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameOut" dir=out program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log ("DEBUG: Added outbound allow rule for " + $ProcName + " : " + $RuleNameOut)
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log ("DEBUG: Failed to add outbound allow rule for " + $ProcName + " : " + $ErrorMessage)
        }
        # Inbound rule
        $RuleNameIn = "GFocus_Allow_In_$($ProcName)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameIn" dir=in program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log ("DEBUG: Added inbound allow rule for " + $ProcName + " : " + $RuleNameIn)
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log ("DEBUG: Failed to add inbound allow rule for " + $ProcName + " : " + $ErrorMessage)
        }
    }

    # Block all other inbound/outbound connections
    $BlockRuleNameOut = "GFocus_Block_All_Out"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameOut" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameOut" dir=out action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all outbound rule: $BlockRuleNameOut"
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log ("DEBUG: Failed to add block-all outbound rule: " + $ErrorMessage)
    }
    $BlockRuleNameIn = "GFocus_Block_All_In"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameIn" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameIn" dir=in action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all inbound rule: $BlockRuleNameIn"
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log ("DEBUG: Failed to add block-all inbound rule: " + $ErrorMessage)
    }

    # Terminate non-whitelisted connections, kill processes, and quarantine
    Terminate-NonWhitelistedConnections -Whitelist $DynamicFocusWhitelist

    # Log network connections
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Checking $($NetConns.Count) connections:"
        foreach ($Conn in $NetConns) {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $ProcName = $Proc.Name -replace '\.exe$', ''
            if ($ProcName -and $DynamicFocusWhitelist -contains $ProcName) {
                Write-Log "  - ALLOWED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            } else {
                Write-Log "  - BLOCKED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            }
        }
    } else {
        Write-Log "No network activity."
    }

    Start-Sleep -Milliseconds $ScanIntervalMs
}

# Define paths and parameters
$taskName = "NetworkDebloatStartup"
$taskDescription = "Runs the NetworkDebloat script at user logon with system privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\NetworkDebloat.ps1"

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Output "Set execution policy to Bypass for current user."
}

# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled task as SYSTEM
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
    Write-Output "Scheduled task '$taskName' registered to run as SYSTEM."
} elseif (-not $isAdmin) {
    Write-Output "Skipping task registration: Admin privileges required"
}

# List of unwanted bindings
$componentsToDisable = @(
    "ms_server",     # File and Printer Sharing
    "ms_msclient",   # Client for Microsoft Networks
    "ms_pacer",      # QoS Packet Scheduler
    "ms_lltdio",     # Link Layer Mapper I/O Driver
    "ms_rspndr",     # Link Layer Responder
)

# Disable on all active adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    foreach ($component in $componentsToDisable) {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Disable NULL sessions for SMB (Server Message Block)
Write-Host "Disabling NULL sessions for SMB..."
$nullSessionRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$nullSessionValueName = "RestrictAnonymous"
$nullSessionValue = 1  # 1 = Deny null sessions

# Set registry key to restrict anonymous access
Set-ItemProperty -Path $nullSessionRegistryPath -Name $nullSessionValueName -Value $nullSessionValue
Write-Host "NULL session access restricted for SMB."

# Disable Anonymous SID in the registry (disabling anonymous logons and null access)
Write-Host "Disabling Anonymous logons and null access..."
$anonymousLogonPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$anonymousLogonValueName = "RestrictAnonymous"

# Setting to 1 denies all anonymous logons (including NULL sessions)
Set-ItemProperty -Path $anonymousLogonPath -Name $anonymousLogonValueName -Value 1
Write-Host "Anonymous logons restricted."

# Ensure that null access is denied to shared folders and other network resources
Write-Host "Ensuring null access is denied on network shares..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Apply and force Group Policy update to apply the changes immediately
Write-Host "Forcing Group Policy update to apply settings..."
gpupdate /force

powercfg -setactive SUB_BATTERY

# Password.ps1
# Author: Gorstak

# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You need to run this script as an administrator."
    exit
}

# Script path for reusable functions
$scriptPath = "$env:ProgramData\PasswordTasks.ps1"

# ---------------------------
# Create main script file
# ---------------------------
$scriptContent = @"
function Generate-RandomPassword {
    \$upper = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    \$lower = [char[]]('abcdefghijklmnopqrstuvwxyz')
    \$digit = [char[]]('0123456789')
    \$special = [char[]]('!@#$%^&*()_+-=[]{}|;:,.<>?')
    \$chars = \$upper + \$lower + \$digit + \$special
    \$password = ''
    \$password += \$upper | Get-Random -Count 2
    \$password += \$lower | Get-Random -Count 2
    \$password += \$digit | Get-Random -Count 2
    \$password += \$special | Get-Random -Count 2
    for (\$i = 8; \$i -lt 16; \$i++) {
        \$password += \$chars | Get-Random -Count 1
    }
    return (\$password | Sort-Object {Get-Random}) -join ''
}

function Reset-UserPassword {
    \$username = \$env:USERNAME
    \$nullPassword = ConvertTo-SecureString "" -AsPlainText -Force
    Set-LocalUser -Name \$username -Password \$nullPassword
}

function Set-NewRandomPassword {
    \$username = \$env:USERNAME
    \$newPassword = Generate-RandomPassword
    \$securePassword = ConvertTo-SecureString -String \$newPassword -AsPlainText -Force
    Set-LocalUser -Name \$username -Password \$securePassword
}
"@

# Save script file
Set-Content -Path $scriptPath -Value $scriptContent -Force

# ---------------------------
# Immediately randomize current user password invisibly
# ---------------------------
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = "powershell.exe"
$startInfo.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Set-NewRandomPassword"
$startInfo.CreateNoWindow = $true
$startInfo.UseShellExecute = $false
$process = [System.Diagnostics.Process]::Start($startInfo)
$process.WaitForExit()

# ---------------------------
# Schedule task: reset password on shutdown/restart (invisible)
# ---------------------------
$shutdownTrigger = New-ScheduledTaskTrigger -OnEvent -LogName "System" -Source "USER32" -EventId 1074
$shutdownAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Reset-UserPassword"
$shutdownTaskName = "ResetPasswordOnShutdown"

if (Get-ScheduledTask -TaskName $shutdownTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $shutdownTaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $shutdownTaskName -Action $shutdownAction -Trigger $shutdownTrigger -User "SYSTEM" -RunLevel Highest

# ---------------------------
# Schedule task: generate random password every 10 minutes after login (invisible)
# ---------------------------
$randomPasswordTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$randomPasswordTrigger.RepetitionInterval = [TimeSpan]::FromMinutes(10)
$randomPasswordTrigger.RepetitionDuration = [TimeSpan]::FromDays(999)
$randomPasswordAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Set-NewRandomPassword"
$randomPasswordTaskName = "GenerateRandomPasswordHourly"

if (Get-ScheduledTask -TaskName $randomPasswordTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $randomPasswordTaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $randomPasswordTaskName -Action $randomPasswordAction -Trigger $randomPasswordTrigger -User $env:USERNAME -RunLevel Highest


# Block LDAP and LDAPS via firewall
$ldapPorts = @(389, 636)
foreach ($port in $ldapPorts) {
    New-NetFirewallRule -DisplayName "Block LDAP Port $port" -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction SilentlyContinue
}


# Start the background job
Start-Job -ScriptBlock {
    while ($true) {
        Terminate-NonConsoleSessions
        Start-Sleep -Seconds 5
    }
}

# Infinite loop to run the functions
function Run-Monitoring {
    while ($true) {
        Ensure-ServicesRunning
        Monitor-LoadedDLLs
        # Monitor-AudioProcesses  # Assuming this is missing; add if defined
        Monitor-Keyloggers
        Monitor-Overlays
        Monitor-Rootkit
        Detect-Keyloggers
        Prevent-RemoteThreadExecution
        Block-RemoteLogins
        Scan-MemoryForMalware
        Block-NonConsoleLogonGroupNetwork
        Is-ProcessFromConsoleLogonGroup  # Added call as it was defined but not used
        Start-Sleep -Seconds 10
    }
}

# Main loop to run resident in memory
Start-Job -ScriptBlock {
while ($true) {
    Detect-And-Terminate-SuspiciousDrivers
    Detect-And-Terminate-Keyloggers
    Detect-And-Terminate-Overlays
    Detect-And-Terminate-WebServerServices
    Detect-And-Terminate-WebServers
    Remove-NetworkBridge
    Start-ProcessKiller
	Start-StealthKiller
	Detect-RootkitByNetstat
    Kill-Listeners
	Start-XSSWatcher
    $detected, $path, $value = Detect-InProcControls
    if ($detected) {
        Remove-InProcControls -path $path -value $value
    } else {
        Write-Host "No InProc controls detected. Checking again in $CheckIntervalSeconds seconds..."
    }
    Start-Sleep -Seconds 10
}
}

# Prevent Remote Desktop Protocol (RDP)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
Stop-Service -Name "TermService" -Force
Set-Service -Name "TermService" -StartupType Disabled

# Disable Remote Assistance
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0

# Block PowerShell Remoting
Disable-PSRemoting -Force
Stop-Service -Name "WinRM" -Force
Set-Service -Name "WinRM" -StartupType Disabled

# Disable Telnet (if enabled)
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart

# Block SMB (File Sharing)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

# Disable Wake-on-LAN (WOL)
Get-NetAdapter | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled"
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled"
}

# Block SSH (if OpenSSH Server is installed)
Stop-Service -Name "sshd" -Force
Set-Service -Name "sshd" -StartupType Disabled

# Block VNC Services (if installed)
Get-Service -Name "*VNC*" | ForEach-Object {
    Stop-Service -Name $_.Name -Force
    Set-Service -Name $_.Name -StartupType Disabled
}

# Enforce Firewall Rules
# Disable RDP ports (3389)
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block

# Disable SMB ports (445, 139)
New-NetFirewallRule -DisplayName "Block SMB TCP 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SMB TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SMB UDP 137-138" -Direction Inbound -LocalPort 137-138 -Protocol UDP -Action Block

# Block WinRM ports (5985, 5986)
New-NetFirewallRule -DisplayName "Block WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Block

# Block Telnet port (23)
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block

# Disable UPnP
Get-Service -Name "SSDPSRV", "upnphost" | ForEach-Object {
    Stop-Service -Name $_.Name -Force
    Set-Service -Name $_.Name -StartupType Disabled
}

# Disable Remote Assistance firewall rule
Get-NetFirewallRule -DisplayName "Remote Assistance*" | Disable-NetFirewallRule

function Detect-RootkitByNetstat {
    # Run netstat -ano and store the output
    $netstatOutput = netstat -ano | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }

    if (-not $netstatOutput) {
        Write-Warning "No network connections found via netstat -ano. Possible rootkit hiding activity."

        # Optionally: Log the suspicious event
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = "$env:TEMP\rootkit_suspected_$timestamp.log"
        "Netstat -ano returned no results. Possible rootkit activity." | Out-File -FilePath $logFile

        # Get all running processes (you could refine this)
        $processes = Get-Process | Where-Object { $_.Id -ne $PID }

        foreach ($proc in $processes) {
            try {
                # Comment this line if you want to observe first
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Output "Stopped process: $($proc.ProcessName) (PID: $($proc.Id))"
            } catch {
                Write-Warning "Could not stop process: $($proc.ProcessName) (PID: $($proc.Id))"
            }
        }
    } else {
        Write-Host "Netstat looks normal. Active connections detected."
    }
}

# PowerShell script to secure Windows Pro/Enterprise/Education from remote access
# Requires Administrator privileges
# Run in an elevated PowerShell session

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting..." -ForegroundColor Red
    exit
}

Write-Host "Starting Windows Remote Access Security Hardening..." -ForegroundColor Green

# 1. Disable Remote Desktop (RDP)
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
Write-Host "Remote Desktop and Remote Assistance disabled."

# 2. Block RDP port (3389) and other common remote access ports in Windows Firewall
Write-Host "Configuring firewall to block common remote access ports..."
# Block RDP (3389)
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Enabled True
# Block common VNC ports (5900-5902)
New-NetFirewallRule -DisplayName "Block VNC Inbound" -Direction Inbound -Protocol TCP -LocalPort 5900-5902 -Action Block -Enabled True
# Block TeamViewer port (5938)
New-NetFirewallRule -DisplayName "Block TeamViewer Inbound" -Direction Inbound -Protocol TCP -LocalPort 5938 -Action Block -Enabled True
# Block AnyDesk port (7070)
New-NetFirewallRule -DisplayName "Block AnyDesk Inbound" -Direction Inbound -Protocol TCP -LocalPort 7070 -Action Block -Enabled True
Write-Host "Firewall rules added to block RDP, VNC, TeamViewer, and AnyDesk ports."

# 3. Disable Remote Desktop Services via Group Policy (if available)
Write-Host "Configuring Group Policy to disable Remote Desktop Services..."
$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $gpPath)) {
    New-Item -Path $gpPath -Force | Out-Null
}
Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
Write-Host "Group Policy updated to disable Remote Desktop Services."

# 4. Disable default Administrator account
Write-Host "Disabling default Administrator account..."
$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($adminAccount) {
    Disable-LocalUser -Name "Administrator"
    Write-Host "Default Administrator account disabled."
} else {
    Write-Host "Default Administrator account not found or already disabled."
}

# 5. Restrict unauthorized software installation via Group Policy
Write-Host "Restricting unauthorized software (e.g., TeamViewer, AnyDesk)..."
$restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $restrictPath)) {
    New-Item -Path $restrictPath -Force | Out-Null
}
# Example: Block TeamViewer and AnyDesk executables
$blockedApps = "TeamViewer.exe,AnyDesk.exe"
Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
New-Item -Path "$restrictPath\DisallowRun" -Force | Out-Null
$blockedApps.Split(",") | ForEach-Object { Set-ItemProperty -Path "$restrictPath\DisallowRun" -Name $_ -Value $_ }
Write-Host "Group Policy updated to block specified remote access software."

# 6. Disable UPnP in Windows (prevents automatic port forwarding)
Write-Host "Disabling UPnP service..."
Set-Service -Name "SSDPSRV" -StartupType Disabled
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Write-Host "UPnP service disabled."

# 7. Enable Windows Defender real-time protection
Write-Host "Ensuring Windows Defender real-time protection is enabled..."
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "Windows Defender real-time protection enabled."

# 8. Verify RDP is not listening
Write-Host "Verifying RDP port (3389) is not listening..."
$rdpPort = netstat -an | Select-String "3389"
if ($rdpPort) {
    Write-Host "WARNING: Port 3389 is still listening. Please check firewall and service settings manually." -ForegroundColor Yellow
} else {
    Write-Host "RDP port 3389 is not listening."
}

# 9. Log completion
Write-Host "Security hardening complete!" -ForegroundColor Green
Write-Host "Recommended manual steps:"
Write-Host "- Check Event Viewer for unauthorized access attempts."
Write-Host "- Ensure Windows is up to date via Settings > Windows Update."
Write-Host "- Consider using a VPN for secure remote access if needed."
Write-Host "- Verify firewall rules and test remote access to ensure it is blocked."

# Troll.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunTrollAtLogon"
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

# Function to check and remove network bridges
function Remove-NetworkBridge {
    try {
        # Run netsh bridge show adapter and capture output
        $netshOutput = netsh bridge show adapter
        $bridgeFound = $false
        $bridgedAdapters = @()

        # Parse netsh output to find adapters with IsBridged: Yes
        foreach ($line in $netshOutput) {
            if ($line -match "Yes\s+.*\s+([^\s]+)$") {
                $bridgeFound = $true
                $bridgedAdapters += $matches[1]  # Capture adapter name
            }
        }

        if ($bridgeFound) {
            Write-Host "Network Bridge detected on adapters: $($bridgedAdapters -join ', '). Attempting to remove..."
            # Attempt to uninstall the bridge
            $uninstallResult = netsh bridge uninstall
            if ($uninstallResult -match "success|completed") {
                Write-Host "Network Bridge removed successfully."
            } else {
                Write-Host "Failed to remove Network Bridge. netsh output: $uninstallResult"
            }
        } else {
            Write-Host "No Network Bridge detected."
        }
    }
    catch {
        Write-Host "Error occurred: $_"
    }
}

# Main loop to persistently monitor and prevent bridge creation
Write-Host "Starting network bridge prevention script. Press Ctrl+C to stop."
Start-Job -ScriptBlock {
    while ($true) {
        Remove-NetworkBridge
        Start-Sleep -Seconds 5  # Check every 5 seconds
    }
}
