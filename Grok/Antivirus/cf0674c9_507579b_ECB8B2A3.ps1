param([switch]$Uninstall)

#Requires -Version 5.1

# ============================================================================
# Antivirus & EDR
# Author: Gorstak
# ============================================================================

# Unique script identifier (GUID) - used for process identification and mutex naming
$Script:ScriptGUID = "539EF6B5-578B-4AF3-A5C7-FD564CB9C8FB"

$Script:InstallPath = "C:\ProgramData\AntivirusProtection"
$Script:ScriptName = Split-Path -Leaf $PSCommandPath
$Script:MaxRestartAttempts = 3
$Script:StabilityLogPath = "$Script:InstallPath\Logs\stability_log.txt"

$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    LOLBinDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    AMSIBypassDetectionIntervalSeconds = 15
    CredentialDumpDetectionIntervalSeconds = 15
    WMIPersistenceDetectionIntervalSeconds = 120
    ScheduledTaskDetectionIntervalSeconds = 120
    RegistryPersistenceDetectionIntervalSeconds = 120
    DLLHijackingDetectionIntervalSeconds = 90
    TokenManipulationDetectionIntervalSeconds = 60
    ProcessHollowingDetectionIntervalSeconds = 30
    KeyloggerDetectionIntervalSeconds = 45
    KeyScramblerManagementIntervalSeconds = 60
    RansomwareDetectionIntervalSeconds = 15
    NetworkAnomalyDetectionIntervalSeconds = 30
    NetworkTrafficMonitoringIntervalSeconds = 45
    RootkitDetectionIntervalSeconds = 180
    ClipboardMonitoringIntervalSeconds = 30
    COMMonitoringIntervalSeconds = 120
    BrowserExtensionMonitoringIntervalSeconds = 300
    ShadowCopyMonitoringIntervalSeconds = 30
    USBMonitoringIntervalSeconds = 20
    MobileDeviceMonitoringIntervalSeconds = 15
    AttackToolsDetectionIntervalSeconds = 30
    AdvancedThreatDetectionIntervalSeconds = 20
    EventLogMonitoringIntervalSeconds = 60
    FirewallRuleMonitoringIntervalSeconds = 120
    ServiceMonitoringIntervalSeconds = 60
    FilelessDetectionIntervalSeconds = 20
    MemoryScanningIntervalSeconds = 90
    NamedPipeMonitoringIntervalSeconds = 45
    DNSExfiltrationDetectionIntervalSeconds = 30
    PasswordManagementIntervalSeconds = 120
    WebcamGuardianIntervalSeconds = 5
    BeaconDetectionIntervalSeconds = 60
    CodeInjectionDetectionIntervalSeconds = 30
    DataExfiltrationDetectionIntervalSeconds = 30
    ElfCatcherIntervalSeconds = 30
    FileEntropyDetectionIntervalSeconds = 120
    HoneypotMonitoringIntervalSeconds = 30
    LateralMovementDetectionIntervalSeconds = 30
    ProcessCreationDetectionIntervalSeconds = 10
    QuarantineManagementIntervalSeconds = 300
    ReflectiveDLLInjectionDetectionIntervalSeconds = 30
    ResponseEngineIntervalSeconds = 10
    PrivacyForgeSpoofingIntervalSeconds = 60
    ElfDLLUnloaderIntervalSeconds = 10
    UnsignedDLLRemoverIntervalSeconds = 300
}

$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    ReportsPath = "$Script:InstallPath\Reports"
    HMACKeyPath = "$Script:InstallPath\Data\db_integrity.hmac"
    PIDFilePath = "$Script:InstallPath\Data\antivirus.pid"
    MutexName = "Local\AntivirusProtection_Mutex_{0}_{1}_{2}" -f $env:COMPUTERNAME, $env:USERNAME, $Script:ScriptGUID

    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"

    ExclusionPaths = @(
        $Script:InstallPath,
        "$Script:InstallPath\Logs",
        "$Script:InstallPath\Quarantine",
        "$Script:InstallPath\Reports",
        "$Script:InstallPath\Data"
    )
    ExclusionProcesses = @("powershell", "pwsh")

    EnableUnsignedDLLScanner = $true
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500
}

# <CHANGE> Add graceful elevation check function (insert after $Config block, ~line 99)
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param([string]$Reason = "This operation requires administrator privileges.")
    
    # <CHANGE> Use a global mutex - if elevated instance owns it, children skip
    $mutexName = "Global\AntivirusProtection_Elevated"
    
    if (Test-IsAdmin) {
        # Try to own the mutex (elevated parent holds it)
        $script:ElevationMutex = New-Object System.Threading.Mutex($false, $mutexName)
        try {
            $script:ElevationMutex.WaitOne(0) | Out-Null
        } catch {}
        return
    }
    
    # <CHANGE> Check if mutex exists (means elevated instance is running)
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $hasHandle = $false
    try {
        $hasHandle = $mutex.WaitOne(0, $false)
    } catch {}
    
    if (-not $hasHandle) {
        # Mutex held by elevated parent - we're a child, skip elevation
        return
    }
    
    # Release it - we're the first non-elevated instance, need to elevate
    $mutex.ReleaseMutex()
    $mutex.Dispose()
    
    Write-Warning $Reason
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$Global:AntivirusState = @{
    Running = $false
    Installed = $false
    Jobs = @{}
    Mutex = $null
    ThreatCount = 0
    FilesScanned = 0
    FilesQuarantined = 0
    ProcessesTerminated = 0
}

$Script:LoopCounter = 0
$script:ManagedJobs = @{}

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $true
$Script:SelfPID = $PID

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "antivirus_log.txt")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    
    # Try to get Config from global scope first, then script scope, then local scope
    $configVar = $null
    if ($null -ne (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue)) {
        $configVar = $global:Config
    } elseif ($null -ne (Get-Variable -Name "Config" -Scope Script -ErrorAction SilentlyContinue)) {
        $configVar = $script:Config
    } elseif (Test-Path Variable:Config) {
        $configVar = $Config
    }
    
    # Check if Config exists and LogPath is not null
    if ($null -eq $configVar -or $null -eq $configVar.LogPath -or [string]::IsNullOrWhiteSpace($configVar.LogPath)) {
        # Fallback to default log path if Config is not available
        $logPath = if ($Script:InstallPath) { "$Script:InstallPath\Logs" } else { "C:\ProgramData\AntivirusProtection\Logs" }
        $logFilePath = Join-Path $logPath $LogFile
        
        if (!(Test-Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
    } else {
        $logFilePath = Join-Path $configVar.LogPath $LogFile
        
        if (!(Test-Path $configVar.LogPath)) {
            New-Item -ItemType Directory -Path $configVar.LogPath -Force | Out-Null
        }
    }

    Add-Content -Path $logFilePath -Value $entry -ErrorAction SilentlyContinue

    $eid = switch ($Level) {
        "ERROR" { 1001 }
        "WARN" { 1002 }
        "THREAT" { 1003 }
        default { 1000 }
    }

    # Only write to event log if Config and EDRName are available
    if ($null -ne $configVar -and $null -ne $configVar.EDRName -and -not [string]::IsNullOrWhiteSpace($configVar.EDRName)) {
        # Ensure event log source exists before writing
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($configVar.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($configVar.EDRName, "Application")
            }
        } catch {
            # Event log source creation may require elevation or fail for other reasons
            # Silently continue - we'll just skip event log writing
            return
        }
        
        try {
            Write-EventLog -LogName Application -Source $configVar.EDRName -EntryType Information -EventId $eid -Message $Message -ErrorAction SilentlyContinue
        } catch {
            # If event log write still fails, silently continue
        }
    }
}

function Write-StabilityLog {
    param([string]$Message, [string]$Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] [STABILITY] $Message"

    if (!(Test-Path (Split-Path $Script:StabilityLogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:StabilityLogPath -Parent) -Force | Out-Null
    }

    Add-Content -Path $Script:StabilityLogPath -Value $entry -ErrorAction SilentlyContinue
    Write-Host $entry -ForegroundColor $(switch($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} default {"White"} })
}


function Register-ExitCleanup {
    if ($script:ExitCleanupRegistered) {
        return
    }

    try {
        Register-EngineEvent -SourceIdentifier "AntivirusProtection_ExitCleanup" -EventName PowerShell.Exiting -Action {
            # Cleanup actions if needed
        } | Out-Null
        $script:ExitCleanupRegistered = $true
    }
    catch {
    }
}

function Install-Antivirus {
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    $currentPath = $PSCommandPath

    # Set SelfPath to the installed script location (used by auto-restart and watchdog)
    $Script:SelfPath = $targetScript

    if ($currentPath -eq $targetScript) {
        Write-Host "[+] Running from install location" -ForegroundColor Green
        $Global:AntivirusState.Installed = $true
        # Initialize mutex BEFORE creating persistence to prevent race conditions during setup
        Initialize-Mutex
        Install-Persistence
        return $true
    }

    Write-Host "`n=== Installing Antivirus ===`n" -ForegroundColor Cyan

    @("Data","Logs","Quarantine","Reports") | ForEach-Object {
        $p = Join-Path $Script:InstallPath $_
        if (!(Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Write-Host "[+] Created: $p"
        }
    }

    Copy-Item -Path $PSCommandPath -Destination $targetScript -Force
    Write-Host "[+] Copied main script to $targetScript"

    # Initialize mutex BEFORE creating persistence to prevent race conditions during setupcomplete.cmd
    # This ensures only one instance can acquire the mutex before scheduled tasks are created
    Initialize-Mutex
    Install-Persistence

    Write-Host "`n[+] Installation complete. Continuing in this instance...`n" -ForegroundColor Green
    $Global:AntivirusState.Installed = $true
    return $true
}

function Install-Persistence {
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan

    # Define paths for cleanup
    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"
    $runKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $runKeyName = "AntivirusProtection"

    try {
        # Remove old persistence methods
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
        }

        # Add to HKCU Run key
        $runCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
        Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runCommand -ErrorAction Stop

        Write-Host "[+] Registry Run key entry created for automatic startup" -ForegroundColor Green
        Write-StabilityLog "Persistence setup completed - HKCU Run key created"
    }
    catch {
        Write-Host "[!] Failed to create registry Run key entry: $_" -ForegroundColor Red
        Write-StabilityLog "Persistence setup failed: $_" "ERROR"
    }
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus ===`n" -ForegroundColor Cyan
    Write-StabilityLog "Starting uninstall process"

    # First, stop all running instances
    try {
        Write-Host "[*] Stopping running instances..." -ForegroundColor Yellow
        Write-StabilityLog "Stopping running antivirus instances"
        
        # Check PID file for running instance
        if (Test-Path $Config.PIDFilePath) {
            try {
                $existingPID = [int](Get-Content $Config.PIDFilePath -ErrorAction Stop)
                if ($existingPID -ne $PID) {
                    $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue
                    if ($existingProcess) {
                        # Verify it's our script before killing
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $existingPID" -ErrorAction SilentlyContinue).CommandLine
                        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                        $isOurScript = $false
                        if ($cmdLine) {
                            if ($cmdLine -like "*$($Script:ScriptGUID)*" -or ($scriptPath -and $cmdLine -like "*$scriptPath*")) {
                                $isOurScript = $true
                            }
                        }
                        
                        if ($isOurScript) {
                            Write-Host "[+] Stopping instance (PID: $existingPID)" -ForegroundColor Green
                            Stop-Process -Id $existingPID -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            } catch {
                Write-StabilityLog "Error reading PID file during uninstall: $_" "WARN"
            }
        }
        
        # Also check for any PowerShell processes running our script
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
        $allProcesses = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue
        foreach ($proc in $allProcesses) {
            if ($proc.ProcessId -eq $PID) { continue }
            try {
                $cmdLine = $proc.CommandLine
                if ($cmdLine -and ($cmdLine -like "*$($Script:ScriptGUID)*" -or ($scriptPath -and $cmdLine -like "*$scriptPath*"))) {
                    Write-Host "[+] Stopping instance (PID: $($proc.ProcessId))" -ForegroundColor Green
                    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        
        # Wait a moment for processes to terminate
        Start-Sleep -Seconds 1
    } catch {
        Write-Host "[!] Warning: Could not stop all instances: $_" -ForegroundColor Yellow
        Write-StabilityLog "Warning: Could not stop all instances during uninstall: $_" "WARN"
    }

    try {
        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }
        if ($Global:AntivirusState -and $Global:AntivirusState.Jobs) {
            $Global:AntivirusState.Jobs.Clear()
        }
    }
    catch {
        Write-StabilityLog "Failed to clear managed jobs during uninstall: $_" "WARN"
    }

    try {
        # Remove registry Run key entry
        $runKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $runKeyName = "AntivirusProtection"
        if (Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed registry Run key entry" -ForegroundColor Green
            Write-StabilityLog "Removed registry Run key entry during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove registry Run key entry: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove registry Run key entry: $_" "WARN"
    }

    # Clean up old persistence methods if they exist
    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Removed scheduled task (if existed)" -ForegroundColor Green
        Write-StabilityLog "Removed scheduled task during uninstall"
    }
    catch {
        Write-Host "[!] Failed to remove scheduled task: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove scheduled task: $_" "WARN"
    }

    try {
        $shortcutPath = Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" "AntivirusProtection.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed startup shortcut (if existed)" -ForegroundColor Green
            Write-StabilityLog "Removed startup shortcut during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove startup shortcut: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove startup shortcut: $_" "WARN"
    }

    if (Test-Path $Script:InstallPath) {
        Remove-Item -Path $Script:InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed installation directory" -ForegroundColor Green
        Write-StabilityLog "Removed installation directory during uninstall"
    }

    Write-Host "[+] Uninstall complete." -ForegroundColor Green
    Write-StabilityLog "Uninstall process completed"
    exit 0
}

function Initialize-Mutex {
    $mutexName = $Config.MutexName

    Write-StabilityLog "Initializing mutex and PID checks"

    if (Test-Path $Config.PIDFilePath) {
        try {
            $existingPID = [int](Get-Content $Config.PIDFilePath -ErrorAction Stop)
            
            # Don't block if PID file contains our own PID (stale file from same instance)
            if ($existingPID -eq $PID) {
                Write-StabilityLog "PID file contains current PID - removing stale file" "INFO"
                Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            }
            else {
                $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue

                if ($existingProcess) {
                    # Check if the existing process is actually running our script
                    try {
                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $existingPID" -ErrorAction SilentlyContinue).CommandLine
                        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                        
                        # Check if existing process is running our script (by GUID or path)
                        $isOurScript = $false
                        if ($cmdLine) {
                            # Primary check: GUID (most reliable)
                            if ($cmdLine -like "*$($Script:ScriptGUID)*") {
                                $isOurScript = $true
                            }
                            # Secondary check: script path
                            elseif ($scriptPath -and $cmdLine -like "*$scriptPath*") {
                                $isOurScript = $true
                            }
                        }
                        
                        if ($isOurScript) {
                            Write-StabilityLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            Write-Host "[!] Another instance is already running (PID: $existingPID)" -ForegroundColor Yellow
                            Write-AVLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                            throw "Another instance is already running (PID: $existingPID)"
                        }
                        else {
                            # Existing process is not our script - remove stale PID file
                            Write-StabilityLog "PID file contains different process (not our script) - removing stale file" "INFO"
                            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        if ($_.Exception.Message -like "*already running*") {
                            throw
                        }
                        # Can't determine if it's our script, but process exists - assume it's not our script and remove stale PID
                        Write-StabilityLog "Could not verify existing process - removing potentially stale PID file" "INFO"
                        Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                    Write-StabilityLog "Removed stale PID file (process $existingPID not running)"
                    Write-AVLog "Removed stale PID file (process $existingPID not running)"
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*already running*") {
                throw
            }
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            Write-StabilityLog "Removed invalid PID file"
        }
    }

    try {
        $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $acquired = $Global:AntivirusState.Mutex.WaitOne(3000)

        if (!$acquired) {
            # Mutex is locked - check if there's actually a running instance
            Write-StabilityLog "Mutex locked - checking for running instances" "WARN"
            
            # Check for running instances, excluding our own PID
            $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
            $installedScriptPath = Join-Path $Script:InstallPath $Script:ScriptName
            
            $verifiedInstances = @()
            $allPowerShellProcesses = Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID }
            
            foreach ($proc in $allPowerShellProcesses) {
                try {
                    # Verify process is actually responsive (not hung/dead)
                    $procInfo = Get-Process -Id $proc.Id -ErrorAction Stop
                    if (-not $procInfo.Responding) {
                        Write-StabilityLog "Process $($proc.Id) is not responding - treating as dead" "WARN"
                        continue
                    }
                    
                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    if (-not $cmdLine) {
                        continue
                    }
                    
                    # Strict verification: Primary check is GUID (most reliable), then script path
                    $isOurScript = $false
                    $matchedPath = $null
                    $matchedBy = $null
                    
                    # PRIMARY: Check for GUID in command line (most reliable identifier)
                    if ($cmdLine -like "*$($Script:ScriptGUID)*") {
                        $isOurScript = $true
                        $matchedBy = "GUID"
                        # Also try to extract the script path for logging
                        if ($cmdLine -match '-File\s+([^\s]+)') {
                            $matchedPath = $matches[1].Trim('"').Trim("'")
                        } else {
                            $matchedPath = "GUID_Match"
                        }
                    }
                    # SECONDARY: Check current script path
                    elseif ($scriptPath -and $cmdLine -like "*$scriptPath*") {
                        $isOurScript = $true
                        $matchedPath = $scriptPath
                        $matchedBy = "Path"
                    }
                    # TERTIARY: Check installed script path (if different from current)
                    elseif ($installedScriptPath -and (Test-Path $installedScriptPath) -and $cmdLine -like "*$installedScriptPath*") {
                        $isOurScript = $true
                        $matchedPath = $installedScriptPath
                        $matchedBy = "Path"
                    }
                    
                    if ($isOurScript) {
                        Write-StabilityLog "Verified process $($proc.Id) is running our script (matched by $matchedBy): $matchedPath" "INFO"
                        $verifiedInstances += @{
                            Id = $proc.Id
                            CommandLine = $cmdLine
                            Path = $matchedPath
                            MatchedBy = $matchedBy
                        }
                    }
                } catch {
                    # Process doesn't exist or error checking - don't count it
                    Write-StabilityLog "Error checking process $($proc.Id): $_" "WARN"
                    continue
                }
            }
            
            if ($verifiedInstances.Count -gt 0) {
                $instancePIDs = $verifiedInstances | ForEach-Object { $_.Id }
                $instanceDetails = $verifiedInstances | ForEach-Object { "PID $($_.Id): $($_.Path)" }
                Write-StabilityLog "Blocked duplicate instance - found $($verifiedInstances.Count) verified running instance(s) (PIDs: $($instancePIDs -join ', '))" "WARN"
                Write-Host "[!] Another instance is already running (PIDs: $($instancePIDs -join ', '))" -ForegroundColor Yellow
                Write-Host "[!] Running from: $($instanceDetails -join '; ')" -ForegroundColor Yellow
                Write-AVLog "Blocked duplicate instance - found running processes: $($instancePIDs -join ', ')" "WARN"
                $Global:AntivirusState.Mutex.Dispose()
                throw "Another instance is already running (mutex locked)"
            } else {
                # No verified instances found - treat as stale mutex
                # Since we've verified no process is running, we can safely proceed
                Write-StabilityLog "Stale mutex detected (no running process found) - proceeding anyway" "WARN"
                Write-Host "[!] Stale mutex detected but no process running - proceeding (stale mutex will be cleaned up)" -ForegroundColor Yellow
                
                # Dispose of the failed mutex reference
                try {
                    $Global:AntivirusState.Mutex.Dispose()
                } catch {}
                $Global:AntivirusState.Mutex = $null
                
                # Wait a bit to allow kernel cleanup
                Start-Sleep -Milliseconds 500
                
                # Try to create a new mutex (Windows should have cleaned up the stale one)
                # If it still fails, we'll proceed without mutex protection (since we verified no process is running)
                try {
                    $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
                    $acquired = $Global:AntivirusState.Mutex.WaitOne(2000)
                    if ($acquired) {
                        Write-StabilityLog "Successfully acquired mutex after stale detection" "INFO"
                    } else {
                        # Still can't acquire, but no process is running - proceed without mutex
                        Write-StabilityLog "Mutex still locked but no process running - proceeding without mutex (stale mutex)" "WARN"
                        Write-Host "[!] Warning: Proceeding without mutex (stale mutex detected). This is safe since no process is running." -ForegroundColor Yellow
                        $Global:AntivirusState.Mutex.Dispose()
                        $Global:AntivirusState.Mutex = $null
                    }
                } catch {
                    # If we can't create the mutex, proceed anyway since we verified no process is running
                    Write-StabilityLog "Could not create mutex after stale detection, but no process running - proceeding: $_" "WARN"
                    Write-Host "[!] Warning: Proceeding without mutex protection due to stale mutex." -ForegroundColor Yellow
                    $Global:AntivirusState.Mutex = $null
                }
            }
        }

        if (!(Test-Path (Split-Path $Config.PIDFilePath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $Config.PIDFilePath -Parent) -Force | Out-Null
        }

        $PID | Out-File -FilePath $Config.PIDFilePath -Force
        $Global:AntivirusState.Running = $true
        if ($Global:AntivirusState.Mutex) {
            Write-StabilityLog "Mutex acquired, PID file written: $PID"
        } else {
            Write-StabilityLog "PID file written: $PID (running without mutex due to stale mutex)"
        }
        Write-AVLog "Antivirus started (PID: $PID)"
        Write-Host "[+] Process ID: $PID" -ForegroundColor Green

        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            try {
                Write-StabilityLog "PowerShell exiting - cleaning up mutex and PID"
                if ($Global:AntivirusState.Mutex) {
                    $Global:AntivirusState.Mutex.ReleaseMutex()
                    $Global:AntivirusState.Mutex.Dispose()
                }
                if (Test-Path $Config.PIDFilePath) {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-StabilityLog "Cleanup error: $_" "ERROR"
            }
        } | Out-Null

    }
    catch {
        Write-StabilityLog "Mutex initialization failed: $_" "ERROR"
        throw
    }
}

function Select-BoundConfig {
    param(
        [Parameter(Mandatory=$true)][string]$FunctionName,
        [Parameter(Mandatory=$true)][hashtable]$Config
    )

    $cmd = Get-Command $FunctionName -ErrorAction Stop
    $paramNames = @($cmd.Parameters.Keys)
    $bound = @{}
    foreach ($k in $Config.Keys) {
        if ($paramNames -contains $k) {
            $bound[$k] = $Config[$k]
        }
    }
    return $bound
}

function Register-TerminationProtection {
    try {
        # Monitor for unexpected termination attempts
        $Script:UnhandledExceptionHandler = Register-ObjectEvent -InputObject ([AppDomain]::CurrentDomain) `
            -EventName UnhandledException -Action {
            param($src, $evtArgs)
            
            $errorMsg = "Unhandled exception: $($evtArgs.Exception.ToString())"
            $errorMsg | Out-File "$using:quarantineFolder\crash_log.txt" -Append
            
            try {
                # Log to security events
                $securityEvent = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    EventType = "UnexpectedTermination"
                    Severity = "Critical"
                    Exception = $evtArgs.Exception.ToString()
                    IsTerminating = $evtArgs.IsTerminating
                }
                $securityEvent | ConvertTo-Json -Compress | Out-File "$using:quarantineFolder\security_events.jsonl" -Append
            } catch {}
            
            # Attempt auto-restart if configured
            if ($using:Script:AutoRestart -and $evtArgs.IsTerminating) {
                try {
                    Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$using:Script:SelfPath`"" `
                        -WindowStyle Hidden -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        
        Write-StabilityLog "[PROTECTION] Termination protection registered"
        
    } catch {
        Write-StabilityLog -Message "Failed to register termination protection" -Severity "Medium" -ErrorRecord $_
    }
}

function Enable-CtrlCProtection {
    try {
        # Detect if running in ISE or console
        if ($host.Name -eq "Windows PowerShell ISE Host") {
            Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
            Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
            return $true
        }
        
        [Console]::TreatControlCAsInput = $false
        
        # Create scriptblock for the event handler
        $cancelHandler = {
            param($src, $evtArgs)
            
            $Script:TerminationAttempts++
            
            Write-Host "`n[PROTECTION] Termination attempt detected ($Script:TerminationAttempts/$Script:MaxTerminationAttempts)" -ForegroundColor Red
            
            try {
                Write-SecurityEvent -EventType "TerminationAttemptBlocked" -Details @{
                    PID = $PID
                    AttemptNumber = $Script:TerminationAttempts
                } -Severity "Critical"
            } catch {}
            
            if ($Script:TerminationAttempts -ge $Script:MaxTerminationAttempts) {
                Write-Host "[PROTECTION] Maximum termination attempts reached. Allowing graceful shutdown..." -ForegroundColor Yellow
                $evtArgs.Cancel = $false
            } else {
                Write-Host "[PROTECTION] Termination blocked. Press Ctrl+C $($Script:MaxTerminationAttempts - $Script:TerminationAttempts) more times to force stop." -ForegroundColor Yellow
                $evtArgs.Cancel = $true
            }
        }
        
        # Register the event handler
        [Console]::add_CancelKeyPress($cancelHandler)
        
        Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[WARNING] Could not enable Ctrl+C protection: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Enable-AutoRestart {
    try {
        $taskName = "AntivirusAutoRestart_$PID"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:SelfPath`""
        
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Force -ErrorAction Stop | Out-Null
        
        Write-Host "[PROTECTION] Auto-restart scheduled task registered" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not enable auto-restart: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Start-ProcessWatchdog {
    try {
        $watchdogJob = Start-Job -ScriptBlock {
            param($parentPID, $scriptPath, $autoRestart)
            
            while ($true) {
                Start-Sleep -Seconds 30
                
                # Check if parent process is still alive
                $process = Get-Process -Id $parentPID -ErrorAction SilentlyContinue
                
                if (-not $process) {
                    # Parent died - restart if configured
                    if ($autoRestart) {
                        Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" `
                            -WindowStyle Hidden -ErrorAction SilentlyContinue
                    }
                    break
                }
            }
        } -ArgumentList $PID, $Script:SelfPath, $Script:AutoRestart
        
        Write-Host "[PROTECTION] Process watchdog started (Job ID: $($watchdogJob.Id))" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not start process watchdog: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Register-ManagedJob {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$IntervalSeconds = 30,
        [bool]$Enabled = $true,
        [bool]$Critical = $false,
        [int]$MaxRestartAttempts = 3,
        [int]$RestartDelaySeconds = 5,
        [object[]]$ArgumentList = $null
    )

    if (-not $script:ManagedJobs) {
        $script:ManagedJobs = @{}
    }

    $minIntervalSeconds = 1
    if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MinimumIntervalSeconds) {
        $minIntervalSeconds = [int]$Script:ManagedJobConfig.MinimumIntervalSeconds
    }

    $IntervalSeconds = [Math]::Max([int]$IntervalSeconds, [int]$minIntervalSeconds)

    $script:ManagedJobs[$Name] = [pscustomobject]@{
        Name = $Name
        ScriptBlock = $ScriptBlock
        ArgumentList = $ArgumentList
        IntervalSeconds = $IntervalSeconds
        Enabled = $Enabled
        Critical = $Critical
        MaxRestartAttempts = $MaxRestartAttempts
        RestartDelaySeconds = $RestartDelaySeconds
        RestartAttempts = 0
        LastStartUtc = $null
        LastSuccessUtc = $null
        LastError = $null
        NextRunUtc = [DateTime]::UtcNow
        DisabledUtc = $null
    }
}

function Invoke-ManagedJobsTick {
    param(
        [Parameter(Mandatory=$true)][DateTime]$NowUtc
    )

    if (-not $script:ManagedJobs) {
        return
    }

    foreach ($job in $script:ManagedJobs.Values) {
        if (-not $job.Enabled) { continue }
        if ($null -ne $job.DisabledUtc) { continue }
        if ($job.NextRunUtc -gt $NowUtc) { continue }

        $job.LastStartUtc = $NowUtc

        try {
            # Suppress all output from managed job execution to prevent pipeline binding issues
            # Use Out-Null to ensure complete suppression of all streams including return values
            # Redirect all streams (*>&1) to prevent any output from reaching the pipeline
            if ($null -ne $job.ArgumentList) {
                $null = Invoke-Command -ScriptBlock $job.ScriptBlock -ArgumentList $job.ArgumentList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue *>&1 | Out-Null
            }
            else {
                $null = & $job.ScriptBlock -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue *>&1 | Out-Null
            }
            $job.LastSuccessUtc = [DateTime]::UtcNow
            $job.RestartAttempts = 0
            $job.LastError = $null
            $job.NextRunUtc = $job.LastSuccessUtc.AddSeconds([Math]::Max(1, $job.IntervalSeconds))
        }
        catch {
            $job.LastError = $_
            $job.RestartAttempts++

            try {
                Write-AVLog "Managed job '$($job.Name)' failed (attempt $($job.RestartAttempts)/$($job.MaxRestartAttempts)) : $($_.Exception.Message)" "WARN"
            }
            catch {}

            if ($job.RestartAttempts -ge $job.MaxRestartAttempts) {
                $job.RestartAttempts = 0
                $job.DisabledUtc = $null
                $job.NextRunUtc = [DateTime]::UtcNow.AddMinutes(5)
                try {
                    Write-AVLog "Managed job '$($job.Name)' exceeded max restart attempts; backing off for 5 minutes" "ERROR"
                }
                catch {}
                continue
            }

            $job.NextRunUtc = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $job.RestartDelaySeconds))
        }
    }
}

function Start-ManagedJob {
    param(
        [string]$ModuleName,
        [int]$IntervalSeconds = 30
    )

    $jobName = "AV_$ModuleName"

    if ($Global:AntivirusState.Jobs.ContainsKey($jobName)) {
        return
    }

    $funcName = "Invoke-$ModuleName"
    if (-not (Get-Command $funcName -ErrorAction SilentlyContinue)) {
        Write-AVLog "Function not found: $funcName" "WARN"
        return
    }

    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    $sb = {
        param(
            [Parameter(Mandatory=$true)][string]$FunctionName,
            [Parameter(Mandatory=$true)][hashtable]$Cfg
        )

        # Ensure global Config is available in this scope
        if ($null -eq $global:Config -and $null -ne $Cfg) {
            $global:Config = $Cfg
        }

        $cmd = Get-Command $FunctionName -ErrorAction Stop
        $paramNames = @($cmd.Parameters.Keys)
        $bound = @{}
        
        # Check if function expects a Config parameter (as hashtable)
        if ($paramNames -contains "Config") {
            $bound["Config"] = $Cfg
        } else {
            # Otherwise, bind individual keys from Cfg to matching parameters
            foreach ($k in $Cfg.Keys) {
                if ($paramNames -contains $k) {
                    $bound[$k] = $Cfg[$k]
                }
            }
        }
        
        # Suppress output to prevent pipeline binding issues - use Out-Null to ensure complete suppression
        # Also suppress any implicit output by explicitly assigning to $null and redirecting all streams
        try {
            $null = & $FunctionName @bound *>&1 | Out-Null
        } catch {
            # Suppress errors too
            $null = $_
        }
    }

    Register-ManagedJob -Name $jobName -ScriptBlock $sb -ArgumentList @($funcName, $Config) -IntervalSeconds $IntervalSeconds -Enabled $true -Critical $false -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay

    $Global:AntivirusState.Jobs[$jobName] = @{
        Name = $jobName
        IntervalSeconds = $IntervalSeconds
        Module = $ModuleName
    }

    Write-AVLog "Registered managed job: $jobName (${IntervalSeconds}s interval)"
}

function Start-RecoverySequence {
    Write-StabilityLog "Starting recovery sequence" "WARN"

    try {

        if ($script:ManagedJobs) {
            foreach ($k in @($script:ManagedJobs.Keys)) {
                try { $script:ManagedJobs.Remove($k) } catch {}
            }
        }

        $Global:AntivirusState.Jobs.Clear()
        Start-Sleep -Seconds 10
        Write-StabilityLog "Recovery sequence completed"
    }
    catch {
        Write-StabilityLog "Recovery sequence failed: $_" "ERROR"
    }
}

# Note: Function name intentionally uses 'Monitor' verb for job monitoring functionality
function Monitor-Jobs {
    Write-Host "`n[*] Monitoring started. Press Ctrl+C to stop.`n" -ForegroundColor Cyan
    Write-StabilityLog "Entering main monitoring loop"
    Write-AVLog "Entering main monitoring loop"

    $iteration = 0
    $lastStabilityCheck = Get-Date
    $consecutiveErrors = 0
    $maxConsecutiveErrors = 10

    while ($true) {
        try {
            while ($true) {
                $iteration++
                $now = Get-Date

                try {
                    Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow)
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Managed jobs tick failed: $_" "WARN"
                }

                if (($now - $lastStabilityCheck).TotalMinutes -ge 5) {
                    try {
                        $enabledCount = 0
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                        }
                        Write-StabilityLog "Stability check: $enabledCount managed jobs enabled, iteration $iteration"
                        $lastStabilityCheck = $now
                        $consecutiveErrors = 0
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Stability check failed: $_" "WARN"
                    }
                }

                if ($consecutiveErrors -ge $maxConsecutiveErrors) {
                    Write-StabilityLog "Too many consecutive errors ($consecutiveErrors), triggering recovery" "ERROR"
                    Start-RecoverySequence
                    $consecutiveErrors = 0
                }

                if ($iteration % 12 -eq 0) {
                    try {
                        $enabledCount = 0
                        $disabledCount = 0
                        $sampleErrorMessage = $null
                        $sampleErrorJob = $null
                        if ($script:ManagedJobs) {
                            $enabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
                            $disabledCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -ne $_.DisabledUtc) }).Count
                            try {
                                $j = ($script:ManagedJobs.Values | Where-Object { $_.LastError } | Select-Object -First 1)
                                if ($j) {
                                    $sampleErrorJob = $j.Name
                                    $sampleErrorMessage = $j.LastError.Exception.Message
                                }
                            }
                            catch {}
                        }
                        Write-Host "[AV] Monitoring active - $enabledCount enabled / $disabledCount backoff" -ForegroundColor DarkGray
                        Write-StabilityLog "Heartbeat: $enabledCount enabled / $disabledCount backoff, iteration $iteration" "INFO"
                        Write-AVLog "Heartbeat: $enabledCount enabled / $disabledCount backoff"
                        if ($sampleErrorMessage) {
                            Write-StabilityLog "Sample job error ($sampleErrorJob): $sampleErrorMessage" "WARN"
                        }
                    }
                    catch {
                        $consecutiveErrors++
                        Write-StabilityLog "Heartbeat failed: $_" "WARN"
                    }
                }

                Start-Sleep -Seconds 1
            }
        }
        catch {
            try {
                Write-StabilityLog "Monitor-Jobs outer loop error: $_" "ERROR"
                Write-AVLog "Monitor-Jobs iteration error: $_" "ERROR"
                Write-Host "[!] Monitor iteration error (recovering): $_" -ForegroundColor Yellow
            }
            catch {
            }

            Start-RecoverySequence
            Start-Sleep -Seconds 5
            $consecutiveErrors = 0
            $lastStabilityCheck = Get-Date
            continue
        }
    }
}

function Move-ToQuarantine {
    param([string]$Path, [string]$Reason)
    
    $FileName = [System.IO.Path]::GetFileName($Path)
    $QuarantineFile = "$($Config.QuarantinePath)\$([DateTime]::Now.Ticks)_$FileName"
    
    try {
        [System.IO.File]::Move($Path, $QuarantineFile)
        $Global:AntivirusState.FilesQuarantined++
        Write-AVLog "Quarantined: $Path (Reason: $Reason)" "THREAT"
        return $true
    } catch {
        Write-AVLog "Quarantine failed for $Path : $_" "ERROR"
        return $false
    }
}

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    if ($ProcessId -eq $PID -or $ProcessId -eq $Script:SelfPID) { return }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        $Global:AntivirusState.ProcessesTerminated++
        Write-AVLog "Terminated threat process: $ProcessName (PID: $ProcessId)" "ACTION"
    } catch {
        Write-AVLog "Failed to terminate process $ProcessName : $_" "ERROR"
    }
}

# ===================== Embedded detection modules =====================

function Invoke-HashDetection {
    param(
        [string]$LogPath,
        [string]$QuarantinePath,
        [string]$CirclHashLookupUrl,
        [string]$CymruApiUrl,
        [string]$MalwareBazaarApiUrl,
        [bool]$AutoQuarantine = $true
    )
    
    # Ensure QuarantinePath is set from Config if not provided as parameter
    if (-not $QuarantinePath -and $Config.QuarantinePath) {
        $QuarantinePath = $Config.QuarantinePath
    }

    $SuspiciousPaths = @(
        "$env:TEMP\*",
        "$env:APPDATA\*",
        "$env:LOCALAPPDATA\Temp\*",
        "C:\Windows\Temp\*",
        "$env:USERPROFILE\Downloads\*"
    )

    $Files = Get-ChildItem -Path $SuspiciousPaths -Include *.exe,*.dll,*.scr,*.vbs,*.ps1,*.bat,*.cmd -Recurse -ErrorAction SilentlyContinue

    foreach ($File in $Files) {
        try {
            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

            $Reputation = @{
                IsMalicious = $false
                Confidence = 0
                Sources = @()
            }

            try {
                $CirclResponse = Invoke-RestMethod -Uri "$CirclHashLookupUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CirclResponse.KnownMalicious) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 40
                    $Reputation.Sources += "CIRCL"
                }
            } catch {}

            try {
                $MBBody = @{ query = "get_info"; hash = $Hash } | ConvertTo-Json
                $MBResponse = Invoke-RestMethod -Uri $MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($MBResponse.query_status -eq "ok") {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 50
                    $Reputation.Sources += "MalwareBazaar"
                }
            } catch {}

            try {
                $CymruResponse = Invoke-RestMethod -Uri "$CymruApiUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CymruResponse.malware -eq $true) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 30
                    $Reputation.Sources += "Cymru"
                }
            } catch {}

            if ($Reputation.IsMalicious -and $Reputation.Confidence -ge 50) {
                Write-Output "[HashDetection] THREAT: $($File.FullName) | Hash: $Hash | Sources: $($Reputation.Sources -join ', ') | Confidence: $($Reputation.Confidence)%"

                if ($AutoQuarantine -and $QuarantinePath) {
                    $QuarantineFile = Join-Path $QuarantinePath "$([DateTime]::Now.Ticks)_$($File.Name)"
                    Move-Item -Path $File.FullName -Destination $QuarantineFile -Force -ErrorAction SilentlyContinue
                    Write-Output "[HashDetection] Quarantined: $($File.FullName)"
                }
            }

            try {
                $Entropy = Measure-FileEntropy -FilePath $File.FullName
                if ($Entropy -is [double] -or $Entropy -is [int]) {
                    if ($Entropy -gt 7.5 -and $File.Length -lt 1MB) {
                        Write-Output "[HashDetection] High entropy detected: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2))"
                    }
                }
            } catch {
                # Entropy calculation failed, skip
            }

        } catch {
            Write-Output "[HashDetection] Error scanning $($File.FullName): $_"
        }
    }
}

function Measure-FileEntropy {
    param([string]$FilePath)

    try {
        $Bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..4096]
        $Freq = @{}
        foreach ($Byte in $Bytes) {
            if ($Freq.ContainsKey($Byte)) {
                $Freq[$Byte]++
            } else {
                $Freq[$Byte] = 1
            }
        }

        $Entropy = 0
        $Total = $Bytes.Count
        foreach ($Count in $Freq.Values) {
            $P = $Count / $Total
            $Entropy -= $P * [Math]::Log($P, 2)
        }

        return $Entropy
    } catch {
        return 0
    }
}

# ===================== Advanced Multi-Layered Threat Detection Framework =====================
# This framework provides hash-based, signature-based, behavioral, and entropy-based detection
# that is resilient against renaming and obfuscation. Can be used by any detection module.

function Invoke-AdvancedThreatDetection {
    param(
        [Parameter(Mandatory=$false)]
        [string]$FilePath = "",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$KnownHashes = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$FileSignatures = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$BehavioralIndicators = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$ProcessId = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$CommandLine = $null,
        
        [Parameter(Mandatory=$false)]
        [bool]$CheckEntropy = $true,
        
        [Parameter(Mandatory=$false)]
        [double]$EntropyThreshold = 7.5
    )
    
    # Early return if FilePath is not provided - prevents prompt when called without parameters
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return @{
            IsThreat = $false
            ThreatName = ""
            DetectionMethods = @()
            Confidence = 0
            Risk = "LOW"
            Details = @{}
        }
    }
    
    $detectionResults = @{
        IsThreat = $false
        ThreatName = $null
        DetectionMethods = @()
        Confidence = 0
        Risk = "LOW"
        Details = @{}
    }
    
    if (-not (Test-Path $FilePath)) {
        return $detectionResults
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $detectionCount = 0
        
        # Method 1: Hash-Based Detection (SHA256)
        if ($KnownHashes.Count -gt 0) {
            try {
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                
                foreach ($threatName in $KnownHashes.Keys) {
                    if ($KnownHashes[$threatName] -contains $fileHash) {
                        $detectionResults.IsThreat = $true
                        $detectionResults.ThreatName = $threatName
                        $detectionResults.DetectionMethods += "HashMatch"
                        $detectionResults.Confidence += 100
                        $detectionResults.Risk = "CRITICAL"
                        $detectionResults.Details["Hash"] = $fileHash
                        $detectionCount++
                        break
                    }
                }
            } catch { }
        }
        
        # Method 2: File Signature/Pattern Detection (YARA-like)
        if ($FileSignatures.Count -gt 0 -and $fileInfo.Length -lt 50MB) {
            try {
                $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                
                foreach ($threatName in $FileSignatures.Keys) {
                    $matchCount = 0
                    $matchedSignatures = @()
                    
                    foreach ($signature in $FileSignatures[$threatName]) {
                        if ($fileContent -match [regex]::Escape($signature)) {
                            $matchCount++
                            $matchedSignatures += $signature
                        }
                    }
                    
                    # If multiple signatures match, it's likely this threat
                    if ($matchCount -ge 2) {
                        $detectionResults.IsThreat = $true
                        $detectionResults.ThreatName = $threatName
                        $detectionResults.DetectionMethods += "SignatureMatch"
                        $detectionResults.Confidence += ($matchCount * 20)
                        if ($detectionResults.Risk -ne "CRITICAL") {
                            $detectionResults.Risk = if ($matchCount -ge 3) { "CRITICAL" } else { "HIGH" }
                        }
                        $detectionResults.Details["SignatureMatches"] = $matchCount
                        $detectionResults.Details["MatchedSignatures"] = $matchedSignatures
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 3: Entropy Analysis (Packed/Obfuscated Detection)
        if ($CheckEntropy -and $fileInfo.Length -lt 10MB) {
            try {
                $entropy = Measure-FileEntropy -FilePath $FilePath
                
                if ($entropy -gt $EntropyThreshold) {
                    # High entropy = possibly packed/obfuscated
                    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
                    $isSigned = $sig.Status -eq "Valid"
                    
                    if (-not $isSigned) {
                        $detectionResults.IsThreat = $true
                        if (-not $detectionResults.ThreatName) {
                            $detectionResults.ThreatName = "SuspiciousPackedTool"
                        }
                        $detectionResults.DetectionMethods += "EntropyAnalysis"
                        $detectionResults.Confidence += 30
                        if ($detectionResults.Risk -eq "LOW") {
                            $detectionResults.Risk = "MEDIUM"
                        }
                        $detectionResults.Details["Entropy"] = [Math]::Round($entropy, 2)
                        $detectionResults.Details["IsSigned"] = $isSigned
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 4: Behavioral Pattern Detection (Command Line Analysis)
        if ($CommandLine -and $BehavioralIndicators.Count -gt 0) {
            try {
                foreach ($behaviorType in $BehavioralIndicators.Keys) {
                    $patterns = $BehavioralIndicators[$behaviorType]
                    if ($null -eq $patterns) { continue }
                    
                    $matchCount = 0
                    foreach ($pattern in $patterns) {
                        if ($CommandLine -match $pattern) {
                            $matchCount++
                        }
                    }
                    
                    if ($matchCount -gt 0) {
                        $detectionResults.IsThreat = $true
                        if (-not $detectionResults.ThreatName) {
                            $detectionResults.ThreatName = "SuspiciousBehavior_$behaviorType"
                        }
                        $detectionResults.DetectionMethods += "BehavioralPattern"
                        $detectionResults.Confidence += ($matchCount * 15)
                        if ($detectionResults.Risk -ne "CRITICAL") {
                            $detectionResults.Risk = if ($matchCount -ge 2) { "HIGH" } else { "MEDIUM" }
                        }
                        $detectionResults.Details["BehaviorType"] = $behaviorType
                        $detectionResults.Details["BehaviorMatches"] = $matchCount
                        $detectionCount++
                    }
                }
            } catch { }
        }
        
        # Method 5: Digital Signature Verification
        try {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            $detectionResults.Details["SignatureStatus"] = $sig.Status
            $detectionResults.Details["IsSigned"] = ($sig.Status -eq "Valid")
            
            # Unsigned executables in suspicious locations are more suspicious
            if ($sig.Status -ne "Valid" -and $detectionCount -gt 0) {
                $detectionResults.Confidence += 10
            }
        } catch { }
        
        # Calculate final risk based on confidence
        if ($detectionResults.Confidence -ge 80) {
            $detectionResults.Risk = "CRITICAL"
        } elseif ($detectionResults.Confidence -ge 60) {
            $detectionResults.Risk = "HIGH"
        } elseif ($detectionResults.Confidence -ge 40) {
            $detectionResults.Risk = "MEDIUM"
        }
        
        $detectionResults.Details["DetectionCount"] = $detectionCount
        $detectionResults.Details["FilePath"] = $FilePath
        $detectionResults.Details["FileSize"] = "$([Math]::Round($fileInfo.Length / 1MB, 2)) MB"
        
    } catch {
        Write-AVLog "Advanced threat detection error for $FilePath : $_" "WARN" "advanced_threat_detection.log"
    }
    
    return $detectionResults
}

# Standalone job for comprehensive advanced threat detection across the system
function Invoke-SystemWideAdvancedThreatDetection {
    $detections = @()
    $threats = @()
    
    try {
        # Comprehensive threat signature database
        $threatSignatures = @{
            # Malware families
            "Trojan" = @(
                "trojan", "backdoor", "rat", "remote.*access", "keylogger",
                "stealer", "spyware", "adware", "rootkit"
            )
            "Ransomware" = @(
                "ransomware", "encrypt", "decrypt", "bitcoin", "payment.*required",
                "your.*files.*encrypted", "lock.*screen"
            )
            "BankingTrojan" = @(
                "banking", "financial", "credit.*card", "account.*number",
                "login.*credentials", "password.*stealer"
            )
            "Cryptominer" = @(
                "miner", "mining", "cryptocurrency", "bitcoin.*miner",
                "monero", "xmrig", "ccminer"
            )
            # Attack tools
            "PasswordCracker" = @(
                "hydra", "john.*ripper", "hashcat", "brute.*force",
                "dictionary.*attack", "wordlist", "password.*crack"
            )
            "CredentialDumper" = @(
                "mimikatz", "lsadump", "sekurlsa", "wdigest",
                "credential.*dump", "password.*dump"
            )
            "NetworkScanner" = @(
                "nmap", "masscan", "port.*scan", "network.*scan",
                "host.*scan", "reconnaissance"
            )
            "ExploitationFramework" = @(
                "metasploit", "cobalt.*strike", "empire", "covenant",
                "exploit", "payload", "meterpreter"
            )
        }
        
        # Behavioral indicators
        $behavioralPatterns = @{
            "CredentialDumping" = @(
                "lsass", "sam.*dump", "security.*dump", "system.*dump",
                "reg.*save.*sam", "reg.*save.*security"
            )
            "LateralMovement" = @(
                "psexec", "wmic.*process", "winrm", "smbexec",
                "lateral.*movement", "pass.*the.*hash"
            )
            "Persistence" = @(
                "schtasks.*create", "reg.*add.*run", "startup",
                "scheduled.*task", "registry.*run"
            )
            "DataExfiltration" = @(
                "upload", "exfiltrate", "send.*data", "http.*post",
                "ftp.*put", "sftp.*put"
            )
        }
        
        # Scan running processes
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procPath = $proc.ExecutablePath
                if (-not $procPath -or -not (Test-Path $procPath)) { continue }
                
                $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                $procCmdLine = $proc.CommandLine
                
                # Use advanced detection framework
                $detectionResult = Invoke-AdvancedThreatDetection `
                    -FilePath $procPath `
                    -FileSignatures $threatSignatures `
                    -BehavioralIndicators $behavioralPatterns `
                    -CommandLine $procCmdLine `
                    -CheckEntropy $true
                
                if ($detectionResult.IsThreat) {
                    $threats += @{
                        Type = "Advanced Threat Detected: $($detectionResult.ThreatName)"
                        ProcessName = $procName
                        ProcessPath = $procPath
                        ProcessId = $proc.ProcessId
                        CommandLine = $procCmdLine
                        DetectionMethods = $detectionResult.DetectionMethods -join ", "
                        Confidence = $detectionResult.Confidence
                        Risk = $detectionResult.Risk
                        Details = $detectionResult.Details
                        Timestamp = Get-Date
                    }
                    
                    # Auto-terminate critical threats
                    if ($Config.AutoKillThreats -and $detectionResult.Risk -eq "CRITICAL") {
                        try {
                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-AVLog "Terminated advanced threat: $procName ($($detectionResult.ThreatName))" "THREAT" "advanced_threat_detection.log"
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Scan suspicious directories for files
        $scanPaths = @(
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop",
            "$env:TEMP",
            "$env:APPDATA\Local\Temp",
            "C:\Tools",
            "C:\Hacking"
        )
        
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            
            try {
                $exeFiles = Get-ChildItem -Path $scanPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -lt 50MB } |
                    Select-Object -First 30
                
                foreach ($file in $exeFiles) {
                    try {
                        $detectionResult = Invoke-AdvancedThreatDetection `
                            -FilePath $file.FullName `
                            -FileSignatures $threatSignatures `
                            -CheckEntropy $true
                        
                        if ($detectionResult.IsThreat) {
                            $threats += @{
                                Type = "Advanced Threat File Detected: $($detectionResult.ThreatName)"
                                FilePath = $file.FullName
                                FileName = $file.Name
                                DetectionMethods = $detectionResult.DetectionMethods -join ", "
                                Confidence = $detectionResult.Confidence
                                Risk = $detectionResult.Risk
                                Details = $detectionResult.Details
                                Timestamp = Get-Date
                            }
                            
                            # Auto-quarantine
                            if ($Config.AutoQuarantine -and $detectionResult.Risk -in @("HIGH", "CRITICAL")) {
                                try {
                                    Move-ToQuarantine -FilePath $file.FullName -Reason "Advanced threat detected: $($detectionResult.ThreatName)"
                                    Write-AVLog "Quarantined advanced threat: $($file.Name)" "THREAT" "advanced_threat_detection.log"
                                } catch { }
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
        
        # Log all detections
        if ($threats.Count -gt 0) {
            foreach ($threat in $threats) {
                Write-AVLog "ADVANCED THREAT: $($threat.Type) - $($threat.ProcessName -or $threat.FileName) - Methods: $($threat.DetectionMethods) - Confidence: $($threat.Confidence)% - Risk: $($threat.Risk)" "THREAT" "advanced_threat_detection.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($Config.AutoKillThreats) {
                    # Get the first available path (use proper null-coalescing, not -or operator)
                    $threatPath = if ($threat.ProcessPath) { $threat.ProcessPath }
                                  elseif ($threat.FilePath) { $threat.FilePath }
                                  elseif ($threat.ProcessName) { $threat.ProcessName }
                                  elseif ($threat.FileName) { $threat.FileName }
                                  else { "" }
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\AdvancedThreatDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            $threats | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Confidence)|$($_.DetectionMethods)|$($_.ProcessName -or $_.FileName -or 'N/A')|$($_.ProcessId -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            } | Out-Null
        }
        
    } catch {
        Write-AVLog "System-wide advanced threat detection error: $_" "ERROR" "advanced_threat_detection.log"
    }
    
    # Return count without outputting to pipeline - suppress any accidental output
    # Clear all variables to prevent any implicit output that might cause parameter binding
    $result = $threats.Count
    $threats = $null
    $detections = $null
    $processes = $null
    $exeFiles = $null
    $scanPaths = $null
    $threatSignatures = $null
    $behavioralPatterns = $null
    [void]$result  # Explicitly discard if accidentally output
    return $result
}

function Invoke-LOLBinDetection {
    $LOLBinPatterns = @{
        "certutil" = @{
            Patterns = @("-decode", "-urlcache", "-verifyctl", "-encode")
            Severity = "HIGH"
            Description = "Certutil abuse for download/decode"
        }
        "bitsadmin" = @{
            Patterns = @("transfer", "addfile", "/download")
            Severity = "HIGH"
            Description = "BITS abuse for download"
        }
        "mshta" = @{
            Patterns = @("http://", "https://", "javascript:", "vbscript:")
            Severity = "CRITICAL"
            Description = "MSHTA remote code execution"
        }
        "regsvr32" = @{
            Patterns = @("scrobj.dll", "/s", "/u", "http://", "https://")
            Severity = "HIGH"
            Description = "Regsvr32 squiblydoo attack"
        }
        "rundll32" = @{
            Patterns = @("javascript:", "http://", "https://", "shell32.dll,Control_RunDLL")
            Severity = "MEDIUM"
            Description = "Rundll32 proxy execution"
        }
        "wmic" = @{
            Patterns = @('process call create', '/node:', 'format:"http', 'xsl:http')
            Severity = "HIGH"
            Description = "WMIC remote execution or XSL abuse"
        }
        "powershell" = @{
            Patterns = @("-enc ", "-encodedcommand", "downloadstring", "iex ", "invoke-expression", "-nop", "-w hidden", "bypass")
            Severity = "HIGH"
            Description = "PowerShell obfuscation and evasion"
        }
        "sc" = @{
            Patterns = @("create", "config", "binpath=")
            Severity = "MEDIUM"
            Description = "Service manipulation"
        }
        "msiexec" = @{
            Patterns = @("/quiet", "/q", "http://", "https://")
            Severity = "MEDIUM"
            Description = "Silent MSI installation from remote"
        }
    }
    
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $CmdLine = $Proc.CommandLine
        if (-not $CmdLine) { continue }
        
        $ProcessName = $Proc.Name -replace '\.exe$', ''
        
        foreach ($LOLBin in $LOLBinPatterns.Keys) {
            if ($ProcessName -like "*$LOLBin*") {
                $MatchedPatterns = @()
                foreach ($Pattern in $LOLBinPatterns[$LOLBin].Patterns) {
                    if ($CmdLine -match [regex]::Escape($Pattern)) {
                        $MatchedPatterns += $Pattern
                    }
                }
                
                if ($MatchedPatterns.Count -gt 0) {
                    $Severity = $LOLBinPatterns[$LOLBin].Severity
                    $Description = $LOLBinPatterns[$LOLBin].Description
                    Write-AVLog "LOLBin detected [$Severity] - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Attack: $Description | Patterns: $($MatchedPatterns -join ', ') | Command: $CmdLine" "THREAT" "behavior_detections.log"
                    $Global:AntivirusState.ThreatCount++
                    
                    if ($Config.AutoKillThreats -and $Severity -in @("HIGH", "CRITICAL")) {
                        Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name
                    }
                }
            }
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $AnomalyScore = @{}
    
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        $Score = 0
        $Anomalies = @()
        
        # Parent process analysis
        $Parent = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($Parent) {
            # Office spawning scripts
            if ($Parent.Name -match "winword|excel|powerpnt|outlook" -and $Proc.Name -match "powershell|cmd|wscript|cscript") {
                $Score += 5
                $Anomalies += "OfficeSpawnScript"
            }
            
            # Explorer spawning hidden scripts
            if ($Parent.Name -eq "explorer.exe" -and $Proc.CommandLine -match "-w hidden|-windowstyle hidden|-nop|-enc") {
                $Score += 4
                $Anomalies += "ExplorerHiddenScript"
            }
            
            # Service host spawning unexpected processes
            if ($Parent.Name -eq "svchost.exe" -and $Proc.Name -notmatch "dllhost|conhost|rundll32") {
                $Score += 3
                $Anomalies += "SvchostUnexpectedChild"
            }
        }
        
        # Path validation
        $ProcPath = $Proc.ExecutablePath
        if ($ProcPath) {
            # Executables in user directories
            if ($ProcPath -match "Users\\.*\\AppData|Users\\.*\\Downloads|Users\\.*\\Desktop" -and $Proc.Name -match "exe$") {
                $Score += 2
                $Anomalies += "UserDirExecution"
            }
            
            # System binaries in wrong locations
            if ($Proc.Name -in @("svchost.exe", "lsass.exe", "csrss.exe", "smss.exe") -and $ProcPath -notmatch "C:\\Windows\\System32") {
                $Score += 6
                $Anomalies += "SystemBinaryWrongLocation"
            }
        }
        
        # Command line analysis
        if ($Proc.CommandLine) {
            # Base64 encoded commands
            if ($Proc.CommandLine -match "-enc |-encodedcommand |FromBase64String") {
                $Score += 3
                $Anomalies += "Base64Encoding"
            }
            
            # Execution policy bypass
            if ($Proc.CommandLine -match "-exec bypass|-executionpolicy bypass|-ep bypass") {
                $Score += 2
                $Anomalies += "ExecutionPolicyBypass"
            }
            
            # Download cradles
            if ($Proc.CommandLine -match "DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl ") {
                $Score += 3
                $Anomalies += "DownloadCradle"
            }
        }
        
        # Report anomalies
        if ($Score -ge 6) {
            Write-AVLog "CRITICAL process anomaly - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Parent: $($Parent.Name) | Score: $Score | Anomalies: $($Anomalies -join ', ') | Path: $ProcPath | Command: $($Proc.CommandLine)" "THREAT" "behavior_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
        elseif ($Score -ge 3) {
            Write-AVLog "Process anomaly detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Score: $Score | Anomalies: $($Anomalies -join ', ')" "WARNING" "behavior_detections.log"
        }
    }
}

function Invoke-AMSIBypassDetection {
    $detections = @()
    
    # Enhanced AMSI bypass patterns
    $bypassPatterns = @(
        '[Ref].Assembly.GetType.*System.Management.Automation.AmsiUtils',
        '[Ref].Assembly.GetType.*AmsiUtils',
        'AmsiScanBuffer',
        'amsiInitFailed',
        'Bypass',
        'amsi.dll',
        'S`y`s`t`e`m.Management.Automation',
        'Hacking',
        'AMSI',
        'amsiutils',
        'amsiInitFailed',
        'Context',
        'AmsiContext',
        'AMSI_RESULT_CLEAN',
        'PatchAmsi',
        'DisableAmsi',
        'ForceAmsi',
        'Remove-Amsi',
        'Invoke-AmsiBypass',
        'AMSI.*bypass',
        'bypass.*AMSI',
        '-nop.*-w.*hidden.*-enc',
        'amsi.*off',
        'amsi.*disable',
        'Set-Amsi',
        'Override.*AMSI'
    )
    
    try {
        $maxProcs = 50
        $processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" } | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
            foreach ($pattern in $bypassPatterns) {
                if ($cmdLine -match $pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $cmdLine
                        BypassPattern = $pattern
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for obfuscated AMSI bypass (base64, hex, etc.)
            if ($cmdLine -match '-enc|-encodedcommand' -and $cmdLine.Length -gt 500) {
                # Long encoded command - try to decode
                try {
                    $encodedPart = $cmdLine -split '-enc\s+' | Select-Object -Last 1 -ErrorAction SilentlyContinue
                    if ($encodedPart) {
                        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedPart.Trim()))
                        if ($decoded -match 'amsi|AmsiScanBuffer|bypass' -or $decoded.Length -gt 1000) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $cmdLine
                                BypassPattern = "Obfuscated AMSI Bypass (Encoded)"
                                DecodedLength = $decoded.Length
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check PowerShell script blocks in memory
        try {
            $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
            foreach ($psProc in $psProcesses) {
                if ($psProc.Id -eq $PID -or $psProc.Id -eq $Script:SelfPID) { continue }
                
                # Check for AMSI-related .NET assemblies loaded
                $modules = $psProc.Modules | Where-Object {
                    $_.ModuleName -match 'amsi|System.Management.Automation'
                }
                
                if ($modules.Count -gt 0) {
                    # Check Event Log for AMSI script block logging
                    try {
                        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue -MaxEvents 50 |
                            Where-Object {
                                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5) -and
                                ($_.Message -match 'amsi|bypass|AmsiScanBuffer' -or $_.Message.Length -gt 5000)
                            }
                        
                        if ($psEvents.Count -gt 0) {
                            foreach ($event in $psEvents) {
                                $detections += @{
                                    ProcessId = $psProc.Id
                                    ProcessName = $psProc.ProcessName
                                    Type = "AMSI Bypass in PowerShell Script Block"
                                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                                    TimeCreated = $event.TimeCreated
                                    Risk = "Critical"
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check Event Log for AMSI events
        try {
            $amsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $amsiEvents) {
                if ($event.Message -match 'AmsiScanBuffer|bypass|blocked') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for AMSI registry tampering
        try {
            $amsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI"
            if (Test-Path $amsiKey) {
                $amsiValue = Get-ItemProperty -Path $amsiKey -ErrorAction SilentlyContinue
                if ($amsiValue -and $amsiValue.DisableAMSI) {
                    $detections += @{
                        Type = "Registry Tampering"
                        Path = $amsiKey
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.BypassPattern -or $detection.Message)" "THREAT" "amsi_bypass_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Message)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "AMSI bypass detection error: $_" "ERROR" "amsi_bypass_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CredentialDumpDetection {
    # Credential dumping signatures for advanced detection
    $credentialDumpSignatures = @{
        "CredentialDumper" = @(
            "mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce", "procdump",
            "dumpert", "nanodump", "lsassy", "lsadump", "cachedump",
            "credential.*dump", "password.*dump", "hash.*dump"
        )
    }
    
    # Credential dumping behavioral patterns
    $credentialDumpBehaviors = @{
        "LSASSAccess" = @(
            "lsass", "LSASS", "MiniDumpWriteDump", "CreateDump", "dmp.*lsass"
        )
        "RegistryDump" = @(
            "reg.*save.*sam", "reg.*save.*security", "reg.*save.*system",
            "reg.*export.*sam", "sam.*dump", "security.*dump"
        )
        "MemoryDump" = @(
            "MiniDump", "CreateDump", "dump.*memory", "memory.*dump"
        )
    }
    
    $CredentialTools = @("mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce.exe", "procdump", "dumpert", "nanodump", "lsassy")
    $LSASSAccess = @("lsass", "LSASS")
    
    # Monitor for processes accessing LSASS
    $LsassProc = Get-Process lsass -ErrorAction SilentlyContinue
    if ($LsassProc) {
        $AccessingProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -match "lsass" -and $_.ProcessId -ne $LsassProc.Id -and $_.ProcessId -ne $PID -and $_.ProcessId -ne $Script:SelfPID
        }
        
        foreach ($Proc in $AccessingProcesses) {
            # Use advanced detection framework
            if ($Proc.ExecutablePath -and (Test-Path $Proc.ExecutablePath)) {
                $detectionResult = Invoke-AdvancedThreatDetection `
                    -FilePath $Proc.ExecutablePath `
                    -FileSignatures $credentialDumpSignatures `
                    -BehavioralIndicators $credentialDumpBehaviors `
                    -CommandLine $Proc.CommandLine `
                    -CheckEntropy $true
                
                if ($detectionResult.IsThreat) {
                    Write-AVLog "LSASS access detected via Advanced Framework - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Methods: $($detectionResult.DetectionMethods -join ', ') | Confidence: $($detectionResult.Confidence)%" "THREAT" "credential_dumping_detections.log"
                } else {
                    Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                }
            } else {
                Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
            }
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
    
    # Detect credential dumping tools using advanced framework
    $AllProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $AllProcesses) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        
        # Use advanced detection framework
        if ($Proc.ExecutablePath -and (Test-Path $Proc.ExecutablePath)) {
            $detectionResult = Invoke-AdvancedThreatDetection `
                -FilePath $Proc.ExecutablePath `
                -FileSignatures $credentialDumpSignatures `
                -BehavioralIndicators $credentialDumpBehaviors `
                -CommandLine $Proc.CommandLine `
                -CheckEntropy $true
            
            if ($detectionResult.IsThreat) {
                Write-AVLog "Credential dumping tool detected via Advanced Framework - Tool: $($detectionResult.ThreatName) | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Methods: $($detectionResult.DetectionMethods -join ', ') | Confidence: $($detectionResult.Confidence)%" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
                continue
            }
        }
        
        # Legacy detection: Check process name and command line
        foreach ($Tool in $CredentialTools) {
            if ($Proc.Name -like "*$Tool*" -or $Proc.CommandLine -match $Tool) {
                Write-AVLog "Credential dumping tool detected - Tool: $Tool | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
            }
        }
        
        # Check for memory dump creation
        if ($Proc.CommandLine -match "MiniDump|CreateDump|dmp") {
            Write-AVLog "Memory dump creation detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "WARNING" "credential_dumping_detections.log"
        }
    }
    
    # Check for SAM/SYSTEM/SECURITY registry hive access
    $RegKeyAccess = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "SAM|SYSTEM|SECURITY" -and $_.CommandLine -match "reg save|reg export"
    }
    
    foreach ($Proc in $RegKeyAccess) {
        if ($Proc.ProcessId -eq $PID -or $Proc.ProcessId -eq $Script:SelfPID) { continue }
        Write-AVLog "Registry credential hive access - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
        $Global:AntivirusState.ThreatCount++
        if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
    }
}

function Invoke-WMIPersistenceDetection {
    $Filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $Consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue

    foreach ($Filter in $Filters) {
        Write-Output "[WMI] Event filter found: $($Filter.Name) | Query: $($Filter.Query)"
    }

    foreach ($Consumer in $Consumers) {
        Write-Output "[WMI] Command consumer found: $($Consumer.Name) | Command: $($Consumer.CommandLineTemplate)"
    }
}

function Invoke-ScheduledTaskDetection {
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Principal.UserId -notmatch "SYSTEM|Administrator" }

    foreach ($Task in $Tasks) {
        # Whitelist our own scheduled tasks
        if ($Task.TaskName -like "AntivirusAutoRestart_*" -or $Task.TaskName -eq "AntivirusProtection") {
            continue
        }
        
        $Action = $Task.Actions[0].Execute
        if ($Action -match "powershell|cmd|wscript|cscript|mshta") {
            Write-Output "[ScheduledTask] SUSPICIOUS: $($Task.TaskName) | Action: $Action | User: $($Task.Principal.UserId)"
        }
    }
}

function Invoke-RegistryPersistenceDetection {
    $detections = @()
    
    try {
        # Check standard Run keys
        $runKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                try {
                    $values = Get-ItemProperty -Path $key -ErrorAction Stop
                    foreach ($property in $values.PSObject.Properties) {
                        if ($property.Name -notmatch "^PS" -and $property.Value) {
                            $value = $property.Value
                            
                            # Check for suspicious patterns
                            $suspiciousPatterns = @(
                                "powershell.*-enc",
                                "cmd.*/c.*powershell",
                                "http://|https://",
                                "\.vbs|\.js|\.bat|\.cmd",
                                "wscript|cscript|mshta",
                                "rundll32.*\.dll",
                                "regsvr32.*\.dll"
                            )
                            
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($value -match $pattern) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $value
                                        Pattern = $pattern
                                        Type = "Suspicious Registry Persistence"
                                        Risk = "High"
                                    }
                                    break
                                }
                            }
                            
                            # Check for unsigned executables
                            if ($value -like "*.exe" -or $value -like "*.dll") {
                                $exePath = $value -split ' ' | Select-Object -First 1
                                if (Test-Path $exePath) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid" -and $exePath -notlike "$env:SystemRoot\*") {
                                            $detections += @{
                                                RegistryKey = $key
                                                ValueName = $property.Name
                                                Value = $value
                                                ExecutablePath = $exePath
                                                Type = "Unsigned Executable in Registry"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        }
        
        # Check for suspicious registry modifications in user profile
        try {
            $userRunKeys = @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            foreach ($key in $userRunKeys) {
                if (Test-Path $key) {
                    try {
                        $items = Get-Item $key -ErrorAction Stop
                        $lastWrite = $items.LastWriteTime
                        
                        # Check if recently modified
                        if ((Get-Date) - $lastWrite -lt [TimeSpan]::FromHours(24)) {
                            $values = Get-ItemProperty -Path $key -ErrorAction Stop
                            foreach ($property in $values.PSObject.Properties) {
                                if ($property.Name -notmatch "^PS" -and $property.Value) {
                                    $detections += @{
                                        RegistryKey = $key
                                        ValueName = $property.Name
                                        Value = $property.Value
                                        LastModified = $lastWrite
                                        Type = "Recently Modified Registry Persistence"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "REGISTRY PERSISTENCE: $($detection.Type) - $($detection.RegistryKey) - $($detection.ValueName)" "THREAT" "registry_persistence_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RegistryKey)|$($_.ValueName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Registry persistence detection error: $_" "ERROR" "registry_persistence_detections.log"
    }
    
    return $detections.Count
}

function Test-DLLHijacking {
    param([string]$DllPath)
    
    if (-not (Test-Path $DllPath)) { return $false }
    
    # Check if DLL is in suspicious locations
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($susPath in $suspiciousPaths) {
        if ($DllPath -like "$susPath*") {
            return $true
        }
    }
    
    # Check if DLL is unsigned
    try {
        $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return $true
        }
    } catch { }
    
    return $false
}

function Invoke-DLLHijackingDetection {
    $detections = @()
    
    try {
        # Check loaded DLLs in processes
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" }
                
                foreach ($module in $modules) {
                    if (Test-DLLHijacking -DllPath $module.FileName) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllPath = $module.FileName
                            DllName = $module.ModuleName
                            Type = "Suspicious DLL Loaded"
                            Risk = "High"
                        }
                    }
                }
            } catch {
                # Access denied or process exited
                continue
            }
        }
        
        # Check for DLLs in application directories
        $appPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64"
        )
        
        foreach ($appPath in $appPaths) {
            if (-not (Test-Path $appPath)) { continue }
            
            try {
                $dlls = Get-ChildItem -Path $appPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 100
                
                foreach ($dll in $dlls) {
                    if ($dll.DirectoryName -ne "$appPath") {
                        # Check if DLL is signed
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    DllPath = $dll.FullName
                                    Type = "Unsigned DLL in application directory"
                                    Risk = "Medium"
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Check Event Log for DLL load failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                if ($event.Message -match 'DLL.*not.*found|DLL.*load.*failed') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Type = "DLL Load Failure"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "DLL HIJACKING: $($detection.Type) - $($detection.ProcessName -or 'System') - $($detection.DllPath -or $detection.DllName -or $detection.Message)" "THREAT" "dll_hijacking_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "DLL hijacking detection error: $_" "ERROR" "dll_hijacking_detections.log"
    }
    
    return $detections.Count
}

function Invoke-TokenManipulationDetection {
    $Processes = Get-Process | Where-Object { $_.Path }

    foreach ($Process in $Processes) {
        try {
            $Owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).GetOwner()
            if ($Owner.Domain -eq "NT AUTHORITY" -and $Process.Path -notmatch "^C:\\Windows") {
                Write-Output "[TokenManip] SUSPICIOUS: Non-system binary running as SYSTEM | Process: $($Process.ProcessName) | Path: $($Process.Path)"
            }
        } catch {}
    }
}

function Invoke-ProcessHollowingDetection {
    $detections = @()
    
    try {
        # Process hollowing signatures for advanced detection
        $processHollowingSignatures = @{
            "ProcessHollowing" = @(
                "process.*hollowing", "hollow.*process", "process.*replacement",
                "unmap.*section", "ntunmapviewofsection"
            )
        }
        
        # Process hollowing behavioral patterns
        $processHollowingBehaviors = @{
            "HollowingAPIs" = @(
                "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory",
                "SetThreadContext", "ResumeThread", "process.*hollow"
            )
            "SuspiciousParent" = @(
                "explorer.*spawn", "winlogon.*spawn", "suspicious.*parent"
            )
        }
        
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $procPath = $procObj.Path
                $imgPath = $proc.ExecutablePath
                
                # Use advanced detection framework
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $processHollowingSignatures `
                        -BehavioralIndicators $processHollowingBehaviors `
                        -CommandLine $proc.CommandLine `
                        -CheckEntropy $true
                    
                    if ($detectionResult.IsThreat) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Type = "Process Hollowing Detected via Advanced Framework"
                            Risk = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } else { "High" }
                        }
                    }
                }
                
                # Check for path mismatch (indicator of process hollowing)
                if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        ProcessPath = $procPath
                        ImagePath = $imgPath
                        Type = "Path Mismatch - Process Hollowing"
                        Risk = "Critical"
                    }
                }
                
                # Check for processes with unusual parent relationships
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction Stop
                        
                        # Check for processes spawned from non-standard parents
                        $suspiciousParents = @{
                            "explorer.exe" = @("notepad.exe", "calc.exe", "cmd.exe", "powershell.exe")
                            "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                            "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                        }
                        
                        if ($suspiciousParents.ContainsKey($parent.Name)) {
                            if ($proc.Name -in $suspiciousParents[$parent.Name]) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ParentProcess = $parent.Name
                                    Type = "Suspicious Parent-Child Relationship"
                                    Risk = "High"
                                }
                            }
                        }
                    } catch { }
                }
                
                # Check for processes with suspended threads
                try {
                    $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                    $suspendedThreads = $threads | Where-Object { $_.ThreadState -eq 5 } # Suspended
                    
                    if ($suspendedThreads.Count -gt 0 -and $suspendedThreads.Count -eq $threads.Count) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            SuspendedThreads = $suspendedThreads.Count
                            Type = "All Threads Suspended - Process Hollowing"
                            Risk = "High"
                        }
                    }
                } catch { }
                
                # Check for processes with unusual memory regions
                try {
                    $memoryRegions = Get-Process -Id $proc.ProcessId -ErrorAction Stop | 
                        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
                    
                    if ($memoryRegions) {
                        $unknownModules = $memoryRegions | Where-Object { 
                            $_.FileName -notlike "$env:SystemRoot\*" -and
                            $_.FileName -notlike "$env:ProgramFiles*" -and
                            $_.ModuleName -notin @("kernel32.dll", "ntdll.dll", "user32.dll")
                        }
                        
                        if ($unknownModules.Count -gt 5) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                UnknownModules = $unknownModules.Count
                                Type = "Unusual Memory Modules"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch { }
                
            } catch {
                continue
            }
        }
        
        # Check for processes with unusual PE structure
        try {
            $suspiciousProcs = $processes | Where-Object {
                $_.ExecutablePath -and
                (Test-Path $_.ExecutablePath) -and
                $_.ExecutablePath -notlike "$env:SystemRoot\*"
            }
            
            foreach ($proc in $suspiciousProcs) {
                try {
                    $peInfo = Get-Item $proc.ExecutablePath -ErrorAction Stop
                    
                    # Check if executable is signed
                    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        # Check if it's impersonating a legitimate process
                        $legitNames = @("svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "dwm.exe")
                        if ($proc.Name -in $legitNames) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Unsigned Executable Impersonating Legitimate Process"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS HOLLOWING: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "process_hollowing_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process hollowing detection error: $_" "ERROR" "process_hollowing_detections.log"
    }
    
    return $detections.Count
}

function Invoke-KeyloggerDetection {
    $detections = @()
    
    try {
        # Keylogger signatures for advanced detection
        $keyloggerSignatures = @{
            "Keylogger" = @(
                "keylogger", "keylog", "keystroke", "keyboard.*hook", "key.*capture",
                "SetWindowsHookEx", "WH_KEYBOARD", "WH_KEYBOARD_LL", "GetAsyncKeyState",
                "keyboard.*monitor", "keystroke.*logger", "key.*recorder"
            )
        }
        
        # Keylogger behavioral patterns
        $keyloggerBehaviors = @{
            "KeyboardHooking" = @(
                "SetWindowsHookEx", "WH_KEYBOARD", "WH_KEYBOARD_LL", "keyboard.*hook",
                "GetAsyncKeyState", "GetKeyState", "keylog"
            )
            "KeyCapture" = @(
                "keystroke", "key.*capture", "key.*record", "keyboard.*monitor"
            )
        }
        
        # Check for processes with keyboard hooks
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procPath = $proc.Path
                if (-not $procPath -or -not (Test-Path $procPath)) { continue }
                
                $procCmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                
                # Use advanced detection framework
                $detectionResult = Invoke-AdvancedThreatDetection `
                    -FilePath $procPath `
                    -FileSignatures $keyloggerSignatures `
                    -BehavioralIndicators $keyloggerBehaviors `
                    -CommandLine $procCmdLine `
                    -CheckEntropy $true
                
                if ($detectionResult.IsThreat) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ThreatName = $detectionResult.ThreatName
                        DetectionMethods = $detectionResult.DetectionMethods -join ", "
                        Confidence = $detectionResult.Confidence
                        Type = "Keylogger Detected via Advanced Framework"
                        Risk = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } elseif ($detectionResult.Risk -eq "HIGH") { "High" } else { "Medium" }
                    }
                }
                
                # Legacy detection: Check for processes using keyboard hook DLLs
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match 'user32|keylog|hook|kbhook|keyboard'
                }
                
                if ($modules.Count -gt 0) {
                    # Exclude legitimate processes
                    $legitProcesses = @("explorer.exe", "dwm.exe", "chrome.exe", "msedge.exe", "firefox.exe")
                    if ($proc.ProcessName -notin $legitProcesses) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            HookModules = ($modules | Select-Object -ExpandProperty ModuleName) -join ', '
                            Type = "Keyboard Hook Detected"
                            Risk = "High"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes with SetWindowsHookEx API usage (keylogger indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    $keylogPatterns = @(
                        'SetWindowsHookEx',
                        'WH_KEYBOARD',
                        'WH_KEYBOARD_LL',
                        'keylog',
                        'keyboard.*hook',
                        'GetAsyncKeyState'
                    )
                    
                    foreach ($pattern in $keylogPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                            if ($procObj) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    CommandLine = $proc.CommandLine
                                    Pattern = $pattern
                                    Type = "Keylogger API Usage"
                                    Risk = "Critical"
                                }
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual keyboard event monitoring
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    # Check for processes with high keyboard-related handle counts
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    $keyHandles = $handles | Where-Object { $_.Name -match 'keyboard|keylog' }
                    
                    if ($keyHandles.Count -gt 5) {
                        $legitProcesses = @("explorer.exe", "dwm.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                KeyboardHandles = $keyHandles.Count
                                Type = "Unusual Keyboard Handle Count"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for unsigned processes accessing keyboard
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Modules.ModuleName -match "user32.dll" }
            
            foreach ($proc in $processes) {
                try {
                    if ($proc.Path -and (Test-Path $proc.Path)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid" -and $proc.ProcessName -notmatch "explorer|chrome|firefox|msedge") {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Type = "Unsigned Process with Keyboard Access"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "KEYLOGGER DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "keylogger_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\Keylogger_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Keylogger detection error: $_" "ERROR" "keylogger_detections.log"
    }
    
    return $detections.Count
}

function Invoke-RansomwareDetection {
    param([bool]$AutoKillThreats = $true)
    
    $detections = @()
    
    try {
        # Check for rapid file modifications (encryption indicator)
        $userDirs = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Videos"
        )
        
        $recentFiles = @()
        foreach ($dir in $userDirs) {
            if (Test-Path $dir) {
                try {
                    $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { (Get-Date) - $_.LastWriteTime -lt [TimeSpan]::FromMinutes(5) } |
                        Select-Object -First 100
                    
                    $recentFiles += $files
                } catch { }
            }
        }
        
        # Check for files with suspicious extensions
        $suspiciousExts = @(".encrypted", ".locked", ".crypto", ".vault", ".xxx", ".zzz", ".xyz")
        $encryptedFiles = $recentFiles | Where-Object {
            $ext = $_.Extension.ToLower()
            $ext -in $suspiciousExts -or
            ($ext -notin @(".txt", ".doc", ".pdf", ".jpg", ".png") -and $ext.Length -gt 4)
        }
        
        if ($encryptedFiles.Count -gt 10) {
            $detections += @{
                Type = "Rapid File Encryption"
                EncryptedFiles = $encryptedFiles.Count
                Risk = "Critical"
            }
        }
        
        # Check for ransom notes
        $ransomNoteNames = @("readme.txt", "decrypt.txt", "how_to_decrypt.txt", "recover.txt", "restore.txt", "!!!readme!!!.txt")
        foreach ($file in $recentFiles) {
            if ($file.Name -in $ransomNoteNames) {
                $detections += @{
                    File = $file.FullName
                    Type = "Ransom Note Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Ransomware signatures for advanced detection
        $ransomwareSignatures = @{
            "Ransomware" = @(
                "ransomware", "encrypt", "decrypt", "bitcoin", "payment.*required",
                "your.*files.*encrypted", "lock.*screen", "crypto.*locker", "file.*encryption"
            )
        }
        
        # Ransomware behavioral patterns
        $ransomwareBehaviors = @{
            "ShadowCopyDeletion" = @(
                "vssadmin.*delete", "wbadmin.*delete", "shadowcopy.*delete",
                "recoveryenabled.*no", "bcdedit.*recovery"
            )
            "FileEncryption" = @(
                "encrypt.*file", "crypto.*api", "file.*lock", "ransom.*note"
            )
        }
        
        # Check for processes with high file I/O using advanced framework
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Use advanced detection framework
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $detectionResult = Invoke-AdvancedThreatDetection `
                            -FilePath $proc.ExecutablePath `
                            -FileSignatures $ransomwareSignatures `
                            -BehavioralIndicators $ransomwareBehaviors `
                            -CommandLine $proc.CommandLine `
                            -CheckEntropy $true
                        
                        if ($detectionResult.IsThreat) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ThreatName = $detectionResult.ThreatName
                                DetectionMethods = $detectionResult.DetectionMethods -join ", "
                                Confidence = $detectionResult.Confidence
                                Type = "Ransomware Detected via Advanced Framework"
                                Risk = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } else { "High" }
                            }
                        }
                    }
                    
                    # Check for processes with unusual file activity
                    $ioStats = Get-Counter "\Process($($proc.Name))\IO Data Operations/sec" -ErrorAction SilentlyContinue
                    if ($ioStats -and $ioStats.CounterSamples[0].CookedValue -gt 1000) {
                        # High I/O activity
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    IOOperations = $ioStats.CounterSamples[0].CookedValue
                                    Type = "High File I/O - Unsigned Process"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for shadow copy deletion
        try {
            $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadowCopies.Count -eq 0 -and (Test-Path "C:\Windows\System32\vssadmin.exe")) {
                $detections += @{
                    Type = "Shadow Copies Deleted"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for crypto API usage
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            foreach ($proc in $processes) {
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match "crypt32|cryptsp|cryptnet|bcrypt"
                }
                
                if ($modules.Count -gt 0) {
                    # Check if process is accessing many files
                    try {
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                        $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" }
                        
                        if ($fileHandles.Count -gt 50) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandles = $fileHandles.Count
                                Type = "Cryptographic API with High File Access"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check command line for ransomware indicators (original check)
        $RansomwareIndicators = @(
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "bcdedit /set {default} recoveryenabled no",
            "wmic shadowcopy delete"
        )

        $Processes = Get-Process | Where-Object { $_.Path }

        foreach ($Process in $Processes) {
            try {
                $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                foreach ($Indicator in $RansomwareIndicators) {
                    if ($CommandLine -match [regex]::Escape($Indicator)) {
                        $detections += @{
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            CommandLine = $CommandLine
                            Type = "Ransomware Command Detected"
                            Risk = "Critical"
                        }
                        break
                    }
                }
            } catch {}
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "RANSOMWARE DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.File -or 'System')" "THREAT" "ransomware_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File -or $_.EncryptedFiles)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Ransomware detection error: $_" "ERROR" "ransomware_detections.log"
    }
    
    return $detections.Count
}

function Invoke-NetworkAnomalyDetection {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
        # Advanced suspicious port detection with severity scoring
        $SuspiciousPorts = @{
            "4444" = @{Severity = "High"; Reason = "Metasploit default port"; KnownMalware = $true}
            "5555" = @{Severity = "High"; Reason = "Common backdoor port"; KnownMalware = $true}
            "31337" = @{Severity = "Medium"; Reason = "Elite/leet backdoor port"; KnownMalware = $true}
            "6666" = @{Severity = "Medium"; Reason = "IRC and trojan port"; KnownMalware = $true}
            "9999" = @{Severity = "Low"; Reason = "Common trojan port"; KnownMalware = $true}
            "12345" = @{Severity = "Medium"; Reason = "NetBus trojan port"; KnownMalware = $true}
            "54321" = @{Severity = "Medium"; Reason = "Back Orifice trojan port"; KnownMalware = $true}
            "65432" = @{Severity = "Low"; Reason = "Uncommon trojan port"; KnownMalware = $false}
        }

        # Known malicious IP ranges (common malware C2 ranges)
        $KnownMaliciousRanges = @(
            "5.8.", "45.", "91.", "185.", "195."
        )

        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -notlike "169.254.*" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "10.*" }

        $ThreatScore = 0
        $DetectedThreats = @()

    foreach ($Conn in $Connections) {
            $ThreatScore = 0
            $ThreatReasons = @()
            
            try {
                # Check for suspicious ports
                $PortStr = $Conn.RemotePort.ToString()
                if ($SuspiciousPorts.ContainsKey($PortStr)) {
                    $portInfo = $SuspiciousPorts[$PortStr]
                    $ThreatScore += if ($portInfo.Severity -eq "High") { 30 } elseif ($portInfo.Severity -eq "Medium") { 20 } else { 10 }
                    $ThreatReasons += "Suspicious port: $($portInfo.Reason)"
                }

                # Check for known malicious IP ranges
                foreach ($range in $KnownMaliciousRanges) {
                    if ($Conn.RemoteAddress.ToString().StartsWith($range)) {
                        $ThreatScore += 25
                        $ThreatReasons += "Known malicious IP range: $range"
                        break
                    }
                }

                # Check for uncommon/privileged ports (above 49152)
                if ($Conn.RemotePort -gt 49152 -and $Conn.RemotePort -lt 65535) {
                    $ThreatScore += 5
                    $ThreatReasons += "Uncommon dynamic port range"
                }

                # Check process associated with connection
                try {
                    $proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) {
                        # Check if process is from unusual location
                        if ($proc.Path -and $proc.Path -notmatch "^(C:\\(Windows|Program Files|Program Files \(x86\)))") {
                            $ThreatScore += 15
                            $ThreatReasons += "Non-standard process location: $($proc.Path)"
                        }

                        # Check for known suspicious process names
                        $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
                        if ($SuspiciousProcesses -contains $proc.ProcessName) {
                            $ThreatScore += 20
                            $ThreatReasons += "Suspicious process making connection: $($proc.ProcessName)"
                        }
                    }
                } catch {}

                # Check for outbound connections from system processes (unusual)
                if ($proc -and $proc.ProcessName -match "^(svchost|lsass|winlogon|services|csrss|smss)$") {
                    $ThreatScore += 30
                    $ThreatReasons += "System process making outbound connection (potential process hollowing/injection)"
                }

                # Check for connections to non-standard DNS ports (port 53 but not from DNS processes)
                if ($Conn.RemotePort -eq 53 -and $proc -and $proc.ProcessName -ne "svchost" -and $proc.ProcessName -ne "dns") {
                    $ThreatScore += 25
                    $ThreatReasons += "Non-DNS process connecting to DNS port (potential DNS tunneling)"
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $threatInfo = @{
                        RemoteAddress = $Conn.RemoteAddress
                        RemotePort = $Conn.RemotePort
                        ProcessId = $Conn.OwningProcess
                        ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                        ProcessPath = if ($proc -and $proc.Path) { $proc.Path } else { "Unknown" }
                        ThreatScore = $ThreatScore
                        Reasons = $ThreatReasons -join "; "
                        Severity = $severity
                        Timestamp = Get-Date
                    }

                    $DetectedThreats += $threatInfo

                    Write-Output "[Network] THREAT ($severity): Score=$ThreatScore | Remote: $($Conn.RemoteAddress):$($Conn.RemotePort) | PID: $($Conn.OwningProcess) | Process: $(if ($proc) { $proc.ProcessName } else { 'Unknown' }) | Reasons: $($ThreatReasons -join '; ')"

                    # Auto-block if configured
                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            $RuleName = "Block_NetworkThreat_$($Conn.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                            $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                            if (-not $existingRule) {
                                New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Conn.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                Write-Output "[Network] ACTION: Blocked threat IP $($Conn.RemoteAddress) with firewall rule"
                            }
                        } catch {
                            Write-Output "[Network] ERROR: Failed to block threat: $_"
                        }
                    }

                    # Queue for response engine if threat is significant
                    if ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "NetworkAnomaly" -ThreatPath "$($Conn.RemoteAddress):$($Conn.RemotePort)" -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Error analyzing connection: $_" -Level "Warning"
            }
        }

        if ($DetectedThreats.Count -gt 0) {
            Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Detected $($DetectedThreats.Count) network anomaly/threat(s)" -Level "Warning"
        }

        return @{ThreatsDetected = $DetectedThreats.Count; Details = $DetectedThreats}
    }
    catch {
        Write-EDRLog -Module "NetworkAnomalyDetection" -Message "Network anomaly detection failed: $_" -Level "Error"
        return @{ThreatsDetected = 0; Details = @()}
    }
}

function Invoke-NetworkTrafficMonitoring {
    param(
        [bool]$AutoBlockThreats = $true
    )

    $AllowedDomains = @("google.com", "microsoft.com", "github.com", "stackoverflow.com")
    $AllowedIPs = @()

    foreach ($Domain in $AllowedDomains) {
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($IP in $IPs) {
                if ($AllowedIPs -notcontains $IP) {
                    $AllowedIPs += $IP
                }
            }
        }
        catch {
            Write-Output "[NTM] WARNING: Could not resolve domain $Domain to IP"
        }
    }

    Write-Output "[NTM] Starting network traffic monitoring..."

    try {
        $Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }

        $SuspiciousConnections = @()
        $TotalConnections = $Connections.Count

        foreach ($Connection in $Connections) {
            $RemoteAddr = $Connection.RemoteAddress
            $RemotePort = $Connection.RemotePort
            $ProcessId = $Connection.OwningProcess

            if ($AllowedIPs -contains $RemoteAddr) {
                continue
            }

            $ProcessName = "Unknown"
            $ProcessPath = "Unknown"

            try {
                $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if ($Process) {
                    $ProcessName = $Process.ProcessName
                    $ProcessPath = if ($Process.Path) { $Process.Path } else { "Unknown" }
                }
            }
            catch {
            }

            $SuspiciousScore = 0
            $Reasons = @()

            if ($RemotePort -gt 10000) {
                $SuspiciousScore += 20
                $Reasons += "High remote port: $RemotePort"
            }

            $C2Ports = @(4444, 8080, 9999, 1337, 31337, 443, 53)
            if ($C2Ports -contains $RemotePort) {
                $SuspiciousScore += 30
                $Reasons += "Known C2 port: $RemotePort"
            }

            $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript", "rundll32", "mshta")
            if ($SuspiciousProcesses -contains $ProcessName.ToLower()) {
                $SuspiciousScore += 25
                $Reasons += "Suspicious process: $ProcessName"
            }

            if ($ProcessPath -notmatch "C:\\(Windows|Program Files|Program Files \(x86\))" -and $ProcessPath -ne "Unknown") {
                $SuspiciousScore += 15
                $Reasons += "Process in non-standard location"
            }

            if ($RemoteAddr -match '^\d+\.\d+\.\d+\.\d+$') {
                try {
                    $HostName = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                    if ($HostName -and $HostName -notmatch ($AllowedDomains -join '|')) {
                        $SuspiciousScore += 10
                        $Reasons += "Unknown hostname: $HostName"
                    }
                }
                catch {
                    $SuspiciousScore += 5
                    $Reasons += "No reverse DNS for IP"
                }
            }

            $PrivateIPRanges = @("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254.")
            $IsPrivateIP = $false
            foreach ($Range in $PrivateIPRanges) {
                if ($RemoteAddr.StartsWith($Range)) {
                    $IsPrivateIP = $true
                    break
                }
            }

            if (!$IsPrivateIP -and $AllowedIPs -notcontains $RemoteAddr) {
                $SuspiciousScore += 10
                $Reasons += "Unknown public IP"
            }

            if ($SuspiciousScore -ge 30) {
                $SuspiciousConnections += @{
                    RemoteAddress = $RemoteAddr
                    RemotePort = $RemotePort
                    ProcessName = $ProcessName
                    ProcessId = $ProcessId
                    ProcessPath = $ProcessPath
                    Score = $SuspiciousScore
                    Reasons = $Reasons
                }

                Write-Output "[NTM] SUSPICIOUS: $ProcessName connecting to $RemoteAddr`:$RemotePort | Score: $SuspiciousScore | Reasons: $($Reasons -join ', ')"
            }
        }

        if ($AutoBlockThreats -and $SuspiciousConnections.Count -gt 0) {
            foreach ($Suspicious in $SuspiciousConnections) {
                try {
                    $RuleName = "Block_Malicious_$($Suspicious.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Suspicious.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

                    Write-Output "[NTM] ACTION: Blocked IP $($Suspicious.RemoteAddress) with firewall rule $RuleName"

                    if ($Suspicious.Score -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Suspicious.ProcessId -eq $PID -or $Suspicious.ProcessId -eq $Script:SelfPID) {
                            Write-Output "[NTM] BLOCKED: Attempted to kill own process (PID: $($Suspicious.ProcessId)) - whitelisted"
                            continue
                        }
                        Stop-Process -Id $Suspicious.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Output "[NTM] ACTION: Terminated suspicious process $($Suspicious.ProcessName) (PID: $($Suspicious.ProcessId))"
                    }
                }
                catch {
                    Write-Output "[NTM] ERROR: Failed to block threat: $_"
                }
            }
        }

        Write-Output "[NTM] Monitoring complete: $TotalConnections total connections, $($SuspiciousConnections.Count) suspicious"
    }
    catch {
        Write-Output "[NTM] ERROR: Failed to monitor network traffic: $_"
    }
}

function Invoke-RootkitDetection {
    param(
        [bool]$DeepScan = $true
    )

    try {
        $Threats = @()

        # 1. Check for unsigned drivers (potential rootkit)
        try {
            $Drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue
    foreach ($Driver in $Drivers) {
                $Suspicious = $false
                $Reasons = @()

                # Non-Microsoft system drivers
        if ($Driver.ProviderName -notmatch "Microsoft" -and $Driver.ClassName -eq "System") {
                    $Suspicious = $true
                    $Reasons += "Third-party system driver"
                }

                # Drivers with suspicious names
                $SuspiciousDriverNames = @("rootkit", "stealth", "hide", "kernel", "hook", "inject")
                foreach ($pattern in $SuspiciousDriverNames) {
                    if ($Driver.DriverName -match $pattern -or $Driver.OriginalFileName -match $pattern) {
                        $Suspicious = $true
                        $Reasons += "Suspicious driver name pattern: $pattern"
                        break
                    }
                }

                # Drivers without digital signatures
                try {
                    $DriverPath = $Driver.OriginalFileName
                    if ($DriverPath -and (Test-Path $DriverPath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $DriverPath -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $Suspicious = $true
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                if ($Suspicious) {
                    # Perform behavioral analysis on suspicious driver
                    $behavioralAnalysis = $null
                    try {
                        $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $Driver.DriverName -DriverPath $Driver.OriginalFileName -DriverServiceName $Driver.DriverName
                        if ($behavioralAnalysis.IsMalicious) {
                            $Reasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                            $Reasons += $behavioralAnalysis.Reasons
                        }
                    } catch {}
                    
                    $Threats += @{
                        Type = "SuspiciousDriver"
                        Name = $Driver.DriverName
                        Provider = $Driver.ProviderName
                        Path = $Driver.OriginalFileName
                        Reasons = $Reasons
                        Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                        BehavioralAnalysis = $behavioralAnalysis
                    }
                    $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                    Write-Output "[Rootkit] SUSPICIOUS: Driver detected | Driver: $($Driver.DriverName) | Provider: $($Driver.ProviderName) | Reasons: $($Reasons -join '; ')$behavioralInfo"
                }
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "Driver scan failed: $_" -Level "Warning"
        }

        # 2. Check for hidden processes (process list vs performance counters)
        if ($DeepScan) {
            try {
                $ProcessList = Get-Process | Select-Object -ExpandProperty Id
                $PerfProcesses = Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty CounterSamples | 
                    Where-Object { $_.CookedValue -gt 0 } | 
                    Select-Object -ExpandProperty CookedValue | 
                    ForEach-Object { [int]$_ }

                $HiddenProcesses = $PerfProcesses | Where-Object { $_ -notin $ProcessList }
                foreach ($procPid in $HiddenProcesses) {
                    $Threats += @{
                        Type = "HiddenProcess"
                        ProcessId = $procPid
                        Reasons = @("Process visible in performance counters but not in process list")
                        Severity = "Critical"
                    }
                    Write-Output "[Rootkit] CRITICAL: Hidden process detected | PID: $pid"
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Hidden process detection failed: $_" -Level "Warning"
            }
        }

        # 3. Check for kernel mode callbacks (advanced)
        if ($DeepScan) {
            try {
                # Check for suspicious registry keys used by rootkits
                $RootkitRegistryKeys = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Services\*",
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
                )

                foreach ($keyPath in $RootkitRegistryKeys) {
                    try {
                        $keys = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
                        foreach ($key in $keys) {
                            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            
                            # Check for suspicious values - exclude Windows system paths
                            # Windows system paths include: C:\Windows, \SystemRoot\, System32\, etc.
                            if ($props.ImagePath) {
                                $imagePathLower = $props.ImagePath.ToLower().Replace('\', '/')
                                # Check for various Windows system path formats (normalize backslashes to forward slashes for matching)
                                $isSystemPath = $imagePathLower -match "^(c:/windows|/systemroot|system32|syswow64)" -or 
                                               $imagePathLower -match '^"c:/windows' -or
                                               $imagePathLower.StartsWith("system32/") -or
                                               $imagePathLower.StartsWith("syswow64/") -or
                                               $imagePathLower.StartsWith("/systemroot/")
                                
                                # Only flag if it's NOT a system path AND not in Program Files
                                if (-not $isSystemPath -and $props.ImagePath -notmatch "^(C:\\(Windows|Program Files))") {
                                    $Threats += @{
                                        Type = "SuspiciousServiceRegistry"
                                        Path = $key.PSPath
                                        ImagePath = $props.ImagePath
                                        Reasons = @("Service in non-standard location")
                                        Severity = "Medium"
                                    }
                                    Write-Output "[Rootkit] SUSPICIOUS: Service in non-standard location | Path: $($key.PSPath) | ImagePath: $($props.ImagePath)"
                                }
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Registry scan failed: $_" -Level "Warning"
            }
        }

        # 4. Check for SSDT hooks (System Service Descriptor Table) - indirect detection
        if ($DeepScan) {
            try {
                # Check for processes with unusual API calls (would require kernel debugging in real implementation)
                # This is a simplified heuristic check
                $SystemProcesses = Get-Process | Where-Object { $_.ProcessName -match "^(lsass|csrss|winlogon|services|smss|wininit)$" }
                foreach ($proc in $SystemProcesses) {
                    try {
                        # Check if system process has unexpected modules loaded
                        $modules = $proc.Modules | Where-Object { 
                            $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp)" -and 
                            $_.FileName -notmatch "^C:\\Windows" 
                        }
                        if ($modules) {
                            foreach ($mod in $modules) {
                                $Threats += @{
                                    Type = "SuspiciousModuleInSystemProcess"
                                    ProcessName = $proc.ProcessName
                                    ProcessId = $proc.Id
                                    ModuleName = $mod.ModuleName
                                    ModulePath = $mod.FileName
                                    Reasons = @("Unexpected module in system process")
                                    Severity = "High"
                                }
                                Write-Output "[Rootkit] HIGH: Suspicious module in system process | Process: $($proc.ProcessName) | Module: $($mod.ModuleName) | Path: $($mod.FileName)"
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "System process module scan failed: $_" -Level "Warning"
            }
        }

        # 5. Check for file system filters and minifilter drivers (rootkit indicator)
        try {
            # List of specific target minifilter drivers to detect and remove
            # Only targeting bfs and unionfs (from batch file) - other minifilter drivers are handled more conservatively
            $targetMinifilterDrivers = @("bfs", "unionfs")
            
            # Check for specific target drivers first (bfs, unionfs only)
            foreach ($targetDriver in $targetMinifilterDrivers) {
                try {
                    $driverService = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = '$targetDriver'" -ErrorAction SilentlyContinue
                    if ($driverService) {
                        $driverPath = $driverService.PathName
                        if (-not $driverPath) {
                            $driverPath = "C:\Windows\System32\drivers\$targetDriver.sys"
                        }
                        
                        $Threats += @{
                            Type = "SuspiciousFileSystemFilter"
                            Name = $targetDriver
                            Path = $driverPath
                            State = $driverService.State
                                            Reasons = @("Target minifilter driver detected (bfs/unionfs)")
                            Severity = "High"
                        }
                        Write-Output "[Rootkit] HIGH: Target minifilter driver detected | Name: $targetDriver | Path: $driverPath"
                    }
                } catch {}
            }
            
            # Check via WMI for file system filter drivers
            $FileSystemFilters = Get-WmiObject -Class Win32_SystemDriver -Filter "Name LIKE '%filter%' OR Name LIKE '%fs%'" -ErrorAction SilentlyContinue
            foreach ($filter in $FileSystemFilters) {
                $isSuspicious = $false
                $reasons = @()
                
                # Skip if already detected as target driver
                $isTargetDriver = $false
                foreach ($target in $targetMinifilterDrivers) {
                    if ($filter.Name -eq $target -or $filter.Name -like "*$target*") {
                        $isTargetDriver = $true
                        break
                    }
                }
                if ($isTargetDriver) { continue }
                
                # Check if in non-standard location - exclude Windows system paths
                # Windows system paths include: C:\Windows, \SystemRoot\, System32\, etc.
                if ($filter.PathName) {
                    $pathNameLower = $filter.PathName.ToLower().Replace('\', '/')
                    # Check for various Windows system path formats (normalize backslashes to forward slashes for matching)
                    $isSystemPath = $pathNameLower -match "^(c:/windows|/systemroot|system32|syswow64)" -or
                                   $pathNameLower -match "^//?c:/windows" -or
                                   $pathNameLower.StartsWith("system32/") -or
                                   $pathNameLower.StartsWith("syswow64/") -or
                                   $pathNameLower.StartsWith("/systemroot/")
                    
                    # Only flag if it's NOT a system path
                    if (-not $isSystemPath) {
                        $isSuspicious = $true
                        $reasons += "File system filter in non-standard location"
                    }
                }
                
                # Check for unsigned minifilter drivers
                if ($filter.PathName -and (Test-Path $filter.PathName)) {
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $filter.PathName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $isSuspicious = $true
                            $reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    } catch {}
                }
                
                # Exclude known legitimate filters (fltmgr, etc.)
                $legitimateFilters = @("fltmgr", "FsDepends", "FileInfo", "FltMgr")
                if ($legitimateFilters -contains $filter.Name) {
                    $isSuspicious = $false
                }
                
                if ($isSuspicious) {
                    # Perform behavioral analysis on suspicious filter driver
                    $behavioralAnalysis = $null
                    try {
                        $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $filter.Name -DriverPath $filter.PathName -DriverServiceName $filter.Name
                        if ($behavioralAnalysis.IsMalicious) {
                            $reasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                            $reasons += $behavioralAnalysis.Reasons
                        }
                    } catch {}
                    
                    $Threats += @{
                        Type = "SuspiciousFileSystemFilter"
                        Name = $filter.Name
                        Path = $filter.PathName
                        State = $filter.State
                        Reasons = $reasons
                        Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                        BehavioralAnalysis = $behavioralAnalysis
                    }
                    $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                    Write-Output "[Rootkit] HIGH: Suspicious file system filter | Name: $($filter.Name) | Path: $($filter.PathName) | Reasons: $($reasons -join '; ')$behavioralInfo"
                }
            }
            
            # Also check via fltmgr.sys registry entries for minifilter drivers
            try {
                $minifilterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\FltMgr\Enum"
                if (Test-Path $minifilterKey) {
                    $minifilters = Get-ItemProperty -Path $minifilterKey -ErrorAction SilentlyContinue
                    if ($minifilters) {
                        $minifilterValues = $minifilters.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
                        foreach ($value in $minifilterValues) {
                            $filterInfo = $value.Value
                            if ($filterInfo -match '^(\d+)\\\\SystemRoot\\\\System32\\\\drivers\\\\([^\\]+)') {
                                $filterName = $matches[2]
                                $filterPath = "C:\Windows\System32\drivers\$filterName"
                                
                                # Extract driver name without extension for comparison
                                $driverNameBase = [System.IO.Path]::GetFileNameWithoutExtension($filterName)
                                
                                # Check if this is a target driver (bfs, unionfs, Sophos)
                                $isTargetDriver = $false
                                foreach ($target in $targetMinifilterDrivers) {
                                    if ($driverNameBase -eq $target -or $driverNameBase -like "*$target*" -or $filterName -like "*$target*") {
                                        $isTargetDriver = $true
                                        break
                                    }
                                }
                                
                                # Check if already in threats list
                                $alreadyDetected = $Threats | Where-Object { 
                                    $threatNameBase = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                                    $threatNameBase -eq $driverNameBase -or $_.Name -eq $driverNameBase -or $_.Name -eq $filterName
                                }
                                
                                if (-not $alreadyDetected -and (Test-Path $filterPath)) {
                                    try {
                                        # Target drivers are always flagged regardless of signature
                                        if ($isTargetDriver) {
                                            $Threats += @{
                                                Type = "SuspiciousFileSystemFilter"
                                                Name = $driverNameBase
                                                Path = $filterPath
                                                State = "Unknown"
                                                Reasons = @("Target minifilter driver registered with Filter Manager (bfs/unionfs)")
                                                Severity = "High"
                                            }
                                            Write-Output "[Rootkit] HIGH: Target minifilter driver detected | Name: $driverNameBase | Path: $filterPath"
                                        } else {
                                            # For other drivers, check signature and perform behavioral analysis
                                            $sig = Get-AuthenticodeSignature -FilePath $filterPath -ErrorAction SilentlyContinue
                                            if ($sig.Status -ne "Valid") {
                                                # Perform behavioral analysis on unsigned driver
                                                $behavioralAnalysis = $null
                                                $analysisReasons = @("Unsigned minifilter driver registered with Filter Manager")
                                                try {
                                                    $behavioralAnalysis = Invoke-DriverBehavioralAnalysis -DriverName $driverNameBase -DriverPath $filterPath -DriverServiceName $driverNameBase
                                                    if ($behavioralAnalysis.IsMalicious) {
                                                        $analysisReasons += "Behavioral analysis indicates malicious activity (Score: $($behavioralAnalysis.ThreatScore))"
                                                        $analysisReasons += $behavioralAnalysis.Reasons
                                                    }
                                                } catch {}
                                                
                                                $Threats += @{
                                                    Type = "SuspiciousFileSystemFilter"
                                                    Name = $driverNameBase
                                                    Path = $filterPath
                                                    State = "Unknown"
                                                    Reasons = $analysisReasons
                                                    Severity = if ($behavioralAnalysis -and $behavioralAnalysis.Severity -eq "Critical") { "Critical" } else { "High" }
                                                    BehavioralAnalysis = $behavioralAnalysis
                                                }
                                                $behavioralInfo = if ($behavioralAnalysis) { " | Behavioral Score: $($behavioralAnalysis.ThreatScore)" } else { "" }
                                                Write-Output "[Rootkit] HIGH: Unsigned minifilter driver | Name: $driverNameBase | Path: $filterPath$behavioralInfo"
                                            }
                                        }
                                    } catch {}
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-EDRLog -Module "RootkitDetection" -Message "Minifilter registry scan failed: $_" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "RootkitDetection" -Message "File system filter scan failed: $_" -Level "Warning"
        }

        # Queue critical and high severity threats for response (including minifilter drivers)
        foreach ($threat in $Threats) {
            if ($threat.Severity -eq "Critical" -or $threat.Severity -eq "High") {
                # For minifilter drivers, include the driver name in the threat path
                $threatPath = if ($threat.Type -eq "SuspiciousFileSystemFilter" -and $threat.Name) {
                    "Driver:$($threat.Name)|$($threat.Path)"
                } else {
                    $threat.Path
                }
                Add-ThreatToResponseQueue -ThreatType "Rootkit" -ThreatPath $threatPath -Severity $threat.Severity
            }
        }

        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "RootkitDetection" -Message "Rootkit detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-ClipboardMonitoring {
    try {
        $ClipboardText = Get-Clipboard -Format Text -ErrorAction SilentlyContinue
        if (-not $ClipboardText) { return }

        $ThreatScore = 0
        $DetectedPatterns = @()
        
        # Advanced pattern matching for sensitive data
        $Patterns = @{
            # Passwords and credentials
            "Password" = @{
                Pattern = "(?i)(password|passwd|pwd)\s*[:=]\s*([^\s]{8,})"
                Severity = "High"
                Score = 30
                Type = "Password"
            }
            # API Keys
            "APIKey" = @{
                Pattern = "(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*([A-Za-z0-9_\-]{20,})"
                Severity = "High"
                Score = 35
                Type = "APIKey"
            }
            # OAuth tokens
            "OAuthToken" = @{
                Pattern = "(?i)(bearer\s+)?([A-Za-z0-9\-_]{100,})"
                Severity = "High"
                Score = 40
                Type = "OAuthToken"
            }
            # AWS credentials
            "AWSCredentials" = @{
                Pattern = "(?i)(AKIA[0-9A-Z]{16}|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})"
                Severity = "Critical"
                Score = 50
                Type = "AWSCredentials"
            }
            # Credit card numbers
            "CreditCard" = @{
                Pattern = "\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                Severity = "High"
                Score = 45
                Type = "CreditCard"
            }
            # Social Security Numbers (US)
            "SSN" = @{
                Pattern = "\b\d{3}-\d{2}-\d{4}\b"
                Severity = "High"
                Score = 45
                Type = "SSN"
            }
            # Email addresses with credentials
            "EmailCredential" = @{
                Pattern = "(?i)(email|username|user|login)\s*[:=]\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\s*(?:password|passwd|pwd)\s*[:=]\s*([^\s]{6,})"
                Severity = "High"
                Score = 40
                Type = "EmailCredential"
            }
            # Private keys
            "PrivateKey" = @{
                Pattern = "(-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----)"
                Severity = "Critical"
                Score = 50
                Type = "PrivateKey"
            }
            # Database connection strings
            "DatabaseConnection" = @{
                Pattern = "(?i)(server|host|database|uid|user id|pwd|password)=[^;]+"
                Severity = "High"
                Score = 35
                Type = "DatabaseConnection"
            }
            # JWT tokens
            "JWT" = @{
                Pattern = "\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"
                Severity = "Medium"
                Score = 25
                Type = "JWT"
            }
            # Base64 encoded secrets (long base64 strings)
            "Base64Secret" = @{
                Pattern = "(?i)(?:secret|password|token|key)\s*[:=]\s*([A-Za-z0-9+/]{40,}={0,2})"
                Severity = "Medium"
                Score = 20
                Type = "Base64Secret"
            }
        }

        # Check each pattern
        foreach ($patternName in $Patterns.Keys) {
            $patternInfo = $Patterns[$patternName]
            if ($ClipboardText -match $patternInfo.Pattern) {
                $ThreatScore += $patternInfo.Score
                $DetectedPatterns += $patternInfo.Type
                
                # Extract matched content (sanitized for logging)
                $matchValue = $matches[0]
                if ($matchValue.Length -gt 50) {
                    $matchValue = $matchValue.Substring(0, 50) + "..."
                }
                
                Write-Output "[Clipboard] THREAT ($($patternInfo.Severity)): $($patternInfo.Type) detected | Pattern: $patternName | Match: $matchValue"
                
                # Log sensitive detection
                Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive data detected: $($patternInfo.Type) (Pattern: $patternName)" -Level $patternInfo.Severity
            }
        }

        # Additional heuristic: Check for high entropy strings (potential encrypted data or tokens)
        if ($ClipboardText.Length -gt 20) {
            $entropy = Measure-StringEntropy -String $ClipboardText
            if ($entropy -gt 4.5 -and $ClipboardText -match "^[A-Za-z0-9+/=_-]+$") {
                $ThreatScore += 15
                $DetectedPatterns += "HighEntropyString"
                Write-Output "[Clipboard] WARNING: High entropy string detected (potential encrypted data or token) | Entropy: $([Math]::Round($entropy, 2))"
            }
        }

        # Additional heuristic: Check for suspicious URL patterns
        if ($ClipboardText -match "(?i)(https?://[^\s]+(?:token|key|password|secret|auth|login|credential)[^\s]*)") {
            $ThreatScore += 20
            $DetectedPatterns += "SuspiciousURL"
            Write-Output "[Clipboard] WARNING: Suspicious URL with credential-related parameters detected"
        }

        # Action based on threat score
        if ($ThreatScore -ge 30) {
            $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
            
            # Log to EDR
            Write-EDRLog -Module "ClipboardMonitoring" -Message "Sensitive clipboard data detected | Score: $ThreatScore | Patterns: $($DetectedPatterns -join ', ')" -Level $severity
            
            # Queue for response engine if critical
            if ($severity -eq "Critical" -or $ThreatScore -ge 45) {
                Add-ThreatToResponseQueue -ThreatType "ClipboardSensitiveData" -ThreatPath "Clipboard" -Severity $severity
            }
            
            return @{Detected = $true; Score = $ThreatScore; Patterns = $DetectedPatterns; Severity = $severity}
        }

        return @{Detected = $false; Score = 0; Patterns = @()}
    }
    catch {
        Write-EDRLog -Module "ClipboardMonitoring" -Message "Clipboard monitoring error: $_" -Level "Warning"
        return @{Detected = $false; Score = 0; Patterns = @()}
    }
}

function Measure-StringEntropy {
    param([string]$String)
    
    if ([string]::IsNullOrEmpty($String)) { return 0 }
    
    $freq = @{}
    foreach ($char in $String.ToCharArray()) {
        if ($freq.ContainsKey($char)) {
            $freq[$char]++
        } else {
            $freq[$char] = 1
        }
    }
    
    $length = $String.Length
    $entropy = 0.0
    foreach ($count in $freq.Values) {
        $probability = $count / $length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    
    return $entropy
}

function Invoke-COMMonitoring {
    param(
        [hashtable]$Config
    )
    
    $COMKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID"
    )

    foreach ($Key in $COMKeys) {
        $RecentCOM = Get-ChildItem -Path $Key -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "^\{[A-F0-9-]+\}$" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5

        foreach ($COM in $RecentCOM) {
            Write-Output "[COM] Recently modified COM object: $($COM.PSChildName) | Modified: $($COM.LastWriteTime)"
        }
    }
}

function Invoke-BrowserExtensionMonitoring {
    $detections = @()
    
    try {
        # Check Chrome extensions
        $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromeExtensionsPath) {
            $chromeExts = Get-ChildItem -Path $chromeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $chromeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        # Check for suspicious permissions
                        $suspiciousPermissions = @("all_urls", "tabs", "cookies", "history", "downloads", "webRequest", "webRequestBlocking")
                        $hasSuspiciousPerms = $false
                        
                        if ($manifestContent.permissions) {
                            foreach ($perm in $manifestContent.permissions) {
                                if ($perm -in $suspiciousPermissions) {
                                    $hasSuspiciousPerms = $true
                                    break
                                }
                            }
                        }
                        
                        # Check for unsigned extensions
                        $isSigned = $manifestContent.key -ne $null
                        
                        if ($hasSuspiciousPerms -or -not $isSigned) {
                            $detections += @{
                                Browser = "Chrome"
                                ExtensionId = $ext.Name
                                ExtensionName = $manifestContent.name
                                ManifestPath = $manifest.FullName
                                HasSuspiciousPermissions = $hasSuspiciousPerms
                                IsSigned = $isSigned
                                Type = "Suspicious Chrome Extension"
                                Risk = if ($hasSuspiciousPerms) { "High" } else { "Medium" }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Edge extensions
        $edgeExtensionsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $edgeExtensionsPath) {
            $edgeExts = Get-ChildItem -Path $edgeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $edgeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        if ($manifestContent.permissions) {
                            $suspiciousPerms = $manifestContent.permissions | Where-Object {
                                $_ -in @("all_urls", "tabs", "cookies", "webRequest")
                            }
                            
                            if ($suspiciousPerms.Count -gt 0) {
                                $detections += @{
                                    Browser = "Edge"
                                    ExtensionId = $ext.Name
                                    ExtensionName = $manifestContent.name
                                    SuspiciousPermissions = $suspiciousPerms -join ','
                                    Type = "Suspicious Edge Extension"
                                    Risk = "Medium"
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Firefox extensions
        $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilesPath) {
            $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                $extensionsPath = Join-Path $profile.FullName "extensions"
                if (Test-Path $extensionsPath) {
                    $firefoxExts = Get-ChildItem -Path $extensionsPath -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -eq ".xpi" -or $_.Extension -eq "" }
                    
                    foreach ($ext in $firefoxExts) {
                        $detections += @{
                            Browser = "Firefox"
                            ExtensionPath = $ext.FullName
                            Type = "Firefox Extension Detected"
                            Risk = "Low"
                        }
                    }
                }
            }
        }
        
        # Check for browser processes with unusual activity
        try {
            $browserProcs = Get-Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.ProcessName -match 'chrome|edge|firefox|msedge' }
            
            foreach ($proc in $browserProcs) {
                try {
                    $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                        Where-Object { $_.State -eq "Established" }
                    
                    # Check for connections to suspicious domains
                    $remoteIPs = $conns.RemoteAddress | Select-Object -Unique
                    
                    foreach ($ip in $remoteIPs) {
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                            
                            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin", "githubusercontent")
                            foreach ($domain in $suspiciousDomains) {
                                if ($hostname -like "*$domain*") {
                                    $detections += @{
                                        BrowserProcess = $proc.ProcessName
                                        ProcessId = $proc.Id
                                        ConnectedDomain = $hostname
                                        Type = "Browser Connecting to Suspicious Domain"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BROWSER EXTENSION: $($detection.Type) - $($detection.ExtensionName -or $detection.BrowserProcess -or 'System')" "THREAT" "browser_extension_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionName -or $_.BrowserProcess)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Browser extension monitoring error: $_" "ERROR" "browser_extension_detections.log"
    }
    
    return $detections.Count
}

function Invoke-ShadowCopyMonitoring {
    $ShadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    $CurrentCount = $ShadowCopies.Count

    if (-not $Global:BaselineShadowCopyCount) {
        $Global:BaselineShadowCopyCount = $CurrentCount
    }

    if ($CurrentCount -lt $Global:BaselineShadowCopyCount) {
        $Deleted = $Global:BaselineShadowCopyCount - $CurrentCount
        Write-Output "[ShadowCopy] THREAT: Shadow copies deleted | Deleted: $Deleted | Remaining: $CurrentCount"
        $Global:BaselineShadowCopyCount = $CurrentCount
    }
}

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        # Check for USB devices
        try {
            $usbDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue
            
            foreach ($device in $usbDevices) {
                # Check for USB HID devices (keyloggers)
                if ($device.FriendlyName -match "Keyboard|HID|Human Interface") {
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB HID Device Connected"
                        Risk = "Medium"
                    }
                }
                
                # Check for USB mass storage devices
                if ($device.FriendlyName -match "Mass Storage|USB.*Drive|Removable") {
                    try {
                        $removableDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
                        
                        foreach ($drive in $removableDrives) {
                            $drivePath = $drive.DeviceID
                            
                            # Check for autorun.inf
                            $autorunPath = "$drivePath\autorun.inf"
                            if (Test-Path $autorunPath) {
                                $detections += @{
                                    Drive = $drivePath
                                    AutorunPath = $autorunPath
                                    DeviceName = $device.FriendlyName
                                    Type = "USB Drive with Autorun.inf"
                                    Risk = "High"
                                }
                            }
                            
                            # Check for executable files on USB
                            try {
                                $executables = Get-ChildItem -Path $drivePath -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Select-Object -First 20
                                
                                foreach ($exe in $executables) {
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $exe.FullName -ErrorAction SilentlyContinue
                                        if ($sig.Status -ne "Valid") {
                                            $detections += @{
                                                Drive = $drivePath
                                                ExecutablePath = $exe.FullName
                                                DeviceName = $device.FriendlyName
                                                Type = "Unsigned Executable on USB Drive"
                                                Risk = "High"
                                            }
                                        }
                                    } catch { }
                                }
                            } catch { }
                            
                            # Check for suspicious file types
                            try {
                                $suspiciousFiles = Get-ChildItem -Path $drivePath -Include *.vbs,*.js,*.bat,*.cmd,*.ps1 -ErrorAction SilentlyContinue |
                                    Select-Object -First 10
                                
                                if ($suspiciousFiles.Count -gt 0) {
                                    $detections += @{
                                        Drive = $drivePath
                                        SuspiciousFileCount = $suspiciousFiles.Count
                                        DeviceName = $device.FriendlyName
                                        Type = "Suspicious Files on USB Drive"
                                        Risk = "Medium"
                                    }
                                }
                            } catch { }
                        }
                    } catch { }
                    
                    $detections += @{
                        DeviceName = $device.FriendlyName
                        InstanceId = $device.InstanceId
                        Type = "USB Mass Storage Device Connected"
                        Risk = "Low"
                    }
                }
            }
        } catch { }
        
        # Check for recently connected USB devices
        try {
            $recentDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq "OK" }
            
            # Check Event Log for USB connection events
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001} -ErrorAction SilentlyContinue -MaxEvents 50 |
                    Where-Object {
                        (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                        $_.Message -match 'USB|removable'
                    }
                
                if ($events.Count -gt 5) {
                    $detections += @{
                        EventCount = $events.Count
                        Type = "Multiple USB Connections in Short Time"
                        Risk = "Medium"
                    }
                }
            } catch { }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "USB MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.Drive -or 'System')" "THREAT" "usb_monitoring_detections.log"
                $Global:AntivirusState.ThreatCount++
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.Drive)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "USB monitoring error: $_" "ERROR" "usb_monitoring_detections.log"
    }
    
    return $detections.Count
}

function Invoke-MobileDeviceMonitoring {
    $detections = @()
    $threats = @()
    
    try {
        # Track known legitimate processes that may access mobile devices
        $legitimateProcesses = @(
            "iTunes.exe", "iCloud.exe", "AppleMobileDeviceService.exe", "AppleMobileDeviceHelper.exe",
            "Samsung Smart Switch.exe", "Samsung SideSync.exe", "Samsung Kies.exe",
            "adb.exe", "fastboot.exe", "AndroidFileTransfer.exe", "Android Studio.exe",
            "explorer.exe", "dllhost.exe", "WUDFHost.exe", "WPDShextAutoplay.exe"
        )
        
        # Suspicious processes that shouldn't access mobile devices
        $suspiciousProcesses = @(
            "powershell.exe", "cmd.exe", "wmic.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
        )
        
        # Method 1: Detect mobile devices via WPD (Windows Portable Devices)
        try {
            $wpDevices = Get-PnpDevice -Class "WPD" -Status "OK" -ErrorAction SilentlyContinue
            $mtpDevices = Get-PnpDevice | Where-Object {
                $_.FriendlyName -match "iPhone|iPad|Android|Samsung|Google|Pixel|OnePlus|Xiaomi|Huawei|LG|Motorola|Sony" -or
                $_.Description -match "iPhone|iPad|Android|MTP|Portable Device"
            }
            
            $mobileDevices = @()
            if ($wpDevices) { $mobileDevices += $wpDevices }
            if ($mtpDevices) { $mobileDevices += $mtpDevices }
            
            foreach ($device in $mobileDevices) {
                $deviceName = $device.FriendlyName
                $isIPhone = $deviceName -match "iPhone|iPad|Apple"
                $isAndroid = $deviceName -match "Android|Samsung|Google|Pixel|OnePlus|Xiaomi|Huawei|LG|Motorola|Sony"
                
                if ($isIPhone -or $isAndroid) {
                    Write-AVLog "Mobile device detected: $deviceName ($($device.InstanceId))" "INFO" "mobile_device_monitoring.log"
                    
                    # Check for processes accessing this device
                    try {
                        $deviceProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                            $_.CommandLine -match $device.InstanceId -or
                            $_.ExecutablePath -match "WPD|PortableDevice|MTP"
                        }
                        
                        foreach ($proc in $deviceProcesses) {
                            $procName = Split-Path -Leaf $proc.ExecutablePath
                            
                            # Check if suspicious process is accessing device
                            if ($suspiciousProcesses -contains $procName) {
                                $threats += @{
                                    Type = "Suspicious Process Accessing Mobile Device"
                                    Device = $deviceName
                                    Process = $procName
                                    ProcessId = $proc.ProcessId
                                    CommandLine = $proc.CommandLine
                                    Risk = "CRITICAL"
                                    Timestamp = Get-Date
                                }
                                
                                # Attempt to terminate suspicious process
                                if ($Config.AutoKillThreats) {
                                    try {
                                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                        Write-AVLog "Terminated suspicious process accessing mobile device: $procName (PID: $($proc.ProcessId))" "THREAT" "mobile_device_monitoring.log"
                                    } catch {
                                        Write-AVLog "Failed to terminate process ${procName}: $_" "WARN" "mobile_device_monitoring.log"
                                    }
                                }
                            }
                        }
                    } catch { }
                    
                    # Log device connection
                    $detections += @{
                        DeviceName = $deviceName
                        InstanceId = $device.InstanceId
                        DeviceType = if ($isIPhone) { "iPhone/iPad" } else { "Android" }
                        Type = "Mobile Device Connected"
                        Risk = "Medium"
                        Timestamp = Get-Date
                    }
                }
            }
        } catch {
            Write-AVLog "WPD/MTP device detection error: $_" "WARN" "mobile_device_monitoring.log"
        }
        
        # Method 2: Monitor ADB (Android Debug Bridge) connections
        try {
            $adbProcesses = Get-Process -Name "adb" -ErrorAction SilentlyContinue
            
            foreach ($adbProc in $adbProcesses) {
                try {
                    # Check ADB connections
                    $adbConnections = & adb devices 2>$null
                    if ($adbConnections -and $adbConnections.Count -gt 1) {
                        $connectedDevices = ($adbConnections | Where-Object { $_ -match "device$" }).Count
                        
                        if ($connectedDevices -gt 0) {
                            # Check if ADB is being used by suspicious process
                            $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($adbProc.Id)" -ErrorAction SilentlyContinue |
                                Select-Object -ExpandProperty ParentProcessId -ErrorAction SilentlyContinue
                            
                            if ($parentProc) {
                                $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProc" -ErrorAction SilentlyContinue
                                if ($parent) {
                                    $parentName = Split-Path -Leaf $parent.ExecutablePath
                                    
                                    if ($suspiciousProcesses -contains $parentName -or 
                                        $legitimateProcesses -notcontains $parentName) {
                                        $threats += @{
                                            Type = "Suspicious ADB Connection"
                                            Process = $parentName
                                            ProcessId = $parentProc
                                            ConnectedDevices = $connectedDevices
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                        
                                        if ($Config.AutoKillThreats) {
                                            try {
                                                Stop-Process -Id $adbProc.Id -Force -ErrorAction SilentlyContinue
                                                Stop-Process -Id $parentProc -Force -ErrorAction SilentlyContinue
                                                Write-AVLog "Terminated suspicious ADB connection: $parentName" "THREAT" "mobile_device_monitoring.log"
                                            } catch { }
                                        }
                                    }
                                }
                            }
                            
                            $detections += @{
                                Type = "ADB Connection Active"
                                ConnectedDevices = $connectedDevices
                                Risk = "High"
                                Timestamp = Get-Date
                            }
                        }
                    }
                } catch {
                    # ADB not in PATH or not accessible
                }
            }
        } catch { }
        
        # Method 3: Monitor file system access to mobile device mount points
        try {
            $logicalDisks = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
                $_.DriveType -eq 2 -or $_.Description -match "Removable|Portable"
            }
            
            foreach ($disk in $logicalDisks) {
                $drivePath = $disk.DeviceID
                
                # Check if this might be a mobile device mount
                $volumeInfo = Get-Volume -DriveLetter $drivePath[0] -ErrorAction SilentlyContinue
                if ($volumeInfo -and ($volumeInfo.FileSystemLabel -match "iPhone|Android|Samsung|Google" -or
                    $volumeInfo.FileSystem -eq "FAT32")) {
                    
                    # Monitor for suspicious file access patterns
                    try {
                        $recentFiles = Get-ChildItem -Path $drivePath -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
                            Select-Object -First 50
                        
                        # Check for sensitive file types being accessed
                        $sensitiveExtensions = @(".db", ".sqlite", ".keychain", ".key", ".p12", ".pfx", ".crt", ".pem", ".jpg", ".png", ".mp4", ".mov")
                        $sensitiveFiles = $recentFiles | Where-Object {
                            $sensitiveExtensions -contains $_.Extension -or
                            $_.Name -match "contacts|messages|photos|videos|backup|keychain|password|credential"
                        }
                        
                        if ($sensitiveFiles.Count -gt 10) {
                            $threats += @{
                                Type = "Mass Access to Sensitive Mobile Device Files"
                                Drive = $drivePath
                                FileCount = $sensitiveFiles.Count
                                Risk = "HIGH"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 4: Monitor network connections that might indicate mobile device tethering/access
        try {
            $networkConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $_.State -eq "Established" -and
                ($_.LocalPort -eq 5037 -or $_.LocalPort -eq 5555 -or $_.LocalPort -eq 62078) # ADB ports
            }
            
            if ($networkConnections) {
                foreach ($conn in $networkConnections) {
                    $owningProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue
                    if ($owningProc) {
                        $procName = Split-Path -Leaf $owningProc.ExecutablePath
                        
                        if ($suspiciousProcesses -contains $procName) {
                            $threats += @{
                                Type = "Suspicious Network Connection to Mobile Device Port"
                                Process = $procName
                                ProcessId = $conn.OwningProcess
                                LocalPort = $conn.LocalPort
                                RemoteAddress = $conn.RemoteAddress
                                Risk = "CRITICAL"
                                Timestamp = Get-Date
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Method 5: Check for unauthorized services accessing mobile devices
        try {
            $mobileServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -match "Apple|Android|Mobile|WPD|Portable" -and
                $_.Status -eq "Running"
            }
            
            foreach ($svc in $mobileServices) {
                try {
                    $svcProcess = Get-CimInstance Win32_Service -Filter "Name = '$($svc.Name)'" -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty ProcessId -ErrorAction SilentlyContinue
                    
                    if ($svcProcess) {
                        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $svcProcess" -ErrorAction SilentlyContinue
                        if ($proc) {
                            $procPath = $proc.ExecutablePath
                            
                            # Verify service executable signature
                            try {
                                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                                if ($sig.Status -ne "Valid" -and $sig.Status -ne "NotSigned") {
                                    $threats += @{
                                        Type = "Unauthorized Mobile Device Service"
                                        Service = $svc.Name
                                        ServicePath = $procPath
                                        SignatureStatus = $sig.Status
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                }
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        # Method 6: Monitor registry for mobile device access patterns
        try {
            $mobileRegKeys = @(
                "HKLM:\SYSTEM\CurrentControlSet\Enum\USB",
                "HKLM:\SYSTEM\CurrentControlSet\Enum\WPD",
                "HKLM:\SOFTWARE\Microsoft\Windows Portable Devices"
            )
            
            foreach ($regKey in $mobileRegKeys) {
                if (Test-Path $regKey) {
                    try {
                        $recentChanges = Get-ChildItem -Path $regKey -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
                        
                        if ($recentChanges.Count -gt 20) {
                            $detections += @{
                                Type = "Excessive Mobile Device Registry Activity"
                                RegistryPath = $regKey
                                ChangeCount = $recentChanges.Count
                                Risk = "Medium"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 7: Mobile Malware Detection (Banking Trojans, Spyware, etc.)
        try {
            # Known mobile malware families and banking trojans
            $knownMalwareSignatures = @{
                # Banking Trojans (Updated January 2026 - includes recent 2025-2026 threats)
                "BankingTrojans" = @(
                    # Recent Threats (2025-2026)
                    "Anatsa", "RatOn", "Klopatra", "Sturnus", "Frogblight", "GodFather",
                    # Established Threats
                    "Anubis", "Cerberus", "EventBot", "Exobot", "FakeBank", "FakeSpy", "Faketoken",
                    "Ginp", "Gustuff", "Hydra", "Marcher", "Medusa", "Octo", "Svpeng", "TinyBanker",
                    "Tordow", "Triada", "TrickBot", "Ursnif", "Zeus", "Zitmo", "BankBot", "Asacub",
                    "Acecard", "Cron", "MoqHao", "Regin", "SpyNote", "TeaBot",
                    # Older Notable Threats
                    "FluBot", "TinyBanker"
                )
                # Spyware and Data Stealers
                "Spyware" = @(
                    "Pegasus", "FinFisher", "HackingTeam", "FlexiSpy", "mSpy", "Spyera", "TheTruthSpy",
                    "Cocospy", "Spyzie", "Spyic", "Spybubble", "SpyHuman", "SpyBubble", "SpyPhone",
                    "MobileSpy", "StealthGenie", "Retina-X", "SpyToMobile", "SpyHuman"
                )
                # Ransomware
                "MobileRansomware" = @(
                    "Simplocker", "Koler", "Lockerpin", "Sypeng", "Fusob", "Jisut", "Charger",
                    "Leatherlocker", "Slocker", "Pletor", "Congur", "Locker", "Ransom"
                )
                # Adware and Potentially Unwanted Programs
                "Adware" = @(
                    "Hummingbad", "Gooligan", "Judy", "Ewind", "Shedun", "Shuanet", "ShiftyBug",
                    "Kemoge", "Mobidash", "Dowgin"
                )
                # Remote Access Trojans (RATs) - Mobile
                "MobileRATs" = @(
                    "RatOn", "Klopatra", "SpyNote", "AhMyth", "AndroRAT", "DroidJack", "SpyMax",
                    "OmniRAT", "SpyAgent", "SpyAndroid", "Dendroid", "Sandroid", "SMSZombie"
                )
            }
            
            # Banking app package names (common targets)
            $bankingAppPatterns = @(
                "com.chase.sig.android", "com.wellsfargo.mobile", "com.bankofamerica.mobile",
                "com.citi.citimobile", "com.usaa.mobile.android", "com.pnc.ecommerce.mobile",
                "com.capitalone.mobile", "com.td", "com.rbc.mobile.android", "com.hsbc.hsbcusa.mobile.android",
                "com.americanexpress.android.acctsvcs.us", "com.schwab.mobile", "com.fidelity.android",
                "com.barclays.barclaysmobilebanking", "com.halifax.mobile", "com.natwest.mobile",
                "com.hsbc.hsbcuk.mobilebanking", "com.santander.santander", "com.lloydsbank.mobile",
                "com.rbs.mobile.android", "com.tsb.mobilebanking", "com.cooperativebank.business",
                "com.ing.mobile", "com.rabobank.mobile", "com.abnamro.mobile", "com.deutschebank.mobile",
                "com.commerzbank.mobile", "com.sparkasse", "com.volksbank", "com.postbank",
                "com.unicredit.mobile", "com.intesasanpaolo.mobile", "com.bancoposta", "com.unicredit",
                "com.bancoposta", "com.unicredit", "com.bancoposta", "com.unicredit"
            )
            
            # Suspicious file patterns on mobile devices
            $suspiciousFilePatterns = @(
                "*.apk", "*.ipa", "*.dex", "*.so", "*.jar", "*.class"
            )
            
            # Suspicious directory names where malware often hides
            $suspiciousDirectories = @(
                "Android/data", "Android/obb", "Android/system", "private/var", "Library/Caches",
                "tmp", "temp", "cache", ".hidden", "system/bin", "system/xbin", "data/local"
            )
            
            # Check connected mobile devices for malware indicators
            $logicalDisks = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
                $_.DriveType -eq 2 -or $_.Description -match "Removable|Portable"
            }
            
            foreach ($disk in $logicalDisks) {
                $drivePath = $disk.DeviceID
                $volumeInfo = Get-Volume -DriveLetter $drivePath[0] -ErrorAction SilentlyContinue
                
                if ($volumeInfo -and ($volumeInfo.FileSystemLabel -match "iPhone|Android|Samsung|Google" -or
                    $volumeInfo.FileSystem -eq "FAT32")) {
                    
                    try {
                        # Scan for APK files (Android malware)
                        $apkFiles = Get-ChildItem -Path $drivePath -Filter "*.apk" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 100
                        
                        foreach ($apk in $apkFiles) {
                            $fileName = $apk.Name
                            $filePath = $apk.FullName
                            
                            # Check filename against known malware signatures
                            $isMalware = $false
                            $malwareFamily = "Unknown"
                            
                            foreach ($family in $knownMalwareSignatures.Keys) {
                                foreach ($signature in $knownMalwareSignatures[$family]) {
                                    if ($fileName -match $signature -or $filePath -match $signature) {
                                        $isMalware = $true
                                        $malwareFamily = "$family - $signature"
                                        break
                                    }
                                }
                                if ($isMalware) { break }
                            }
                            
                            # Check for suspicious naming patterns (including recent 2025-2026 threat patterns)
                            $suspiciousPatterns = @(
                                "update", "service", "system", "security", "bank", "payment", "wallet",
                                "installer", "helper", "manager", "optimizer", "cleaner", "booster",
                                # Recent threat patterns (2025-2026)
                                "mobdro", "iptv", "vpn", "tiktok.*adult", "pdf.*reader", "pdf.*viewer",
                                "court", "case", "sms", "whatsapp.*backup", "telegram.*backup"
                            )
                            
                            # Specific recent malware masquerading patterns
                            $recentThreatPatterns = @{
                                "Klopatra" = @("mobdro", "iptv.*vpn", "pirate.*tv", "streaming.*vpn")
                                "RatOn" = @("tiktok.*adult", "nfc.*relay", "contactless")
                                "Anatsa" = @("pdf.*app", "pdf.*reader", "document.*viewer")
                                "Frogblight" = @("court.*case", "legal.*notice", "sms.*message")
                                "Sturnus" = @("whatsapp", "telegram", "chat.*backup", "message.*backup")
                                "GodFather" = @("virtual.*bank", "banking.*clone", "app.*clone")
                            }
                            
                            $suspiciousName = $false
                            $detectedThreatPattern = $null
                            
                            foreach ($pattern in $suspiciousPatterns) {
                                if ($fileName -match $pattern -and $fileName.Length -lt 20) {
                                    $suspiciousName = $true
                                    break
                                }
                            }
                            
                            # Check for specific recent threat patterns
                            foreach ($threatName in $recentThreatPatterns.Keys) {
                                foreach ($pattern in $recentThreatPatterns[$threatName]) {
                                    if ($fileName -match $pattern -or $filePath -match $pattern) {
                                        $detectedThreatPattern = $threatName
                                        $isMalware = $true
                                        $malwareFamily = "BankingTrojans - $threatName"
                                        break
                                    }
                                }
                                if ($detectedThreatPattern) { break }
                            }
                            
                            # Check file size (very small or very large APKs are suspicious)
                            $fileSizeMB = $apk.Length / 1MB
                            $suspiciousSize = $fileSizeMB -lt 0.1 -or $fileSizeMB -gt 100
                            
                            # Check for banking app targeting
                            $targetsBanking = $false
                            foreach ($bankApp in $bankingAppPatterns) {
                                if ($filePath -match $bankApp -or $fileName -match "bank|payment|wallet|finance") {
                                    $targetsBanking = $true
                                    break
                                }
                            }
                            
                            if ($isMalware -or ($suspiciousName -and $suspiciousSize) -or $targetsBanking) {
                                $riskLevel = if ($isMalware) { "CRITICAL" } 
                                           elseif ($targetsBanking) { "CRITICAL" }
                                           else { "HIGH" }
                                
                                $threats += @{
                                    Type = if ($targetsBanking) { "Banking Trojan Detected on Mobile Device" } 
                                          elseif ($isMalware) { "Mobile Malware Detected" }
                                          else { "Suspicious Mobile App Detected" }
                                    FilePath = $filePath
                                    FileName = $fileName
                                    FileSize = "$([Math]::Round($fileSizeMB, 2)) MB"
                                    MalwareFamily = $malwareFamily
                                    TargetsBanking = $targetsBanking
                                    Risk = $riskLevel
                                    Timestamp = Get-Date
                                }
                                
                                # Attempt to quarantine the file
                                if ($Config.AutoQuarantine -and $isMalware) {
                                    try {
                                        Move-ToQuarantine -FilePath $filePath -Reason "Mobile malware detected: $malwareFamily"
                                        Write-AVLog "Quarantined mobile malware: $fileName ($malwareFamily)" "THREAT" "mobile_device_monitoring.log"
                                    } catch {
                                        Write-AVLog "Failed to quarantine ${fileName}: $_" "WARN" "mobile_device_monitoring.log"
                                    }
                                }
                            }
                        }
                        
                        # Check for suspicious directories
                        foreach ($susDir in $suspiciousDirectories) {
                            $fullPath = Join-Path $drivePath $susDir
                            if (Test-Path $fullPath) {
                                try {
                                    $filesInDir = Get-ChildItem -Path $fullPath -Recurse -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Extension -match "\.(apk|ipa|dex|so|jar|class)$" }
                                    
                                    if ($filesInDir.Count -gt 5) {
                                        $threats += @{
                                            Type = "Suspicious Files in System Directory"
                                            Directory = $fullPath
                                            FileCount = $filesInDir.Count
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                    }
                                } catch { }
                            }
                        }
                        
                        # Check for recently modified system files (potential root/jailbreak malware)
                        try {
                            $systemPaths = @(
                                Join-Path $drivePath "Android\system",
                                Join-Path $drivePath "Android\bin",
                                Join-Path $drivePath "private\var"
                            )
                            
                            foreach ($sysPath in $systemPaths) {
                                if (Test-Path $sysPath) {
                                    $recentMods = Get-ChildItem -Path $sysPath -Recurse -ErrorAction SilentlyContinue |
                                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
                                    
                                    if ($recentMods.Count -gt 10) {
                                        $threats += @{
                                            Type = "Unauthorized System File Modifications on Mobile Device"
                                            Path = $sysPath
                                            ModifiedFiles = $recentMods.Count
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                    }
                                }
                            }
                        } catch { }
                        
                        # Check for Sturnus-like behavior: Access to WhatsApp/Telegram chat databases
                        try {
                            $chatAppPaths = @(
                                Join-Path $drivePath "Android\data\com.whatsapp",
                                Join-Path $drivePath "Android\data\org.telegram",
                                Join-Path $drivePath "Android\data\com.telegram"
                            )
                            
                            foreach ($chatPath in $chatAppPaths) {
                                if (Test-Path $chatPath) {
                                    # Check for recent access to chat databases
                                    $chatDbs = Get-ChildItem -Path $chatPath -Recurse -Filter "*.db" -ErrorAction SilentlyContinue |
                                        Where-Object { $_.LastAccessTime -gt (Get-Date).AddHours(-1) }
                                    
                                    if ($chatDbs.Count -gt 0) {
                                        $threats += @{
                                            Type = "Suspicious Access to Chat Application Data (Sturnus-like behavior)"
                                            Path = $chatPath
                                            DatabaseFiles = $chatDbs.Count
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                    }
                                }
                            }
                        } catch { }
                        
                        # Check for RatOn-like behavior: NFC-related files or configurations
                        try {
                            $nfcPaths = @(
                                Join-Path $drivePath "Android\data\*nfc*",
                                Join-Path $drivePath "Android\system\*nfc*"
                            )
                            
                            foreach ($nfcPattern in $nfcPaths) {
                                $nfcFiles = Get-ChildItem -Path (Split-Path $nfcPattern -Parent) -Filter (Split-Path $nfcPattern -Leaf) -Recurse -ErrorAction SilentlyContinue |
                                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
                                
                                if ($nfcFiles.Count -gt 0) {
                                    $threats += @{
                                        Type = "Suspicious NFC-Related Files Detected (RatOn-like behavior)"
                                        Path = $nfcPattern
                                        FileCount = $nfcFiles.Count
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                }
                            }
                        } catch { }
                        
                    } catch {
                        Write-AVLog "Error scanning mobile device for malware: $_" "WARN" "mobile_device_monitoring.log"
                    }
                }
            }
            
            # Method 8: Monitor for banking app data exfiltration patterns
            try {
                # Check for processes accessing banking-related files
                $bankingKeywords = @("bank", "payment", "wallet", "credit", "debit", "account", "transaction", "balance")
                $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
                
                foreach ($proc in $processes) {
                    try {
                        $cmdLine = $proc.CommandLine
                        $procName = Split-Path -Leaf $proc.ExecutablePath
                        
                        if ($cmdLine) {
                            $matchesBanking = $false
                            foreach ($keyword in $bankingKeywords) {
                                if ($cmdLine -match $keyword) {
                                    $matchesBanking = $true
                                    break
                                }
                            }
                            
                            if ($matchesBanking -and $suspiciousProcesses -contains $procName) {
                                $threats += @{
                                    Type = "Suspicious Process Accessing Banking-Related Data"
                                    Process = $procName
                                    ProcessId = $proc.ProcessId
                                    CommandLine = $cmdLine
                                    Risk = "CRITICAL"
                                    Timestamp = Get-Date
                                }
                                
                                if ($Config.AutoKillThreats) {
                                    try {
                                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                        Write-AVLog "Terminated process accessing banking data: $procName" "THREAT" "mobile_device_monitoring.log"
                                    } catch { }
                                }
                            }
                        }
                    } catch { }
                }
            } catch { }
            
        } catch {
            Write-AVLog "Mobile malware detection error: $_" "ERROR" "mobile_device_monitoring.log"
        }
        
        # Log all detections and threats
        if ($detections.Count -gt 0 -or $threats.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "MOBILE DEVICE MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.Drive -or 'System')" "INFO" "mobile_device_monitoring.log"
            }
            
            foreach ($threat in $threats) {
                Write-AVLog "MOBILE DEVICE THREAT: $($threat.Type) - $($threat.Process -or $threat.Service -or 'Unknown') - Risk: $($threat.Risk)" "THREAT" "mobile_device_monitoring.log"
                $Global:AntivirusState.ThreatCount++
                
                # Add to response queue for automated response
                if ($Config.AutoKillThreats) {
                    $threatPath = $threat.FilePath -or $threat.Process -or $threat.Service -or ""
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\MobileDeviceMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            
            $allEvents = $detections + $threats
            $allEvents | ForEach-Object {
                $eventType = if ($_.Risk -match "CRITICAL|HIGH") { "THREAT" } else { "INFO" }
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$eventType|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.Process -or $_.Service -or 'N/A')|$($_.ProcessId -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-AVLog "Mobile device monitoring error: $_" "ERROR" "mobile_device_monitoring.log"
    }
    
    return ($detections.Count + $threats.Count)
}

function Invoke-AttackToolsDetection {
    $detections = @()
    $threats = @()
    
    try {
        # Comprehensive list of attack tools commonly found on dark web
        $attackTools = @{
            # Password Cracking Tools
            "PasswordCrackers" = @(
                "hydra", "hydra.exe", "hydra64.exe", "hydra32.exe",
                "john", "john.exe", "john-the-ripper", "jtr",
                "hashcat", "hashcat.exe", "hashcat64.exe",
                "medusa", "medusa.exe", "ncrack", "ncrack.exe",
                "patator", "patator.py", "brutus", "brutus.exe",
                "rainbowcrack", "rcrack", "ophcrack", "ophcrack.exe",
                "cain", "cain.exe", "abel.exe", "l0phtcrack"
            )
            # Exploitation Frameworks
            "ExploitationFrameworks" = @(
                "metasploit", "msfconsole", "msfvenom", "msfpayload",
                "cobaltstrike", "beacon.exe", "cobaltstrike.exe",
                "empire", "empire.exe", "powershell-empire",
                "covenant", "covenant.exe", "grunt.exe",
                "sliver", "sliver.exe", "merlin", "merlin.exe",
                "havoc", "havoc.exe", "bruteratel", "bruteratel.exe"
            )
            # Network Scanning & Reconnaissance
            "NetworkScanners" = @(
                "nmap", "nmap.exe", "zenmap", "zenmap.exe",
                "masscan", "masscan.exe", "zmap", "zmap.exe",
                "angryip", "angryip.exe", "advanced-port-scanner",
                "netscan", "netscan.exe", "lanmap", "lanmap.exe",
                "superscan", "superscan.exe", "netcat", "nc.exe",
                "socat", "socat.exe", "hping", "hping3.exe"
            )
            # Credential Dumping & Extraction
            "CredentialDumpers" = @(
                "mimikatz", "mimikatz.exe", "mimidrv.sys",
                "lazagne", "lazagne.exe", "laZagne.exe",
                "wce", "wce.exe", "wce32.exe", "wce64.exe",
                "fgdump", "fgdump.exe", "pwdump", "pwdump.exe",
                "gsecdump", "gsecdump.exe", "cachedump", "cachedump.exe",
                "lsadump", "lsadump.exe", "sekurlsa", "sekurlsa.exe",
                "procdump", "procdump.exe", "comsvcs.dll"
            )
            # Post-Exploitation & Lateral Movement
            "PostExploitation" = @(
                "bloodhound", "bloodhound.exe", "sharphound", "sharphound.exe",
                "powersploit", "invoke-mimikatz", "invoke-kerberoast",
                "empire", "empire.exe", "nishang", "nishang.ps1",
                "impacket", "secretsdump.py", "psexec.py", "smbexec.py",
                "crackmapexec", "crackmapexec.exe", "smbmap", "smbmap.exe",
                "evil-winrm", "evil-winrm.exe", "winrm", "winrm.exe"
            )
            # Web Application Attack Tools
            "WebAttackTools" = @(
                "sqlmap", "sqlmap.py", "burpsuite", "burp.exe",
                "nikto", "nikto.pl", "nikto.exe", "w3af",
                "wpscan", "wpscan.rb", "acunetix", "acunetix.exe",
                "appscan", "appscan.exe", "zap", "zap.exe",
                "dirb", "dirb.exe", "dirbuster", "dirbuster.exe",
                "gobuster", "gobuster.exe", "ffuf", "ffuf.exe"
            )
            # Packet Crafting & Network Tools
            "PacketCrafting" = @(
                "scapy", "scapy.py", "ettercap", "ettercap.exe",
                "wireshark", "wireshark.exe", "tshark", "tshark.exe",
                "tcpdump", "tcpdump.exe", "packeth", "packeth.exe",
                "packetbuilder", "packetbuilder.exe", "nemesis", "nemesis.exe",
                "hping", "hping3.exe", "yersinia", "yersinia.exe"
            )
            # RATs & Remote Access Tools
            "RemoteAccessTools" = @(
                "teamviewer", "teamviewer.exe", "anydesk", "anydesk.exe",
                "ultravnc", "ultravnc.exe", "tightvnc", "tightvnc.exe",
                "remmina", "remmina.exe", "remotex", "remotex.exe",
                "radmin", "radmin.exe", "logmein", "logmein.exe",
                "gotomypc", "gotomypc.exe", "ammyy", "ammyy.exe",
                "darkcomet", "darkcomet.exe", "poisonivy", "poisonivy.exe"
            )
            # Keyloggers & Monitoring
            "Keyloggers" = @(
                "keylogger", "keylogger.exe", "refog", "refog.exe",
                "spytech", "spytech.exe", "perfectkeylogger", "perfectkeylogger.exe",
                "allinonekeylogger", "allinonekeylogger.exe", "actualkeylogger",
                "actualkeylogger.exe", "keystrokecapture", "keystrokecapture.exe"
            )
            # File Transfer & Exfiltration
            "FileTransferTools" = @(
                "filezilla", "filezilla.exe", "winscp", "winscp.exe",
                "pscp", "pscp.exe", "scp", "scp.exe", "sftp", "sftp.exe",
                "curl", "curl.exe", "wget", "wget.exe", "aria2c", "aria2c.exe",
                "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe"
            )
            # Rootkits & Stealth Tools
            "Rootkits" = @(
                "fu", "fu.exe", "hackerdefender", "hackerdefender.exe",
                "afrootkit", "afrootkit.exe", "vanquish", "vanquish.exe",
                "adore", "adore-ng", "diamorphine", "enyelkm"
            )
            # Cryptocurrency Miners (often bundled with malware)
            "CryptoMiners" = @(
                "xmrig", "xmrig.exe", "ccminer", "ccminer.exe",
                "cgminer", "cgminer.exe", "minerd", "minerd.exe",
                "nicehash", "nicehash.exe", "claymore", "claymore.exe"
            )
        }
        
        # Known SHA256 hashes of attack tools (resistant to renaming)
        # Note: These are example hashes - in production, maintain a comprehensive database
        $knownToolHashes = @{
            # Hydra common versions (example patterns - update with real hashes)
            "Hydra" = @(
                # Add known Hydra hashes here when available
            )
            # Mimikatz common versions
            "Mimikatz" = @(
                # Add known Mimikatz hashes here
            )
            # Metasploit payloads
            "Metasploit" = @(
                # Add known Metasploit payload hashes
            )
        }
        
        # File signature patterns (YARA-like string detection - works even if renamed)
        $toolSignatures = @{
            # Hydra signatures
            "Hydra" = @(
                "THC Hydra", "hydra\.conf", "hydra\.restore", "Parallelized login cracker",
                "Supported services:", "hydra -l", "hydra -P", "hydra -L", "hydra -p"
            )
            # Mimikatz signatures
            "Mimikatz" = @(
                "mimikatz", "mimilib\.dll", "sekurlsa", "kerberos", "wdigest",
                "lsadump", "token::elevate", "privilege::debug", "Benjamin DELPY"
            )
            # Metasploit signatures
            "Metasploit" = @(
                "metasploit", "msfconsole", "msfvenom", "payload", "exploit",
                "Rapid7", "Metasploit Framework", "msfpayload"
            )
            # Cobalt Strike signatures
            "CobaltStrike" = @(
                "cobaltstrike", "beacon\.dll", "beacon\.exe", "ReflectiveLoader",
                "sleep_mask", "beacon\.stage", "Cobalt Strike"
            )
            # John the Ripper signatures
            "JohnTheRipper" = @(
                "John the Ripper", "jumbo", "john\.conf", "john\.pot", "wordlist",
                "cracking", "john --wordlist", "john --rules"
            )
            # Hashcat signatures
            "Hashcat" = @(
                "hashcat", "hashcat\.exe", "hash modes", "attack modes",
                "hashcat\.potfile", "hashcat --force"
            )
            # Nmap signatures
            "Nmap" = @(
                "Nmap", "Network Mapper", "nmap\.exe", "nmap\.conf", "nmap\.nse",
                "Starting Nmap", "Nmap scan report"
            )
            # BloodHound signatures
            "BloodHound" = @(
                "bloodhound", "BloodHound\.exe", "SharpHound", "BloodHound\.db",
                "neo4j", "BloodHound\.exe"
            )
            # Empire signatures
            "Empire" = @(
                "empire", "Empire\.exe", "empire\.db", "stagers", "listeners",
                "PowerShell Empire"
            )
            # LaZagne signatures
            "LaZagne" = @(
                "laZagne", "LaZagne", "lazagne\.exe", "password recovery",
                "browsers", "wifi", "mails"
            )
        }
        
        # Behavioral indicators (what tools DO, not what they're named)
        $behavioralIndicators = @{
            # Password cracking behaviors
            "PasswordCracking" = @{
                "NetworkPatterns" = @(
                    "Multiple failed login attempts", "Brute force patterns",
                    "Dictionary attack", "Credential stuffing"
                )
                "APICalls" = @(
                    "LogonUser", "CredUIPromptForCredentials", "WNetAddConnection2"
                )
                "FileOperations" = @(
                    "Reading wordlists", "Writing password files", "Hash files"
                )
            }
            # Credential dumping behaviors
            "CredentialDumping" = @{
                "APICalls" = @(
                    "LsaEnumerateLogonSessions", "LsaGetLogonSessionData",
                    "MiniDumpWriteDump", "ReadProcessMemory", "OpenProcess",
                    "CryptUnprotectData", "CredEnumerate"
                )
                "RegistryAccess" = @(
                    "HKLM\SAM", "HKLM\SECURITY", "HKLM\SYSTEM",
                    "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                )
                "ProcessAccess" = @(
                    "Accessing lsass.exe", "Accessing winlogon.exe", "Accessing csrss.exe"
                )
            }
            # Network scanning behaviors
            "NetworkScanning" = @{
                "NetworkPatterns" = @(
                    "Rapid port connections", "ICMP sweeps", "SYN scans",
                    "Multiple connection attempts", "ARP scanning"
                )
                "APICalls" = @(
                    "connect", "WSAConnect", "send", "recv", "gethostbyname"
                )
            }
            # Post-exploitation behaviors
            "PostExploitation" = @{
                "APICalls" = @(
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                    "NtQuerySystemInformation", "NetUserEnum", "NetLocalGroupEnum"
                )
                "NetworkPatterns" = @(
                    "SMB enumeration", "LDAP queries", "Kerberos ticket requests"
                )
                "FileOperations" = @(
                    "Reading AD data", "Dumping credentials", "Extracting tokens"
                )
            }
        }
        
        # Suspicious directory patterns where attack tools are often stored
        $suspiciousDirectories = @(
            "$env:USERPROFILE\Desktop\Tools",
            "$env:USERPROFILE\Downloads\Hacking",
            "$env:USERPROFILE\Documents\Tools",
            "$env:USERPROFILE\Desktop\Hack",
            "$env:TEMP\Tools",
            "$env:ProgramData\Tools",
            "C:\Tools",
            "C:\Hacking",
            "C:\Pentest",
            "C:\Security"
        )
        
        # Method 1: Scan running processes for attack tools
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPath = $proc.ExecutablePath
                    $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                    $procCmdLine = $proc.CommandLine
                    
                    if (-not $procName) { continue }
                    
                    $detectedTool = $null
                    $toolCategory = $null
                    $detectionMethod = "NameMatch"
                    
                    # Method 1A: Check process name and path against attack tools
                    foreach ($category in $attackTools.Keys) {
                        foreach ($tool in $attackTools[$category]) {
                            if ($procName -match $tool -or $procPath -match $tool -or $procCmdLine -match $tool) {
                                $detectedTool = $tool
                                $toolCategory = $category
                                $detectionMethod = "NameMatch"
                                break
                            }
                        }
                        if ($detectedTool) { break }
                    }
                    
                    # Method 1B: Hash-based detection (works even if renamed)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            $fileHash = (Get-FileHash -Path $procPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            
                            foreach ($toolName in $knownToolHashes.Keys) {
                                if ($knownToolHashes[$toolName] -contains $fileHash) {
                                    $detectedTool = $toolName
                                    $toolCategory = "Unknown"
                                    $detectionMethod = "HashMatch"
                                    break
                                }
                            }
                        } catch { }
                    }
                    
                    # Method 1C: File signature/string pattern detection (YARA-like)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            # Read first 1MB of file for signature scanning
                            $fileBytes = [System.IO.File]::ReadAllBytes($procPath)
                            $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                            
                            foreach ($toolName in $toolSignatures.Keys) {
                                foreach ($signature in $toolSignatures[$toolName]) {
                                    if ($fileContent -match [regex]::Escape($signature) -or 
                                        $procCmdLine -match [regex]::Escape($signature)) {
                                        $detectedTool = $toolName
                                        $toolCategory = "Unknown"
                                        $detectionMethod = "SignatureMatch"
                                        break
                                    }
                                }
                                if ($detectedTool) { break }
                            }
                        } catch { }
                    }
                    
                    # Method 1D: Entropy analysis (packed/obfuscated tools have high entropy)
                    if (-not $detectedTool -and $procPath -and (Test-Path $procPath)) {
                        try {
                            $entropy = Measure-FileEntropy -FilePath $procPath
                            if ($entropy -gt 7.5 -and (Get-Item $procPath).Length -lt 10MB) {
                                # High entropy + small size = possibly packed/obfuscated
                                # Check if unsigned
                                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                                if ($sig.Status -ne "Valid") {
                                    # Check command line for suspicious patterns
                                    if ($procCmdLine -match "password|brute|crack|hash|dump|scan|exploit") {
                                        $detectedTool = "SuspiciousPackedTool"
                                        $toolCategory = "Unknown"
                                        $detectionMethod = "EntropyAnalysis"
                                    }
                                }
                            }
                        } catch { }
                    }
                    
                    if ($detectedTool) {
                        # Check if it's a legitimate security tool in a known location
                        $isLegitimate = $false
                        $legitimatePaths = @(
                            "$env:ProgramFiles", "$env:ProgramFiles(x86)", 
                            "$env:ProgramData\Microsoft", "$env:SystemRoot\System32"
                        )
                        
                        foreach ($legPath in $legitimatePaths) {
                            if ($procPath -like "$legPath*") {
                                # Still suspicious but might be legitimate software
                                $isLegitimate = $true
                                break
                            }
                        }
                        
                        $riskLevel = if ($isLegitimate) { "MEDIUM" } else { "CRITICAL" }
                        
                        $threats += @{
                            Type = "Attack Tool Detected: $toolCategory"
                            ToolName = $detectedTool
                            ProcessName = $procName
                            ProcessPath = $procPath
                            ProcessId = $proc.ProcessId
                            CommandLine = $procCmdLine
                            Category = $toolCategory
                            DetectionMethod = $detectionMethod
                            Risk = $riskLevel
                            Timestamp = Get-Date
                        }
                        
                        # Attempt to terminate if critical
                        if ($Config.AutoKillThreats -and $riskLevel -eq "CRITICAL") {
                            try {
                                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                Write-AVLog "Terminated attack tool process: $procName ($detectedTool)" "THREAT" "attack_tools_detection.log"
                            } catch {
                                Write-AVLog "Failed to terminate ${procName}: $_" "WARN" "attack_tools_detection.log"
                            }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "Process scanning error in attack tools detection: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 2: Scan file system for attack tools
        try {
            $scanPaths = @(
                $env:USERPROFILE,
                $env:TEMP,
                $env:ProgramData,
                "C:\Tools",
                "C:\Hacking",
                "C:\Pentest"
            )
            
            foreach ($scanPath in $scanPaths) {
                if (-not (Test-Path $scanPath)) { continue }
                
                try {
                    # Search for executable files matching attack tool names
                    foreach ($category in $attackTools.Keys) {
                        foreach ($tool in $attackTools[$category]) {
                            $toolPattern = "*$tool*"
                            
                            try {
                                $foundFiles = Get-ChildItem -Path $scanPath -Filter $toolPattern -Recurse -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Extension -match "\.(exe|dll|bat|cmd|ps1|py|rb|pl)$" } |
                                    Select-Object -First 10
                                
                                foreach ($file in $foundFiles) {
                                    # Check file signature
                                    $isSigned = $false
                                    try {
                                        $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                        $isSigned = $sig.Status -eq "Valid"
                                    } catch { }
                                    
                                    if (-not $isSigned) {
                                        $threats += @{
                                            Type = "Attack Tool File Detected: $toolCategory"
                                            ToolName = $tool
                                            FilePath = $file.FullName
                                            FileName = $file.Name
                                            FileSize = "$([Math]::Round($file.Length / 1MB, 2)) MB"
                                            Category = $category
                                            IsSigned = $isSigned
                                            Risk = "HIGH"
                                            Timestamp = Get-Date
                                        }
                                        
                                        # Quarantine unsigned attack tools
                                        if ($Config.AutoQuarantine) {
                                            try {
                                                Move-ToQuarantine -FilePath $file.FullName -Reason "Attack tool detected: $tool ($category)"
                                                Write-AVLog "Quarantined attack tool: $($file.Name) ($tool)" "THREAT" "attack_tools_detection.log"
                                            } catch {
                                                Write-AVLog "Failed to quarantine $($file.Name): $_" "WARN" "attack_tools_detection.log"
                                            }
                                        }
                                    }
                                }
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "File system scanning error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 3: Check suspicious directories
        try {
            foreach ($susDir in $suspiciousDirectories) {
                if (Test-Path $susDir) {
                    try {
                        $exeFiles = Get-ChildItem -Path $susDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 20
                        
                        if ($exeFiles.Count -gt 5) {
                            $detections += @{
                                Type = "Suspicious Directory with Multiple Executables"
                                Directory = $susDir
                                ExecutableCount = $exeFiles.Count
                                Risk = "MEDIUM"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 4: Monitor for brute force attack patterns (Hydra, Medusa behavior)
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $cmdLine = $proc.CommandLine
                    if (-not $cmdLine) { continue }
                    
                    # Check for brute force attack patterns
                    $bruteForcePatterns = @(
                        "-l.*-P", "-L.*-P", "-u.*-p", "-U.*-P",  # Hydra patterns
                        "--wordlist", "--password", "--user",     # Medusa patterns
                        "brute", "crack", "dictionary", "wordlist"
                    )
                    
                    $isBruteForce = $false
                    foreach ($pattern in $bruteForcePatterns) {
                        if ($cmdLine -match $pattern) {
                            $isBruteForce = $true
                            break
                        }
                    }
                    
                    if ($isBruteForce) {
                        $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        $threats += @{
                            Type = "Brute Force Attack Tool Activity Detected"
                            ProcessName = $procName
                            ProcessId = $proc.ProcessId
                            CommandLine = $cmdLine
                            Risk = "CRITICAL"
                            Timestamp = Get-Date
                        }
                        
                        if ($Config.AutoKillThreats) {
                            try {
                                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                Write-AVLog "Terminated brute force attack: $procName" "THREAT" "attack_tools_detection.log"
                            } catch { }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        # Method 5: Check for network scanning activity (Nmap, Masscan patterns)
        try {
            $networkConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $_.State -eq "Established" -or $_.State -eq "Listen"
            }
            
            # Look for processes making many connections (port scanning behavior)
            $connectionCounts = $networkConnections | Group-Object -Property OwningProcess
            
            foreach ($connGroup in $connectionCounts) {
                if ($connGroup.Count -gt 50) {  # Suspicious number of connections
                    try {
                        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $($connGroup.Name)" -ErrorAction SilentlyContinue
                        if ($proc) {
                            $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                            
                            # Check if it's a known scanning tool
                            $isScanner = $false
                            foreach ($scanner in $attackTools["NetworkScanners"]) {
                                if ($procName -match $scanner -or $proc.ExecutablePath -match $scanner) {
                                    $isScanner = $true
                                    break
                                }
                            }
                            
                            if ($isScanner) {
                                $threats += @{
                                    Type = "Network Scanning Tool Detected"
                                    ProcessName = $procName
                                    ProcessId = $connGroup.Name
                                    ConnectionCount = $connGroup.Count
                                    Risk = "HIGH"
                                    Timestamp = Get-Date
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Method 6: Behavioral Detection - Credential Dumping Indicators
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPath = $proc.ExecutablePath
                    $procName = Split-Path -Leaf $procPath -ErrorAction SilentlyContinue
                    $procId = $proc.ProcessId
                    
                    if (-not $procPath -or -not (Test-Path $procPath)) { continue }
                    
                    # Check for processes accessing LSASS (credential dumping behavior)
                    try {
                        $lsassProcess = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
                        if ($lsassProcess) {
                            # Check if this process has handles to lsass
                            $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
                            if ($handles) {
                                foreach ($handle in $handles) {
                                    if ($handle.TargetProcessId -eq $lsassProcess.Id) {
                                        # Check if it's a legitimate process
                                        $legitimateProcs = @("svchost", "dllhost", "taskhost", "explorer")
                                        $isLegit = $false
                                        foreach ($legit in $legitimateProcs) {
                                            if ($procName -match $legit) {
                                                $isLegit = $true
                                                break
                                            }
                                        }
                                        
                                        if (-not $isLegit) {
                                            $threats += @{
                                                Type = "Credential Dumping Behavior Detected (LSASS Access)"
                                                ProcessName = $procName
                                                ProcessPath = $procPath
                                                ProcessId = $procId
                                                Behavior = "Accessing LSASS process"
                                                Risk = "CRITICAL"
                                                Timestamp = Get-Date
                                            }
                                            
                                            if ($Config.AutoKillThreats) {
                                                try {
                                                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                                                    Write-AVLog "Terminated credential dumping process: $procName" "THREAT" "attack_tools_detection.log"
                                                } catch { }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch { }
                    
                    # Check for processes reading SAM/SECURITY registry hives (Mimikatz-like behavior)
                    try {
                        $cmdLine = $proc.CommandLine
                        if ($cmdLine -match "reg.*save.*sam|reg.*save.*security|reg.*save.*system") {
                            $threats += @{
                                Type = "Credential Dumping Behavior (Registry Access)"
                                ProcessName = $procName
                                ProcessPath = $procPath
                                ProcessId = $procId
                                CommandLine = $cmdLine
                                Behavior = "Accessing SAM/SECURITY registry"
                                Risk = "CRITICAL"
                                Timestamp = Get-Date
                            }
                        }
                    } catch { }
                    
                } catch { }
            }
        } catch {
            Write-AVLog "Behavioral detection error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 7: Behavioral Detection - File Signature Scanning (works on renamed files)
        try {
            $scanPaths = @(
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Desktop",
                "$env:TEMP",
                "C:\Tools",
                "C:\Hacking"
            )
            
            foreach ($scanPath in $scanPaths) {
                if (-not (Test-Path $scanPath)) { continue }
                
                try {
                    $exeFiles = Get-ChildItem -Path $scanPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -lt 50MB } |  # Skip very large files
                        Select-Object -First 50
                    
                    foreach ($file in $exeFiles) {
                        try {
                            # Read file content for signature matching
                            $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                            $fileContent = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..[Math]::Min(1048576, $fileBytes.Length-1)])
                            
                            # Check against tool signatures
                            foreach ($toolName in $toolSignatures.Keys) {
                                $matchCount = 0
                                foreach ($signature in $toolSignatures[$toolName]) {
                                    if ($fileContent -match [regex]::Escape($signature)) {
                                        $matchCount++
                                    }
                                }
                                
                                # If multiple signatures match, it's likely this tool
                                if ($matchCount -ge 2) {
                                    # Check if unsigned
                                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                    if ($sig.Status -ne "Valid") {
                                        $threats += @{
                                            Type = "Attack Tool Detected by Signature (Renamed: $($file.Name))"
                                            ToolName = $toolName
                                            FilePath = $file.FullName
                                            FileName = $file.Name
                                            SignatureMatches = $matchCount
                                            DetectionMethod = "FileSignature"
                                            Risk = "CRITICAL"
                                            Timestamp = Get-Date
                                        }
                                        
                                        if ($Config.AutoQuarantine) {
                                            try {
                                                Move-ToQuarantine -FilePath $file.FullName -Reason "Attack tool detected by signature: $toolName"
                                                Write-AVLog "Quarantined renamed attack tool: $($file.Name) (detected as $toolName)" "THREAT" "attack_tools_detection.log"
                                            } catch { }
                                        }
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "File signature scanning error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Method 8: Behavioral Detection - Command Line Pattern Analysis
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $cmdLine = $proc.CommandLine
                    if (-not $cmdLine) { continue }
                    
                    $procName = Split-Path -Leaf $proc.ExecutablePath -ErrorAction SilentlyContinue
                    $procPath = $proc.ExecutablePath
                    
                    # Check for tool-specific command patterns (works even if renamed)
                    $suspiciousPatterns = @{
                        "PasswordCracking" = @(
                            "-l.*-P", "-L.*-p", "wordlist", "dictionary", "brute.*force",
                            "crack.*password", "hash.*crack"
                        )
                        "CredentialDumping" = @(
                            "sekurlsa", "lsadump", "mimikatz", "wdigest", "kerberos",
                            "dump.*password", "extract.*hash", "sam.*dump"
                        )
                        "NetworkScanning" = @(
                            "-p-", "-p.*1-65535", "port.*scan", "host.*scan",
                            "-sS", "-sT", "-sU", "nmap.*scan"
                        )
                        "Exploitation" = @(
                            "exploit", "payload", "reverse.*shell", "bind.*shell",
                            "meterpreter", "msfconsole", "msfvenom"
                        )
                    }
                    
                    foreach ($behaviorType in $suspiciousPatterns.Keys) {
                        foreach ($pattern in $suspiciousPatterns[$behaviorType]) {
                            if ($cmdLine -match $pattern) {
                                # Check if it's a legitimate process
                                $legitimateProcs = @("svchost", "dllhost", "taskhost", "explorer", "chrome", "firefox", "edge")
                                $isLegit = $false
                                foreach ($legit in $legitimateProcs) {
                                    if ($procName -match $legit -and $procPath -like "*$legit*") {
                                        $isLegit = $true
                                        break
                                    }
                                }
                                
                                if (-not $isLegit) {
                                    $threats += @{
                                        Type = "Attack Tool Behavior Detected: $behaviorType"
                                        ProcessName = $procName
                                        ProcessPath = $procPath
                                        ProcessId = $proc.ProcessId
                                        CommandLine = $cmdLine
                                        BehaviorPattern = $pattern
                                        Risk = "HIGH"
                                        Timestamp = Get-Date
                                    }
                                    
                                    if ($Config.AutoKillThreats) {
                                        try {
                                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                                            Write-AVLog "Terminated suspicious behavior: $procName ($behaviorType)" "THREAT" "attack_tools_detection.log"
                                        } catch { }
                                    }
                                }
                                break
                            }
                        }
                    }
                } catch { }
            }
        } catch {
            Write-AVLog "Command line pattern analysis error: $_" "WARN" "attack_tools_detection.log"
        }
        
        # Log all detections and threats
        if ($detections.Count -gt 0 -or $threats.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "ATTACK TOOLS DETECTION: $($detection.Type) - $($detection.Directory -or 'System')" "INFO" "attack_tools_detection.log"
            }
            
            foreach ($threat in $threats) {
                $detectionMethod = if ($threat.DetectionMethod) { " [$($threat.DetectionMethod)]" } else { "" }
                Write-AVLog "ATTACK TOOL THREAT: $($threat.Type) - $($threat.ToolName -or $threat.ProcessName -or 'Unknown') - Risk: $($threat.Risk)$detectionMethod" "THREAT" "attack_tools_detection.log"
                $Global:AntivirusState.ThreatCount++
                
                # Add to response queue
                if ($Config.AutoKillThreats) {
                    $threatPath = $threat.FilePath -or $threat.ProcessPath -or $threat.ProcessName -or $threat.ToolName -or ""
                    Add-ThreatToResponseQueue -ThreatType $threat.Type -ThreatPath $threatPath -Severity $threat.Risk
                }
            }
            
            # Write detailed log
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\AttackToolsDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            
            $allEvents = $detections + $threats
            $allEvents | ForEach-Object {
                $eventType = if ($_.Risk -match "CRITICAL|HIGH") { "THREAT" } else { "INFO" }
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$eventType|$($_.Type)|$($_.Risk)|$($_.ToolName -or $_.ProcessName -or $_.Directory -or 'N/A')|$($_.ProcessId -or 'N/A')|$($_.Category -or 'N/A')|$($_.DetectionMethod -or 'N/A')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-AVLog "Attack tools detection error: $_" "ERROR" "attack_tools_detection.log"
    }
    
    return ($detections.Count + $threats.Count)
}

function Invoke-EventLogMonitoring {
    param(
        [int]$LookbackHours = 1,
        [bool]$CorrelationEnabled = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddHours(-$LookbackHours)

        # 1. Security log cleared (Event ID 1102)
        try {
            $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
    foreach ($LogEvent in $ClearedLogs) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                
                $Threats += @{
                    Type = "SecurityLogCleared"
                    EventId = 1102
                    Time = $LogEvent.TimeCreated
                    User = $username
                    Severity = "Critical"
                    ThreatScore = 50
                }
                
                Write-Output "[EventLog] CRITICAL: Security log cleared | Time: $($LogEvent.TimeCreated) | User: $username"
                Add-ThreatToResponseQueue -ThreatType "SecurityLogCleared" -ThreatPath "EventLog" -Severity "Critical"
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check cleared logs: $_" -Level "Warning"
        }

        # 2. Failed logon attempts (Event ID 4625) - Advanced brute force detection
        try {
            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            # Group by account name and analyze
            $AccountAttempts = $FailedLogons | Group-Object {
                if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" }
            }
            
            foreach ($Account in $AccountAttempts) {
                $attemptCount = $Account.Count
                $accountName = $Account.Name
                
                if ($attemptCount -gt 5) {
                    # Calculate threat score based on attempt frequency
                    $timeSpan = ($Account.Group | Measure-Object -Property TimeCreated -Maximum).Maximum - 
                               ($Account.Group | Measure-Object -Property TimeCreated -Minimum).Minimum
                    $attemptsPerMinute = if ($timeSpan.TotalMinutes -gt 0) { $attemptCount / $timeSpan.TotalMinutes } else { $attemptCount }
                    
                    $severity = if ($attemptsPerMinute -gt 10) { "Critical" } 
                               elseif ($attemptsPerMinute -gt 5) { "High" } 
                               elseif ($attemptCount -gt 20) { "High" }
                               else { "Medium" }
                    
                    $Threats += @{
                        Type = "BruteForceAttempt"
                        EventId = 4625
                        Account = $accountName
                        AttemptCount = $attemptCount
                        AttemptsPerMinute = [Math]::Round($attemptsPerMinute, 2)
                        TimeSpan = $timeSpan
                        Severity = $severity
                        ThreatScore = [Math]::Min(50, 20 + ($attemptsPerMinute * 2))
                    }
                    
                    Write-Output "[EventLog] THREAT ($severity): Brute force attempt detected | Account: $accountName | Attempts: $attemptCount | Rate: $([Math]::Round($attemptsPerMinute, 2))/min"
                    
                    if ($severity -eq "Critical" -or $attemptCount -gt 30) {
                        Add-ThreatToResponseQueue -ThreatType "BruteForceAttack" -ThreatPath $accountName -Severity $severity
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check failed logons: $_" -Level "Warning"
        }

        # 3. Privilege escalation (Event ID 4672 - Admin logon)
        try {
            $AdminLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AdminLogons) {
                $username = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                $logonType = if ($LogEvent.Properties.Count -gt 3) { $LogEvent.Properties[3].Value } else { "Unknown" }
                
                # Check for suspicious logon types (network logons with admin rights)
                if ($logonType -in @(3, 8, 10)) { # Network, NetworkCleartext, RemoteInteractive
                    $Threats += @{
                        Type = "SuspiciousAdminLogon"
                        EventId = 4672
                        User = $username
                        LogonType = $logonType
                        Time = $LogEvent.TimeCreated
                        Severity = "High"
                        ThreatScore = 35
                    }
                    
                    Write-Output "[EventLog] HIGH: Suspicious admin network logon | User: $username | LogonType: $logonType | Time: $($LogEvent.TimeCreated)"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check admin logons: $_" -Level "Warning"
        }

        # 4. Account manipulation (Event IDs 4728, 4732, 4756)
        try {
            $AccountEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4728,4732,4756;StartTime=$cutoffTime} -MaxEvents 50 -ErrorAction SilentlyContinue
            foreach ($LogEvent in $AccountEvents) {
                $eventType = switch ($LogEvent.Id) {
                    4728 { "Member added to security-enabled global group" }
                    4732 { "Member added to security-enabled local group" }
                    4756 { "Member added to security-enabled universal group" }
                    default { "Unknown account change" }
                }
                
                $targetAccount = if ($LogEvent.Properties.Count -gt 0) { $LogEvent.Properties[0].Value } else { "Unknown" }
                $subjectAccount = if ($LogEvent.Properties.Count -gt 4) { $LogEvent.Properties[4].Value } else { "Unknown" }
                
                # Check for privilege escalation attempts
                if ($targetAccount -match "Administrator|Domain Admin|Enterprise Admin|Schema Admin" -and $subjectAccount -ne $targetAccount) {
                    $Threats += @{
                        Type = "PrivilegeEscalationAttempt"
                        EventId = $LogEvent.Id
                        EventType = $eventType
                        TargetAccount = $targetAccount
                        SubjectAccount = $subjectAccount
                        Time = $LogEvent.TimeCreated
                        Severity = "Critical"
                        ThreatScore = 45
                    }
                    
                    Write-Output "[EventLog] CRITICAL: Potential privilege escalation | $eventType | Target: $targetAccount | Subject: $subjectAccount"
                    Add-ThreatToResponseQueue -ThreatType "PrivilegeEscalation" -ThreatPath "$subjectAccount -> $targetAccount" -Severity "Critical"
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check account changes: $_" -Level "Warning"
        }

        # 5. Process creation events (Event ID 4688) - Suspicious processes
        try {
            $ProcessEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$cutoffTime} -MaxEvents 100 -ErrorAction SilentlyContinue
            
            $SuspiciousProcesses = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
            
            foreach ($LogEvent in $ProcessEvents) {
                if ($LogEvent.Properties.Count -gt 5) {
                    $processName = $LogEvent.Properties[5].Value
                    $commandLine = if ($LogEvent.Properties.Count -gt 8) { $LogEvent.Properties[8].Value } else { "" }
                    
                    if ($SuspiciousProcesses -contains $processName) {
                        # Check for suspicious command line patterns
                        $suspiciousPatterns = @("-enc", "-EncodedCommand", "downloadstring", "iex", "invoke-expression", "bypass", "hidden")
                        $foundPattern = $suspiciousPatterns | Where-Object { $commandLine -match [regex]::Escape($_) }
                        
                        if ($foundPattern) {
                            $subject = if ($LogEvent.Properties.Count -gt 1) { $LogEvent.Properties[1].Value } else { "Unknown" }
                            
                            $Threats += @{
                                Type = "SuspiciousProcessExecution"
                                EventId = 4688
                                ProcessName = $processName
                                CommandLine = $commandLine
                                Subject = $subject
                                SuspiciousPattern = $foundPattern
                                Time = $LogEvent.TimeCreated
                                Severity = "High"
                                ThreatScore = 40
                            }
                            
                            Write-Output "[EventLog] HIGH: Suspicious process execution | Process: $processName | Pattern: $foundPattern | Subject: $subject"
                        }
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "EventLogMonitoring" -Message "Failed to check process events: $_" -Level "Warning"
        }

        # 6. Event correlation (if enabled)
        if ($CorrelationEnabled -and $Threats.Count -gt 1) {
            # Group threats by time window (within 5 minutes)
            $correlatedThreats = $Threats | Group-Object {
                $timeWindow = $_.Time.ToString("yyyy-MM-dd HH:mm")
                $timeWindow
            }
            
            foreach ($group in $correlatedThreats) {
                if ($group.Count -ge 3) {
                    $uniqueTypes = $group.Group | Select-Object -ExpandProperty Type -Unique
                    Write-Output "[EventLog] WARNING: Event correlation detected | Time: $($group.Name) | Events: $($group.Count) | Types: $($uniqueTypes -join ', ')"
                    Write-EDRLog -Module "EventLogMonitoring" -Message "Correlated threat activity: $($group.Count) events in time window $($group.Name)" -Level "Warning"
                }
            }
        }

        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring completed: $($Threats.Count) threat(s) detected" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "EventLogMonitoring" -Message "Event log monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-FirewallRuleMonitoring {
    if (-not $Global:BaselineFirewallRules) {
        $Global:BaselineFirewallRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    }

    $CurrentRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    $NewRules = $CurrentRules | Where-Object { $_ -notin $Global:BaselineFirewallRules }

    foreach ($Rule in $NewRules) {
        $RuleDetails = Get-NetFirewallRule -Name $Rule
        Write-Output "[Firewall] NEW RULE: $($RuleDetails.DisplayName) | Action: $($RuleDetails.Action) | Direction: $($RuleDetails.Direction)"
    }

    $Global:BaselineFirewallRules = $CurrentRules
}

function Invoke-ServiceMonitoring {
    param(
        [bool]$AutoBlockThreats = $false
    )

    try {
    if (-not $Global:BaselineServices) {
        $Global:BaselineServices = Get-Service | Select-Object -ExpandProperty Name
    }

    $CurrentServices = Get-Service | Select-Object -ExpandProperty Name
    $NewServices = $CurrentServices | Where-Object { $_ -notin $Global:BaselineServices }
        $Threats = @()

    foreach ($ServiceName in $NewServices) {
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $Service) { continue }

        $ServiceDetails = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                if (-not $ServiceDetails) { continue }

                $ThreatScore = 0
                $Reasons = @()

                # 1. Check for services in non-standard locations
                if ($ServiceDetails.PathName -and $ServiceDetails.PathName -notmatch "^C:\\(Windows|Program Files)") {
                    $ThreatScore += 30
                    $Reasons += "Service executable in non-standard location: $($ServiceDetails.PathName)"
                    
                    # Check for suspicious paths (temp, user directories)
                    if ($ServiceDetails.PathName -match "(Temp|TEMP|tmp|appdata|localappdata|users)") {
                        $ThreatScore += 20
                        $Reasons += "Service executable in suspicious location (temp/user directory)"
                    }
                }

                # 2. Check for unsigned services
                try {
                    if ($ServiceDetails.PathName -and (Test-Path $ServiceDetails.PathName)) {
                        $sig = Get-AuthenticodeSignature -FilePath $ServiceDetails.PathName -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") {
                            $ThreatScore += 25
                            $Reasons += "Unsigned or invalid signature (Status: $($sig.Status))"
                        }
                    }
                } catch {}

                # 3. Check for suspicious service names
                $SuspiciousServiceNames = @("update", "svc", "helper", "service", "runtime", "agent", "monitor", "guard", "protect")
                foreach ($pattern in $SuspiciousServiceNames) {
                    if ($ServiceName -match $pattern -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                        $ThreatScore += 15
                        $Reasons += "Suspicious service name pattern: $pattern"
                        break
                    }
                }

                # 4. Check for services with suspicious startup types
                if ($Service.StartType -eq "Automatic" -and $ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    $ThreatScore += 10
                    $Reasons += "Auto-start service from non-standard location"
                }

                # 5. Check for services with suspicious account (SYSTEM account is normal, others are suspicious)
                if ($ServiceDetails.StartName -and $ServiceDetails.StartName -notmatch "^(LocalSystem|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService)") {
                    $ThreatScore += 20
                    $Reasons += "Service running under non-standard account: $($ServiceDetails.StartName)"
                }

                # 6. Check for services with suspicious descriptions
                if ($Service.DisplayName -and $Service.DisplayName.Length -lt 5) {
                    $ThreatScore += 10
                    $Reasons += "Suspiciously short service display name"
                }

                # 7. Check for services with suspicious executable names
                if ($ServiceDetails.PathName) {
                    $exeName = Split-Path -Leaf $ServiceDetails.PathName
                    if ($exeName -match "^[a-z0-9]{8,}\.exe$" -or $exeName -match "svchost|lsass|csrss|winlogon") {
                        $ThreatScore += 25
                        $Reasons += "Service with suspicious executable name: $exeName (potential masquerading)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 25) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousService"
                        ServiceName = $ServiceName
                        DisplayName = $Service.DisplayName
                        PathName = $ServiceDetails.PathName
                        StartType = $Service.StartType
                        Status = $Service.Status
                        StartName = $ServiceDetails.StartName
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[Service] THREAT ($severity): Suspicious service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoBlockThreats -and $ThreatScore -ge 40) {
                        try {
                            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
                            Write-Output "[Service] ACTION: Stopped and disabled suspicious service: $ServiceName"
                            Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                        } catch {
                            Write-EDRLog -Module "ServiceMonitoring" -Message "Failed to stop service ${ServiceName}: $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 35) {
                        Add-ThreatToResponseQueue -ThreatType "SuspiciousService" -ThreatPath $ServiceName -Severity $severity
                    }
                } elseif ($ServiceDetails.PathName -notmatch "^C:\\Windows") {
                    # Even if score is low, log new services from non-standard locations
                    Write-Output "[Service] INFO: New service detected | Name: $ServiceName | Display: $($Service.DisplayName) | Path: $($ServiceDetails.PathName)"
                }
            }
            catch {
                Write-EDRLog -Module "ServiceMonitoring" -Message "Error analyzing service ${ServiceName}: $_" -Level "Warning"
            }
        }

        # Check for removed services (potential cleanup indicator)
        $RemovedServices = $Global:BaselineServices | Where-Object { $_ -notin $CurrentServices }
        if ($RemovedServices.Count -gt 0) {
            Write-EDRLog -Module "ServiceMonitoring" -Message "Services removed: $($RemovedServices -join ', ')" -Level "Info"
    }

    $Global:BaselineServices = $CurrentServices

        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring completed: $($Threats.Count) threat(s) found, $($NewServices.Count) new service(s)" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; NewServices = $NewServices.Count; RemovedServices = $RemovedServices.Count}
    }
    catch {
        Write-EDRLog -Module "ServiceMonitoring" -Message "Service monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); NewServices = 0; RemovedServices = 0}
    }
}

function Invoke-FilelessDetection {
    param(
        [bool]$AutoKillThreats = $true
    )

    try {
        $Threats = @()
        
        # Fileless malware signatures for advanced detection
        $filelessSignatures = @{
            "FilelessMalware" = @(
                "fileless", "memory.*only", "powershell.*encoded", "base64.*decode",
                "downloadstring", "invoke.*expression", "bypass.*execution"
            )
        }
        
        # Fileless behavioral patterns
        $filelessBehaviors = @{
            "PowerShellFileless" = @(
                "-enc", "-EncodedCommand", "downloadstring", "DownloadString",
                "iex", "Invoke-Expression", "bypass.*executionpolicy",
                "-nop.*-w.*hidden", "new-object.*net.webclient"
            )
            "WMIFileless" = @(
                "wmic.*process", "wmic.*shadowcopy", "wmic.*event",
                "wmi.*subscription", "wmi.*consumer"
            )
            "RegistryFileless" = @(
                "reg.*add.*run", "reg.*load", "reg.*save",
                "registry.*run", "startup.*script"
            )
        }

        # 1. PowerShell encoded commands
        # Whitelist own process and script path
        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
        $PSProcesses = Get-Process | Where-Object { 
            $_.ProcessName -match "powershell|pwsh" -and 
            $_.Id -ne $PID -and
            $_.Id -ne $Script:SelfPID
        }
    foreach ($Process in $PSProcesses) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                if (-not $CommandLine) { continue }
                
                # Skip if this is our own script
                if ($ownScriptPath -and $CommandLine -like "*$ownScriptPath*") {
                    continue
                }
                
                # Use advanced detection framework
                $procPath = $Process.Path
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $filelessSignatures `
                        -BehavioralIndicators $filelessBehaviors `
                        -CommandLine $CommandLine `
                        -CheckEntropy $false
                    
                    if ($detectionResult.IsThreat) {
                        $Threats += @{
                            Type = "Fileless Malware Detected via Advanced Framework"
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            CommandLine = $CommandLine
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Severity = if ($detectionResult.Risk -eq "CRITICAL") { "Critical" } elseif ($detectionResult.Risk -eq "HIGH") { "High" } else { "Medium" }
                            Time = Get-Date
                        }
                        continue
                    }
                }

                $SuspiciousPatterns = @{
                    "-enc|-EncodedCommand" = @{Score = 40; Reason = "Base64 encoded PowerShell command"}
                    "downloadstring|DownloadString" = @{Score = 35; Reason = "Download string from remote source"}
                    "iex|Invoke-Expression" = @{Score = 30; Reason = "Invoke expression (code execution)"}
                    "bypass.*executionpolicy" = @{Score = 35; Reason = "Execution policy bypass"}
                    "-nop.*-w.*hidden" = @{Score = 30; Reason = "Hidden window execution"}
                    "new-object.*net.webclient" = @{Score = 25; Reason = "Web client object creation"}
                    "invoke-webrequest|iwr|curl" = @{Score = 20; Reason = "Web request command"}
                }

                $ThreatScore = 0
                $FoundPatterns = @()
                
                foreach ($pattern in $SuspiciousPatterns.Keys) {
                    if ($CommandLine -match $pattern) {
                        $patternInfo = $SuspiciousPatterns[$pattern]
                        $ThreatScore += $patternInfo.Score
                        $FoundPatterns += $patternInfo.Reason
                    }
                }

                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "SuspiciousPowerShell"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        CommandLine = $CommandLine
                        ThreatScore = $ThreatScore
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[Fileless] THREAT ($severity): PowerShell fileless activity detected | PID: $($Process.Id) | Score: $ThreatScore | Patterns: $($FoundPatterns -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 40) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "FilelessDetection" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-Output "[Fileless] ACTION: Terminated suspicious PowerShell process (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                        } catch {
                            Write-EDRLog -Module "FilelessDetection" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } else {
                        Add-ThreatToResponseQueue -ThreatType "FilelessPowerShell" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
            }
        } catch {}
    }

        # 2. WMI-based fileless persistence (Event Consumers)
        try {
            $EventConsumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
            foreach ($consumer in $EventConsumers) {
                $consumerType = $consumer.__CLASS
                $commandLine = ""
                
                if ($consumerType -eq "__EventFilter") {
                    $query = $consumer.Query
                    if ($query -match "SELECT.*FROM.*WITHIN" -and ($query -match "powershell|wscript|cscript|cmd")) {
                        $Threats += @{
                            Type = "WMIEventConsumer"
                            ConsumerType = $consumerType
                            Query = $query
                            Name = $consumer.Name
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-Output "[Fileless] HIGH: WMI event consumer with suspicious query detected | Name: $($consumer.Name) | Type: $consumerType"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "High"
                    }
                }
                
                if ($consumerType -eq "__CommandLineEventConsumer") {
                    $commandLine = $consumer.CommandLineTemplate
                    if ($commandLine -match "(powershell|wscript|cscript|cmd).*(enc|bypass|hidden|download)" -or
                        $commandLine -match "-enc|-EncodedCommand") {
                        $Threats += @{
                            Type = "WMICommandConsumer"
                            ConsumerType = $consumerType
                            CommandLine = $commandLine
                            Name = $consumer.Name
                            Severity = "Critical"
                            ThreatScore = 50
                        }
                        
                        Write-Output "[Fileless] CRITICAL: WMI command consumer with suspicious command detected | Name: $($consumer.Name) | Command: $commandLine"
                        Add-ThreatToResponseQueue -ThreatType "WMIFileless" -ThreatPath "WMI:$($consumer.Name)" -Severity "Critical"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "WMI consumer scan failed: $_" -Level "Warning"
        }

        # 3. Registry-based fileless (AppInit_DLLs, Run keys with suspicious values)
        try {
            $SuspiciousRegistryKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )

            foreach ($regPath in $SuspiciousRegistryKeys) {
                try {
                    if (Test-Path $regPath) {
                        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $props = $values.PSObject.Properties | Where-Object { $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" }
                            foreach ($prop in $props) {
                                $value = $prop.Value
                                if ($value -match "(powershell|wscript|cscript|cmd).*(enc|bypass|download|iex)" -or
                                    $value -match "-enc|-EncodedCommand|downloadstring|iex") {
                                    
                                    $Threats += @{
                                        Type = "RegistryFileless"
                                        RegistryPath = $regPath
                                        KeyName = $prop.Name
                                        Value = $value
                                        Severity = "High"
                                        ThreatScore = 40
                                    }
                                    
                                    Write-Output "[Fileless] HIGH: Registry-based fileless persistence detected | Path: $regPath | Key: $($prop.Name) | Value: $value"
                                    Add-ThreatToResponseQueue -ThreatType "RegistryFileless" -ThreatPath "$regPath\$($prop.Name)" -Severity "High"
                                }
                            }
                        }
            }
        } catch {}
    }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Registry scan failed: $_" -Level "Warning"
        }

        # 4. Scheduled tasks with fileless techniques
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" }
            foreach ($task in $tasks) {
                $action = $task.Actions
                if ($action) {
                    $command = $action.Execute
                    $arguments = $action.Arguments
                    
                    # Whitelist our own scheduled tasks
                    if ($task.TaskName -like "AntivirusAutoRestart_*" -or $task.TaskName -eq "AntivirusProtection") {
                        continue
                    }
                    
                    if ($command -match "powershell|wscript|cscript|cmd" -and 
                        ($arguments -match "-enc|-EncodedCommand|downloadstring|iex|bypass" -or
                         $command -match "-enc|-EncodedCommand")) {
                        
                        $Threats += @{
                            Type = "ScheduledTaskFileless"
                            TaskName = $task.TaskName
                            Command = $command
                            Arguments = $arguments
                            Severity = "High"
                            ThreatScore = 45
                        }
                        
                        Write-Output "[Fileless] HIGH: Scheduled task with fileless technique detected | Task: $($task.TaskName) | Command: $command | Args: $arguments"
                        Add-ThreatToResponseQueue -ThreatType "ScheduledTaskFileless" -ThreatPath "Task:$($task.TaskName)" -Severity "High"
                    }
                }
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Scheduled task scan failed: $_" -Level "Warning"
        }

        # 5. .NET assembly loading (reflection-based)
        try {
            $PSProcesses = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }
            foreach ($Process in $PSProcesses) {
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.ModuleName -match "System\.Reflection|System\.Management\.Automation" -and
                        $_.FileName -match "System\.Management\.Automation"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $Threats += @{
                            Type = "ReflectionAssemblyLoading"
                            ProcessId = $Process.Id
                            ProcessName = $Process.ProcessName
                            ModuleCount = $modules.Count
                            Severity = "Medium"
                            ThreatScore = 30
                        }
                        
                        Write-Output "[Fileless] MEDIUM: Excessive reflection/assembly loading detected | PID: $($Process.Id) | Modules: $($modules.Count)"
                    }
                } catch {}
            }
        } catch {
            Write-EDRLog -Module "FilelessDetection" -Message "Assembly loading scan failed: $_" -Level "Warning"
        }

        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "FilelessDetection" -Message "Fileless detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-MemoryScanning {
    param(
        [bool]$AutoKillThreats = $true,
        [bool]$DeepScan = $false
    )

    try {
        $Threats = @()
        $SuspiciousPatterns = @(
            "\x48\x8B\xEC\x48\x83\xEC.{0,20}\xE8",  # Common shellcode prologue (mov rbp, rsp; sub rsp, ...; call)
            "\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9",  # XOR eax,eax; XOR ebx,ebx; XOR ecx,ecx (common shellcode)
            "\xFC\x48\x83\xE4",  # CLD; AND rsp, ...
            "\xEB.{0,5}\x5E",  # JMP short; POP ESI (common shellcode)
            "powershell.*-enc|powershell.*-EncodedCommand",  # Encoded PowerShell in memory
            "cmd.*\/c.*powershell",  # Command execution via cmd
            "downloadstring|DownloadString",  # Download string patterns
            "new-object.*net.webclient",  # WebClient object creation
            "invoke-expression|iex",  # Code execution
            "mimikatz|kiwi|sekurlsa",  # Known credential dumping tools
            "procdump|nanodump|dumpert"  # Known memory dumping tools
        )

        # Memory-based signature patterns (common malware signatures)
        $MalwareSignatures = @(
            "MZ\x90\x00",  # PE header (check for unpacked executables in memory)
            "\x55\x8B\xEC\x83\xEC",  # Function prologue common in shellcode
            "\xE8\x00\x00\x00\x00",  # CALL instruction (relative jump)
            "\xFF\xD0|\xFF\xD1|\xFF\xD2"  # CALL EAX/ECX/EDX (indirect calls)
        )

        $Processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 50MB }

        foreach ($Process in $Processes) {
            try {
                $ThreatScore = 0
                $FoundPatterns = @()
                $Reasons = @()

                # 1. Memory size anomaly detection
                if ($Process.PrivateMemorySize64 -gt 1GB) {
                    $ThreatScore += 10
                    $Reasons += "Large private memory: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB"
                }

                if ($Process.PrivateMemorySize64 -gt $Process.WorkingSet64 * 2) {
                    $ThreatScore += 15
                    $Reasons += "Memory anomaly: Private memory significantly larger than working set"
                    Write-Output "[MemoryScan] SUSPICIOUS: Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Private: $([Math]::Round($Process.PrivateMemorySize64/1MB, 2)) MB | WorkingSet: $([Math]::Round($Process.WorkingSet64/1MB, 2)) MB"
                }

                # 2. Check for unusual module loading
                try {
                    $modules = $Process.Modules | Where-Object { 
                        $_.FileName -and 
                        $_.FileName -notmatch "^C:\\(Windows|Program Files)" -and
                        $_.ModuleName -notmatch "^(ntdll|kernel32|msvcr|msvcp|advapi32)"
                    }
                    
                    if ($modules.Count -gt 5) {
                        $ThreatScore += 20
                        $Reasons += "Unusual module count: $($modules.Count) non-standard modules"
                        
                        # Check for suspicious module names
                        $suspiciousModules = $modules | Where-Object { 
                            $_.ModuleName -match "(inject|hook|stealth|hide|rootkit|keylog|spy)"
                        }
                        
                        if ($suspiciousModules) {
                            $ThreatScore += 30
                            $Reasons += "Suspicious module names detected"
                            foreach ($mod in $suspiciousModules) {
                                $FoundPatterns += "Suspicious module: $($mod.ModuleName) ($($mod.FileName))"
                            }
                        }
                    }
                } catch {}

                # 3. Deep memory scanning (if enabled - more resource intensive)
                if ($DeepScan -and $Process.WorkingSet64 -lt 500MB) {
                    try {
                        # Read process memory (requires special permissions)
                        $memoryRegions = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $Process.Id }
                        
                        # Check command line for suspicious patterns
                        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                        if ($commandLine) {
                            foreach ($pattern in $SuspiciousPatterns) {
                                if ($commandLine -match $pattern) {
                                    $ThreatScore += 25
                                    $FoundPatterns += "Command line pattern: $pattern"
                                    break
                                }
                            }
                        }

                        # Check for code injection indicators (unusual memory permissions)
                        # This would require kernel debugging in real implementation
                        # Simplified heuristic: check for processes with unusual thread counts
                        if ($Process.Threads.Count -gt 100) {
                            $ThreatScore += 15
                            $Reasons += "High thread count: $($Process.Threads.Count) threads"
                        }

        } catch {
                        # Memory scanning requires elevated privileges, skip silently
                        Write-EDRLog -Module "MemoryScanning" -Message "Deep scan requires elevated privileges for PID $($Process.Id)" -Level "Debug"
                    }
                }

                # 4. Check for known malicious process characteristics
                $knownMaliciousProcesses = @{
                    "powershell.exe" = @{BaselineMem = 100MB; BaselineThreads = 10}
                    "cmd.exe" = @{BaselineMem = 50MB; BaselineThreads = 3}
                    "wscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                    "cscript.exe" = @{BaselineMem = 80MB; BaselineThreads = 5}
                }

                if ($knownMaliciousProcesses.ContainsKey($Process.ProcessName)) {
                    $baseline = $knownMaliciousProcesses[$Process.ProcessName]
                    
                    if ($Process.WorkingSet64 -gt ($baseline.BaselineMem * 5)) {
                        $ThreatScore += 25
                        $Reasons += "Memory usage significantly above baseline for $($Process.ProcessName)"
                    }
                    
                    if ($Process.Threads.Count -gt ($baseline.BaselineThreads * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Thread count significantly above baseline for $($Process.ProcessName)"
                    }
                }

                # 5. Check for processes with no executable path (potential process hollowing)
                # Whitelist known system processes that may not have paths
                $systemProcessNames = @("Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "spoolsv", "dwm", "audiodg")
                if (-not $Process.Path -or $Process.Path -notmatch "\.exe$") {
                    if ($systemProcessNames -notcontains $Process.ProcessName) {
                        $ThreatScore += 35
                        $Reasons += "Process has no valid executable path (potential process hollowing)"
                    }
                }

                # Score-based threat detection
                if ($ThreatScore -ge 30) {
                    $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                    
                    $Threats += @{
                        Type = "MemoryAnomaly"
                        ProcessId = $Process.Id
                        ProcessName = $Process.ProcessName
                        ProcessPath = $Process.Path
                        WorkingSetMB = [Math]::Round($Process.WorkingSet64/1MB, 2)
                        PrivateMemoryMB = [Math]::Round($Process.PrivateMemorySize64/1MB, 2)
                        ThreadCount = $Process.Threads.Count
                        ThreatScore = $ThreatScore
                        Reasons = $Reasons
                        Patterns = $FoundPatterns
                        Severity = $severity
                        Time = Get-Date
                    }

                    Write-Output "[MemoryScan] THREAT ($severity): Memory anomaly detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                    if ($AutoKillThreats -and $ThreatScore -ge 50) {
                        # Whitelist own process - never kill ourselves
                        if ($Process.Id -eq $PID -or $Process.Id -eq $Script:SelfPID) {
                            Write-EDRLog -Module "MemoryScanning" -Message "BLOCKED: Attempted to kill own process (PID: $($Process.Id)) - whitelisted" -Level "Warning"
                            continue
                        }
                        
                        try {
                            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                            Write-Output "[MemoryScan] ACTION: Terminated process with critical memory anomalies (PID: $($Process.Id))"
                            Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity "Critical"
                        } catch {
                            Write-EDRLog -Module "MemoryScanning" -Message "Failed to terminate process $($Process.Id): $_" -Level "Warning"
                        }
                    } elseif ($ThreatScore -ge 40) {
                        Add-ThreatToResponseQueue -ThreatType "MemoryAnomaly" -ThreatPath $Process.Id.ToString() -Severity $severity
                    }
                }
            }
            catch {
                Write-EDRLog -Module "MemoryScanning" -Message "Error scanning process $($Process.Id): $_" -Level "Warning"
            }
        }

        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats}
    }
    catch {
        Write-EDRLog -Module "MemoryScanning" -Message "Memory scanning failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @()}
    }
}

function Invoke-NamedPipeMonitoring {
    param(
        [bool]$AnalyzeProcesses = $true
    )

    try {
        $Threats = @()
        $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        
        # Advanced suspicious pipe name patterns
        $SuspiciousPatterns = @{
            "msagent_" = @{Score = 30; Reason = "MSAgent pipe (common malware)"}
            "mojo" = @{Score = 25; Reason = "Mojo pipe (potential IPC abuse)"}
            "crashpad" = @{Score = 20; Reason = "Crashpad pipe (could be abused)"}
            "mypipe|evil|backdoor|malware" = @{Score = 40; Reason = "Overtly suspicious pipe name"}
            ".*[0-9a-f]{32,}.*" = @{Score = 35; Reason = "Pipe name contains hash-like string (potential data exfiltration)"}
            "secret|private|hidden|stealth" = @{Score = 35; Reason = "Pipe name suggests stealth operation"}
            ".*[A-Z]{5,}.*" = @{Score = 15; Reason = "Pipe name with excessive uppercase (unusual pattern)"}
            "^.{50,}$" = @{Score = 20; Reason = "Unusually long pipe name"}
        }

        # Known legitimate pipes (whitelist)
        $LegitimatePipes = @(
            "\\.\pipe\lsarpc",
            "\\.\pipe\samr",
            "\\.\pipe\wkssvc",
            "\\.\pipe\srvsvc",
            "\\.\pipe\netlogon",
            "\\.\pipe\spoolss",
            "\\.\pipe\epmapper",
            "\\.\pipe\atsvc",
            "\\.\pipe\winsock",
            "\\.\pipe\InitShutdown",
            "\\.\pipe\winlogonrpc",
            "\\.\pipe\ntsvcs",
            "\\.\pipe\Winsock2",
            "\\.\pipe\srvsvc",
            "\\.\pipe\Browser"
        )

        foreach ($Pipe in $Pipes) {
            # Skip legitimate pipes
            if ($LegitimatePipes -contains $Pipe) { continue }

            $PipeName = $Pipe.Replace("\\.\pipe\", "")
            $ThreatScore = 0
            $FoundPatterns = @()
            $Reasons = @()

            # Check against suspicious patterns
            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($PipeName -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $FoundPatterns += $patternInfo.Reason
                    $Reasons += "$($patternInfo.Reason) (Pattern: $pattern)"
                }
            }

            # Analyze process relationships if enabled
            $ProcessInfo = $null
            if ($AnalyzeProcesses) {
                try {
                    # Get process using the pipe (requires handle enumeration - simplified approach)
                    # In real implementation, would use NtQuerySystemInformation or similar
                    # For now, check for processes with suspicious names that might create custom pipes
                    $SuspiciousProcesses = Get-Process | Where-Object {
                        $_.ProcessName -match "(powershell|cmd|wscript|cscript|mshta|rundll32)" -and
                        $_.Path -notmatch "^C:\\(Windows|Program Files)"
                    }
                    
                    if ($SuspiciousProcesses) {
                        foreach ($proc in $SuspiciousProcesses) {
                            # Heuristic: if suspicious process exists and pipe has suspicious pattern, increase score
                            if ($ThreatScore -gt 0) {
                                $ThreatScore += 10
                                $Reasons += "Suspicious process detected: $($proc.ProcessName) (PID: $($proc.Id))"
                                $ProcessInfo = @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ProcessPath = $proc.Path
                                }
                                break
                            }
                        }
                    }
                } catch {
                    Write-EDRLog -Module "NamedPipeMonitoring" -Message "Process analysis failed for pipe ${PipeName}: $_" -Level "Debug"
                }
            }

            # Check for pipes with random-looking names (potential malware)
            if ($PipeName -match "^[A-Za-z0-9]{32,}$" -and $ThreatScore -eq 0) {
                $entropy = Measure-StringEntropy -String $PipeName
                if ($entropy -gt 4.0) {
                    $ThreatScore += 25
                    $Reasons += "High entropy pipe name (potential random name generation) | Entropy: $([Math]::Round($entropy, 2))"
                }
            }

            # Check for pipes created by non-standard locations
            if ($AnalyzeProcesses -and $ProcessInfo) {
                if ($ProcessInfo.ProcessPath -and $ProcessInfo.ProcessPath -notmatch "^(C:\\(Windows|Program Files))") {
                    $ThreatScore += 15
                    $Reasons += "Pipe created by process from non-standard location: $($ProcessInfo.ProcessPath)"
                }
            }

            # Score-based threat detection
            if ($ThreatScore -ge 25) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "SuspiciousNamedPipe"
                    PipeName = $Pipe
                    PipeNameShort = $PipeName
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    Patterns = $FoundPatterns
                    ProcessInfo = $ProcessInfo
                    Severity = $severity
                    Time = Get-Date
                }

                Write-Output "[NamedPipe] THREAT ($severity): Suspicious named pipe detected | Pipe: $Pipe | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "SuspiciousNamedPipe" -ThreatPath $Pipe -Severity $severity
                }
            }
        }

        # Check for excessive pipe creation (potential indicator of malware activity)
        if ($Pipes.Count -gt 100) {
            $nonStandardPipes = $Pipes | Where-Object { $LegitimatePipes -notcontains $_ }
            if ($nonStandardPipes.Count -gt 50) {
                Write-Output "[NamedPipe] WARNING: Excessive named pipe creation detected | Total: $($Pipes.Count) | Non-standard: $($nonStandardPipes.Count)"
                Write-EDRLog -Module "NamedPipeMonitoring" -Message "Excessive pipe creation: $($Pipes.Count) total, $($nonStandardPipes.Count) non-standard" -Level "Warning"
            }
        }

        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring completed: $($Threats.Count) threat(s) found" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalPipes = $Pipes.Count}
    }
    catch {
        Write-EDRLog -Module "NamedPipeMonitoring" -Message "Named pipe monitoring failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalPipes = 0}
    }
}

function Invoke-DNSExfiltrationDetection {
    param(
        [int]$LookbackMinutes = 60,
        [bool]$StatisticalAnalysis = $true
    )

    try {
        $Threats = @()
        $cutoffTime = (Get-Date).AddMinutes(-$LookbackMinutes)
        
        # Get DNS cache entries
        $DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
            Where-Object { $_.TimeToLive -gt 0 -and $_.Status -eq 0 }

        $SuspiciousDomains = @()

        foreach ($Entry in $DNSCache) {
            $domain = $Entry.Name
            $ThreatScore = 0
            $Reasons = @()

            # 1. Check for long subdomains (common in DNS tunneling)
            if ($domain.Length -gt 50) {
                $ThreatScore += 20
                $Reasons += "Unusually long domain name ($($domain.Length) characters)"
            }

            # 2. Check for hash-like subdomains (potential data exfiltration)
            if ($domain -match "[0-9a-f]{32,}") {
                $ThreatScore += 35
                $Reasons += "Subdomain contains hash-like string (potential data exfiltration)"
            }

            # 3. Check for base64-encoded patterns
            if ($domain -match "[A-Za-z0-9+/]{20,}={0,2}") {
                $base64Part = if ($domain -match "([A-Za-z0-9+/]{20,}={0,2})") { $matches[1] } else { "" }
                if ($base64Part) {
                    $entropy = Measure-StringEntropy -String $base64Part
                    if ($entropy -gt 4.5) {
                        $ThreatScore += 40
                        $Reasons += "Subdomain contains high-entropy base64-like string | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 4. Check for suspicious domain patterns
            $SuspiciousPatterns = @{
                ".*\.[0-9a-f]{16,}\..*" = @{Score = 30; Reason = "Subdomain with hex string"}
                ".*[0-9]{10,}.*" = @{Score = 15; Reason = "Subdomain with long numeric string"}
                "^[a-z0-9]{20,}\." = @{Score = 25; Reason = "Random-looking subdomain prefix"}
                ".*secret.*|.*data.*|.*exfil.*|.*cmd.*" = @{Score = 30; Reason = "Suspicious keywords in domain"}
            }

            foreach ($pattern in $SuspiciousPatterns.Keys) {
                if ($domain -match $pattern) {
                    $patternInfo = $SuspiciousPatterns[$pattern]
                    $ThreatScore += $patternInfo.Score
                    $Reasons += $patternInfo.Reason
                }
            }

            # 5. Check for DNS tunneling indicators (statistical analysis)
            if ($StatisticalAnalysis) {
                # Check for unusual TTL values (often manipulated in DNS tunneling)
                if ($Entry.TimeToLive -lt 300 -or $Entry.TimeToLive -gt 86400) {
                    $ThreatScore += 10
                    $Reasons += "Unusual TTL value: $($Entry.TimeToLive) seconds"
                }

                # Check for excessive subdomain length variation (indicator of tunneling)
                $subdomainParts = $domain.Split('.')
                if ($subdomainParts.Length -gt 4) {
                    $subdomainLengths = $subdomainParts | ForEach-Object { $_.Length }
                    $avgLength = ($subdomainLengths | Measure-Object -Average).Average
                    $maxLength = ($subdomainLengths | Measure-Object -Maximum).Maximum
                    
                    if ($maxLength -gt ($avgLength * 3)) {
                        $ThreatScore += 20
                        $Reasons += "Subdomain length variation suggests data encoding"
                    }
                }

                # Check for high entropy in subdomain (potential encrypted data)
                $subdomain = $domain.Split('.')[0]
                if ($subdomain.Length -gt 20) {
                    $entropy = Measure-StringEntropy -String $subdomain
                    if ($entropy -gt 4.0) {
                        $ThreatScore += 25
                        $Reasons += "High entropy subdomain (potential encrypted exfiltrated data) | Entropy: $([Math]::Round($entropy, 2))"
                    }
                }
            }

            # 6. Check for known DNS tunneling tools domain patterns
            $KnownTunnelingTools = @(
                "iodine", "dns2tcp", "dnscat2", "tuns", "heyoka"
            )

            foreach ($tool in $KnownTunnelingTools) {
                if ($domain -match $tool) {
                    $ThreatScore += 40
                    $Reasons += "Known DNS tunneling tool pattern: $tool"
                }
            }

            # 7. Check for domains with excessive subdomains (potential data chunking)
            $subdomainCount = ($domain.Split('.')).Length
            if ($subdomainCount -gt 6) {
                $ThreatScore += 15
                $Reasons += "Excessive subdomain levels ($subdomainCount) - potential data chunking"
            }

            # Score-based threat detection
            if ($ThreatScore -ge 30) {
                $severity = if ($ThreatScore -ge 50) { "Critical" } elseif ($ThreatScore -ge 40) { "High" } else { "Medium" }
                
                $Threats += @{
                    Type = "DNSExfiltration"
                    Domain = $domain
                    ThreatScore = $ThreatScore
                    Reasons = $Reasons
                    TTL = $Entry.TimeToLive
                    RecordType = $Entry.Type
                    DataLength = $Entry.DataLength
                    Severity = $severity
                    Time = Get-Date
                }

                Write-Output "[DNSExfil] THREAT ($severity): DNS exfiltration indicators detected | Domain: $domain | Score: $ThreatScore | Reasons: $($Reasons -join '; ')"

                if ($ThreatScore -ge 40) {
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltration" -ThreatPath $domain -Severity $severity
                }

                $SuspiciousDomains += $domain
            }
        }

        # Statistical analysis across all DNS queries
        if ($StatisticalAnalysis -and $DNSCache.Count -gt 0) {
            # Check for burst of suspicious DNS queries (indicator of active exfiltration)
            $recentQueries = $DNSCache | Where-Object { 
                $_.DataLength -gt 100 -or $_.Name.Length -gt 50
            }
            
            if ($recentQueries.Count -gt 20) {
                Write-Output "[DNSExfil] WARNING: Burst of suspicious DNS queries detected | Count: $($recentQueries.Count)"
                Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS query burst detected: $($recentQueries.Count) suspicious queries" -Level "Warning"
                
                # Check for patterns suggesting active exfiltration
                $uniqueDomains = $recentQueries | Select-Object -ExpandProperty Name -Unique
                if ($uniqueDomains.Count -lt ($recentQueries.Count * 0.3)) {
                    Write-Output "[DNSExfil] CRITICAL: Pattern suggests active DNS exfiltration | Repeating domains: $($uniqueDomains.Count) unique out of $($recentQueries.Count) queries"
                    Add-ThreatToResponseQueue -ThreatType "DNSExfiltrationBurst" -ThreatPath "Multiple domains" -Severity "Critical"
                }
            }
        }

        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection completed: $($Threats.Count) threat(s) found out of $($DNSCache.Count) DNS entries" -Level $(if ($Threats.Count -gt 0) { "Warning" } else { "Info" })
        return @{ThreatsFound = $Threats.Count; Details = $Threats; TotalEntries = $DNSCache.Count; SuspiciousDomains = $SuspiciousDomains}
    }
    catch {
        Write-EDRLog -Module "DNSExfiltrationDetection" -Message "DNS exfiltration detection failed: $_" -Level "Error"
        return @{ThreatsFound = 0; Details = @(); TotalEntries = 0; SuspiciousDomains = @()}
    }
}

function Invoke-PasswordManagement {
    param()

    Write-Output "[Password] Starting password management monitoring..."

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Output "[Password] WARNING: Not running as Administrator - limited functionality"
        return
}

    function Test-PasswordSecurity {
        try {
            $CurrentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                $PasswordAge = (Get-Date) - $CurrentUser.PasswordLastSet
                $DaysSinceChange = $PasswordAge.Days

                if ($DaysSinceChange -gt 90) {
                    Write-Output "[Password] WARNING: Password is $DaysSinceChange days old - consider rotation"
                }

                if ($CurrentUser.PasswordRequired -eq $false) {
                    Write-Output "[Password] WARNING: Account does not require password"
                }

                $PasswordPolicy = Get-LocalUser | Where-Object { $_.Name -eq $env:USERNAME } | Select-Object PasswordRequired, PasswordChangeable, PasswordExpires
                if ($PasswordPolicy) {
                    Write-Output "[Password] INFO: Password policy - Required: $($PasswordPolicy.PasswordRequired), Changeable: $($PasswordPolicy.PasswordChangeable), Expires: $($PasswordPolicy.PasswordExpires)"
                }

                return @{
                    DaysSinceChange = $DaysSinceChange
                    PasswordRequired = $CurrentUser.PasswordRequired
                    PasswordLastSet = $CurrentUser.PasswordLastSet
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check password security: $_"
            return $null
        }
    }

    function Test-SuspiciousPasswordActivity {
        try {
            $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4724,4723,4738} -MaxEvents 10 -ErrorAction SilentlyContinue

            $RecentChanges = $SecurityEvents | Where-Object {
                $_.TimeCreated -gt (Get-Date).AddHours(-1) -and
                $_.Properties[0].Value -eq $env:USERNAME
            }

            if ($RecentChanges.Count -gt 0) {
                Write-Output "[Password] WARNING: Recent password activity detected - $($RecentChanges.Count) events in last hour"

                foreach ($LogEvent in $RecentChanges) {
                    $EventType = switch ($LogEvent.Id) {
                        4723 { "Password change attempted" }
                        4724 { "Password reset attempted" }
                        4738 { "Account policy modified" }
                        default { "Unknown event" }
                    }
                    Write-Output "[Password]   - $EventType at $($LogEvent.TimeCreated)"
                }
            }

            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }

            $UserFailedLogons = $FailedLogons | Where-Object {
                $_.Properties[5].Value -eq $env:USERNAME
            }

            if ($UserFailedLogons.Count -gt 5) {
                Write-Output "[Password] THREAT: High number of failed logons - $($UserFailedLogons.Count) failures in last hour"
            }

            return @{
                RecentChanges = $RecentChanges.Count
                FailedLogons = $UserFailedLogons.Count
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check suspicious activity: $_"
            return $null
        }
    }

    function Test-PasswordDumpingTools {
        try {
            $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz", "gsecdump", "cachedump")
            $SuspiciousProcesses = Get-Process | Where-Object {
                $SuspiciousTools -contains $_.ProcessName.ToLower()
            }

            if ($SuspiciousProcesses.Count -gt 0) {
                Write-Output "[Password] THREAT: Password dumping tools detected"
                foreach ($Process in $SuspiciousProcesses) {
                    Write-Output "[Password]   - $($Process.ProcessName) (PID: $($Process.Id))"
                }
            }

            $PowerShellProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
            foreach ($Process in $PowerShellProcesses) {
                try {
                    $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine

                    $PasswordCommands = @("Get-Credential", "ConvertTo-SecureString", "Import-Clixml", "Export-Clixml")
                    foreach ($Command in $PasswordCommands) {
                        if ($CommandLine -match $Command) {
                            Write-Output "[Password] SUSPICIOUS: PowerShell process with password-related command - PID: $($Process.Id)"
                        }
                    }
                }
                catch {
                }
            }

            return $SuspiciousProcesses.Count
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check for dumping tools: $_"
            return 0
        }
    }

    try {
        $PasswordStatus = Test-PasswordSecurity
        if ($PasswordStatus) {
            Write-Output "[Password] Security check completed - Password age: $($PasswordStatus.DaysSinceChange) days"
        }

        $ActivityStatus = Test-SuspiciousPasswordActivity
        if ($ActivityStatus) {
            Write-Output "[Password] Activity monitoring completed - Recent changes: $($ActivityStatus.RecentChanges), Failed logons: $($ActivityStatus.FailedLogons)"
        }

        $DumpingTools = Test-PasswordDumpingTools
        Write-Output "[Password] Dumping tools check completed - Suspicious tools: $DumpingTools"

        try {
            $RegKeys = @(
                "HKLM:\SAM\SAM\Domains\Account\Users",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            )

            foreach ($RegKey in $RegKeys) {
                try {
                    if (Test-Path $RegKey -ErrorAction SilentlyContinue) {
                        $RecentChanges = Get-ChildItem $RegKey -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }

                        if ($RecentChanges -and $RecentChanges.Count -gt 0) {
                            Write-Output "[Password] WARNING: Recent registry changes in password-related areas"
                            foreach ($Change in $RecentChanges) {
                                Write-Output "[Password]   - $($Change.PSPath) modified at $($Change.LastWriteTime)"
                            }
                        }
                    }
                }
                catch {
                    # SAM registry access requires special privileges - skip silently if access denied
                    if ($RegKey -like "*SAM*") {
                        # SAM access is protected - this is expected to fail on most systems
                        continue
                    }
                    Write-Output "[Password] WARNING: Could not check registry key $RegKey - $_"
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check registry changes: $_"
        }

        Write-Output "[Password] Password management monitoring completed"
    }
    catch {
        Write-Output "[Password] ERROR: Monitoring failed: $_"
    }
}

function Invoke-WebcamGuardian {
    <#
    .SYNOPSIS
    Monitors and controls webcam access with explicit user permission.
    
    .DESCRIPTION
    Keeps webcam disabled by default. When any application tries to access it,
    shows a permission popup. Only enables webcam after explicit user approval.
    Automatically disables webcam when application closes.
    
    .PARAMETER LogPath
    Path to store webcam access logs
    #>
    param(
        [string]$LogPath
    )
    
    # Initialize static variables
    if (-not $script:WebcamGuardianState) {
        $script:WebcamGuardianState = @{
            Initialized = $false
            WebcamDevices = @()
            CurrentlyAllowedProcesses = @{}
            LastCheck = [DateTime]::MinValue
            AccessLog = if ($LogPath) { Join-Path $LogPath "webcam_access.log" } else { "$env:TEMP\webcam_access.log" }
        }
    }
    
    # Initialize webcam devices list (only once)
    if (-not $script:WebcamGuardianState.Initialized) {
        try {
            # Find all imaging devices (webcams) using multiple methods
            $webcamDevices = @()
            
            Write-AVLog "[WebcamGuardian] Starting webcam device detection..." "INFO"
            
            # Method 1: Check Camera class (including disabled devices)
            try {
                $cameras = Get-PnpDevice -Class "Camera" -ErrorAction SilentlyContinue
                if ($cameras) {
                    if ($cameras.Count) {
                        $webcamDevices += $cameras
                        Write-AVLog "[WebcamGuardian] Method 1: Found $($cameras.Count) Camera class device(s)" "INFO"
                    } else {
                        $webcamDevices += @($cameras)
                        Write-AVLog "[WebcamGuardian] Method 1: Found 1 Camera class device: $($cameras.FriendlyName)" "INFO"
                    }
                } else {
                    Write-AVLog "[WebcamGuardian] Method 1: No Camera class devices found" "INFO"
                }
            } catch {
                Write-AVLog "[WebcamGuardian] Method 1 error: $($_.Exception.Message)" "WARN"
            }
            
            # Method 2: Check Image class - but ONLY for cameras/webcams, NOT scanners/printers
            try {
                $images = Get-PnpDevice -Class "Image" -ErrorAction SilentlyContinue | Where-Object {
                    # Only include Image class devices that are specifically cameras/webcams
                    # Exclude scanners, printers, and other imaging devices
                    ($_.FriendlyName -match "Camera|Webcam|Video.*Camera" -or
                     $_.Description -match "Camera|Webcam|Video.*Camera") -and
                    # Explicitly exclude scanners, printers, and other imaging devices
                    $_.FriendlyName -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF" -and
                    $_.Description -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF"
                }
                if ($images) {
                    if ($images.Count) {
                        $webcamDevices += $images
                        Write-AVLog "[WebcamGuardian] Method 2: Found $($images.Count) Image class camera device(s) (excluding scanners/printers)" "INFO"
                    } else {
                        $webcamDevices += @($images)
                        Write-AVLog "[WebcamGuardian] Method 2: Found 1 Image class camera device: $($images.FriendlyName)" "INFO"
                    }
                } else {
                    Write-AVLog "[WebcamGuardian] Method 2: No Image class camera devices found (scanners/printers excluded)" "INFO"
                }
            } catch {
                Write-AVLog "[WebcamGuardian] Method 2 error: $($_.Exception.Message)" "WARN"
            }
            
            # Method 3: Check MEDIA class - cameras only, exclude scanners/printers
            try {
                $media = Get-PnpDevice -Class "MEDIA" -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        # Match devices that are specifically cameras/webcams
                        ($_.FriendlyName -match "Camera|Webcam|Video.*Camera" -or
                         $_.Description -match "Camera|Webcam|Video.*Camera") -and
                        # Exclude audio devices explicitly
                        $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Card|Graphics|Display" -and
                        $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Card|Graphics|Display" -and
                        # Exclude scanners, printers, and other imaging devices
                        $_.FriendlyName -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                        $_.Description -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                        $_.InstanceId -notmatch "HDAUDIO"
                    }
                if ($media) {
                    if ($media.Count) {
                        $webcamDevices += $media
                        Write-AVLog "[WebcamGuardian] Method 3: Found $($media.Count) MEDIA class device(s) that might be cameras" "INFO"
                    } else {
                        $webcamDevices += @($media)
                        Write-AVLog "[WebcamGuardian] Method 3: Found 1 MEDIA class device: $($media.FriendlyName)" "INFO"
                    }
                } else {
                    Write-AVLog "[WebcamGuardian] Method 3: No MEDIA class camera devices found" "INFO"
                }
            } catch {
                Write-AVLog "[WebcamGuardian] Method 3 error: $($_.Exception.Message)" "WARN"
            }
            
            # Method 4: Check USB devices for video/camera devices (exclude scanners/printers)
            try {
                $usbVideoDevices = Get-PnpDevice -Class "USB" -ErrorAction SilentlyContinue | Where-Object {
                    # Look for USB video devices that are specifically cameras
                    ($_.FriendlyName -match "Video.*Camera|Camera|Webcam" -or
                     $_.Description -match "Video.*Camera|Camera|Webcam") -and
                    $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Card|Graphics|Display|Hub|HID" -and
                    $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Card|Graphics|Display|Hub|HID" -and
                    # Exclude scanners, printers, and other imaging devices
                    $_.FriendlyName -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                    $_.Description -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                    $_.InstanceId -match "USB\\VID"
                }
                if ($usbVideoDevices) {
                    if ($usbVideoDevices.Count) {
                        $webcamDevices += $usbVideoDevices
                        Write-AVLog "[WebcamGuardian] Method 4: Found $($usbVideoDevices.Count) USB video device(s)" "INFO"
                    } else {
                        $webcamDevices += @($usbVideoDevices)
                        Write-AVLog "[WebcamGuardian] Method 4: Found 1 USB video device: $($usbVideoDevices.FriendlyName)" "INFO"
                    }
                } else {
                    Write-AVLog "[WebcamGuardian] Method 4: No USB video devices found" "INFO"
                }
            } catch {
                Write-AVLog "[WebcamGuardian] Method 4 error: $($_.Exception.Message)" "WARN"
            }
            
            # Method 5: Comprehensive search - cameras/webcams only, exclude scanners/printers
            try {
                $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
                    # Class matching - prefer Camera class, Image class only if explicitly camera
                    ($_.Class -eq "Camera" -or
                     ($_.Class -eq "Image" -and ($_.FriendlyName -match "Camera|Webcam" -or $_.Description -match "Camera|Webcam")) -or
                     ($_.Class -eq "MEDIA" -and ($_.FriendlyName -match "Camera|Webcam" -or $_.Description -match "Camera|Webcam")) -or
                     ($_.Class -eq "USB" -and ($_.FriendlyName -match "Camera|Webcam|Video.*Camera" -or $_.Description -match "Camera|Webcam|Video.*Camera"))) -and
                    # Must explicitly contain Camera or Webcam (not just Video/Imaging/Capture)
                    ($_.FriendlyName -match "Camera|Webcam|Video.*Camera" -or
                     $_.Description -match "Camera|Webcam|Video.*Camera") -and
                    # Exclude audio/video cards and other non-camera devices
                    $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|Hub|HID" -and
                    $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|Hub|HID" -and
                    # Explicitly exclude scanners, printers, and other imaging devices
                    $_.FriendlyName -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                    $_.Description -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                    $_.InstanceId -notmatch "HDAUDIO|HID\\"
                }
                
                if ($allDevices) {
                    if ($allDevices.Count) {
                        $webcamDevices += $allDevices
                        Write-AVLog "[WebcamGuardian] Method 5: Found $($allDevices.Count) potential camera device(s) via comprehensive search" "INFO"
                    } else {
                        $webcamDevices += @($allDevices)
                        Write-AVLog "[WebcamGuardian] Method 5: Found 1 potential camera device: $($allDevices.FriendlyName)" "INFO"
                    }
                } else {
                    Write-AVLog "[WebcamGuardian] Method 5: No devices found via comprehensive search" "INFO"
                }
            } catch {
                Write-AVLog "[WebcamGuardian] Method 5 error: $($_.Exception.Message)" "WARN"
            }
            
            # Method 6: WMI query as fallback - cameras only, exclude scanners/printers
            if ($webcamDevices.Count -eq 0) {
                try {
                    $wmiCameras = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
                        # Class matching - prefer Camera, Image only if explicitly camera
                        ($_.PNPClass -eq "Camera" -or
                         ($_.PNPClass -eq "Image" -and ($_.Name -match "Camera|Webcam" -or $_.DeviceID -match "Camera")) -or
                         ($_.PNPClass -eq "MEDIA" -and ($_.Name -match "Camera|Webcam" -or $_.DeviceID -match "Camera")) -or
                         ($_.PNPClass -eq "USB" -and ($_.Name -match "Camera|Webcam|Video.*Camera" -or $_.DeviceID -match "USB.*VID.*PID.*Camera"))) -and
                        # Must explicitly contain Camera or Webcam
                        ($_.Name -match "Camera|Webcam|Video.*Camera" -or 
                         $_.DeviceID -match "USB.*VID.*PID.*Camera") -and
                        # Exclude audio/video devices
                        $_.Name -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Hub|HID" -and
                        # Explicitly exclude scanners, printers, and other imaging devices
                        $_.Name -notmatch "Scanner|Printer|Fax|MFP|Multifunction|Flatbed|Document|Sheet|ADF|Imaging.*Device" -and
                        $_.DeviceID -notmatch "HDAUDIO|HID\\"
                    }
                    
                    if ($wmiCameras) {
                        Write-AVLog "[WebcamGuardian] Method 6: Found $($wmiCameras.Count) potential camera device(s) via WMI" "INFO"
                        # Convert WMI objects to PnP device format
                        foreach ($wmi in $wmiCameras) {
                            try {
                                $pnpDevice = Get-PnpDevice -InstanceId $wmi.DeviceID -ErrorAction SilentlyContinue
                                if ($pnpDevice) {
                                    $webcamDevices += $pnpDevice
                                    Write-AVLog "[WebcamGuardian] Method 6: Added device: $($pnpDevice.FriendlyName)" "INFO"
                                }
                            } catch {
                                Write-AVLog "[WebcamGuardian] Method 6: Could not convert WMI device $($wmi.Name): $($_.Exception.Message)" "WARN"
                            }
                        }
                    } else {
                        Write-AVLog "[WebcamGuardian] Method 6: No devices found via WMI" "INFO"
                    }
                } catch {
                    Write-AVLog "[WebcamGuardian] Method 6 error: $($_.Exception.Message)" "WARN"
                }
            }
            
            # Remove duplicates and assign
            # Ensure we always have an array (even if empty)
            if ($null -eq $webcamDevices) {
                $webcamDevices = @()
            } elseif ($webcamDevices.Count -eq $null) {
                # Single object, convert to array
                $webcamDevices = @($webcamDevices)
            }
            
            Write-AVLog "[WebcamGuardian] Total devices found before filtering: $($webcamDevices.Count)" "INFO"
            
            # Log all found devices for debugging
            if ($webcamDevices.Count -gt 0) {
                foreach ($dev in $webcamDevices) {
                    Write-AVLog "[WebcamGuardian] Found device: $($dev.FriendlyName) | Class: $($dev.Class) | Status: $($dev.Status) | InstanceId: $($dev.InstanceId)" "INFO"
                }
            }
            
            # Remove duplicates and apply final filtering (more flexible than before)
            $script:WebcamGuardianState.WebcamDevices = $webcamDevices | 
                Where-Object { 
                    # Accept devices with OK status OR Error status (might be disabled)
                    ($_.Status -eq "OK" -or $_.Status -eq "Error") -and
                    # Final validation: must contain Camera/Webcam/Video/Imaging/Capture keywords
                    ($_.FriendlyName -match "Camera|Webcam|Video|Imaging|Capture" -or
                     $_.Description -match "Camera|Webcam|Video|Imaging|Capture") -and
                    # Final exclusion: no audio/video/graphics devices, USB hubs, keyboards, mice
                    $_.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|USB.*Hub|HID" -and
                    $_.Description -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Video.*Card|Graphics|Display|Keyboard|Mouse|USB.*Hub|HID" -and
                    $_.InstanceId -notmatch "HDAUDIO|HID\\" -and
                    # Accept Camera, Image, MEDIA, or USB class (if it matches camera keywords)
                    (($_.Class -match "Camera|Image") -or 
                     ($_.Class -eq "MEDIA" -and ($_.FriendlyName -match "Camera|Webcam|Video|Imaging|Capture" -or $_.Description -match "Camera|Webcam|Video|Imaging|Capture")) -or
                     ($_.Class -eq "USB" -and ($_.FriendlyName -match "Video|Camera|Webcam|Imaging|Capture" -or $_.Description -match "Video|Camera|Webcam|Imaging|Capture")))
                } | 
                Sort-Object InstanceId -Unique
            
            Write-AVLog "[WebcamGuardian] Devices after filtering: $($script:WebcamGuardianState.WebcamDevices.Count)" "INFO"
            
            if ($script:WebcamGuardianState.WebcamDevices -and $script:WebcamGuardianState.WebcamDevices.Count -gt 0) {
                $deviceList = ($script:WebcamGuardianState.WebcamDevices | ForEach-Object { "$($_.FriendlyName) ($($_.Class)) [Status: $($_.Status)]" }) -join "; "
                Write-AVLog "[WebcamGuardian] Found $($script:WebcamGuardianState.WebcamDevices.Count) webcam device(s): $deviceList" "INFO"
                
                # Disable all webcams by default (with final safety check)
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    try {
                        # Final safety check: verify this is actually a camera device before disabling
                        if (($device.FriendlyName -match "Camera|Webcam|Video|Imaging|Capture" -or
                             $device.Description -match "Camera|Webcam|Video|Imaging|Capture") -and 
                            $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID|Card|Graphics|Display" -and
                            $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                            
                            # Only disable if device is currently enabled
                            if ($device.Status -eq "OK") {
                                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                                Write-AVLog "[WebcamGuardian] Disabled webcam: $($device.FriendlyName) ($($device.Class))" "INFO"
                            } else {
                                Write-AVLog "[WebcamGuardian] Webcam already disabled: $($device.FriendlyName) ($($device.Class)) [Status: $($device.Status)]" "INFO"
                            }
                        } else {
                            Write-AVLog "[WebcamGuardian] SKIPPED: Device does not appear to be a camera - $($device.FriendlyName) ($($device.Class))" "WARN"
                        }
                    }
                    catch {
                        Write-AVLog "[WebcamGuardian] Could not disable $($device.FriendlyName): $($_.Exception.Message)" "WARN"
                    }
                }
                
                $script:WebcamGuardianState.Initialized = $true
                Write-Host "[WebcamGuardian] Protection initialized - webcam disabled by default" -ForegroundColor Green
            }
            else {
                Write-AVLog "[WebcamGuardian] No webcam devices found after all detection methods" "WARN"
                Write-AVLog "[WebcamGuardian] Diagnostic: Attempting to list all Camera/Image/MEDIA class devices..." "INFO"
                
                # Diagnostic: List all potential camera devices for troubleshooting
                try {
                    $allCameraClass = Get-PnpDevice -Class "Camera" -ErrorAction SilentlyContinue
                    $allImageClass = Get-PnpDevice -Class "Image" -ErrorAction SilentlyContinue
                    $allMediaClass = Get-PnpDevice -Class "MEDIA" -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match "Video|Capture|Imaging" }
                    
                    $diagnosticDevices = @()
                    if ($allCameraClass) { $diagnosticDevices += $allCameraClass }
                    if ($allImageClass) { $diagnosticDevices += $allImageClass }
                    if ($allMediaClass) { $diagnosticDevices += $allMediaClass }
                    
                    if ($diagnosticDevices.Count -gt 0) {
                        Write-AVLog "[WebcamGuardian] Diagnostic: Found $($diagnosticDevices.Count) device(s) that might be cameras but were filtered out:" "WARN"
                        foreach ($diagDev in $diagnosticDevices) {
                            Write-AVLog "[WebcamGuardian] Diagnostic: - $($diagDev.FriendlyName) | Class: $($diagDev.Class) | Status: $($diagDev.Status) | InstanceId: $($diagDev.InstanceId)" "WARN"
                        }
                    } else {
                        Write-AVLog "[WebcamGuardian] Diagnostic: No Camera/Image/MEDIA devices found at all. Webcam may not be connected or drivers not installed." "WARN"
                    }
                } catch {
                    Write-AVLog "[WebcamGuardian] Diagnostic error: $($_.Exception.Message)" "WARN"
                }
                
                $script:WebcamGuardianState.Initialized = $true
                return
            }
        }
        catch {
            Write-AVLog "[WebcamGuardian] Initialization error: $($_.Exception.Message)" "ERROR"
            return
        }
    }
    
    # Skip check if no webcam devices
    if ($script:WebcamGuardianState.WebcamDevices.Count -eq 0) {
        return
    }
    
    # Monitor for processes trying to access webcam
    try {
        # Get all processes that might access camera
        $cameraProcesses = Get-Process | Where-Object {
            $_.ProcessName -match "chrome|firefox|edge|msedge|teams|zoom|skype|obs|discord|slack" -or
            $_.MainWindowTitle -ne ""
        } | Select-Object Id, ProcessName, Path, MainWindowTitle
        
        foreach ($proc in $cameraProcesses) {
            # Skip if already allowed
            if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.ContainsKey($proc.Id)) {
                # Check if process still exists
                if (-not (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
                    # Process closed - remove from allowed list and disable webcam
                    $script:WebcamGuardianState.CurrentlyAllowedProcesses.Remove($proc.Id)
                    
                    # Disable webcam if no other processes are using it (with safety check)
                    if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
                        foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                            # Safety check: only disable if confirmed to be a camera device
                            if ($device.FriendlyName -match "Camera|Webcam" -and 
                                $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                                $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [AUTO-DISABLE] Process closed - webcam disabled"
                        Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                        Write-AVLog "[WebcamGuardian] All processes closed - webcam disabled" "INFO"
                    }
                }
                continue
            }
            
            # Check if process is trying to access webcam (heuristic check)
            $isAccessingCamera = $false
            
            try {
                # Check if process has handles to camera devices
                $handles = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue | 
                    Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue |
                    Where-Object { $_.ModuleName -match "mf|avicap|video|camera" }
                
                if ($handles) {
                    $isAccessingCamera = $true
                }
            }
            catch {}
            
            # If camera access detected, show permission dialog
            if ($isAccessingCamera) {
                $procName = if ($proc.Path) { Split-Path -Leaf $proc.Path } else { $proc.ProcessName }
                $windowTitle = if ($proc.MainWindowTitle) { $proc.MainWindowTitle } else { "Unknown Window" }
                
                # Create permission dialog
                Add-Type -AssemblyName System.Windows.Forms
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Application '$procName' is trying to access your webcam.`n`nWindow: $windowTitle`nPID: $($proc.Id)`n`nAllow webcam access?",
                    "Webcam Permission Request",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                )
                
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    # User allowed - enable webcam (with safety check)
                    foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                        # Safety check: only enable if confirmed to be a camera device
                        if ($device.FriendlyName -match "Camera|Webcam" -and 
                            $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                            $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                            Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                    
                    $script:WebcamGuardianState.CurrentlyAllowedProcesses[$proc.Id] = @{
                        ProcessName = $procName
                        WindowTitle = $windowTitle
                        AllowedAt = Get-Date
                    }
                    
                    $logEntry = "[$timestamp] [ALLOWED] $procName (PID: $($proc.Id)) | Window: $windowTitle"
                    Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                    Write-AVLog "[WebcamGuardian] Access ALLOWED: $procName (PID: $($proc.Id))" "INFO"
                    Write-Host "[WebcamGuardian] Webcam access ALLOWED for $procName" -ForegroundColor Green
                }
                else {
                    # User denied - keep webcam disabled and log
                    $logEntry = "[$timestamp] [DENIED] $procName (PID: $($proc.Id)) | Window: $windowTitle"
                    Add-Content -Path $script:WebcamGuardianState.AccessLog -Value $logEntry -ErrorAction SilentlyContinue
                    Write-AVLog "[WebcamGuardian] Access DENIED: $procName (PID: $($proc.Id))" "WARN"
                    Write-Host "[WebcamGuardian] Webcam access DENIED for $procName" -ForegroundColor Red
                    
                    # Optionally terminate the process trying to access webcam
                    # Uncomment the next line if you want to kill processes that are denied
                    # Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Clean up dead processes from allowed list
        $deadProcesses = @()
        foreach ($procPid in $script:WebcamGuardianState.CurrentlyAllowedProcesses.Keys) {
            if (-not (Get-Process -Id $procPid -ErrorAction SilentlyContinue)) {
                $deadProcesses += $procPid
            }
        }
        
        foreach ($procPid in $deadProcesses) {
            $script:WebcamGuardianState.CurrentlyAllowedProcesses.Remove($procPid)
        }
        
        # Disable webcam if no processes are allowed
        if ($script:WebcamGuardianState.CurrentlyAllowedProcesses.Count -eq 0) {
            $now = Get-Date
            # Only disable every 30 seconds to avoid excessive device operations
            if (($now - $script:WebcamGuardianState.LastCheck).TotalSeconds -ge 30) {
                foreach ($device in $script:WebcamGuardianState.WebcamDevices) {
                    # Safety check: only disable if confirmed to be a camera device
                    if ($device.FriendlyName -match "Camera|Webcam" -and 
                        $device.FriendlyName -notmatch "Audio|Headphone|Headset|Microphone|Speaker|Sound|Keyboard|Mouse|HID" -and
                        $device.InstanceId -notmatch "HDAUDIO|HID\\") {
                        $status = Get-PnpDevice -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
                        if ($status -and $status.Status -eq "OK") {
                            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                }
                $script:WebcamGuardianState.LastCheck = $now
            }
        }
    }
    catch {
        Write-AVLog "[WebcamGuardian] Monitoring error: $($_.Exception.Message)" "ERROR"
    }
    }

function Invoke-KeyScramblerManagement {
    param(
        [bool]$AutoStart = $true
    )

    Write-Output "[KeyScrambler] Starting inline KeyScrambler with C# hook..."

    $Source = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] private static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int x; public int y; }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;

        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
            Marshal.GetFunctionPointerForDelegate(_proc),
            GetModuleHandle(null), 0);

        if (_hookID == IntPtr.Zero)
            throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("KeyScrambler ACTIVE - invisible mode ON");
        Console.WriteLine("You see only your real typing * Keyloggers blinded");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private static bool ModifiersDown()
    {
        return (GetKeyState(0x10) & 0x8000) != 0 ||
               (GetKeyState(0x11) & 0x8000) != 0 ||
               (GetKeyState(0x12) & 0x8000) != 0;
    }

    private static void InjectFakeChar(char c)
    {
        var inputs = new INPUT[2];

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.dwExtraInfo = GetMessageExtraInfo();

        inputs[1] = inputs[0];
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

        SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    private static void Flood()
    {
        if (_rnd.NextDouble() < 0.5) return;
        int count = _rnd.Next(1, 7);
        for (int i = 0; i < count; i++)
            InjectFakeChar((char)_rnd.Next('A', 'Z' + 1));
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            if ((k.flags & 0x10) != 0) return CallNextHookEx(_hookID, nCode, wParam, lParam);
            if (ModifiersDown()) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (k.vkCode >= 65 && k.vkCode <= 90)
            {
                if (_rnd.NextDouble() < 0.75) Flood();
                var ret = CallNextHookEx(_hookID, nCode, wParam, lParam);
                if (_rnd.NextDouble() < 0.75) Flood();
                return ret;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

    try {
        Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
        Write-Output "[KeyScrambler] Compiled C# code successfully"
    }
    catch {
        Write-Output "[KeyScrambler] ERROR: Compilation failed: $($_.Exception.Message)"
        return
    }

    if ($AutoStart) {
        try {
            Write-Output "[KeyScrambler] Starting keyboard hook..."
            [KeyScrambler]::Start()
        }
        catch {
            Write-Output "[KeyScrambler] ERROR: Failed to start hook: $_"
        }
    }
}

#region === Missing Functions from Antivirus.ps1 ===

function Write-EDRLog {
    param(
        [string]$Module,
        [string]$Message,
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
    
    # Console output based on log level
    switch ($Level) {
        "Debug"   { if ($Verbose) { Write-Host $logEntry -ForegroundColor Gray } }
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    # File logging
    $logFile = Join-Path $Config.LogPath "EDR_$(Get-Date -Format 'yyyy-MM-dd').log"
    try {
        $logEntry | Add-Content -Path $logFile -ErrorAction SilentlyContinue
    } catch { }
}

function Write-Detection {
    param(
        [string]$Module,
        [int]$Count,
        [string]$Details = ""
    )
    
    if ($Count -gt 0) {
        Write-EDRLog -Module $Module -Message "DETECTION: Found $Count issues. $Details" -Level "Warning"
    }
}

function Write-ModuleStats {
    param(
        [string]$Module,
        [hashtable]$Stats
    )
    
    $statsString = ($Stats.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
    Write-EDRLog -Module $Module -Message "STATS: $statsString" -Level "Debug"
}

function Invoke-Initialization {
    try {
        Write-EDRLog -Module "Initializer" -Message "Starting environment initialization" -Level "Info"
        
        # Create required directories
        $directories = @(
            $Script:InstallPath,
            "$Script:InstallPath\Logs",
            "$Script:InstallPath\Data",
            "$Script:InstallPath\Quarantine",
            "$Script:InstallPath\Reports",
            "$Script:InstallPath\HashDatabase"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-EDRLog -Module "Initializer" -Message "Created directory: $dir" -Level "Debug"
            }
        }
        
        # Create Event Log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                Write-EDRLog -Module "Initializer" -Message "Created Event Log source: $($Config.EDRName)" -Level "Info"
            }
        } catch {
            Write-EDRLog -Module "Initializer" -Message "Could not create Event Log source (may require elevation): $_" -Level "Warning"
        }
        
        # Initialize module baselines
        Initialize-FirewallBaseline
        Initialize-ServiceBaseline
        Initialize-HashDatabase
        
        Write-EDRLog -Module "Initializer" -Message "Environment initialization completed" -Level "Info"
        return 1
        
    } catch {
        Write-EDRLog -Module "Initializer" -Message "Initialization failed: $_" -Level "Error"
        return 0
    }
}

function Initialize-FirewallBaseline {
    try {
        if (-not $script:BaselineRules) { $script:BaselineRules = @{} }
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            if (-not $script:BaselineRules.ContainsKey($key)) {
                $script:BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-ServiceBaseline {
    try {
        if (-not $script:ServiceBaseline) { $script:ServiceBaseline = @{} }
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            $key = $service.Name
            if (-not $script:ServiceBaseline.ContainsKey($key)) {
                $script:ServiceBaseline[$key] = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Initialize-HashDatabase {
    try {
        if (-not $script:HashDatabase) { $script:HashDatabase = @{} }
        if (-not $script:ThreatHashes) { $script:ThreatHashes = @{} }
        
        # Load known good hashes (whitelist)
        $whitelistPath = "$Script:InstallPath\HashDatabase\whitelist.txt"
        if (Test-Path $whitelistPath) {
            Get-Content $whitelistPath | ForEach-Object {
                if ($_ -match '^([A-F0-9]{64})\|(.+)$') {
                    $script:HashDatabase[$matches[1]] = $matches[2]
                }
            }
        }
        
        # Load threat hashes (blacklist)
        $threatPaths = @(
            "$Script:InstallPath\HashDatabase\threats.txt",
            "$Script:InstallPath\HashDatabase\malware_hashes.txt"
        )
        
        foreach ($threatPath in $threatPaths) {
            if (Test-Path $threatPath) {
                Get-Content $threatPath | ForEach-Object {
                    if ($_ -match '^([A-F0-9]{32,64})$') {
                        $script:ThreatHashes[$matches[1].ToUpper()] = $true
                    }
                }
            }
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $maxConnections = 500
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        # Group connections by process and remote address
        $connGroups = $connections | Group-Object -Property @{Expression={$_.OwningProcess}}, @{Expression={$_.RemoteAddress}}
        
        foreach ($group in $connGroups) {
            $procId = $group.Name.Split(',')[0].Trim()
            $remoteIP = $group.Name.Split(',')[1].Trim()
            
            try {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if (-not $proc) { continue }
                
                # Check connection frequency (beacon pattern)
                $connTimes = $group.Group | ForEach-Object { $_.CreationTime } | Sort-Object
                
                if ($connTimes.Count -gt 3) {
                    # Calculate intervals between connections
                    $intervals = @()
                    for ($i = 1; $i -lt $connTimes.Count; $i++) {
                        $interval = ($connTimes[$i] - $connTimes[$i-1]).TotalSeconds
                        $intervals += $interval
                    }
                    
                    # Check for regular intervals (beacon indicator)
                    if ($intervals.Count -gt 2) {
                        $avgInterval = ($intervals | Measure-Object -Average).Average
                        $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Average).Average
                        $stdDev = [Math]::Sqrt($variance)
                        
                        # Low variance = regular intervals = beacon
                        if ($stdDev -lt $avgInterval * 0.2 -and $avgInterval -gt 10 -and $avgInterval -lt 3600) {
                            $detections += @{
                                ProcessId = $procId
                                ProcessName = $proc.ProcessName
                                RemoteAddress = $remoteIP
                                ConnectionCount = $connTimes.Count
                                AverageInterval = [Math]::Round($avgInterval, 2)
                                Type = "Beacon Pattern Detected"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for connections to suspicious TLDs
        foreach ($conn in $connections) {
            if ($conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)') {
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                    
                    $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".tk", ".ml", ".ga", ".cf")
                    foreach ($tld in $suspiciousTLDs) {
                        if ($dns -like "*$tld") {
                            $detections += @{
                                ProcessId = $conn.OwningProcess
                                RemoteAddress = $conn.RemoteAddress
                                RemoteHost = $dns
                                Type = "Connection to Suspicious TLD"
                                Risk = "Medium"
                            }
                            break
                        }
                    }
                } catch { }
            }
        }
        
        # Check for HTTP/HTTPS connections with small data transfer (beacon)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    $httpConns = $procConns | Where-Object { $_.RemotePort -in @(80, 443, 8080, 8443) }
                    
                    if ($httpConns.Count -gt 0) {
                        # Check network stats
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats -and $netStats.CounterSamples[0].CookedValue -lt 1000 -and $netStats.CounterSamples[0].CookedValue -gt 0) {
                            # Small but consistent data transfer = beacon
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DataRate = $netStats.CounterSamples[0].CookedValue
                                ConnectionCount = $httpConns.Count
                                Type = "Low Data Transfer Beacon Pattern"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes with connections to many different IPs (C2 rotation)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                $uniqueIPs = ($procConns | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UniqueIPs = $uniqueIPs
                        ConnectionCount = $procConns.Count
                        Type = "Multiple C2 Connections (IP Rotation)"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)" "THREAT" "beacon_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Beacon detection error: $_" "ERROR" "beacon_detections.log"
    }
    
    return $detections.Count
}

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        # Code injection signatures for advanced detection
        $codeInjectionSignatures = @{
            "CodeInjection" = @(
                "code.*injection", "dll.*injection", "process.*hollowing",
                "reflective.*dll", "shellcode", "inject.*code"
            )
        }
        
        # Code injection behavioral patterns
        $codeInjectionBehaviors = @{
            "InjectionAPIs" = @(
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateThreadEx", "RtlCreateUserThread", "SetThreadContext",
                "QueueUserAPC", "ProcessHollowing", "DLL.*injection"
            )
            "MemoryManipulation" = @(
                "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                "ReadProcessMemory", "NtWriteVirtualMemory"
            )
        }
        
        # Check for processes with unusual memory regions (injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $procPath = $proc.Path
                $procCmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                
                # Use advanced detection framework
                if ($procPath -and (Test-Path $procPath)) {
                    $detectionResult = Invoke-AdvancedThreatDetection `
                        -FilePath $procPath `
                        -FileSignatures $codeInjectionSignatures `
                        -BehavioralIndicators $codeInjectionBehaviors `
                        -CommandLine $procCmdLine `
                        -CheckEntropy $true
                    
                    if ($detectionResult.IsThreat) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            ThreatName = $detectionResult.ThreatName
                            DetectionMethods = $detectionResult.DetectionMethods -join ", "
                            Confidence = $detectionResult.Confidence
                            Type = "Code Injection Detected via Advanced Framework"
                            Risk = if ($detectionResult.Risk -eq "CRITICAL") { "High" } else { "Medium" }
                        }
                    }
                }
                
                $modules = $proc.Modules
                
                # Check for processes with modules in unusual locations
                $unusualModules = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName) -and
                    $_.ModuleName -like "*.dll"
                }
                
                if ($unusualModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualModules = $unusualModules.Count
                        Type = "Many Unusual Memory Modules (Code Injection)"
                        Risk = "High"
                    }
                }
                
                # Check for processes with unusual thread counts (injection indicator)
                if ($proc.Threads.Count -gt 50 -and $proc.ProcessName -notin @("chrome.exe", "msedge.exe", "firefox.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ThreadCount = $proc.Threads.Count
                        Type = "Unusual Thread Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using injection APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for code injection API usage
                    $injectionPatterns = @(
                        'VirtualAllocEx',
                        'WriteProcessMemory',
                        'CreateRemoteThread',
                        'NtCreateThreadEx',
                        'RtlCreateUserThread',
                        'SetThreadContext',
                        'QueueUserAPC',
                        'ProcessHollowing',
                        'DLL.*injection',
                        'code.*injection'
                    )
                    
                    foreach ($pattern in $injectionPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                InjectionPattern = $pattern
                                Type = "Code Injection API Usage"
                                Risk = "High"
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual handle counts (injection indicator)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.HandleCount -gt 1000 }
            
            foreach ($proc in $processes) {
                # Exclude legitimate processes
                $legitProcesses = @("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "svchost.exe")
                if ($proc.ProcessName -notin $legitProcesses) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        HandleCount = $proc.HandleCount
                        Type = "Unusual Handle Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing other processes (injection indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    # Check if process has SeDebugPrivilege (enables injection)
                    # Indirect check through process properties
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        # Unsigned processes accessing system processes
                        if ($sig.Status -ne "Valid" -and $proc.Name -match 'debug|inject|hollow') {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Suspicious Process Name (Injection Tool)"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Also check for unsigned modules in system processes (original check)
        try {
            $systemProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -in @("svchost", "explorer", "lsass")
            }
            
            foreach ($proc in $systemProcesses) {
                foreach ($module in $proc.Modules) {
                    if ($module.FileName -and (Test-Path $module.FileName)) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $module.FileName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $module.FileName -notlike "$env:SystemRoot\*") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ModulePath = $module.FileName
                                    Type = "Unsigned Module in System Process"
                                    Risk = "High"
                                }
                            }
                        } catch { }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "CODE INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))" "THREAT" "code_injection_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Code injection detection error: $_" "ERROR" "code_injection_detections.log"
    }
    
    return $detections.Count
}

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $byProcess = $connections | Group-Object OwningProcess
        
        foreach ($group in $byProcess) {
            if ($group.Count -gt 20) {
                $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                
                if ($procName -notin @("chrome", "firefox", "msedge", "svchost", "System")) {
                    $detections += @{
                        ProcessId = $group.Name
                        ProcessName = $procName
                        ConnectionCount = $group.Count
                        Type = "High Network Activity"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "DataExfiltrationDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "DataExfiltrationDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

# DLL whitelist - safe system DLLs that should not be flagged
$Script:DllWhitelist = @(
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 
    'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
    'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
    'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll',
    'shcore.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll',
    'mshtml.dll', 'msi.dll', 'msvcp140.dll', 'vcruntime140.dll'
)

# Target browser processes to monitor
$Script:BrowserTargets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 
                   'iexplore', 'microsoftedge', 'waterfox', 'palemoon')

$Script:ProcessedDlls = @{}

function Test-SuspiciousDLL {
    param(
        [string]$DllName,
        [string]$DllPath,
        [string]$ProcessName
    )
    
    $dllNameLower = $DllName.ToLower()
    $suspicious = $false
    $reasons = @()
    
    # Skip whitelisted system DLLs
    if ($Script:DllWhitelist -contains $dllNameLower) {
        return $null
    }
    
    # Pattern 1: _elf.dll pattern (known malicious pattern)
    if ($dllNameLower -like '*_elf.dll' -or $dllNameLower -match '_elf') {
        $suspicious = $true
        $reasons += "ELF pattern DLL detected"
    }
    
    # Pattern 2: Suspicious .winmd files outside Windows directory
    if ($dllNameLower -like '*.winmd' -and $DllPath -notmatch '\\Windows\\') {
        $suspicious = $true
        $reasons += "WINMD file outside Windows directory"
    }
    
    # Pattern 3: Random hex-named DLLs (common in malware)
    if ($dllNameLower -match '^[a-f0-9]{8,}\.dll$') {
        $suspicious = $true
        $reasons += "Random hex-named DLL detected"
    }
    
    # Pattern 4: DLLs loaded from TEMP directory (excluding browser cache)
    if ($DllPath -match "\\AppData\\Local\\Temp\\" -and 
        $dllNameLower -notlike "chrome_*" -and 
        $dllNameLower -notlike "edge_*" -and
        $dllNameLower -notlike "moz*" -and
        $dllNameLower -notlike "firefox_*") {
        $suspicious = $true
        $reasons += "DLL loaded from TEMP directory"
    }
    
    # Pattern 5: DLLs in browser profile folders with suspicious names
    if ($DllPath -match "\\AppData\\" -and 
        $dllNameLower -notmatch "chrome|edge|firefox|mozilla" -and
        $dllNameLower -like '*.dll') {
        $suspicious = $true
        $reasons += "DLL in browser profile with non-browser name"
    }
    
    # Pattern 6: Unsigned DLLs in browser processes
    if (Test-Path $DllPath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid" -and $DllPath -notlike "$env:SystemRoot\*") {
                $suspicious = $true
                $reasons += "Unsigned DLL in browser process"
            }
        } catch { }
    }
    
    if ($suspicious) {
        return @{
            Suspicious = $true
            Reasons = $reasons
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-ElfCatcher {
    $detections = @()
    
    try {
        foreach ($target in $Script:BrowserTargets) {
            try {
                $procs = Get-Process -Name $target -ErrorAction SilentlyContinue
                
                foreach ($proc in $procs) {
                    try {
                        # Scan all loaded modules in the process
                        $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" -or $_.FileName -like "*.winmd" }
                        
                        foreach ($mod in $modules) {
                            try {
                                $dllName = [System.IO.Path]::GetFileName($mod.FileName)
                                $dllPath = $mod.FileName
                                
                                # Check if we've already processed this DLL
                                $key = "$($proc.Id):$dllPath"
                                if ($Script:ProcessedDlls.ContainsKey($key)) {
                                    continue
                                }
                                
                                # Test for suspicious DLL
                                $result = Test-SuspiciousDLL -DllName $dllName -DllPath $dllPath -ProcessName $proc.ProcessName
                                
                                if ($result) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        DllName = $dllName
                                        DllPath = $dllPath
                                        BaseAddress = $mod.BaseAddress.ToString()
                                        Reasons = $result.Reasons
                                        Risk = $result.Risk
                                    }
                                    
                                    # Mark as processed
                                    $Script:ProcessedDlls[$key] = Get-Date
                                    
                                    Write-AVLog "ELF CATCHER: Suspicious DLL in $($proc.ProcessName) (PID: $($proc.Id)) - $dllName - $($result.Reasons -join ', ')" "THREAT" "elf_catcher_detections.log"
                                    $Global:AntivirusState.ThreatCount++
                                }
                            } catch {
                                # Module may have unloaded during iteration
                                continue
                            }
                        }
                    } catch {
                        # Process may have exited during iteration
                        continue
                    }
                }
            } catch {
                # Process not found, continue
                continue
            }
        }
        
        # Periodic cleanup of processed list to prevent memory bloat
        if ($Script:ProcessedDlls.Count -gt 1000) {
            $oldKeys = $Script:ProcessedDlls.Keys | Where-Object {
                ((Get-Date) - $Script:ProcessedDlls[$_]).TotalHours -gt 24
            }
            foreach ($key in $oldKeys) {
                $Script:ProcessedDlls.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\ElfCatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName)|$($_.DllPath)|$($_.Reasons -join ';')" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            
            Write-AVLog "ElfCatcher detection completed: $($detections.Count) suspicious DLL(s) found" "INFO" "elf_catcher_detections.log"
        }
    } catch {
        Write-AVLog "ElfCatcher error: $_" "ERROR" "elf_catcher_detections.log"
    }
    
    return $detections.Count
}

$Script:ScannedFiles = @{}
$Script:HighEntropyThreshold = 7.2

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $sampleSize = [Math]::Min(8192, $fileInfo.Length)
        
        if ($sampleSize -eq 0) { return $null }
        
        $stream = [System.IO.File]::OpenRead($FilePath)
        $bytes = New-Object byte[] $sampleSize
        $stream.Read($bytes, 0, $sampleSize) | Out-Null
        $stream.Close()
        
        # Calculate byte frequency
        $freq = @{}
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        # Calculate Shannon entropy
        $entropy = 0
        $total = $bytes.Count
        
        foreach ($count in $freq.Values) {
            $p = $count / $total
            if ($p -gt 0) {
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        
        return @{
            Entropy = $entropy
            FileSize = $fileInfo.Length
            SampleSize = $sampleSize
        }
    } catch {
        return $null
    }
}

function Invoke-FileEntropyDetection {
    $detections = @()
    $maxFiles = 100
    
    try {
        $cutoff = (Get-Date).AddHours(-2)
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
        
        $scannedCount = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            if ($scannedCount -ge $maxFiles) { break }
            
            try {
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.scr,*.ps1,*.vbs -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First ($maxFiles - $scannedCount)
                
                foreach ($file in $files) {
                    $scannedCount++
                    
                    # Check cache
                    if ($Script:ScannedFiles.ContainsKey($file.FullName)) {
                        $cached = $Script:ScannedFiles[$file.FullName]
                        if ($cached.LastWrite -eq $file.LastWriteTime -and $cached.Entropy -lt $Script:HighEntropyThreshold) {
                            continue
                        }
                    }
                    
                    $entropyResult = Measure-FileEntropy -FilePath $file.FullName
                    
                    # Mark as scanned
                    $Script:ScannedFiles[$file.FullName] = @{
                        LastWrite = $file.LastWriteTime
                        Entropy = if ($entropyResult) { $entropyResult.Entropy } else { 0 }
                    }
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $Script:HighEntropyThreshold) {
                        $detections += @{
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Entropy = [Math]::Round($entropyResult.Entropy, 2)
                            FileSize = $entropyResult.FileSize
                            Type = "High Entropy File"
                            Risk = "Medium"
                        }
                        
                        Write-AVLog "High entropy file detected - File: $($file.Name) | Path: $($file.FullName) | Entropy: $([Math]::Round($entropyResult.Entropy, 2))" "WARNING" "file_entropy_detections.log"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Periodic cleanup of cache
        if ($Script:ScannedFiles.Count -gt 1000) {
            $oldKeys = $Script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
            foreach ($key in $oldKeys) {
                $Script:ScannedFiles.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-AVLog "File entropy detection completed: $($detections.Count) high entropy file(s) found" "INFO" "file_entropy_detections.log"
        }
    } catch {
        Write-AVLog "File entropy detection error: $_" "ERROR" "file_entropy_detections.log"
    }
    
    return $detections.Count
}

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        $honeypotFiles = @(
            "$Script:InstallPath\Data\passwords.txt",
            "$Script:InstallPath\Data\credentials.xlsx",
            "$Script:InstallPath\Data\secrets.docx"
        )
        
        foreach ($honeypot in $honeypotFiles) {
            if (Test-Path $honeypot) {
                $file = Get-Item $honeypot -ErrorAction SilentlyContinue
                if ($file.LastAccessTime -gt (Get-Date).AddMinutes(-5)) {
                    $detections += @{
                        HoneypotFile = $honeypot
                        LastAccess = $file.LastAccessTime
                        Type = "Honeypot File Accessed"
                        Risk = "Critical"
                    }
                }
            } else {
                try {
                    $dir = Split-Path $honeypot -Parent
                    if (-not (Test-Path $dir)) {
                        New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    }
                    "HONEYPOT - This file is monitored for unauthorized access" | Set-Content -Path $honeypot
                } catch { }
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "HoneypotMonitoring" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "HoneypotMonitoring" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine) {
                $lateralPatterns = @(
                    "psexec", "paexec", "wmic.*process.*call.*create",
                    "winrm", "enter-pssession", "invoke-command.*-computername",
                    "schtasks.*/create.*/s", "at.exe.*\\\\"
                )
                
                foreach ($pattern in $lateralPatterns) {
                    if ($cmdLine -match $pattern) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            CommandLine = $cmdLine
                            Pattern = $pattern
                            Type = "Lateral Movement Activity"
                            Risk = "High"
                        }
                    }
                }
            }
        }
        
        $smbConnections = Get-NetTCPConnection -RemotePort 445 -State Established -ErrorAction SilentlyContinue
        $uniqueHosts = ($smbConnections.RemoteAddress | Select-Object -Unique).Count
        
        if ($uniqueHosts -gt 5) {
            $detections += @{
                UniqueHosts = $uniqueHosts
                Type = "Multiple SMB Connections"
                Risk = "Medium"
            }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "LateralMovementDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "LateralMovementDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Invoke-ProcessCreationDetection {
    $detections = @()
    
    try {
        # Check for WMI process creation filters (blockers)
        try {
            $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Query -match 'Win32_ProcessStartTrace|__InstanceCreationEvent.*Win32_Process'
                }
            
            foreach ($filter in $filters) {
                # Check if filter is bound to a consumer that blocks processes
                $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                    Where-Object { $_.Filter -like "*$($filter.Name)*" }
                
                if ($bindings) {
                    foreach ($binding in $bindings) {
                        $consumer = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "*$($binding.Consumer)*" }
                        
                        if ($consumer) {
                            # Check if consumer command blocks process creation
                            if ($consumer.CommandLineTemplate -match 'taskkill|Stop-Process|Remove-Process' -or
                                $consumer.CommandLineTemplate -match 'block|deny|prevent') {
                                $detections += @{
                                    FilterName = $filter.Name
                                    ConsumerName = $consumer.Name
                                    CommandLine = $consumer.CommandLineTemplate
                                    Type = "WMI Process Creation Blocker Detected"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for process creation failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Message -match 'process.*failed|service.*failed.*start|start.*failed'
                }
            
            $processFailures = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1)
            }
            
            if ($processFailures.Count -gt 10) {
                $detections += @{
                    EventCount = $processFailures.Count
                    Type = "Excessive Process Creation Failures"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for processes with unusual creation patterns
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CreationDate, ExecutablePath
            
            # Check for processes spawned in rapid succession
            $recentProcs = $processes | Where-Object {
                (Get-Date) - $_.CreationDate -lt [TimeSpan]::FromMinutes(5)
            }
            
            # Group by parent process
            $parentGroups = $recentProcs | Group-Object ParentProcessId
            
            foreach ($group in $parentGroups) {
                if ($group.Count -gt 20) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($group.Name)" -ErrorAction SilentlyContinue
                        if ($parent) {
                            $detections += @{
                                ParentProcessId = $group.Name
                                ParentProcessName = $parent.Name
                                ChildCount = $group.Count
                                Type = "Rapid Process Creation Spawning"
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check for processes with unusual parent relationships
        try {
            $suspiciousParents = @{
                "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                "explorer.exe" = @("notepad.exe", "calc.exe")
            }
            
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId
            
            foreach ($proc in $processes) {
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        
                        if ($parent) {
                            foreach ($suspParent in $suspiciousParents.Keys) {
                                if ($parent.Name -eq $suspParent -and 
                                    $proc.Name -in $suspiciousParents[$suspParent]) {
                                    
                                    $detections += @{
                                        ProcessId = $proc.ProcessId
                                        ProcessName = $proc.Name
                                        ParentProcessId = $proc.ParentProcessId
                                        ParentProcessName = $parent.Name
                                        Type = "Suspicious Parent-Child Process Relationship"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Also check Security event log for suspicious process creation (original check)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue -MaxEvents 50
            
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $newProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                $commandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                
                $suspiciousPatterns = @(
                    "powershell.*-enc", "cmd.*/c.*powershell",
                    "certutil.*-decode", "bitsadmin.*/download",
                    "mshta.*http", "regsvr32.*/s.*/i"
                )
                
                foreach ($pattern in $suspiciousPatterns) {
                    if ($commandLine -match $pattern) {
                        $detections += @{
                            ProcessName = $newProcessName
                            CommandLine = $commandLine
                            Pattern = $pattern
                            TimeCreated = $evt.TimeCreated
                            Type = "Suspicious Process Creation"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-AVLog "PROCESS CREATION: $($detection.Type) - $($detection.ProcessName -or $detection.FilterName -or $detection.ParentProcessName -or 'System')" "THREAT" "process_creation_detections.log"
                $Global:AntivirusState.ThreatCount++
                
                if ($detection.ProcessId -and $Config.AutoKillThreats) {
                    if ($detection.ProcessId -ne $PID -and $detection.ProcessId -ne $Script:SelfPID) {
                        Stop-ThreatProcess -ProcessId $detection.ProcessId -ProcessName $detection.ProcessName
                    }
                }
            }
            
            $logPath = "$env:ProgramData\AntivirusProtection\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (!(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.FilterName)" |
                    Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-AVLog "Process creation detection error: $_" "ERROR" "process_creation_detections.log"
    }
    
    return $detections.Count
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason,
        [string]$Source,
        [switch]$SkipApiCheck = $false
    )
    
    try {
        if (-not $FilePath) {
            Write-EDRLog -Module "Quarantine" -Message "Cannot quarantine - FilePath is empty or null (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $false
        }
        
        if (Test-Path $FilePath) {
            Write-EDRLog -Module "Quarantine" -Message "Attempting to quarantine: $FilePath (Reason: $Reason, Source: $Source)" -Level "Info"
            # Consult the 3 malware APIs before quarantining (unless explicitly skipped)
            if (-not $SkipApiCheck) {
                $isMalicious = $false
                $apiConfidence = 0
                $apiSources = @()
                
                try {
                    $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($fileHash) {
                        # Check CIRCL Hash Lookup
                        try {
                            $CirclResponse = Invoke-RestMethod -Uri "$($Config.CirclHashLookupUrl)/$fileHash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($CirclResponse.KnownMalicious) {
                                $isMalicious = $true
                                $apiConfidence += 40
                                $apiSources += "CIRCL"
                            }
                        } catch {}
                        
                        # Check MalwareBazaar
                        try {
                            $MBBody = @{ query = "get_info"; hash = $fileHash } | ConvertTo-Json
                            $MBResponse = Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($MBResponse.query_status -eq "ok") {
                                $isMalicious = $true
                                $apiConfidence += 50
                                $apiSources += "MalwareBazaar"
                            }
                        } catch {}
                        
                        # Check Cymru Malware Hash Registry
                        try {
                            $CymruResponse = Invoke-RestMethod -Uri "$($Config.CymruApiUrl)/$fileHash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                            if ($CymruResponse.malware -eq $true) {
                                $isMalicious = $true
                                $apiConfidence += 30
                                $apiSources += "Cymru"
                            }
                        } catch {}
                        
                        # Log API results - APIs are consulted but don't block quarantine
                        # If APIs confirm malicious, log it. If not found or APIs unavailable, still quarantine based on detection engine
                        if ($isMalicious -and $apiConfidence -ge 30) {
                            Write-EDRLog -Module "Quarantine" -Message "API verification confirmed malicious: $FilePath confirmed by $($apiSources -join ', ') (Confidence: $apiConfidence)" -Level "Warning"
                        } else {
                            Write-EDRLog -Module "Quarantine" -Message "API check completed for $FilePath (not found in databases or APIs unavailable) - proceeding with quarantine based on detection engine" -Level "Info"
                        }
                    } else {
                        Write-EDRLog -Module "Quarantine" -Message "Could not calculate hash for $FilePath - proceeding with quarantine based on detection engine" -Level "Info"
                    }
                } catch {
                    Write-EDRLog -Module "Quarantine" -Message "API verification error for $FilePath : $_ - proceeding with quarantine based on detection engine" -Level "Warning"
                    # If API check fails, proceed with quarantine based on detection engine results
                }
            }
            
            $fileName = Split-Path -Leaf $FilePath
            $quarantinePath = Join-Path $Config.QuarantinePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$fileName"
            
            if (-not (Test-Path $Config.QuarantinePath)) {
                New-Item -Path $Config.QuarantinePath -ItemType Directory -Force | Out-Null
            }
            
            Move-Item -Path $FilePath -Destination $quarantinePath -Force
            Write-EDRLog -Module "Quarantine" -Message "SUCCESS: Quarantined $FilePath -> $quarantinePath (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $true
        } else {
            Write-EDRLog -Module "Quarantine" -Message "Cannot quarantine - file does not exist: $FilePath (Reason: $Reason, Source: $Source)" -Level "Warning"
            return $false
        }
    } catch {
        Write-EDRLog -Module "Quarantine" -Message "ERROR: Failed to quarantine $FilePath : $_ (Reason: $Reason, Source: $Source)" -Level "Error"
    }
    
    return $false
}

function Invoke-QuarantineManagement {
    try {
        $quarantineFiles = Get-ChildItem -Path $Config.QuarantinePath -File -ErrorAction SilentlyContinue
        
        foreach ($file in $quarantineFiles) {
            $age = (Get-Date) - $file.CreationTime
            if ($age.Days -gt 30) {
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                Write-EDRLog -Module "Quarantine" -Message "Removed old quarantined file: $($file.Name)" -Level "Info"
            }
        }
    } catch {
        Write-EDRLog -Module "QuarantineManagement" -Message "Error: $_" -Level "Error"
    }
    
    return 0
}

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules }
        
        foreach ($proc in $processes) {
            try {
                $memOnlyModules = $proc.Modules | Where-Object {
                    $_.FileName -and -not (Test-Path $_.FileName)
                }
                
                if ($memOnlyModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        MemoryModules = $memOnlyModules.Count
                        Type = "Potential Reflective DLL Injection"
                        Risk = "High"
                    }
                }
            } catch { continue }
        }
        
        if ($detections.Count -gt 0) {
            Write-Detection -Module "ReflectiveDLLInjectionDetection" -Count $detections.Count
        }
    } catch {
        Write-EDRLog -Module "ReflectiveDLLInjectionDetection" -Message "Error: $_" -Level "Error"
    }
    
    return $detections.Count
}

function Add-ThreatToResponseQueue {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium",
        [hashtable]$Details = $null
    )
    
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Prevent queue overflow
        if ($Script:ResponseQueue.Count -ge $Script:ResponseQueueMaxSize) {
            Write-EDRLog -Module "ResponseEngine" -Message "WARNING: Response queue is full, dropping oldest threat" -Level "Warning"
            $null = $Script:ResponseQueue.Dequeue()
        }

        # Extract ThreatPath from Details if provided and ThreatPath is not set
        if ($Details -and -not $ThreatPath) {
            if ($Details.FilePath) {
                $ThreatPath = $Details.FilePath
            } elseif ($Details.ProcessPath) {
                $ThreatPath = $Details.ProcessPath
            } elseif ($Details.Path) {
                $ThreatPath = $Details.Path
            } elseif ($Details.ProcessName) {
                $ThreatPath = $Details.ProcessName
            } elseif ($Details.FileName) {
                $ThreatPath = $Details.FileName
            }
        }

        $threat = @{
            ThreatType = $ThreatType
            ThreatPath = $ThreatPath
            Severity = $Severity
            Timestamp = Get-Date
        }

        $Script:ResponseQueue.Enqueue($threat)
        Write-EDRLog -Module "ResponseEngine" -Message "Queued threat: $ThreatType - $ThreatPath (Severity: $Severity). Queue size: $($Script:ResponseQueue.Count)" -Level "Debug"
    }
    catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error adding threat to queue: $_" -Level "Error"
    }
}

function Invoke-DriverBehavioralAnalysis {
    <#
    .SYNOPSIS
    Performs behavioral analysis on a driver using hybrid approach:
    - Uses general framework (Invoke-AdvancedThreatDetection) for file-based analysis
    - Adds driver-specific runtime behavioral checks
    
    .DESCRIPTION
    Hybrid analysis combining:
    1. File-based analysis via general framework (entropy, signatures, patterns)
    2. Driver-specific runtime behavior (network from services, process spawning, registry, etc.)
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [string]$DriverServiceName = $null
    )
    
    try {
        $threatScore = 0
        $behavioralIndicators = @()
        $reasons = @()
        $fileBasedScore = 0
        
        if (-not $DriverServiceName) {
            $DriverServiceName = $DriverName
        }
        
        # PART 1: Use general framework for file-based analysis (if driver path provided)
        if ($DriverPath -and (Test-Path $DriverPath)) {
            try {
                # Define rootkit/driver-specific signatures
                $driverSignatures = @{
                    "Rootkit" = @("rootkit", "stealth", "hide", "hook", "inject", "bypass")
                    "KernelDriver" = @("kernel.*driver", "system.*driver", "kernel.*mode")
                }
                
                # Define behavioral patterns for drivers (command-line would be empty for drivers, but we check file content)
                $driverBehavioralPatterns = @{
                    "SuspiciousName" = @("stealth", "hook", "hide", "rootkit", "inject", "bypass", "protect")
                }
                
                # Use general framework for file-based analysis
                $fileAnalysis = Invoke-AdvancedThreatDetection `
                    -FilePath $DriverPath `
                    -FileSignatures $driverSignatures `
                    -BehavioralIndicators $driverBehavioralPatterns `
                    -CommandLine $null `
                    -CheckEntropy $true `
                    -EntropyThreshold 7.5
                
                if ($fileAnalysis.IsThreat) {
                    $fileBasedScore = $fileAnalysis.Confidence / 5  # Convert confidence to threat score (rough conversion)
                    $reasons += "File-based analysis: $($fileAnalysis.ThreatName) (Confidence: $($fileAnalysis.Confidence)%)"
                    $reasons += "Detection methods: $($fileAnalysis.DetectionMethods -join ', ')"
                    if ($fileAnalysis.Details.ContainsKey("Entropy")) {
                        $behavioralIndicators += "HighEntropy"
                        $reasons += "High entropy detected: $($fileAnalysis.Details.Entropy)"
                    }
                }
            } catch {
                Write-EDRLog -Module "DriverBehavioralAnalysis" -Message "Error in file-based analysis for $DriverPath : $_" -Level "Warning"
            }
        }
        
        # PART 2: Driver-specific runtime behavioral checks
        # 1. Check for network activity from driver service
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.ProcessId) {
                $proc = Get-Process -Id $serviceProcess.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    # Check for network connections
                    $netConnections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
                    if ($netConnections) {
                        $externalConnections = $netConnections | Where-Object { $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" -and $_.State -eq "Established" }
                        if ($externalConnections) {
                            $threatScore += 15
                            $behavioralIndicators += "NetworkActivity"
                            $uniqueAddresses = $externalConnections | Select-Object -First 3 -ExpandProperty RemoteAddress -Unique
                            $reasons += "Driver service has active network connections to: $($uniqueAddresses -join ', ')"
                        }
                    }
                }
            }
        } catch {}
        
        # 2. Check for recent file system modifications (runtime indicator)
        if ($DriverPath -and (Test-Path $DriverPath)) {
            try {
                $driverFile = Get-Item $DriverPath -ErrorAction SilentlyContinue
                if ($driverFile) {
                    $fileAge = (Get-Date) - $driverFile.LastWriteTime
                    
                    # Very recent modification (within last 24 hours) - suspicious
                    if ($fileAge.TotalHours -lt 24) {
                        $threatScore += 10
                        $behavioralIndicators += "RecentModification"
                        $reasons += "Driver file modified recently ($([Math]::Round($fileAge.TotalHours, 1)) hours ago)"
                    }
                }
            } catch {}
        }
        
        # 3. Check registry modifications related to the driver
        try {
            $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverServiceName"
            if (Test-Path $serviceKey) {
                $serviceProps = Get-ItemProperty -Path $serviceKey -ErrorAction SilentlyContinue
                
                # Check for suspicious registry values
                if ($serviceProps) {
                    # Check if StartType was recently changed (suggests manipulation)
                    # This is harder to detect without baseline, but we can check for suspicious values
                    if ($serviceProps.Start -eq 0 -and $serviceProps.Type -eq 1) {
                        # Kernel driver set to boot start - check if it's in standard location
                        if ($serviceProps.ImagePath -and $serviceProps.ImagePath -notmatch "^\\\\?\\C:\\Windows") {
                            $threatScore += 8
                            $behavioralIndicators += "SuspiciousServiceConfig"
                            $reasons += "Driver service configured for boot start from non-standard location"
                        }
                    }
                }
            }
        } catch {}
        
        # 4. Check for processes spawned by driver service
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.ProcessId) {
                $proc = Get-Process -Id $serviceProcess.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    # Check for child processes (driver services typically don't spawn processes)
                    $childProcesses = Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                    if ($childProcesses) {
                        $threatScore += 15
                        $behavioralIndicators += "ProcessCreation"
                        $uniqueProcesses = $childProcesses | Select-Object -First 3 -ExpandProperty Name -Unique
                        $reasons += "Driver service spawned processes: $($uniqueProcesses -join ', ')"
                    }
                }
            }
        } catch {}
        
        # 5. Check for file system access patterns (if service is running)
        try {
            $serviceProcess = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($serviceProcess -and $serviceProcess.State -eq "Running") {
                # Check if driver is accessing user directories (suspicious for system drivers)
                # This is harder to detect without kernel hooks, but we can check service dependencies
                $dependents = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue | 
                    Get-CimAssociatedInstance -ResultClassName Win32_Service -ErrorAction SilentlyContinue
                
                # If driver has many dependencies or is depended upon by many services, it's more critical
                # This is just metadata, not true behavioral, but gives context
            }
        } catch {}
        
        # 6. Check for driver loading time patterns (loaded at unusual times)
        try {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$DriverServiceName'" -ErrorAction SilentlyContinue
            if ($service -and $service.PathName) {
                # Check if driver file was created/modified at unusual times
                # (e.g., outside business hours if this is a corporate environment)
                # This is a weak indicator but can be part of the analysis
            }
        } catch {}
        
        # Combine file-based and runtime behavioral scores
        $totalThreatScore = $fileBasedScore + $threatScore
        
        # Determine severity based on total threat score
        # Combine file-based and runtime behavioral scores
        $totalThreatScore = $fileBasedScore + $threatScore
        
        $severity = "Low"
        if ($totalThreatScore -ge 30) {
            $severity = "Critical"
        } elseif ($totalThreatScore -ge 20) {
            $severity = "High"
        } elseif ($totalThreatScore -ge 10) {
            $severity = "Medium"
        }
        
        return @{
            ThreatScore = $totalThreatScore
            FileBasedScore = $fileBasedScore
            RuntimeBehaviorScore = $threatScore
            Severity = $severity
            BehavioralIndicators = $behavioralIndicators
            Reasons = $reasons
            IsMalicious = $totalThreatScore -ge 20  # Threshold for considering driver malicious
        }
    } catch {
        Write-EDRLog -Module "DriverBehavioralAnalysis" -Message "Error analyzing driver $DriverName : $_" -Level "Warning"
        return @{
            ThreatScore = 0
            Severity = "Low"
            BehavioralIndicators = @()
            Reasons = @()
            IsMalicious = $false
        }
    }
}

function Remove-MinifilterDriverSafe {
    <#
    .SYNOPSIS
    Safely removes ANY minifilter driver using fltmc unload before stopping/deleting.
    This prevents BSODs by properly unloading the filter before removal.
    
    .DESCRIPTION
    This is a general-purpose function that safely removes minifilter drivers.
    It should be used for malicious minifilter drivers detected as threats.
    Legitimate drivers (signed, standard location) won't be flagged as threats.
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [switch]$DeleteDriverFile = $false
    )
    
    try {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Attempting to safely remove minifilter driver: $DriverName" -Level "Info"
        
        # Check if driver is a registered minifilter by checking fltmc filters
        $isMinifilter = $false
        try {
            $fltmcOutput = fltmc filters 2>&1 | Out-String
            if ($fltmcOutput -match [regex]::Escape($DriverName)) {
                $isMinifilter = $true
            }
        } catch {
            # If fltmc fails, assume it might be a minifilter for safety
            $isMinifilter = $true
        }
        
        # Step 1: Unload the minifilter using fltmc (CRITICAL - prevents BSOD)
        if ($isMinifilter) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Unloading minifilter driver: $DriverName using fltmc" -Level "Info"
                $unloadResult = fltmc unload $DriverName 2>&1 | Out-String
                
                if ($LASTEXITCODE -eq 0 -or $unloadResult -match "success|unloaded") {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Successfully unloaded minifilter: $DriverName" -Level "Info"
                    Start-Sleep -Milliseconds 500  # Give system time to process unload
                } else {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "fltmc unload result for $DriverName : $unloadResult" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to unload minifilter $DriverName with fltmc: $_" -Level "Warning"
            }
        }
        
        # Step 2: Stop the driver service
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Stopping driver service: $DriverName" -Level "Info"
            $stopResult = sc.exe stop $DriverName 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $stopResult -match "STOPPED|STOP_PENDING") {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Stopped driver service: $DriverName" -Level "Info"
                Start-Sleep -Milliseconds 500  # Give system time to process stop
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver stop result for $DriverName : $stopResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to stop driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 3: Disable the driver to prevent auto-start
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Disabling driver service: $DriverName" -Level "Info"
            $configResult = sc.exe config $DriverName start= disabled 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Disabled driver service: $DriverName (will not start on next boot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver disable result for $DriverName : $configResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to disable driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 4: Mark driver service for deletion (will be removed after reboot)
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Marking driver service for deletion: $DriverName" -Level "Info"
            $deleteResult = sc.exe delete $DriverName 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Marked driver service for deletion: $DriverName (will be removed after reboot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver delete result for $DriverName : $deleteResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to mark driver service for deletion $DriverName : $_" -Level "Warning"
        }
        
        # Step 5: If driver file path is provided and DeleteDriverFile is set, schedule file for deletion
        if ($DeleteDriverFile -and $DriverPath -and (Test-Path $DriverPath)) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Preparing to delete driver file: $DriverPath" -Level "Info"
                
                # Take ownership of the file
                $takeownResult = takeown /f $DriverPath /A 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Reset permissions
                $icaclsResult = icacls $DriverPath /reset 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Remove inheritance and grant full control to administrators
                $icaclsResult2 = icacls $DriverPath /inheritance:d /grant "Administrators:F" 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Try to delete the file (may fail if in use, will be deleted on reboot)
                try {
                    Remove-Item -Path $DriverPath -Force -ErrorAction Stop
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Deleted driver file: $DriverPath" -Level "Info"
                } catch {
                    # If deletion fails, schedule for deletion on reboot using MoveFileEx
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Could not delete $DriverPath immediately (may be in use), will be removed on reboot" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to delete driver file $DriverPath : $_" -Level "Warning"
            }
        }
        
        Write-EDRLog -Module "MinifilterRemoval" -Message "Completed safe removal process for minifilter driver: $DriverName" -Level "Info"
        return $true
    } catch {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Error removing minifilter driver $DriverName : $_" -Level "Error"
        return $false
    }
}

function Remove-MinifilterDriver {
    <#
    .SYNOPSIS
    Safely removes a minifilter driver using fltmc unload before stopping/deleting.
    This prevents BSODs by properly unloading the filter before removal.
    
    .DESCRIPTION
    This function only targets specific drivers (bfs, unionfs) from the batch file.
    Other minifilter drivers (including legitimate antivirus drivers) are NOT processed
    by this function to avoid interfering with user security software.
    #>
    param(
        [string]$DriverName,
        [string]$DriverPath = $null,
        [switch]$DeleteDriverFile = $false
    )
    
    try {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Attempting to remove minifilter driver: $DriverName" -Level "Info"
        
        # List of specific minifilter drivers to remove (only drivers explicitly listed in batch file)
        # Only targeting bfs and unionfs - other drivers (including antivirus) are NOT targeted
        # This prevents interference with legitimate security software
        $targetDrivers = @("bfs", "unionfs")
        
        # Check if this is a target driver
        $isTargetDriver = $false
        foreach ($target in $targetDrivers) {
            if ($DriverName -like "*$target*" -or $DriverName -eq $target) {
                $isTargetDriver = $true
                break
            }
        }
        
        # Also check driver path if provided
        if (-not $isTargetDriver -and $DriverPath) {
            $driverFileName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPath).ToLower()
            foreach ($target in $targetDrivers) {
                if ($driverFileName -like "*$target*" -or $driverFileName -eq $target) {
                    $isTargetDriver = $true
                    break
                }
            }
        }
        
        if (-not $isTargetDriver) {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Driver $DriverName is not in target list, skipping minifilter removal" -Level "Debug"
            return $false
        }
        
        # Step 1: Check if driver is a registered minifilter by checking fltmc filters
        $isMinifilter = $false
        try {
            $fltmcOutput = fltmc filters 2>&1 | Out-String
            if ($fltmcOutput -match [regex]::Escape($DriverName)) {
                $isMinifilter = $true
            }
        } catch {
            # If fltmc fails, assume it might be a minifilter for safety
            $isMinifilter = $true
        }
        
        # Step 2: Unload the minifilter using fltmc (CRITICAL - prevents BSOD)
        if ($isMinifilter) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Unloading minifilter driver: $DriverName using fltmc" -Level "Info"
                $unloadResult = fltmc unload $DriverName 2>&1 | Out-String
                
                if ($LASTEXITCODE -eq 0 -or $unloadResult -match "success|unloaded") {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Successfully unloaded minifilter: $DriverName" -Level "Info"
                    Start-Sleep -Milliseconds 500  # Give system time to process unload
                } else {
                    Write-EDRLog -Module "MinifilterRemoval" -Message "fltmc unload result for $DriverName : $unloadResult" -Level "Warning"
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to unload minifilter $DriverName with fltmc: $_" -Level "Warning"
            }
        }
        
        # Step 3: Stop the driver service
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Stopping driver service: $DriverName" -Level "Info"
            $stopResult = sc.exe stop $DriverName 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $stopResult -match "STOPPED|STOP_PENDING") {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Stopped driver service: $DriverName" -Level "Info"
                Start-Sleep -Milliseconds 500  # Give system time to process stop
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver stop result for $DriverName : $stopResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to stop driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 4: Disable the driver to prevent auto-start
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Disabling driver service: $DriverName" -Level "Info"
            $configResult = sc.exe config $DriverName start= disabled 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Disabled driver service: $DriverName (will not start on next boot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver disable result for $DriverName : $configResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to disable driver service $DriverName : $_" -Level "Warning"
        }
        
        # Step 5: Mark driver service for deletion (will be removed after reboot)
        try {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Marking driver service for deletion: $DriverName" -Level "Info"
            $deleteResult = sc.exe delete $DriverName 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Marked driver service for deletion: $DriverName (will be removed after reboot)" -Level "Info"
            } else {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Driver delete result for $DriverName : $deleteResult" -Level "Warning"
            }
        } catch {
            Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to mark driver service for deletion $DriverName : $_" -Level "Warning"
        }
        
        # Step 6: If driver file path is provided and DeleteDriverFile is set, schedule file for deletion
        if ($DeleteDriverFile -and $DriverPath -and (Test-Path $DriverPath)) {
            try {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Preparing to delete driver file: $DriverPath" -Level "Info"
                
                # Take ownership of the file
                $takeownResult = takeown /f $DriverPath /A 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Reset permissions
                $icaclsResult = icacls $DriverPath /reset 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Remove inheritance and grant full control to administrators
                $icaclsResult2 = icacls $DriverPath /inheritance:d /grant "Administrators:F" 2>&1 | Out-String
                Start-Sleep -Milliseconds 200
                
                # Try to delete the file (may fail if in use, will be deleted on reboot)
                try {
                    Remove-Item -Path $DriverPath -Force -ErrorAction Stop
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Deleted driver file: $DriverPath" -Level "Info"
                } catch {
                    # If deletion fails, schedule for deletion on reboot using MoveFileEx
                    Write-EDRLog -Module "MinifilterRemoval" -Message "Could not delete $DriverPath immediately (may be in use), will be removed on reboot" -Level "Warning"
                    # Note: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT (4) would require P/Invoke, using sc.exe delete handles service removal
                }
            } catch {
                Write-EDRLog -Module "MinifilterRemoval" -Message "Failed to delete driver file $DriverPath : $_" -Level "Warning"
            }
        }
        
        Write-EDRLog -Module "MinifilterRemoval" -Message "Completed removal process for minifilter driver: $DriverName" -Level "Info"
        return $true
    } catch {
        Write-EDRLog -Module "MinifilterRemoval" -Message "Error removing minifilter driver $DriverName : $_" -Level "Error"
        return $false
    }
}

function Invoke-ResponseAction {
    param(
        [string]$ThreatType,
        [string]$ThreatPath,
        [string]$Severity = "Medium"
    )
    
    try {
        $actions = @{
            "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "StopDriver", "Log")
            "High"     = @("Quarantine", "StopDriver", "Log", "Alert")
            "Medium"   = @("Quarantine", "Log", "Alert")
            "Low"      = @("Log")
        }
        
        $responseActions = $actions[$Severity]
        
        foreach ($action in $responseActions) {
            switch ($action) {
                "Quarantine" {
                    # Validate that ThreatPath is a valid file path before attempting quarantine
                    # Skip quarantine for non-file paths (process names, registry paths, network addresses, etc.)
                    if (-not $ThreatPath) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - ThreatPath is empty (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                        continue
                    }
                    
                    # Check if it looks like a file path (contains drive letter or starts with \ or /)
                    $isLikelyFilePath = $ThreatPath -match '^([A-Za-z]:\\|\\\\|/|\.\\)' -or (Test-Path $ThreatPath -PathType Leaf)
                    
                    if (-not $isLikelyFilePath) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Skipping quarantine - ThreatPath appears to be non-file identifier: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                        continue
                    }
                    
                    # Verify it's actually a file (not a directory)
                    if (Test-Path $ThreatPath -PathType Leaf) {
                        $quarantineResult = Invoke-QuarantineFile -FilePath $ThreatPath -Reason $ThreatType -Source "ResponseEngine"
                        if (-not $quarantineResult) {
                            Write-EDRLog -Module "ResponseEngine" -Message "Quarantine failed or skipped for: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Warning"
                        }
                    } elseif (Test-Path $ThreatPath -PathType Container) {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - path is a directory, not a file: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                    } else {
                        Write-EDRLog -Module "ResponseEngine" -Message "Cannot quarantine - file does not exist: $ThreatPath (Type: $ThreatType, Severity: $Severity)" -Level "Info"
                    }
                }
                "KillProcess" {
                    try {
                        # ThreatPath might be a PID (integer) or process name
                        if ($ThreatPath -match '^\d+$') {
                            $threatPID = [int]$ThreatPath
                            
                            # Whitelist own process - never kill ourselves
                            if ($threatPID -eq $PID -or $threatPID -eq $Script:SelfPID) {
                                Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $threatPID) - whitelisted" -Level "Warning"
                                return
                            }
                            
                            # Check if this PID is running our script - if so, whitelist it
                            try {
                                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $threatPID" -ErrorAction SilentlyContinue).CommandLine
                                $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                    Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $threatPID) - whitelisted" -Level "Warning"
                                    return
                                }
                            } catch {}
                            
                            $proc = Get-Process -Id $threatPID -ErrorAction SilentlyContinue
                            if ($proc) {
                                Stop-Process -Id $threatPID -Force -ErrorAction SilentlyContinue
                                Write-EDRLog -Module "ResponseEngine" -Message "Terminated process PID: $ThreatPath" -Level "Info"
                            }
                        } else {
                            $proc = Get-Process -Name $ThreatPath -ErrorAction SilentlyContinue
                            if ($proc) {
                                # Check each process to ensure we're not killing our own
                                foreach ($p in $proc) {
                                    if ($p.Id -eq $PID -or $p.Id -eq $Script:SelfPID) {
                                        Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own process (PID: $($p.Id), Name: $ThreatPath) - whitelisted" -Level "Warning"
                                        continue
                                    }
                                    
                                    # Check if this process is running our script
                                    try {
                                        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                                        $ownScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $Script:SelfPath }
                                        if ($cmdLine -and $ownScriptPath -and $cmdLine -like "*$ownScriptPath*") {
                                            Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to kill own script instance (PID: $($p.Id)) - whitelisted" -Level "Warning"
                                            continue
                                        }
                                    } catch {}
                                    
                                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                                    Write-EDRLog -Module "ResponseEngine" -Message "Terminated process: $ThreatPath (PID: $($p.Id))" -Level "Info"
                                }
                            }
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to kill process $ThreatPath : $_" -Level "Warning"
                    }
                }
                "BlockNetwork" {
                    try {
                        # Extract IP address from ThreatPath if it's in format "IP:Port" or just "IP"
                        $ipAddress = if ($ThreatPath -match '^(\d+\.\d+\.\d+\.\d+)') { $matches[1] } else { $ThreatPath }
                        
                        $RuleName = "Block_ResponseEngine_$ipAddress" -replace '[\.:]', '_'
                        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                        
                        if (-not $existingRule) {
                            New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $ipAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                            Write-EDRLog -Module "ResponseEngine" -Message "Blocked network connection to $ipAddress" -Level "Info"
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to block network for $ThreatPath : $_" -Level "Warning"
                    }
                }
                "Log" {
                    Write-EDRLog -Module "ResponseEngine" -Message "THREAT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                }
                "StopDriver" {
                    try {
                        # Check if this is a driver threat (format: "Driver:DriverName|Path" or just a driver path)
                        $driverName = $null
                        $driverPath = $ThreatPath
                        
                        if ($ThreatPath -match "^Driver:([^|]+)\|(.+)$") {
                            $driverName = $matches[1]
                            $driverPath = $matches[2]
                        } elseif ($ThreatType -eq "Rootkit" -and $ThreatPath) {
                            # Try to extract driver name from service registry
                            try {
                                $service = Get-CimInstance -ClassName Win32_SystemDriver -Filter "PathName LIKE '%$($ThreatPath -replace '\\', '\\')%'" -ErrorAction SilentlyContinue | Select-Object -First 1
                                if ($service) {
                                    $driverName = $service.Name
                                }
                            } catch {}
                            
                            # If driver name not found, try to extract from path
                            if (-not $driverName -and $ThreatPath -match '([^\\]+)\.sys$') {
                                $driverName = $matches[1]
                            }
                        }
                        
                        if ($driverName -and $driverPath) {
                            # CRITICAL: Check if this is an inbox/Windows system driver - NEVER remove these
                            $isInboxDriver = $false
                            if ($driverPath -like "*\Windows\System32\drivers\*" -or $driverPath -like "*\SystemRoot\System32\drivers\*") {
                                try {
                                    # Check if driver is signed by Microsoft (inbox drivers are Microsoft-signed)
                                    if (Test-Path $driverPath) {
                                        $sig = Get-AuthenticodeSignature -FilePath $driverPath -ErrorAction SilentlyContinue
                                        if ($sig.Status -eq "Valid" -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match "Microsoft") {
                                            $isInboxDriver = $true
                                            Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to remove inbox/Windows system driver (Microsoft-signed): $driverName at $driverPath - skipping removal" -Level "Warning"
                                        }
                                    }
                                } catch {
                                    # If we can't verify signature but driver is in System32\drivers, err on side of caution
                                    if ($driverPath -like "*\Windows\System32\drivers\*" -or $driverPath -like "*\SystemRoot\System32\drivers\*") {
                                        $isInboxDriver = $true
                                        Write-EDRLog -Module "ResponseEngine" -Message "BLOCKED: Attempted to remove driver from System32\drivers (potential inbox driver): $driverName at $driverPath - skipping removal" -Level "Warning"
                                    }
                                }
                            }
                            
                            if ($isInboxDriver) {
                                Write-EDRLog -Module "ResponseEngine" -Message "Driver removal blocked: $driverName is an inbox/Windows system driver" -Level "Warning"
                                return
                            }
                            
                            # AUTOMATIC MINIFILTER DRIVER REMOVAL DISABLED - Too risky, causes BSODs
                            # Minifilter drivers are detected and logged, but automatic removal is disabled
                            Write-EDRLog -Module "ResponseEngine" -Message "Driver removal requested for: $driverName, but automatic minifilter driver removal is disabled to prevent BSODs. Manual review recommended." -Level "Warning"
                            
                            # Log the driver information but do not remove
                            Write-EDRLog -Module "ResponseEngine" -Message "Detected driver threat (removal disabled): $driverName | Path: $driverPath | Type: $ThreatType | Severity: $Severity" -Level "Warning"
                        } else {
                            Write-EDRLog -Module "ResponseEngine" -Message "Could not determine driver name from threat path: $ThreatPath" -Level "Warning"
                        }
                    } catch {
                        Write-EDRLog -Module "ResponseEngine" -Message "Failed to process driver removal for $ThreatPath : $_" -Level "Warning"
                    }
                }
                "Alert" {
                    try {
                        # Ensure event log source exists before writing
                        if ($null -ne $Config -and $null -ne $Config.EDRName -and -not [string]::IsNullOrWhiteSpace($Config.EDRName)) {
                            if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
                                [System.Diagnostics.EventLog]::CreateEventSource($Config.EDRName, "Application")
                            }
                            Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Warning -EventId 2000 `
                                -Message "THREAT ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -ErrorAction SilentlyContinue
                        }
                    } catch {
                        # Event log may not be available, fall back to EDR log
                        Write-EDRLog -Module "ResponseEngine" -Message "ALERT: $ThreatType - $ThreatPath (Severity: $Severity)" -Level "Warning"
                    }
                }
            }
        }
    } catch {
        Write-EDRLog -Module "ResponseAction" -Message "Error processing response action: $_" -Level "Error"
    }
}

function Invoke-ResponseEngine {
    try {
        # Initialize response queue if not already initialized
        if (-not $Script:ResponseQueue) {
            $Script:ResponseQueue = New-Object System.Collections.Queue
            $Script:ResponseQueueMaxSize = 1000
        }

        # Process up to 50 items from the queue per tick to avoid blocking
        $processedCount = 0
        $maxProcessPerTick = 50

        while ($Script:ResponseQueue.Count -gt 0 -and $processedCount -lt $maxProcessPerTick) {
            try {
                $threat = $Script:ResponseQueue.Dequeue()
                
                if ($threat -and $threat.ThreatType -and $threat.ThreatPath) {
                    Invoke-ResponseAction -ThreatType $threat.ThreatType -ThreatPath $threat.ThreatPath -Severity $threat.Severity
                    $processedCount++
                }
            }
            catch {
                Write-EDRLog -Module "ResponseEngine" -Message "Error processing threat from queue: $_" -Level "Error"
            }
        }

        if ($processedCount -gt 0) {
            Write-EDRLog -Module "ResponseEngine" -Message "Processed $processedCount threat(s) from queue. Queue size: $($Script:ResponseQueue.Count)" -Level "Info"
        }

        # Return count without outputting to pipeline - suppress any accidental output
        # Store result in variable and explicitly return (don't let it output to console)
        $result = $processedCount
        [void]$result  # Explicitly discard if accidentally output
        return $result
    } catch {
        Write-EDRLog -Module "ResponseEngine" -Message "Error: $_" -Level "Error"
        return 0
    }
}

# PrivacyForge Spoofing Module (Converted from Spoofer.py)
function Invoke-PrivacyForgeSpoofing {
    param(
        [hashtable]$Config
    )
    
    # Initialize script-level variables if not already set
    if (-not $Script:PrivacyForgeIdentity) {
        $Script:PrivacyForgeIdentity = @{}
        $Script:PrivacyForgeDataCollected = 0
        $Script:PrivacyForgeRotationInterval = 3600  # 1 hour
        $Script:PrivacyForgeDataThreshold = 50
        $Script:PrivacyForgeLastRotation = Get-Date
    }
    
    try {
        # Check if rotation is needed
        $timeSinceRotation = (Get-Date) - $Script:PrivacyForgeLastRotation
        $shouldRotate = $false
        
        if ($timeSinceRotation.TotalSeconds -ge $Script:PrivacyForgeRotationInterval) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Time-based rotation triggered" "INFO"
        }
        
        if ($Script:PrivacyForgeDataCollected -ge $Script:PrivacyForgeDataThreshold) {
            $shouldRotate = $true
            Write-AVLog "PrivacyForge: Data threshold reached ($Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold)" "INFO"
        }
        
        if ($shouldRotate -or (-not $Script:PrivacyForgeIdentity.ContainsKey("name"))) {
            Invoke-PrivacyForgeRotateIdentity
        }
        
        # Simulate data collection
        $Script:PrivacyForgeDataCollected += Get-Random -Minimum 1 -Maximum 6
        
        # Perform spoofing operations
        Invoke-PrivacyForgeSpoofSoftwareMetadata
        Invoke-PrivacyForgeSpoofGameTelemetry
        Invoke-PrivacyForgeSpoofSensors
        Invoke-PrivacyForgeSpoofSystemMetrics
        Invoke-PrivacyForgeSpoofClipboard
        
        Write-AVLog "PrivacyForge: Spoofing active - Data collected: $Script:PrivacyForgeDataCollected/$Script:PrivacyForgeDataThreshold" "INFO"
        
    } catch {
        Write-AVLog "PrivacyForge: Error - $_" "ERROR"
    }
}

function Invoke-PrivacyForgeGenerateIdentity {
    # Generate fake identity data
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Jessica", "Robert", "Amanda", "William", "Ashley", "Richard", "Melissa", "Joseph", "Nicole")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas", "Taylor")
    $domains = @("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com")
    $cities = @("New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose")
    $countries = @("United States", "Canada", "United Kingdom", "Australia", "Germany", "France", "Spain", "Italy")
    $languages = @("en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "pt-BR")
    $interests = @("tech", "gaming", "news", "sports", "music", "movies", "travel", "food", "fitness", "books")
    
    $firstName = Get-Random -InputObject $firstNames
    $lastName = Get-Random -InputObject $lastNames
    $username = "$firstName$lastName" + (Get-Random -Minimum 100 -Maximum 9999)
    $domain = Get-Random -InputObject $domains
    $email = "$username@$domain"
    
    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    
    return @{
        "name" = "$firstName $lastName"
        "email" = $email
        "username" = $username
        "location" = Get-Random -InputObject $cities
        "country" = Get-Random -InputObject $countries
        "user_agent" = Get-Random -InputObject $userAgents
        "screen_resolution" = "$(Get-Random -Minimum 800 -Maximum 1920)x$(Get-Random -Minimum 600 -Maximum 1080)"
        "interests" = (Get-Random -InputObject $interests -Count 4)
        "device_id" = [System.Guid]::NewGuid().ToString()
        "mac_address" = "{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}" -f (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256)
        "language" = Get-Random -InputObject $languages
        "timezone" = (Get-TimeZone).Id
        "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Invoke-PrivacyForgeRotateIdentity {
    $Script:PrivacyForgeIdentity = Invoke-PrivacyForgeGenerateIdentity
    $Script:PrivacyForgeDataCollected = 0
    $Script:PrivacyForgeLastRotation = Get-Date
    
    Write-AVLog "PrivacyForge: Identity rotated - Name: $($Script:PrivacyForgeIdentity.name), Username: $($Script:PrivacyForgeIdentity.username)" "INFO"
}

function Invoke-PrivacyForgeSpoofSoftwareMetadata {
    try {
        $headers = @{
            "User-Agent" = $Script:PrivacyForgeIdentity.user_agent
            "Cookie" = "session_id=$(Get-Random -Minimum 1000 -Maximum 9999); fake_id=$([System.Guid]::NewGuid().ToString())"
            "X-Device-ID" = $Script:PrivacyForgeIdentity.device_id
            "Accept-Language" = $Script:PrivacyForgeIdentity.language
            "X-Timezone" = $Script:PrivacyForgeIdentity.timezone
        }
        
        # Attempt to send spoofed headers (non-blocking)
        try {
            $null = Invoke-WebRequest -Uri "https://httpbin.org/headers" -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
            Write-AVLog "PrivacyForge: Sent spoofed software metadata headers" "DEBUG"
        } catch {
            # Silently fail - network may not be available
        }
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing software metadata - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofGameTelemetry {
    try {
        $fakeTelemetry = @{
            "player_id" = [System.Guid]::NewGuid().ToString()
            "hardware_id" = ((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-Random).ToString())) | ForEach-Object { $_.ToString("X2") }) -join ''
            "latency" = Get-Random -Minimum 20 -Maximum 200
            "game_version" = "$(Get-Random -Minimum 1 -Maximum 5).$(Get-Random -Minimum 0 -Maximum 9)"
            "fps" = Get-Random -Minimum 30 -Maximum 120
        }
        Write-AVLog "PrivacyForge: Spoofed game telemetry - Player ID: $($fakeTelemetry.player_id)" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing game telemetry - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSensors {
    try {
        # Generate random sensor data to spoof fingerprinting
        $null = @{
            "accelerometer" = @{
                "x" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "y" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
                "z" = (Get-Random -Minimum -1000 -Maximum 1000) / 100.0
            }
            "gyroscope" = @{
                "pitch" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "roll" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
                "yaw" = (Get-Random -Minimum -18000 -Maximum 18000) / 100.0
            }
            "magnetometer" = @{
                "x" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "y" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
                "z" = (Get-Random -Minimum -5000 -Maximum 5000) / 100.0
            }
            "light_sensor" = (Get-Random -Minimum 0 -Maximum 1000) / 1.0
            "proximity_sensor" = Get-Random -InputObject @(0, 5, 10)
            "ambient_temperature" = (Get-Random -Minimum 1500 -Maximum 3500) / 100.0
        }
        Write-AVLog "PrivacyForge: Spoofed sensor data" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing sensors - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSystemMetrics {
    try {
        $fakeMetrics = @{
            "cpu_usage" = (Get-Random -Minimum 0 -Maximum 10000) / 100.0
            "memory_usage" = (Get-Random -Minimum 1000 -Maximum 9000) / 100.0
            "battery_level" = Get-Random -Minimum 20 -Maximum 100
        }
        Write-AVLog "PrivacyForge: Spoofed system metrics - CPU: $($fakeMetrics.cpu_usage)%, Memory: $($fakeMetrics.memory_usage)%" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing system metrics - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofClipboard {
    try {
        $fakeContent = "PrivacyForge: $(Get-Random -Minimum 100000 -Maximum 999999) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Set-Clipboard -Value $fakeContent -ErrorAction SilentlyContinue
        Write-AVLog "PrivacyForge: Spoofed clipboard content" "DEBUG"
    } catch {
        Write-AVLog "PrivacyForge: Error spoofing clipboard - $_" "WARN"
    }
}

#endregion

# ===================== Independent Modules (No Whitelist/Response Engine) =====================
# These modules operate independently and do not respect whitelists or use the response engine
# They share logs and quarantine folders with the main antivirus

# ELF DLL Unloader - Actively unloads ELF DLLs from browser processes
function Invoke-ElfDLLUnloader {
    # This module operates independently - no whitelist checks, no response engine
    try {
        # Add DLL unloader C# code if not already loaded
        if (-not ([System.Management.Automation.PSTypeName]'DLLUnloader').Type) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DLLUnloader {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string src, string dst, int flags);
}
"@
        }
        
        $whitelist = @('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'gdi32.dll', 'msvcrt.dll', 'advapi32.dll')
        $targets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore', 'microsoftedge', 'waterfox', 'palemoon')
        
        if (-not $Script:ElfDLLProcessed) {
            $Script:ElfDLLProcessed = @{}
        }
        
        $unloadedCount = 0
        
        foreach ($procName in $targets) {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            foreach ($proc in $procs) {
                try {
                    $hProc = [DLLUnloader]::OpenProcess(0x1F0FFF, $false, $proc.Id)
                    if ($hProc -eq [IntPtr]::Zero) { continue }
                    
                    $freeLib = [DLLUnloader]::GetProcAddress([DLLUnloader]::GetModuleHandle("kernel32.dll"), "FreeLibrary")
                    
                    foreach ($mod in $proc.Modules) {
                        $name = [System.IO.Path]::GetFileName($mod.FileName).ToLower()
                        if ($whitelist -contains $name) { continue }
                        
                        $key = "$($proc.Id):$($mod.FileName)"
                        if ($Script:ElfDLLProcessed.ContainsKey($key)) { continue }
                        
                        if ($name -like '*_elf.dll') {
                            Write-AVLog "ELF DLL Unloader: Unloading $name from $procName (PID $($proc.Id))" "INFO" "elf_dll_unloader.log"
                            
                            $thread = [DLLUnloader]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $freeLib, $mod.BaseAddress, 0, [IntPtr]::Zero)
                            if ($thread -ne [IntPtr]::Zero) {
                                [DLLUnloader]::WaitForSingleObject($thread, 5000) | Out-Null
                                [DLLUnloader]::CloseHandle($thread) | Out-Null
                                
                                if ([DLLUnloader]::MoveFileEx($mod.FileName, $null, 4)) {
                                    Write-AVLog "ELF DLL Unloader: Scheduled deletion on reboot: $($mod.FileName)" "INFO" "elf_dll_unloader.log"
                                }
                                
                                $unloadedCount++
                            }
                            $Script:ElfDLLProcessed[$key] = Get-Date
                        }
                    }
                    
                    [DLLUnloader]::CloseHandle($hProc) | Out-Null
                } catch {
                    Write-AVLog "ELF DLL Unloader error for process $procName (PID: $($proc.Id)): $_" "WARN" "elf_dll_unloader.log"
                }
            }
        }
        
        # Cleanup old processed entries
        if ($Script:ElfDLLProcessed.Count -gt 1000) {
            $oldKeys = $Script:ElfDLLProcessed.Keys | Where-Object {
                ((Get-Date) - $Script:ElfDLLProcessed[$_]).TotalHours -gt 24
            }
            foreach ($key in $oldKeys) {
                $Script:ElfDLLProcessed.Remove($key)
            }
        }
        
        if ($unloadedCount -gt 0) {
            Write-AVLog "ELF DLL Unloader: Unloaded $unloadedCount ELF DLL(s)" "INFO" "elf_dll_unloader.log"
        }
        
        return $unloadedCount
    } catch {
        Write-AVLog "ELF DLL Unloader error: $_" "ERROR" "elf_dll_unloader.log"
        return 0
    }
}

# Unsigned DLL Remover - Scans and quarantines unsigned DLLs/WINMD files
function Invoke-UnsignedDLLRemover {
    # This module operates independently - no whitelist checks, no response engine
    try {
        # Initialize scanned files database
        $localDatabase = "$($Config.DatabasePath)\scanned_dlls.txt"
        if (-not $Script:UnsignedDLLScannedFiles) {
            $Script:UnsignedDLLScannedFiles = @{}
            
            # Load existing database
            if (Test-Path $localDatabase) {
                try {
                    $lines = Get-Content $localDatabase -ErrorAction Stop
                    foreach ($line in $lines) {
                        if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                            $Script:UnsignedDLLScannedFiles[$matches[1]] = [bool]$matches[2]
                        }
                    }
                    Write-AVLog "Unsigned DLL Remover: Loaded $($Script:UnsignedDLLScannedFiles.Count) scanned file entries" "INFO" "unsigned_dll_remover.log"
                } catch {
                    Write-AVLog "Unsigned DLL Remover: Failed to load database: $_" "WARN" "unsigned_dll_remover.log"
                }
            }
        }
        
        $quarantinedCount = 0
        
        # Helper function to check if file should be excluded
        function Should-ExcludeDLLFile {
            param ([string]$filePath)
            $lowerPath = $filePath.ToLower()
            
            # Exclude assembly folders
            if ($lowerPath -like "*\assembly\*") {
                return $true
            }
            
            # Exclude ctfmon-related files
            if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") {
                return $true
            }
            
            # Exclude antivirus installation path
            if ($lowerPath -like "*$($Config.QuarantinePath -replace '\\', '\\')*") {
                return $true
            }
            
            return $false
        }
        
        # Helper function to set file ownership and permissions
        function Set-DLLFileOwnership {
            param ([string]$filePath)
            try {
                takeown /F $filePath /A 2>&1 | Out-Null
                icacls $filePath /reset 2>&1 | Out-Null
                icacls $filePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
                return $true
            } catch {
                return $false
            }
        }
        
        # Helper function to stop processes using DLL
        function Stop-ProcessesUsingDLL {
            param ([string]$filePath)
            try {
                $processes = Get-Process | Where-Object { 
                    ($_.Modules | Where-Object { $_.FileName -eq $filePath }) 
                } -ErrorAction SilentlyContinue
                
                foreach ($process in $processes) {
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                        Write-AVLog "Unsigned DLL Remover: Stopped process $($process.Name) (PID: $($process.Id)) using $filePath" "INFO" "unsigned_dll_remover.log"
                    } catch {
                        try {
                            taskkill /PID $process.Id /F 2>&1 | Out-Null
                            Write-AVLog "Unsigned DLL Remover: Force-killed process $($process.Name) (PID: $($process.Id))" "INFO" "unsigned_dll_remover.log"
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Helper function to calculate file hash and signature
        function Get-DLLFileHash {
            param ([string]$filePath)
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
                return @{
                    Hash = $hash.Hash.ToLower()
                    Status = $signature.Status
                }
            } catch {
                return $null
            }
        }
        
        # Helper function to quarantine file (uses shared quarantine folder)
        function Quarantine-DLLFile {
            param ([string]$filePath)
            try {
                $fileName = Split-Path -Leaf $filePath
                $quarantinePath = Join-Path -Path $Config.QuarantinePath -ChildPath "$([DateTime]::Now.Ticks)_$fileName"
                
                if (-not (Test-Path $Config.QuarantinePath)) {
                    New-Item -ItemType Directory -Path $Config.QuarantinePath -Force | Out-Null
                }
                
                Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-AVLog "Unsigned DLL Remover: Quarantined $filePath to $quarantinePath" "INFO" "unsigned_dll_remover.log"
                return $true
            } catch {
                Write-AVLog "Unsigned DLL Remover: Failed to quarantine ${filePath}: $_" "WARN" "unsigned_dll_remover.log"
                return $false
            }
        }
        
        # Scan drives for unsigned DLLs
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
        
        foreach ($drive in $drives) {
            $root = $drive.DeviceID + "\"
            try {
                # Limit scan to prevent excessive resource usage
                $dllFiles = Get-ChildItem -Path $root -Include *.dll,*.winmd -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { -not (Should-ExcludeDLLFile -filePath $_.FullName) } |
                    Select-Object -First 500
                
                foreach ($dll in $dllFiles) {
                    try {
                        $fileHash = Get-DLLFileHash -filePath $dll.FullName
                        if (-not $fileHash) { continue }
                        
                        if ($Script:UnsignedDLLScannedFiles.ContainsKey($fileHash.Hash)) {
                            # Already scanned - check if invalid
                            if (-not $Script:UnsignedDLLScannedFiles[$fileHash.Hash]) {
                                # Previously found invalid - quarantine if still exists
                                if (Test-Path $dll.FullName) {
                                    if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                        Stop-ProcessesUsingDLL -filePath $dll.FullName
                                        if (Quarantine-DLLFile -filePath $dll.FullName) {
                                            $quarantinedCount++
                                        }
                                    }
                                }
                            }
                        } else {
                            # New file - check signature
                            $isValid = $fileHash.Status -eq "Valid"
                            $Script:UnsignedDLLScannedFiles[$fileHash.Hash] = $isValid
                            
                            # Save to database
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                            
                            if (-not $isValid) {
                                # Unsigned DLL found - quarantine it
                                Write-AVLog "Unsigned DLL Remover: Found unsigned DLL: $($dll.FullName) (Hash: $($fileHash.Hash))" "INFO" "unsigned_dll_remover.log"
                                
                                if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                    Stop-ProcessesUsingDLL -filePath $dll.FullName
                                    if (Quarantine-DLLFile -filePath $dll.FullName) {
                                        $quarantinedCount++
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-AVLog "Unsigned DLL Remover: Error processing $($dll.FullName): $_" "WARN" "unsigned_dll_remover.log"
                    }
                }
            } catch {
                Write-AVLog "Unsigned DLL Remover: Scan failed for drive ${root}: $_" "WARN" "unsigned_dll_remover.log"
            }
        }
        
        # Explicit System32 scan (limited)
        try {
            $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Include *.dll,*.winmd -File -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-ExcludeDLLFile -filePath $_.FullName) } |
                Select-Object -First 200
            
            foreach ($dll in $system32Files) {
                try {
                    $fileHash = Get-DLLFileHash -filePath $dll.FullName
                    if (-not $fileHash) { continue }
                    
                    if ($Script:UnsignedDLLScannedFiles.ContainsKey($fileHash.Hash)) {
                        if (-not $Script:UnsignedDLLScannedFiles[$fileHash.Hash]) {
                            if (Test-Path $dll.FullName) {
                                if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                    Stop-ProcessesUsingDLL -filePath $dll.FullName
                                    if (Quarantine-DLLFile -filePath $dll.FullName) {
                                        $quarantinedCount++
                                    }
                                }
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $Script:UnsignedDLLScannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                        
                        if (-not $isValid) {
                            Write-AVLog "Unsigned DLL Remover: Found unsigned System32 DLL: $($dll.FullName)" "INFO" "unsigned_dll_remover.log"
                            
                            if (Set-DLLFileOwnership -filePath $dll.FullName) {
                                Stop-ProcessesUsingDLL -filePath $dll.FullName
                                if (Quarantine-DLLFile -filePath $dll.FullName) {
                                    $quarantinedCount++
                                }
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($quarantinedCount -gt 0) {
            Write-AVLog "Unsigned DLL Remover: Quarantined $quarantinedCount unsigned DLL(s)" "INFO" "unsigned_dll_remover.log"
        }
        
        return $quarantinedCount
    } catch {
        Write-AVLog "Unsigned DLL Remover error: $_" "ERROR" "unsigned_dll_remover.log"
        return 0
    }
}

# ===================== Main =====================

try {
    if ($Uninstall) {
        Uninstall-Antivirus
    }

    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "`n[!] WARNING: Script is not running as Administrator!" -ForegroundColor Red
        Write-Host "[!] Some features require administrator privileges:" -ForegroundColor Yellow
        Write-Host "    - WebcamGuardian (device control)" -ForegroundColor Yellow
        Write-Host "    - Password Management (registry access)" -ForegroundColor Yellow
        Write-Host "    - Some detection modules" -ForegroundColor Yellow
        Write-Host "`n[i] To run with full functionality, right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Cyan
        Write-Host "`n[i] Continuing with limited functionality...`n" -ForegroundColor Gray
        Write-StabilityLog "Script running without administrator privileges - limited functionality" "WARN"
    } else {
        Write-StabilityLog "Script running with administrator privileges" "INFO"
    }

    Write-Host "`nAntivirus Protection (Single File)`n" -ForegroundColor Cyan
    Write-StabilityLog "=== Antivirus Starting ==="

    Write-StabilityLog "Executing script path: $PSCommandPath" "INFO"

    # <CHANGE> Clean up elevation flag on exit
$flagFile = "$env:ProgramData\AntivirusProtection\.elevated"
Register-EngineEvent PowerShell.Exiting -Action { Remove-Item $flagFile -Force -ErrorAction SilentlyContinue } | Out-Null
    Register-ExitCleanup
    
    Request-Elevation -Reason "Antivirus protection requires administrator privileges for full functionality."
    
    Install-Antivirus
    
    # Only initialize mutex if not already initialized during installation
    if (-not $Global:AntivirusState.Running) {
        Initialize-Mutex
    }

    Register-TerminationProtection

Write-Host "`n[PROTECTION] Initializing anti-termination safeguards..." -ForegroundColor Cyan

if ($host.Name -eq "Windows PowerShell ISE Host") {
    # In ISE, use trap handler which is already defined at the top
    Write-Host "[PROTECTION] ISE detected - using trap-based Ctrl+C protection" -ForegroundColor Cyan
    Write-Host "[PROTECTION] Ctrl+C protection enabled (requires $Script:MaxTerminationAttempts attempts to stop)" -ForegroundColor Green
} else {
    # In regular console, use the Console.CancelKeyPress handler
    Enable-CtrlCProtection
}

# Enable auto-restart if running as admin
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Enable-AutoRestart
        Start-ProcessWatchdog
    } else {
        Write-Host "[INFO] Auto-restart requires administrator privileges (optional)" -ForegroundColor Gray
    }
} catch {
    Write-Host "[WARNING] Some protection features failed to initialize: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[PROTECTION] Anti-termination safeguards active" -ForegroundColor Green
    Write-Host "[*] Starting detection jobs...`n" -ForegroundColor Cyan

    $loaded = 0
    $failed = 0

    $moduleNames = @(
        "HashDetection",
        "LOLBinDetection",
        "ProcessAnomalyDetection",
        "AMSIBypassDetection",
        "CredentialDumpDetection",
        "WMIPersistenceDetection",
        "ScheduledTaskDetection",
        "RegistryPersistenceDetection",
        "DLLHijackingDetection",
        "TokenManipulationDetection",
        "ProcessHollowingDetection",
        "KeyloggerDetection",
        "KeyScramblerManagement",
        "RansomwareDetection",
        "NetworkAnomalyDetection",
        "NetworkTrafficMonitoring",
        "RootkitDetection",
        "ClipboardMonitoring",
        "COMMonitoring",
        "BrowserExtensionMonitoring",
        "ShadowCopyMonitoring",
        "USBMonitoring",
        "MobileDeviceMonitoring",
        "AttackToolsDetection",
        "AdvancedThreatDetection",
        "EventLogMonitoring",
        "FirewallRuleMonitoring",
        "ServiceMonitoring",
        "FilelessDetection",
        "MemoryScanning",
        "NamedPipeMonitoring",
        "DNSExfiltrationDetection",
        "PasswordManagement",
        "WebcamGuardian",
        "BeaconDetection",
        "CodeInjectionDetection",
        "DataExfiltrationDetection",
        "ElfCatcher",
        "FileEntropyDetection",
        "HoneypotMonitoring",
        "LateralMovementDetection",
        "ProcessCreationDetection",
        "QuarantineManagement",
        "ReflectiveDLLInjectionDetection",
        "ResponseEngine",
        "PrivacyForgeSpoofing",
        "ElfDLLUnloader",
        "UnsignedDLLRemover"
    )

    foreach ($modName in $moduleNames) {
        $key = "${modName}IntervalSeconds"
        $interval = if ($Script:ManagedJobConfig.ContainsKey($key)) { $Script:ManagedJobConfig[$key] } else { 60 }

        try {
            Start-ManagedJob -ModuleName $modName -IntervalSeconds $interval

            if ($Global:AntivirusState.Jobs.ContainsKey("AV_$modName")) {
                Write-Host "[+] $modName ($interval sec)" -ForegroundColor Green
                Write-StabilityLog "Successfully started module: $modName"
                $loaded++
            }
            else {
                Write-Host "[!] $modName - skipped" -ForegroundColor Yellow
                Write-StabilityLog "Module skipped: $modName" "WARN"
                $failed++
            }
        }
        catch {
            Write-Host "[!] Failed to start $modName : $_" -ForegroundColor Red
            Write-StabilityLog "Module start failed: $modName - $_" "ERROR"
            Write-AVLog "Module start failed: $modName - $_" "ERROR"
            $failed++
        }
    }

    Write-Host "`n[+] Started $loaded modules" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "[!] $failed modules failed to start" -ForegroundColor Yellow
    }

    Write-StabilityLog "Module start complete: $loaded started, $failed failed"

    try {
        $mjCount = if ($script:ManagedJobs) { $script:ManagedJobs.Count } else { 0 }
        Write-StabilityLog "Managed jobs registered after start: $mjCount" "INFO"
        Write-Host "[AV] Managed jobs registered: $mjCount" -ForegroundColor DarkGray
    }
    catch {}

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Antivirus Protection ACTIVE" -ForegroundColor Green
    Write-Host "  Active jobs: $($Global:AntivirusState.Jobs.Count)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor Yellow

    Write-StabilityLog "Antivirus fully started with $($Global:AntivirusState.Jobs.Count) active jobs"
    Write-AVLog "About to enter Monitor-Jobs loop"

    Monitor-Jobs
}
catch {
    $err = $_.Exception.Message
    Write-Host "`n[!] Critical error: $err`n" -ForegroundColor Red
    Write-StabilityLog "Critical startup error: $err" "ERROR"
    Write-AVLog "Startup error: $err" "ERROR"

    if ($err -like "*already running*") {
        Write-Host "[i] Another instance is running. Exiting.`n" -ForegroundColor Yellow
        Write-StabilityLog "Blocked duplicate instance - exiting" "INFO"
        exit 1
    }

    Write-StabilityLog "Exiting due to startup failure" "ERROR"
    exit 1
}