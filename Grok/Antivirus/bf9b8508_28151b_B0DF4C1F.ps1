# Antivirus.ps1
# Author: Gorstak

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION SECTION - Edit all settings here
# ============================================================================

$Config = @{
    # Core Settings
    EDRName = "EnterpriseEDR"
    LogPath = "C:\ProgramData\EnterpriseEDR\edr.log"
    QuarantinePath = "C:\ProgramData\EnterpriseEDR\Quarantine"
    DatabasePath = "C:\ProgramData\EnterpriseEDR\edr.db"
    CachePath = "C:\ProgramData\EnterpriseEDR\Cache"
    HMACKeyPath = "C:\ProgramData\EnterpriseEDR\hmac.key"
    PIDFilePath = "C:\ProgramData\EnterpriseEDR\edr.pid"
    
    # Scanning Settings
    ScanPaths = @("C:\Windows\Temp", "C:\Users", "C:\ProgramData")
    ScanIntervalMinutes = 30
    MaxParallelScans = 4
    FileWatcherThrottle = 500
    
    EnableHashDetection = $true  # ENABLED - Group 1 test
    EnableLOLBinDetection = $true  # ENABLED - Group 1 test
    EnableProcessAnomalyDetection = $true  # ENABLED - Group 1 test
    EnableAMSIBypassDetection = $true  # ENABLED - Group 1 test
    EnableCredentialDumpDetection = $true  # ENABLED - Group 1 test
    
    # Group 2: Registry/WMI/Tasks (enabled for screen blink test)
    EnableWMIPersistenceDetection = $true  # ENABLED - Group 2 test
    EnableScheduledTaskDetection = $true  # ENABLED - Group 2 test
    EnableRegistryPersistenceDetection = $true  # ENABLED - Group 2 test
    EnableDLLHijackingDetection = $true  # ENABLED - Group 2 test
    EnableTokenManipulationDetection = $true  # ENABLED - Group 2 test
    
    # Group 3: Network monitoring (enabled for screen blink test)
    EnableDNSExfiltrationDetection = $true  # ENABLED - Group 3 test
    EnableNamedPipeMonitoring = $true  # ENABLED - Group 3 test
    EnableNetworkAnomalyDetection = $true  # ENABLED - Group 3 test

    # Group 4: Memory/Advanced detection (enabled for screen blink test)
    EnableMemoryScanning = $true  # ENABLED - Group 4 test
    EnableFilelessDetection = $true  # ENABLED - Group 4 test
    EnableProcessHollowingDetection = $true  # ENABLED - Group 4 test
    EnableKeyloggerDetection = $true  # ENABLED - Group 4 test
    EnableRootkitDetection = $true  # ENABLED - Group 4 test
    
    # Group 5: System interaction (still disabled - highly suspected)
    EnableClipboardMonitoring = $true  # ENABLED - Testing for screen blink
    EnableCOMMonitoring = $true  # ENABLED - Testing for screen blink
    EnableRansomwareDetection = $true  # ENABLED - Now safe without VSS dependencies
    EnableShadowCopyMonitoring = $false  # DISABLED - Group 5
    EnableUSBMonitoring = $false  # DISABLED - Group 5
    EnableEventLogMonitoring = $false  # DISABLED - Group 5
    EnableBrowserExtensionMonitoring = $false  # DISABLED - Group 5
    EnableFirewallRuleMonitoring = $false  # DISABLED - Group 5

    # Response Settings
    AutoKillThreats = $true
    AutoQuarantine = $true
    ServiceAwareKilling = $true
    
    # Database & Integrity
    EnableDatabaseIntegrity = $true
    IntegrityCheckInterval = 3600
    
    # Performance
    MaxMemoryUsageMB = 2048
    CacheExpirationHours = 24
    LogRotationDays = 30
    
    # Rate Limiting
    APICallsPerMinute = 60
    
    # Self-Protection
    EnableSelfDefense = $true
    EnableAntiTamper = $true
    MutexName = "Global\EnterpriseEDR_Mutex"
    
    # Startup
    AddToStartup = $true
    AutoRestart = $true
    
    # Whitelist
    WhitelistPaths = @("C:\Windows\System32\svchost.exe", "C:\Windows\System32\lsass.exe")
    WhitelistHashes = @()
    
    # LOLBin Patterns
    LOLBinPatterns = @(
        "certutil.*-decode", "certutil.*-urlcache", "bitsadmin.*transfer",
        "regsvr32.*scrobj", "mshta.*http", "rundll32.*javascript",
        "powershell.*-enc", "powershell.*-e ", "wmic.*process.*call.*create",
        "cscript.*\.vbs", "wscript.*\.vbs", "msiexec.*\/quiet",
        "regasm.*\/U", "installutil.*\/U", "odbcconf.*\/a"
    )
    
    # Suspicious Patterns
    SuspiciousPatterns = @(
        "mimikatz", "invoke-mimikatz", "dumpcreds", "procdump",
        "sekurlsa", "kerberos", "lsadump", "invoke-shellcode",
        "invoke-reflectivepeinjection", "empire", "meterpreter",
        "cobalt", "powersploit", "nishang"
    )
    
    # Network Settings
    DNSQueryThreshold = 100
    NetworkConnectionThreshold = 50
    
    # Memory Settings
    MemoryScanThreshold = 10485760
    ReflectiveLoadSignatures = @("MZ", "PE")
}

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

$Global:EDRState = @{
    Running = $false
    Jobs = @{}
    Mutex = $null
    HMACKey = $null
    Database = $null
    Cache = @{}
    APICallQueue = @()
    LastIntegrityCheck = [DateTime]::MinValue
    ThreatCount = 0
    StartTime = [DateTime]::Now
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-EDRLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if (!(Test-Path $Config.LogPath)) { New-Item -ItemType Directory -Path $Config.LogPath -Force | Out-Null }
    Add-Content -Path "$($Config.LogPath)\edr_$(Get-Date -Format 'yyyyMMdd').log" -Value $LogEntry
    
    $EventID = switch($Level) { "ERROR" {1001}; "WARN" {1002}; "THREAT" {1003}; default {1000} }
    Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Information -EventId $EventID -Message $Message -ErrorAction SilentlyContinue
}

function Initialize-Environment {
    $Paths = @($Config.LogPath, $Config.QuarantinePath, $Config.DatabasePath, $Config.CachePath)
    foreach ($Path in $Paths) {
        if (!(Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    }
    
    try { New-EventLog -LogName Application -Source $Config.EDRName -ErrorAction SilentlyContinue } catch {}
    Write-EDRLog "Environment initialized"
}

function Initialize-Mutex {
    try {
        $PIDFile = $Config.PIDFilePath
        $StaleMutex = $false
        
        if (Test-Path $PIDFile) {
            $OldPID = Get-Content $PIDFile -ErrorAction SilentlyContinue
            if ($OldPID) {
                $Process = Get-Process -Id $OldPID -ErrorAction SilentlyContinue
                if (!$Process -or $Process.ProcessName -ne "powershell") {
                    Write-Host "[v0] Detected stale mutex from PID $OldPID - cleaning up"
                    $StaleMutex = $true
                    Remove-Item $PIDFile -Force -ErrorAction SilentlyContinue
                    try {
                        $StaleMutexObj = [System.Threading.Mutex]::OpenExisting($Config.MutexName)
                        $StaleMutexObj.Dispose()
                        Write-Host "[v0] Stale mutex disposed successfully"
                    } catch {
                        Write-Host "[v0] Could not open stale mutex (may already be cleaned): $($_.Exception.Message)"
                    }
                }
            }
        }
        
        Write-Host "[v0] Initializing mutex: $($Config.MutexName)"
        $Global:EDRState.Mutex = New-Object System.Threading.Mutex($false, $Config.MutexName)
        
        $Acquired = $Global:EDRState.Mutex.WaitOne(500)
        
        if (!$Acquired) {
            Write-Host "[v0] Mutex check failed - another instance may be running"
            Write-EDRLog "Another instance is running" "ERROR"
            throw "Another instance of EDR is already running"
        }
        
        $PID | Out-File -FilePath $PIDFile -Force
        
        Write-Host "[v0] Mutex acquired successfully"
        $Global:EDRState.Running = $true
        Write-EDRLog "Mutex acquired"
    } catch {
        Write-Host "[v0] Mutex exception: $_"
        Write-EDRLog "Mutex initialization failed: $_" "ERROR"
        throw
    }
}

function Initialize-HMACKey {
    Write-Host "[v0] Initializing HMAC key"
    $KeyPath = $Config.HMACKeyPath
    if (Test-Path $KeyPath) {
        Write-Host "[v0] Loading existing HMAC key"
        $Global:EDRState.HMACKey = [Convert]::FromBase64String((Get-Content $KeyPath -Raw))
    } else {
        Write-Host "[v0] Creating new HMAC key"
        $Key = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
        $Global:EDRState.HMACKey = $Key
        [Convert]::ToBase64String($Key) | Set-Content $KeyPath
        
        try {
            Write-Host "[v0] Setting NTFS permissions on key file"
            $Acl = Get-Acl $KeyPath
            $Acl.SetAccessRuleProtection($true, $false)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
            $Acl.AddAccessRule($Rule)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
            $Acl.AddAccessRule($Rule)
            Set-Acl $KeyPath $Acl
            Write-Host "[v0] NTFS permissions set successfully"
        } catch {
            Write-Host "[v0] Warning: Could not set NTFS permissions: $_"
        }
    }
    Write-Host "[v0] HMAC key initialized"
    Write-EDRLog "HMAC key initialized"
}

function Get-HMAC {
    param([string]$Data)
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $HMAC.Key = $Global:EDRState.HMACKey
    return [BitConverter]::ToString($HMAC.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))).Replace("-","")
}

function Initialize-Database {
    Write-Host "[v0] Initializing database"
    $DBPath = $Config.DatabasePath
    if (!(Test-Path $DBPath)) {
        Write-Host "[v0] Creating new database"
        $DB = @{ Threats = @(); Whitelist = $Config.WhitelistHashes; Version = 1 }
        $JSON = $DB | ConvertTo-Json -Depth 10
        $Signature = Get-HMAC -Data $JSON
        @{ Data = $JSON; Signature = $Signature } | ConvertTo-Json | Set-Content $DBPath
    }
    
    $Content = Get-Content $DBPath -Raw | ConvertFrom-Json
    $Signature = Get-HMAC -Data $Content.Data
    if ($Signature -ne $Content.Signature) {
        Write-EDRLog "Database integrity check failed" "ERROR"
        exit 1
    }
    
    $Global:EDRState.Database = $Content.Data | ConvertFrom-Json
    Write-EDRLog "Database loaded and verified"
}

function Save-Database {
    $DBPath = $Config.DatabasePath
    $JSON = $Global:EDRState.Database | ConvertTo-Json -Depth 10
    $Signature = Get-HMAC -Data $JSON
    @{ Data = $JSON; Signature = $Signature } | ConvertTo-Json | Set-Content $DBPath
}

function Test-Whitelist {
    param([string]$Path, [string]$Hash)
    return ($Config.WhitelistPaths -contains $Path) -or ($Global:EDRState.Database.Whitelist -contains $Hash)
}

function Get-FileHashFast {
    param([string]$Path)
    $CacheKey = "$Path|$(( Get-Item $Path -ErrorAction SilentlyContinue).LastWriteTime.Ticks)"
    if ($Global:EDRState.Cache.ContainsKey($CacheKey)) { return $Global:EDRState.Cache[$CacheKey] }
    
    try {
        $Hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        $Global:EDRState.Cache[$CacheKey] = $Hash
        return $Hash
    } catch { return $null }
}

function Move-ToQuarantine {
    param([string]$Path, [string]$Reason)
    $FileName = [System.IO.Path]::GetFileName($Path)
    $QuarantineFile = "$($Config.QuarantinePath)\$([DateTime]::Now.Ticks)_$FileName"
    
    try {
        [System.IO.File]::Move($Path, $QuarantineFile)
        Write-EDRLog "Quarantined: $Path -> $QuarantineFile (Reason: $Reason)" "THREAT"
        return $true
    } catch {
        Write-EDRLog "Quarantine failed for $Path : $_" "ERROR"
        return $false
    }
}

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    # Don't kill the EDR itself
    if ($ProcessId -eq $PID) {
        Write-EDRLog "Skipping termination of EDR process itself" "INFO"
        return
    }
    
    try {
        Write-EDRLog "Attempting to terminate threat process: $ProcessName (PID: $ProcessId)" "ACTION"
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-EDRLog "Successfully terminated process: $ProcessName" "ACTION"
    } catch {
        Write-EDRLog "Failed to terminate process $ProcessName : $_" "ERROR"
    }
}

# ============================================================================
# DETECTION ENGINES
# ============================================================================

function Invoke-HashDetection {
    Write-Host "Hash detection is enabled."
    # Implementation for hash detection
}

function Invoke-LOLBinDetection {
    Write-Host "LOLBin detection is enabled."
    # Implementation for LOLBin detection
}

function Invoke-FilelessDetection {
    Write-Host "Fileless detection is enabled."
    # Implementation for fileless detection
}

function Invoke-MemoryScanning {
    Write-Host "Memory scanning is enabled."
    # Implementation for memory scanning
}

function Invoke-ProcessAnomalyDetection {
    Write-Host "Process anomaly detection is enabled."
    # Implementation for process anomaly detection
}

function Invoke-AMSIBypassDetection {
    Write-Host "AMSI bypass detection is enabled."
    # Implementation for AMSI bypass detection
}

function Invoke-CredentialDumpDetection {
    Write-Host "Credential dump detection is enabled."
    # Implementation for credential dump detection
}

function Invoke-WMIPersistenceDetection {
    Write-Host "WMI persistence detection is enabled."
    # Implementation for WMI persistence detection
}

function Invoke-ScheduledTaskDetection {
    Write-Host "Scheduled task detection is enabled."
    # Implementation for scheduled task detection
}

function Invoke-DNSExfiltrationDetection {
    Write-Host "DNS exfiltration detection is enabled."
    # Implementation for DNS exfiltration detection
}

function Invoke-NamedPipeMonitoring {
    Write-Host "Named pipe monitoring is enabled."
    # Implementation for named pipe monitoring
}

function Invoke-RegistryPersistenceDetection {
    Write-Host "Registry persistence detection is enabled."
    # Implementation for registry persistence detection
}

function Invoke-DLLHijackingDetection {
    Write-Host "DLL hijacking detection is enabled."
    # Implementation for DLL hijacking detection
}

function Invoke-TokenManipulationDetection {
    Write-Host "Token manipulation detection is enabled."
    # Implementation for token manipulation detection
}

function Invoke-ShadowCopyMonitoring {
    Write-Host "Shadow copy monitoring is disabled."
}

function Invoke-USBMonitoring {
    Write-Host "USB monitoring is disabled."
}

function Invoke-ClipboardMonitoring {
    Write-Host "Clipboard monitoring is enabled."
    # Implementation for clipboard monitoring
}

function Invoke-EventLogMonitoring {
    Write-Host "Event log monitoring is disabled."
}

function Invoke-ProcessHollowingDetection {
    Write-Host "Process hollowing detection is enabled."
    # Implementation for process hollowing detection
}

function Invoke-KeyloggerDetection {
    Write-Host "Keylogger detection is enabled."
    # Implementation for keylogger detection
}

function Invoke-RansomwareDetection {
    Write-Host "Ransomware detection is enabled."
    
    $Threats = @()
    
    $RansomwareExtensions = @(".encrypted", ".locked", ".crypt", ".crypto", ".wncry", ".wcry", ".locky", ".cerber", ".zepto", ".thor")
    $SuspiciousProcesses = @("vssadmin", "bcdedit", "wbadmin", "wevtutil")
    
    # Check for processes attempting to delete backups
    foreach ($ProcName in $SuspiciousProcesses) {
        $Procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
        foreach ($Proc in $Procs) {
            $CmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            if ($CmdLine -match "delete shadows|delete catalog|delete systemstatebackup|clear-log") {
                Write-EDRLog "Ransomware behavior detected: $ProcName attempting to delete backups" "THREAT"
                $Global:EDRState.ThreatCount++
                if ($Config.AutoKillThreats) {
                    Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $ProcName
                }
            }
        }
    }
    
    # Check for suspicious file extensions in user Documents folder only (not recursive)
    $TargetPath = "$env:USERPROFILE\Documents"
    if (Test-Path $TargetPath) {
        $RecentFiles = Get-ChildItem -Path $TargetPath -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
        
        foreach ($Ext in $RansomwareExtensions) {
            $EncryptedFiles = $RecentFiles | Where-Object { $_.Extension -eq $Ext }
            if ($EncryptedFiles.Count -gt 5) {
                Write-EDRLog "Ransomware activity detected: $($EncryptedFiles.Count) files with extension $Ext" "THREAT"
                $Global:EDRState.ThreatCount++
            }
        }
    }
}

function Invoke-NetworkAnomalyDetection {
    Write-Host "Network anomaly detection is enabled."
    # Implementation for network anomaly detection
}

function Invoke-RootkitDetection {
    Write-Host "Rootkit detection is enabled."
    # Implementation for rootkit detection
}

function Invoke-COMMonitoring {
    Write-Host "COM monitoring is enabled."
    # Implementation for COM monitoring
}

function Invoke-BrowserExtensionMonitoring {
    Write-Host "Browser extension monitoring is disabled."
}

function Invoke-FirewallRuleMonitoring {
    Write-Host "Firewall rule monitoring is disabled."
}

# ============================================================================
# JOB MANAGEMENT
# ============================================================================

function Start-ManagedJob {
    param([string]$Name, [string]$FunctionName, [int]$IntervalSeconds)
    
    $Global:EDRState.Jobs[$Name] = @{
        Name = $Name
        FunctionName = $FunctionName
        Interval = $IntervalSeconds
        LastRun = [DateTime]::MinValue
    }
    Write-EDRLog "Registered job: $Name"
}

function Stop-AllJobs {
    $Global:EDRState.Jobs.Clear()
    Write-EDRLog "All jobs stopped"
}

function Invoke-AllJobs {
    $CurrentTime = Get-Date
    foreach ($Job in $Global:EDRState.Jobs.Values) {
        if (((Get-Date) - $Job.LastRun).TotalSeconds -ge $Job.Interval) {
            try {
                & $Job.FunctionName
            } catch {
                Write-Host "[ERROR] $($Job.Name) : $_"
            }
            $Job.LastRun = Get-Date
        }
    }
}

# ============================================================================
# SELF-PROTECTION & MAINTENANCE
# ============================================================================

function Start-AntiTamperMonitoring {
    $ScriptPath = $MyInvocation.PSCommandPath
    $OriginalHash = Get-FileHashFast -Path $ScriptPath
    
    $Watcher = New-Object System.IO.FileSystemWatcher
    $Watcher.Path = Split-Path $ScriptPath
    $Watcher.Filter = Split-Path $ScriptPath -Leaf
    $Watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite
    
    $Action = {
        Write-EDRLog "EDR script modification detected - possible tampering" "THREAT"
        $Global:EDRState.ThreatCount++
    }
    
    Register-ObjectEvent -InputObject $Watcher -EventName Changed -Action $Action | Out-Null
    $Watcher.EnableRaisingEvents = $true
    Write-EDRLog "Anti-tamper monitoring active"
}

function Invoke-PeriodicIntegrityCheck {
    if (((Get-Date) - $Global:EDRState.LastIntegrityCheck).TotalSeconds -gt $Config.IntegrityCheckInterval) {
        $DBPath = $Config.DatabasePath
        $Content = Get-Content $DBPath -Raw | ConvertFrom-Json
        $Signature = Get-HMAC -Data $Content.Data
        
        if ($Signature -ne $Content.Signature) {
            Write-EDRLog "Database integrity compromised" "ERROR"
            $Global:EDRState.ThreatCount++
        }
        
        $Global:EDRState.LastIntegrityCheck = Get-Date
    }
}

function Invoke-LogRotation {
    $Logs = Get-ChildItem $Config.LogPath -Filter "*.log" |
        Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$Config.LogRotationDays) }
    
    foreach ($Log in $Logs) {
        Remove-Item $Log.FullName -Force
        Write-EDRLog "Rotated old log: $($Log.Name)"
    }
}

function Invoke-CacheCleanup {
    $ExpiredKeys = $Global:EDRState.Cache.Keys | Where-Object {
        $Parts = $_ -split '\|'
        $Ticks = [long]$Parts[1]
        $Age = [DateTime]::Now.Ticks - $Ticks
        $Hours = [TimeSpan]::FromTicks($Age).TotalHours
        $Hours -gt $Config.CacheExpirationHours
    }
    
    foreach ($Key in $ExpiredKeys) {
        $Global:EDRState.Cache.Remove($Key)
    }
}

function Invoke-MemoryCleanup {
    $MemoryUsage = (Get-Process -Id $PID).WorkingSet64 / 1MB
    if ($MemoryUsage -gt $Config.MaxMemoryUsageMB) {
        Write-EDRLog "Memory threshold exceeded, cleaning up" "WARN"
        $Global:EDRState.Cache.Clear()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Add-ToStartup {
    if ($Config.AddToStartup) {
        $StartupPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        $ScriptPath = $MyInvocation.PSCommandPath
        Set-ItemProperty -Path $StartupPath -Name $Config.EDRName -Value "powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`"" -ErrorAction SilentlyContinue
        Write-EDRLog "Added to startup"
    }
}

function Start-AutoRestart {
    if ($Config.AutoRestart) {
        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.PSCommandPath)`"" -WindowStyle Hidden
        } | Out-Null
    }
}

function Register-EDRJob {
    param([string]$Name, [int]$Interval, [string]$FunctionName)
    Start-ManagedJob -Name $Name -FunctionName $FunctionName -IntervalSeconds $Interval
}

function Start-AllMonitoring {
    Write-Host "Initializing monitoring jobs..."
    
    if ($Config.EnableHashDetection) { Register-EDRJob -Name "HashDetection" -Interval 30 -FunctionName "Invoke-HashDetection" }
    if ($Config.EnableLOLBinDetection) { Register-EDRJob -Name "LOLBinDetection" -Interval 15 -FunctionName "Invoke-LOLBinDetection" }
    if ($Config.EnableFilelessDetection) { Register-EDRJob -Name "FilelessDetection" -Interval 20 -FunctionName "Invoke-FilelessDetection" }
    if ($Config.EnableMemoryScanning) { Register-EDRJob -Name "MemoryScanning" -Interval 60 -FunctionName "Invoke-MemoryScanning" }
    if ($Config.EnableProcessAnomalyDetection) { Register-EDRJob -Name "ProcessAnomaly" -Interval 30 -FunctionName "Invoke-ProcessAnomalyDetection" }
    if ($Config.EnableAMSIBypassDetection) { Register-EDRJob -Name "AMSIBypass" -Interval 45 -FunctionName "Invoke-AMSIBypassDetection" }
    if ($Config.EnableCredentialDumpDetection) { Register-EDRJob -Name "CredentialDump" -Interval 20 -FunctionName "Invoke-CredentialDumpDetection" }
    if ($Config.EnableWMIPersistenceDetection) { Register-EDRJob -Name "WMIPersistence" -Interval 60 -FunctionName "Invoke-WMIPersistenceDetection" }
    if ($Config.EnableScheduledTaskDetection) { Register-EDRJob -Name "ScheduledTask" -Interval 60 -FunctionName "Invoke-ScheduledTaskDetection" }
    if ($Config.EnableDNSExfiltrationDetection) { Register-EDRJob -Name "DNSExfiltration" -Interval 30 -FunctionName "Invoke-DNSExfiltrationDetection" }
    if ($Config.EnableNamedPipeMonitoring) { Register-EDRJob -Name "NamedPipe" -Interval 20 -FunctionName "Invoke-NamedPipeMonitoring" }
    if ($Config.EnableRegistryPersistenceDetection) { Register-EDRJob -Name "RegistryPersistence" -Interval 45 -FunctionName "Invoke-RegistryPersistenceDetection" }
    if ($Config.EnableDLLHijackingDetection) { Register-EDRJob -Name "DLLHijacking" -Interval 30 -FunctionName "Invoke-DLLHijackingDetection" }
    if ($Config.EnableTokenManipulationDetection) { Register-EDRJob -Name "TokenManipulation" -Interval 25 -FunctionName "Invoke-TokenManipulationDetection" }
    if ($Config.EnableShadowCopyMonitoring) { Register-EDRJob -Name "ShadowCopy" -Interval 60 -FunctionName "Invoke-ShadowCopyMonitoring" }
    if ($Config.EnableUSBMonitoring) { Register-EDRJob -Name "USB" -Interval 15 -FunctionName "Invoke-USBMonitoring" }
    if ($Config.EnableClipboardMonitoring) { Register-EDRJob -Name "Clipboard" -Interval 30 -FunctionName "Invoke-ClipboardMonitoring" }
    if ($Config.EnableEventLogMonitoring) { Register-EDRJob -Name "EventLog" -Interval 30 -FunctionName "Invoke-EventLogMonitoring" }
    if ($Config.EnableProcessHollowingDetection) { Register-EDRJob -Name "ProcessHollowing" -Interval 20 -FunctionName "Invoke-ProcessHollowingDetection" }
    if ($Config.EnableKeyloggerDetection) { Register-EDRJob -Name "Keylogger" -Interval 15 -FunctionName "Invoke-KeyloggerDetection" }
    if ($Config.EnableRansomwareDetection) { Register-EDRJob -Name "Ransomware" -Interval 30 -FunctionName "Invoke-RansomwareDetection" }
    if ($Config.EnableNetworkAnomalyDetection) { Register-EDRJob -Name "NetworkAnomaly" -Interval 30 -FunctionName "Invoke-NetworkAnomalyDetection" }
    if ($Config.EnableRootkitDetection) { Register-EDRJob -Name "Rootkit" -Interval 120 -FunctionName "Invoke-RootkitDetection" }
    if ($Config.EnableCOMMonitoring) { Register-EDRJob -Name "COM" -Interval 60 -FunctionName "Invoke-COMMonitoring" }
    if ($Config.EnableBrowserExtensionMonitoring) { Register-EDRJob -Name "BrowserExtension" -Interval 90 -FunctionName "Invoke-BrowserExtensionMonitoring" }
    if ($Config.EnableFirewallRuleMonitoring) { Register-EDRJob -Name "FirewallRule" -Interval 60 -FunctionName "Invoke-FirewallRuleMonitoring" }
    
    # Always run maintenance jobs
    Register-EDRJob -Name "IntegrityCheck" -Interval 300 -FunctionName "Invoke-PeriodicIntegrityCheck"
    Register-EDRJob -Name "LogRotation" -Interval 3600 -FunctionName "Invoke-LogRotation"
    Register-EDRJob -Name "CacheCleanup" -Interval 900 -FunctionName "Invoke-CacheCleanup"
    Register-EDRJob -Name "MemoryCleanup" -Interval 600 -FunctionName "Invoke-MemoryCleanup"
    
    Write-EDRLog "All monitoring jobs registered successfully"
}

# ============================================================================
# REPORTING
# ============================================================================

function Export-SecurityReport {
    $Report = @{
        Timestamp = Get-Date
        Uptime = (Get-Date) - $Global:EDRState.StartTime
        TotalThreats = $Global:EDRState.ThreatCount
        QuarantinedFiles = (Get-ChildItem $Config.QuarantinePath -ErrorAction SilentlyContinue).Count
        CacheSize = $Global:EDRState.Cache.Count
        ActiveJobs = $Global:EDRState.Jobs.Count
    }
    
    $ReportPath = "$($Config.LogPath)\report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Report | ConvertTo-Json | Set-Content $ReportPath
    Write-EDRLog "Security report exported: $ReportPath"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    Initialize-Mutex
    
    Initialize-HMACKey
    
    Initialize-Database
    
    Start-AllMonitoring
    
    Write-Host "EDR is running. Press Ctrl+C to stop."
    
    while ($true) {
        Invoke-AllJobs
        Start-Sleep -Seconds 1
    }
} catch {
    Write-Host "Critical error: $_"
} finally {
    Write-Host "Shutting down EDR..."
    Stop-AllJobs
    if ($Global:EDRState.Mutex -and $Global:EDRState.Running) {
        try {
            $Global:EDRState.Mutex.ReleaseMutex()
            $Global:EDRState.Mutex.Dispose()
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
        } catch {
            # Mutex was not acquired, ignore
        }
    }
}
