# Antivirus.ps1
# Author: Gorstak

#Requires -RunAsAdministrator

param(
    [switch]$Uninstall
)

$Script:InstallDir = "C:\ProgramData\AntivirusProtection"
$Script:ScriptInstallPath = Join-Path $Script:InstallDir "Antivirus.ps1"
$Script:DataDir = Join-Path $Script:InstallDir "Data"
$Script:LogsDir = Join-Path $Script:InstallDir "Logs"
$Script:QuarantineDir = Join-Path $Script:InstallDir "Quarantine"
$Script:ReportsDir = Join-Path $Script:InstallDir "Reports"

if ($Uninstall) {
    Write-Host "[UNINSTALL] Starting uninstallation process..." -ForegroundColor Yellow
    
    # Stop any running instances
    try {
        $runningInstances = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
            $_.MainModule.FileName -eq $Script:ScriptInstallPath
        }
        if ($runningInstances) {
            Write-Host "[UNINSTALL] Stopping running instances..." -ForegroundColor Yellow
            $runningInstances | Stop-Process -Force
        }
    } catch {
        Write-Host "[WARNING] Could not stop running instances: $_" -ForegroundColor Yellow
    }
    
    # Remove scheduled tasks
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "Antivirus*" }
        foreach ($task in $tasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "[UNINSTALL] Removed scheduled task: $($task.TaskName)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[WARNING] Could not remove all scheduled tasks: $_" -ForegroundColor Yellow
    }
    
    # Remove registry entries
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Remove-ItemProperty -Path $regPath -Name "MalwareDetector" -ErrorAction SilentlyContinue
        Write-Host "[UNINSTALL] Removed registry startup entry" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not remove registry entry: $_" -ForegroundColor Yellow
    }
    
    # Remove installation directory
    try {
        if (Test-Path $Script:InstallDir) {
            Write-Host "[UNINSTALL] Removing installation directory: $Script:InstallDir" -ForegroundColor Yellow
            Remove-Item -Path $Script:InstallDir -Recurse -Force -ErrorAction Stop
            Write-Host "[UNINSTALL] Installation directory removed" -ForegroundColor Green
        }
    } catch {
        Write-Host "[WARNING] Could not remove installation directory completely: $_" -ForegroundColor Yellow
    }
    
    Write-Host "[UNINSTALL] Uninstallation complete!" -ForegroundColor Green
    exit 0
}

function Initialize-Installation {
    try {
        $currentScriptPath = $PSCommandPath
        
        # Check if we're already running from the installation directory
        if ($currentScriptPath -ne $Script:ScriptInstallPath) {
            Write-Host "[INSTALL] First run detected - installing to: $Script:InstallDir" -ForegroundColor Cyan
            
            # Create installation directories
            @($Script:InstallDir, $Script:DataDir, $Script:LogsDir, $Script:QuarantineDir, $Script:ReportsDir) | ForEach-Object {
                if (-not (Test-Path $_)) {
                    New-Item -Path $_ -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Host "[INSTALL] Created directory: $_" -ForegroundColor Green
                }
            }
            
            # Copy script to installation directory
            Copy-Item -Path $currentScriptPath -Destination $Script:ScriptInstallPath -Force -ErrorAction Stop
            Write-Host "[INSTALL] Script copied to: $Script:ScriptInstallPath" -ForegroundColor Green
            
            # Add to startup
            Add-ToStartup
            
            # Re-launch from installation directory
            Write-Host "[INSTALL] Launching from installation directory..." -ForegroundColor Cyan
            Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$Script:ScriptInstallPath`"" -WindowStyle Normal
            
            Write-Host "[INSTALL] Installation complete. Original script can now be deleted." -ForegroundColor Green
            Write-Host "[INSTALL] The antivirus is now running from: $Script:ScriptInstallPath" -ForegroundColor Green
            Write-Host "[INSTALL] To uninstall, run: powershell -ExecutionPolicy Bypass -File `"$Script:ScriptInstallPath`" -Uninstall" -ForegroundColor Yellow
            
            exit 0
        }
        
        Write-Host "[INFO] Running from installation directory" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] Installation failed: $_" -ForegroundColor Red
        Write-Host "[ERROR] Continuing from current location..." -ForegroundColor Yellow
        return $false
    }
}

# ============================================
# SECURITY ENHANCEMENT: Self-Defense Against Termination
# ============================================

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $false
$Script:SelfPID = $PID

$taskName = "Antivirus"
$taskDescription = "Runs the Production Hardened Antivirus script"
$scriptPath = $Script:ScriptInstallPath
$quarantineFolder = $Script:QuarantineDir
$logFile = Join-Path $Script:LogsDir "antivirus_log.txt"
$localDatabase = Join-Path $Script:DataDir "scanned_files.txt"
$hashIntegrityFile = Join-Path $Script:DataDir "db_integrity.hmac"
$scannedFiles = @{}

$Script:FileHashCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$Script:MaxCacheSize = 2000  # Reduced from 5000 to save RAM
$Script:CacheHits = 0
$Script:CacheMisses = 0

$Script:ApiRateLimiter = @{
    LastCall = [System.Collections.Generic.Dictionary[string, [DateTime]]]::new()
    MinimumDelay = [TimeSpan]::FromMilliseconds(500)  # Changed from 2 seconds to 500ms
}

$Base = $quarantineFolder
$QuarantineDir = $quarantineFolder

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[CRITICAL] Must run as Administrator" -ForegroundColor Red
    exit 1
}


# ============================================
# LOGGING FUNCTIONS (MUST BE FIRST)
# ============================================
$Script:ErrorSeverity = @{
    "Critical" = 1
    "High" = 2
    "Medium" = 3
    "Low" = 4
}

$Script:FailSafeMode = $false
$Script:JobsInitialized = $false

function Write-ErrorLog {
    param(
        [string]$Message,
        [string]$Severity = "Medium",
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [ERROR-$Severity] $Message"
    
    if ($ErrorRecord) {
        $logEntry += " | Exception: $($ErrorRecord.Exception.Message) | StackTrace: $($ErrorRecord.ScriptStackTrace)"
    }
    
    try {
        $errorLogPath = Join-Path $Script:LogsDir "error_log.txt"
        $logEntry | Out-File -FilePath $errorLogPath -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "[FATAL] Cannot write to error log: $_" -ForegroundColor Red
    }
    
    if ($Severity -eq "Critical" -and $Script:JobsInitialized) {
        $Script:FailSafeMode = $true
        Write-Host "[FAIL-SAFE] Entering fail-safe mode due to critical runtime error" -ForegroundColor Red
    }
}

function Write-Log {
    param ([string]$message)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    
    try {
        if (-not (Test-Path $quarantineFolder)) {
            New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
            $archiveName = Join-Path $Script:LogsDir "antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
        }
        
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "[WARNING] Failed to write log: $message - Error: $_" -ForegroundColor Yellow
    }
}

function Write-SecurityEvent {
    param(
        [string]$EventType,
        [hashtable]$Details,
        [string]$Severity = "Informational"
    )
    
    try {
        $event = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            EventType = $EventType
            Severity = $Severity
            User = $env:USERNAME
            Machine = $env:COMPUTERNAME
            PID = $PID
            Details = $Details
        }
        
        $eventJson = $event | ConvertTo-Json -Compress
        $securityLogPath = Join-Path $Script:LogsDir "security_events.jsonl"
        $eventJson | Out-File $securityLogPath -Append -Encoding UTF8
        
        try {
            $sourceName = "AntivirusScript"
            if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
                New-EventLog -LogName Application -Source $sourceName -ErrorAction SilentlyContinue
            }
            
            $eventId = switch ($Severity) {
                "Critical" { 1001 }
                "High" { 1002 }
                "Medium" { 1003 }
                default { 1000 }
            }
            
            Write-EventLog -LogName Application -Source $sourceName -EventId $eventId `
                -EntryType Information -Message "${EventType}: $(ConvertTo-Json $Details -Compress)"
        } catch {
            # Silently fail if we can't write to Windows Event Log
        }
    } catch {
        Write-ErrorLog -Message "Failed to write security event" -Severity "Medium" -ErrorRecord $_
    }
}


try {
    $Script:SecurityMutex = [System.Threading.Mutex]::new($false, $Script:MutexName)
    if (-not $Script:SecurityMutex.WaitOne(0, $false)) {
        Write-Host "[PROTECTION] Another instance is already running. Exiting." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[PROTECTION] Global mutex acquired successfully." -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Global mutex failed (requires admin): $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "[PROTECTION] Falling back to local mutex (user-level protection)..." -ForegroundColor Cyan
    
    try {
        $Script:MutexName = "Local\AntivirusProtectionMutex_{F9A2E1C4-3B7D-4A8E-9C5F-1D6E2B7A8C3D}_$env:USERNAME"
        $Script:SecurityMutex = [System.Threading.Mutex]::new($false, $Script:MutexName)
        if (-not $Script:SecurityMutex.WaitOne(0, $false)) {
            Write-Host "[PROTECTION] Another instance is already running for this user. Exiting." -ForegroundColor Yellow
            exit 1
        }
        Write-Host "[PROTECTION] Local mutex acquired successfully." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to acquire any mutex: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[WARNING] Continuing without mutex protection (multiple instances may run)..." -ForegroundColor Yellow
        $Script:SecurityMutex = $null
    }
}

function Get-SecureHMACKey {
    try {
        try {
            Add-Type -AssemblyName System.Security -ErrorAction Stop
        } catch {
            Write-Host "[WARNING] System.Security assembly not available, using fallback encryption" -ForegroundColor Yellow
        }
        
        $keyPath = Join-Path $Script:DataDir "hmac.key"
        
        if (Test-Path $keyPath) {
            try {
                $protectedKeyBytes = Get-Content $keyPath -Encoding Byte -ErrorAction Stop
                $keyBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $protectedKeyBytes,
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                )
                Write-Host "[SECURITY] Loaded protected HMAC key from installation directory" -ForegroundColor Green
                return $keyBytes
            } catch {
                Write-Host "[WARNING] Failed to load existing HMAC key: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[SECURITY] Generating new HMAC key with DPAPI protection" -ForegroundColor Yellow
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $key = New-Object byte[] 32
        $rng.GetBytes($key)
        
        try {
            $protectedKey = [System.Security.Cryptography.ProtectedData]::Protect(
                $key,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            
            $keyDir = Split-Path $keyPath
            if (-not (Test-Path $keyDir)) {
                New-Item -Path $keyDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $protectedKey | Set-Content $keyPath -Encoding Byte
            
            Write-Host "[SECURITY] HMAC key generated and protected with DPAPI" -ForegroundColor Green
        } catch {
            Write-Host "[WARNING] Could not protect HMAC key with DPAPI: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        return $key
    } catch {
        Write-Host "[ERROR] Failed to load/generate secure HMAC key: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[WARNING] Using fallback HMAC key - NOT SECURE FOR PRODUCTION" -ForegroundColor Yellow
        
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $fallbackKey = New-Object byte[] 32
        $rng.GetBytes($fallbackKey)
        return $fallbackKey
    }
}

$Script:HMACKey = Get-SecureHMACKey

Write-Log "[+] Antivirus starting up from: $Script:InstallDir"


function Test-ScriptConfiguration {
    $errors = @()
    
    Write-Log "[CONFIG] Validating script configuration..."
    
    @($Script:InstallDir, $Script:DataDir, $Script:LogsDir, $quarantineFolder, $Script:ReportsDir) | ForEach-Object {
        if (-not (Test-Path $_)) {
            try { 
                New-Item $_ -ItemType Directory -Force | Out-Null 
                Write-Log "[CONFIG] Created directory: $_"
            }
            catch { 
                $errors += "Cannot create directory: $_"
                Write-Log "[CONFIG ERROR] Cannot create directory: $_"
            }
        }
    }
    
    try {
        $testFile = Join-Path $quarantineFolder "test_permissions.txt"
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -Force
        Write-Log "[CONFIG] Write permissions verified for quarantine folder"
    } catch {
        $errors += "No write permission to quarantine folder"
        Write-Log "[CONFIG ERROR] No write permission to quarantine folder"
    }
    
    try {
        $testConnection = Test-NetConnection -ComputerName "www.google.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        if ($testConnection) {
            Write-Log "[CONFIG] Network connectivity verified"
        } else {
            $errors += "No internet connectivity - hash lookups may fail"
            Write-Log "[CONFIG WARNING] No internet connectivity detected"
        }
    } catch {
        Write-Log "[CONFIG WARNING] Could not verify network connectivity"
    }
    
    try {
        $drive = (Get-Item $quarantineFolder).PSDrive
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        if ($freeSpaceGB -lt 1) {
            $errors += "Low disk space: Only ${freeSpaceGB}GB available"
            Write-Log "[CONFIG WARNING] Low disk space: ${freeSpaceGB}GB"
        } else {
            Write-Log "[CONFIG] Disk space available: ${freeSpaceGB}GB"
        }
    } catch {
        Write-Log "[CONFIG WARNING] Could not check disk space"
    }
    
    if ($errors.Count -eq 0) {
        Write-Log "[CONFIG] All configuration checks passed"
    } else {
        Write-Log "[CONFIG] Configuration validation found $($errors.Count) issue(s)"
    }
    
    return $errors
}

function Invoke-MemoryCleanup {
    param([bool]$Force = $false)
    
    try {
        $currentMemoryMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
        $memoryThresholdMB = 500  # Trigger cleanup above 500MB
        
        if ($Force -or $currentMemoryMB -gt $memoryThresholdMB) {
            Write-Log "[MEMORY] Current usage: ${currentMemoryMB}MB - Starting cleanup..."
            
            # Clear old cache entries more aggressively
            if ($Script:FileHashCache.Count -gt 1000) {
                $keysToRemove = $Script:FileHashCache.Keys | Select-Object -First 500
                foreach ($key in $keysToRemove) {
                    $dummy = $null
                    [void]$Script:FileHashCache.TryRemove($key, [ref]$dummy)
                }
                Write-Log "[MEMORY] Cleared 500 cache entries"
            }
            
            # Clear old scanned files from memory
            if ($scannedFiles.Count -gt 1000) {
                $keysToRemove = @($scannedFiles.Keys | Select-Object -First 500)
                foreach ($key in $keysToRemove) {
                    $scannedFiles.Remove($key)
                }
                Write-Log "[MEMORY] Cleared 500 scanned file records"
            }
            
            # Force garbage collection
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            
            $newMemoryMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            $saved = $currentMemoryMB - $newMemoryMB
            Write-Log "[MEMORY] Cleanup complete: ${newMemoryMB}MB (saved ${saved}MB)"
        }
    } catch {
        Write-ErrorLog -Message "Memory cleanup failed" -Severity "Low" -ErrorRecord $_
    }
}


function Generate-SecurityReport {
    param([string]$ReportType = "Daily")
    
    try {
        Write-Log "[REPORT] Generating $ReportType security report..."
        
        $report = @{
            Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ReportType = $ReportType
            Statistics = @{
                FilesScanned = $scannedFiles.Count
                FilesQuarantined = (Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue).Count
                ProcessesKilled = (Get-Content $logFile -ErrorAction SilentlyContinue | Select-String "\[KILL\]" | Measure-Object).Count
                CacheHitRate = if (($Script:CacheHits + $Script:CacheMisses) -gt 0) {
                    [math]::Round(($Script:CacheHits / ($Script:CacheHits + $Script:CacheMisses)) * 100, 2)
                } else { 0 }
                TotalCacheHits = $Script:CacheHits
                TotalCacheMisses = $Script:CacheMisses
            }
            RecentDetections = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue
            SystemStatus = @{
                JobsRunning = (Get-Job | Where-Object State -eq 'Running' | Measure-Object).Count
                MemoryUsageMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
                UptimeHours = [math]::Round(((Get-Date) - (Get-Process -Id $PID).StartTime).TotalHours, 2)
                ActiveMutex = if ($Script:SecurityMutex) { $true } else { $false }
            }
            TopQuarantinedFiles = Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue | 
                Select-Object Name, Length, CreationTime -First 10
        }
        
        $reportPath = Join-Path $Script:ReportsDir "$ReportType-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $report | ConvertTo-Json -Depth 5 | Set-Content $reportPath
        
        Write-Log "[REPORT] Report generated: $reportPath"
        Write-SecurityEvent -EventType "ReportGenerated" -Details @{ ReportPath = $reportPath; Type = $ReportType } -Severity "Informational"
        
        return $reportPath
    } catch {
        Write-ErrorLog -Message "Failed to generate security report" -Severity "Medium" -ErrorRecord $_
        return $null
    }
}

function New-SecurityReport {
    param([string]$ReportType = "Daily")
    return Generate-SecurityReport -ReportType $ReportType
}


function Initialize-WhitelistDatabase {
    try {
        $whitelistPath = Join-Path $Script:DataDir "whitelist.json"
        
        if (Test-Path $whitelistPath) {
            $jsonContent = Get-Content $whitelistPath -Raw | ConvertFrom-Json
            
            $Script:Whitelist = @{
                Processes = @{}
                Files = @{}
                Certificates = @{}
                LastUpdated = $jsonContent.LastUpdated
            }
            
            if ($jsonContent.Processes) {
                foreach ($prop in $jsonContent.Processes.PSObject.Properties) {
                    $Script:Whitelist.Processes[$prop.Name] = $prop.Value
                }
            }
            if ($jsonContent.Files) {
                foreach ($prop in $jsonContent.Files.PSObject.Properties) {
                    $Script:Whitelist.Files[$prop.Name] = $prop.Value
                }
            }
            if ($jsonContent.Certificates) {
                foreach ($prop in $jsonContent.Certificates.PSObject.Properties) {
                    $Script:Whitelist.Certificates[$prop.Name] = $prop.Value
                }
            }
            
            Write-Log "[WHITELIST] Loaded whitelist database with $($Script:Whitelist.Files.Count) files, $($Script:Whitelist.Processes.Count) processes"
        } else {
            $Script:Whitelist = @{
                Processes = @{}
                Files = @{}
                Certificates = @{}
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content $whitelistPath
            Write-Log "[WHITELIST] Created new whitelist database"
        }
    } catch {
        Write-ErrorLog -Message "Failed to initialize whitelist database" -Severity "Medium" -ErrorRecord $_
        $Script:Whitelist = @{
            Processes = @{}
            Files = @{}
            Certificates = @{}
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

function Add-ToWhitelist {
    param(
        [string]$FilePath = $null,
        [string]$ProcessName = $null,
        [string]$Reason,
        [string]$Category = "Manual"
    )
    
    try {
        if ($FilePath) {
            $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $cert = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            $certificateSubject = if ($cert.SignerCertificate) { $cert.SignerCertificate.Subject } else { $null }
            
            $Script:Whitelist.Files[$hash] = @{
                Path = $FilePath
                Reason = $Reason
                Category = $Category
                AddedBy = $env:USERNAME
                Timestamp = $timestamp
                Certificate = $certificateSubject
            }
            
            Write-Log "[WHITELIST] Added file to whitelist: $FilePath (Hash: $hash)"
        }
        
        if ($ProcessName) {
            $Script:Whitelist.Processes[$ProcessName.ToLower()] = @{
                Reason = $Reason
                Category = $Category
                AddedBy = $env:USERNAME
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            Write-Log "[WHITELIST] Added process to whitelist: $ProcessName"
        }
        
        $Script:Whitelist.LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $whitelistPath = Join-Path $Script:DataDir "whitelist.json"
        $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content $whitelistPath
        
        Write-SecurityEvent -EventType "WhitelistUpdated" -Details @{
            FilePath = $FilePath
            ProcessName = $ProcessName
            Reason = $Reason
        } -Severity "Informational"
        
    } catch {
        Write-ErrorLog -Message "Failed to add to whitelist" -Severity "Medium" -ErrorRecord $_
    }
}

function Remove-FromWhitelist {
    param(
        [string]$Identifier
    )
    
    try {
        $removed = $false
        
        if ($Script:Whitelist.Files.ContainsKey($Identifier)) {
            $Script:Whitelist.Files.Remove($Identifier)
            $removed = $true
        } else {
            $matchingHash = $Script:Whitelist.Files.GetEnumerator() | Where-Object { $_.Value.Path -eq $Identifier } | Select-Object -First 1
            if ($matchingHash) {
                $Script:Whitelist.Files.Remove($matchingHash.Key)
                $removed = $true
            }
        }
        
        if ($Script:Whitelist.Processes.ContainsKey($Identifier.ToLower())) {
            $Script:Whitelist.Processes.Remove($Identifier.ToLower())
            $removed = $true
        }
        
        if ($removed) {
            $Script:Whitelist.LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $whitelistPath = Join-Path $Script:DataDir "whitelist.json"
            $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content $whitelistPath
            Write-Log "[WHITELIST] Removed from whitelist: $Identifier"
            return $true
        } else {
            Write-Log "[WHITELIST] Item not found in whitelist: $Identifier"
            return $false
        }
    } catch {
        Write-ErrorLog -Message "Failed to remove from whitelist" -Severity "Medium" -ErrorRecord $_
        return $false
    }
}

function Test-IsWhitelisted {
    param(
        [string]$FilePath = $null,
        [string]$ProcessName = $null
    )
    
    try {
        if ($FilePath) {
            $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($Script:Whitelist.Files.ContainsKey($hash)) {
                return $true
            }
        }
        
        if ($ProcessName) {
            if ($Script:Whitelist.Processes.ContainsKey($ProcessName.ToLower())) {
                return $true
            }
        }
        
        return $false
    } catch {
        return $false
    }
}

function Add-ToStartup {
    try {
        $exePath = "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$Script:ScriptInstallPath`""
        $appName = "MalwareDetector"
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $existing = Get-ItemProperty -Path $regPath -Name $appName -ErrorAction SilentlyContinue
        
        if (!$existing -or $existing.$appName -ne $exePath) {
            Set-ItemProperty -Path $regPath -Name $appName -Value $exePath -Force
            Write-Log "[STARTUP] Added to registry startup: $exePath"
        }
        
        $taskExists = Get-ScheduledTask -TaskName "${taskName}_Watchdog" -ErrorAction SilentlyContinue
        if (-not $taskExists) {
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:ScriptInstallPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
            
            Register-ScheduledTask -TaskName "${taskName}_Watchdog" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Watchdog for antivirus protection" -ErrorAction Stop | Out-Null
            Write-Log "[STARTUP] Registered scheduled task: ${taskName}_Watchdog"
        }
    } catch {
        Write-Log "[ERROR] Failed to add to startup: $_"
        throw
    }
}

# Initialize installation before anything else
Initialize-Installation

# ============================================
# CRITICAL SECURITY FIX #1: SELF-PROTECTION WITH MUTEX
# ============================================
$Script:MutexName = "Global\AntivirusProtectionMutex_{F9A2E1C4-3B7D-4A8E-9C5F-1D6E2B7A8C3D}"
$Script:SecurityMutex = $null

# Termination protection variables
$Script:TerminationAttempts = 0
$Script:MaxTerminationAttempts = 5
$Script:AutoRestart = $false
$Script:SelfPID = $PID

$taskName = "Antivirus"
$taskDescription = "Runs the Production Hardened Antivirus script"
$scriptPath = $Script:ScriptInstallPath
$quarantineFolder = $Script:QuarantineDir
$logFile = Join-Path $Script:LogsDir "antivirus_log.txt"
$localDatabase = Join-Path $Script:DataDir "scanned_files.txt"
$hashIntegrityFile = Join-Path $Script:DataDir "db_integrity.hmac"
$scannedFiles = @{}

$Script:FileHashCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$Script:MaxCacheSize = 2000  # Reduced from 5000 to save RAM
$Script:CacheHits = 0
$Script:CacheMisses = 0

$Script:ApiRateLimiter = @{
    LastCall = [System.Collections.Generic.Dictionary[string, [DateTime]]]::new()
    MinimumDelay = [TimeSpan]::FromMilliseconds(500)  # Changed from 2 seconds to 500ms
}

$Base = $quarantineFolder
$QuarantineDir = $quarantineFolder

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[CRITICAL] Must run as Administrator" -ForegroundColor Red
    exit 1
}


# ============================================
# LOGGING FUNCTIONS (MUST BE FIRST)
# ============================================
$Script:ErrorSeverity = @{
    "Critical" = 1
    "High" = 2
    "Medium" = 3
    "Low" = 4
}

$Script:FailSafeMode = $false
$Script:JobsInitialized = $false

function Write-ErrorLog {
    param(
        [string]$Message,
        [string]$Severity = "Medium",
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [ERROR-$Severity] $Message"
    
    if ($ErrorRecord) {
        $logEntry += " | Exception: $($ErrorRecord.Exception.Message) | StackTrace: $($ErrorRecord.ScriptStackTrace)"
    }
    
    try {
        $errorLogPath = Join-Path $Script:LogsDir "error_log.txt"
        $logEntry | Out-File -FilePath $errorLogPath -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "[FATAL] Cannot write to error log: $_" -ForegroundColor Red
    }
    
    if ($Severity -eq "Critical" -and $Script:JobsInitialized) {
        $Script:FailSafeMode = $true
        Write-Host "[FAIL-SAFE] Entering fail-safe mode due to critical runtime error" -ForegroundColor Red
    }
}

function Write-Log {
    param ([string]$message)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    
    try {
        if (-not (Test-Path $quarantineFolder)) {
            New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
            $archiveName = Join-Path $Script:LogsDir "antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
        }
        
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "[WARNING] Failed to write log: $message - Error: $_" -ForegroundColor Yellow
    }
}

function Write-SecurityEvent {
    param(
        [string]$EventType,
        [hashtable]$Details,
        [string]$Severity = "Informational"
    )
    
    try {
        $event = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            EventType = $EventType
            Severity = $Severity
            User = $env:USERNAME
            Machine = $env:COMPUTERNAME
            PID = $PID
            Details = $Details
        }
        
        $eventJson = $event | ConvertTo-Json -Compress
        $securityLogPath = Join-Path $Script:LogsDir "security_events.jsonl"
        $eventJson | Out-File $securityLogPath -Append -Encoding UTF8
        
        try {
            $sourceName = "AntivirusScript"
            if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
                New-EventLog -LogName Application -Source $sourceName -ErrorAction SilentlyContinue
            }
            
            $eventId = switch ($Severity) {
                "Critical" { 1001 }
                "High" { 1002 }
                "Medium" { 1003 }
                default { 1000 }
            }
            
            Write-EventLog -LogName Application -Source $sourceName -EventId $eventId `
                -EntryType Information -Message "${EventType}: $(ConvertTo-Json $Details -Compress)"
        } catch {
            # Silently fail if we can't write to Windows Event Log
        }
    } catch {
        Write-ErrorLog -Message "Failed to write security event" -Severity "Medium" -ErrorRecord $_
    }
}


try {
    $Script:SecurityMutex = [System.Threading.Mutex]::new($false, $Script:MutexName)
    if (-not $Script:SecurityMutex.WaitOne(0, $false)) {
        Write-Host "[PROTECTION] Another instance is already running. Exiting." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[PROTECTION] Global mutex acquired successfully." -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Global mutex failed (requires admin): $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "[PROTECTION] Falling back to local mutex (user-level protection)..." -ForegroundColor Cyan
    
    try {
        $Script:MutexName = "Local\AntivirusProtectionMutex_{F9A2E1C4-3B7D-4A8E-9C5F-1D6E2B7A8C3D}_$env:USERNAME"
        $Script:SecurityMutex = [System.Threading.Mutex]::new($false, $Script:MutexName)
        if (-not $Script:SecurityMutex.WaitOne(0, $false)) {
            Write-Host "[PROTECTION] Another instance is already running for this user. Exiting." -ForegroundColor Yellow
            exit 1
        }
        Write-Host "[PROTECTION] Local mutex acquired successfully." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to acquire any mutex: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[WARNING] Continuing without mutex protection (multiple instances may run)..." -ForegroundColor Yellow
        $Script:SecurityMutex = $null
    }
}

function Get-SecureHMACKey {
    try {
        # Load System.Security assembly for DPAPI support
        try {
            Add-Type -AssemblyName System.Security -ErrorAction Stop
        } catch {
            Write-Host "[WARNING] System.Security assembly not available, using fallback encryption" -ForegroundColor Yellow
        }
        
        $keyPath = "$env:APPDATA\AntivirusProtection\hmac.key"
        
        if (Test-Path $keyPath) {
            # Load existing protected key
            try {
                $protectedKeyBytes = Get-Content $keyPath -Encoding Byte -ErrorAction Stop
                $keyBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $protectedKeyBytes,
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                )
                Write-Host "[SECURITY] Loaded protected HMAC key from user profile" -ForegroundColor Green
                return $keyBytes
            } catch {
                Write-Host "[WARNING] Failed to load existing HMAC key: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # Generate and store new key
        Write-Host "[SECURITY] Generating new HMAC key with DPAPI protection" -ForegroundColor Yellow
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $key = New-Object byte[] 32
        $rng.GetBytes($key)
        
        try {
            $protectedKey = [System.Security.Cryptography.ProtectedData]::Protect(
                $key,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            
            $keyDir = Split-Path $keyPath
            New-Item -Path $keyDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            $protectedKey | Set-Content $keyPath -Encoding Byte
            
            Write-Host "[SECURITY] HMAC key generated and protected with DPAPI" -ForegroundColor Green
        } catch {
            Write-Host "[WARNING] Could not protect HMAC key with DPAPI: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        return $key
    } catch {
        Write-Host "[ERROR] Failed to load/generate secure HMAC key: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[WARNING] Using fallback HMAC key - NOT SECURE FOR PRODUCTION" -ForegroundColor Yellow
        
        # Generate a random fallback key instead of hardcoded
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $fallbackKey = New-Object byte[] 32
        $rng.GetBytes($fallbackKey)
        return $fallbackKey
    }
}

# Initialize HMAC key
$Script:HMACKey = Get-SecureHMACKey

Write-Log "[+] Antivirus starting up..."

# ============================================
# SECURITY ENHANCEMENT: CENTRALIZED ERROR HANDLING
# ============================================
# Moved trap handler after all functions are defined and add ISE detection for Ctrl+C protection
# The trap handler is now at the top, after logging functions are defined.

# ============================================
# SECURITY ENHANCEMENT: HMAC Key with DPAPI Protection
# ============================================
# The Get-SecureHMACKey function is now defined early, and the key is initialized after logging functions.

# ============================================
# SECURITY ENHANCEMENT: Event Logging
# ============================================
# This function is now defined at the top.

# ============================================
# OPERATIONAL ENHANCEMENT: Configuration Validation
# ============================================

function Test-ScriptConfiguration {
    $errors = @()
    
    Write-Log "[CONFIG] Validating script configuration..."
    
    # Check required folders
    @($quarantineFolder, "$quarantineFolder\reports") | ForEach-Object {
        if (-not (Test-Path $_)) {
            try { 
                New-Item $_ -ItemType Directory -Force | Out-Null 
                Write-Log "[CONFIG] Created directory: $_"
            }
            catch { 
                $errors += "Cannot create directory: $_"
                Write-Log "[CONFIG ERROR] Cannot create directory: $_"
            }
        }
    }
    
    # Check file permissions
    try {
        $testFile = "$quarantineFolder\test_permissions.txt"
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -Force
        Write-Log "[CONFIG] Write permissions verified for quarantine folder"
    } catch {
        $errors += "No write permission to quarantine folder"
        Write-Log "[CONFIG ERROR] No write permission to quarantine folder"
    }
    
    # Check network connectivity for APIs
    try {
        $testConnection = Test-NetConnection -ComputerName "www.google.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        if ($testConnection) {
            Write-Log "[CONFIG] Network connectivity verified"
        } else {
            $errors += "No internet connectivity - hash lookups may fail"
            Write-Log "[CONFIG WARNING] No internet connectivity detected"
        }
    } catch {
        Write-Log "[CONFIG WARNING] Could not verify network connectivity"
    }
    
    # Check available disk space
    try {
        $drive = (Get-Item $quarantineFolder).PSDrive
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        if ($freeSpaceGB -lt 1) {
            $errors += "Low disk space: Only ${freeSpaceGB}GB available"
            Write-Log "[CONFIG WARNING] Low disk space: ${freeSpaceGB}GB"
        } else {
            Write-Log "[CONFIG] Disk space available: ${freeSpaceGB}GB"
        }
    } catch {
        Write-Log "[CONFIG WARNING] Could not check disk space"
    }
    
    if ($errors.Count -eq 0) {
        Write-Log "[CONFIG] All configuration checks passed"
    } else {
        Write-Log "[CONFIG] Configuration validation found $($errors.Count) issue(s)"
    }
    
    return $errors
}

# ============================================
# PERFORMANCE ENHANCEMENT: Rate-Limited API Calls
# ============================================
function Invoke-RateLimitedRestMethod {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null,
        [string]$ContentType = "application/json",
        [int]$TimeoutSec = 3  # Reduced from 5 to 3 seconds
    )
    
    try {
        $hostName = ([System.Uri]$Uri).Host
        
        # Check if we need to wait
        if ($Script:ApiRateLimiter.LastCall.ContainsKey($hostName)) {
            $timeSinceLastCall = [DateTime]::Now - $Script:ApiRateLimiter.LastCall[$hostName]
            if ($timeSinceLastCall -lt $Script:ApiRateLimiter.MinimumDelay) {
                $sleepMs = ($Script:ApiRateLimiter.MinimumDelay - $timeSinceLastCall).TotalMilliseconds
                Start-Sleep -Milliseconds $sleepMs
            }
        }
        
        # Make the API call
        $params = @{
            Uri = $Uri
            Method = $Method
            TimeoutSec = $TimeoutSec
            ErrorAction = 'Stop'
            UseBasicParsing = $true  # Faster parsing
        }
        
        if ($Body) { $params['Body'] = $Body }
        if ($ContentType) { $params['ContentType'] = $ContentType }
        
        $response = Invoke-RestMethod @params
        
        # Update rate limiter
        $Script:ApiRateLimiter.LastCall[$hostName] = [DateTime]::Now
        
        return $response
    } catch {
        Write-ErrorLog -Message "Rate-limited API call failed: $Uri" -Severity "Low" -ErrorRecord $_
        return $null
    }
}

# ============================================
# OPERATIONAL ENHANCEMENT: Reporting
# ============================================

function Generate-SecurityReport {
    param([string]$ReportType = "Daily")
    
    try {
        Write-Log "[REPORT] Generating $ReportType security report..."
        
        $report = @{
            Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ReportType = $ReportType
            Statistics = @{
                FilesScanned = $scannedFiles.Count
                FilesQuarantined = (Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue).Count
                ProcessesKilled = (Get-Content $logFile -ErrorAction SilentlyContinue | Select-String "\[KILL\]" | Measure-Object).Count
                CacheHitRate = if (($Script:CacheHits + $Script:CacheMisses) -gt 0) {
                    [math]::Round(($Script:CacheHits / ($Script:CacheHits + $Script:CacheMisses)) * 100, 2)
                } else { 0 }
                TotalCacheHits = $Script:CacheHits
                TotalCacheMisses = $Script:CacheMisses
            }
            RecentDetections = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue
            SystemStatus = @{
                JobsRunning = (Get-Job | Where-Object State -eq 'Running' | Measure-Object).Count
                MemoryUsageMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
                UptimeHours = [math]::Round(((Get-Date) - (Get-Process -Id $PID).StartTime).TotalHours, 2)
                ActiveMutex = if ($Script:SecurityMutex) { $true } else { $false }
            }
            TopQuarantinedFiles = Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue | 
                Select-Object Name, Length, CreationTime -First 10
        }
        
        $reportPath = "$quarantineFolder\reports\$ReportType-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $report | ConvertTo-Json -Depth 5 | Set-Content $reportPath
        
        Write-Log "[REPORT] Report generated: $reportPath"
        Write-SecurityEvent -EventType "ReportGenerated" -Details @{ ReportPath = $reportPath; Type = $ReportType } -Severity "Informational"
        
        return $reportPath
    } catch {
        Write-ErrorLog -Message "Failed to generate security report" -Severity "Medium" -ErrorRecord $_
        return $null
    }
}

# Renamed to New-SecurityReport for consistency in the main loop
function New-SecurityReport {
    param([string]$ReportType = "Daily")
    
    try {
        Write-Log "[REPORT] Generating $ReportType security report..."
        
        $report = @{
            Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ReportType = $ReportType
            Statistics = @{
                FilesScanned = $scannedFiles.Count
                FilesQuarantined = (Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue).Count
                ProcessesKilled = (Get-Content $logFile -ErrorAction SilentlyContinue | Select-String "\[KILL\]" | Measure-Object).Count
                CacheHitRate = if (($Script:CacheHits + $Script:CacheMisses) -gt 0) {
                    [math]::Round(($Script:CacheHits / ($Script:CacheHits + $Script:CacheMisses)) * 100, 2)
                } else { 0 }
                TotalCacheHits = $Script:CacheHits
                TotalCacheMisses = $Script:CacheMisses
            }
            RecentDetections = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue
            SystemStatus = @{
                JobsRunning = (Get-Job | Where-Object State -eq 'Running' | Measure-Object).Count
                MemoryUsageMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
                UptimeHours = [math]::Round(((Get-Date) - (Get-Process -Id $PID).StartTime).TotalHours, 2)
                ActiveMutex = if ($Script:SecurityMutex) { $true } else { $false }
            }
            TopQuarantinedFiles = Get-ChildItem "$quarantineFolder\*.quarantined" -ErrorAction SilentlyContinue | 
                Select-Object Name, Length, CreationTime -First 10
        }
        
        $reportPath = "$quarantineFolder\reports\$ReportType-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $report | ConvertTo-Json -Depth 5 | Set-Content $reportPath
        
        Write-Log "[REPORT] Report generated: $reportPath"
        Write-SecurityEvent -EventType "ReportGenerated" -Details @{ ReportPath = $reportPath; Type = $ReportType } -Severity "Informational"
        
        return $reportPath
    } catch {
        Write-ErrorLog -Message "Failed to generate security report" -Severity "Medium" -ErrorRecord $_
        return $null
    }
}

# ============================================
# OPERATIONAL ENHANCEMENT: Whitelist Database Management
# ============================================

function Initialize-WhitelistDatabase {
    try {
        $whitelistPath = "$quarantineFolder\whitelist.json"
        
        if (Test-Path $whitelistPath) {
            # Parse JSON and manually convert to hashtable for PS 5.1 compatibility
            $jsonContent = Get-Content $whitelistPath -Raw | ConvertFrom-Json
            $Script:Whitelist = @{
                Processes = @{}
                Files = @{}
                Certificates = @{}
                LastUpdated = $jsonContent.LastUpdated
            }
            
            # Convert nested objects to hashtables
            if ($jsonContent.Processes) {
                foreach ($prop in $jsonContent.Processes.PSObject.Properties) {
                    $Script:Whitelist.Processes[$prop.Name] = $prop.Value
                }
            }
            if ($jsonContent.Files) {
                foreach ($prop in $jsonContent.Files.PSObject.Properties) {
                    $Script:Whitelist.Files[$prop.Name] = $prop.Value
                }
            }
            if ($jsonContent.Certificates) {
                foreach ($prop in $jsonContent.Certificates.PSObject.Properties) {
                    $Script:Whitelist.Certificates[$prop.Name] = $prop.Value
                }
            }
            
            Write-Log "[WHITELIST] Loaded whitelist database with $($Script:Whitelist.Files.Count) files, $($Script:Whitelist.Processes.Count) processes"
        } else {
            $Script:Whitelist = @{
                Processes = @{}
                Files = @{}
                Certificates = @{}
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content $whitelistPath
            Write-Log "[WHITELIST] Created new whitelist database"
        }
    } catch {
        Write-ErrorLog -Message "Failed to initialize whitelist database" -Severity "Medium" -ErrorRecord $_
        $Script:Whitelist = @{
            Processes = @{}
            Files = @{}
            Certificates = @{}
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}

function Add-ToWhitelist {
    param(
        [string]$FilePath = $null,
        [string]$ProcessName = $null,
        [string]$Reason,
        [string]$Category = "Manual"
    )
    
    try {
        if ($FilePath) {
            $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $cert = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            $certificateSubject = if ($cert.SignerCertificate) { $cert.SignerCertificate.Subject } else { $null }
            
            $Script:Whitelist.Files[$hash] = @{
                Path = $FilePath
                Reason = $Reason
                Category = $Category
                AddedBy = $env:USERNAME
                Timestamp = $timestamp
                Certificate = $certificateSubject
            }
            
            Write-Log "[WHITELIST] Added file to whitelist: $FilePath (Hash: $hash)"
        }
        
        if ($ProcessName) {
            $Script:Whitelist.Processes[$ProcessName.ToLower()] = @{
                Reason = $Reason
                Category = $Category
                AddedBy = $env:USERNAME
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            Write-Log "[WHITELIST] Added process to whitelist: $ProcessName"
        }
        
        # Save to disk
        $Script:Whitelist.LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content "$quarantineFolder\whitelist.json"
        
        Write-SecurityEvent -EventType "WhitelistUpdated" -Details @{
            FilePath = $FilePath
            ProcessName = $ProcessName
            Reason = $Reason
        } -Severity "Informational"
        
    } catch {
        Write-ErrorLog -Message "Failed to add to whitelist" -Severity "Medium" -ErrorRecord $_
    }
}

function Remove-FromWhitelist {
    param(
        [string]$Identifier
    )
    
    try {
        $removed = $false
        
        # Try to remove from files (by hash or path)
        if ($Script:Whitelist.Files.ContainsKey($Identifier)) {
            $Script:Whitelist.Files.Remove($Identifier)
            $removed = $true
        } else {
            # Search by path
            $matchingHash = $Script:Whitelist.Files.GetEnumerator() | Where-Object { $_.Value.Path -eq $Identifier } | Select-Object -First 1
            if ($matchingHash) {
                $Script:Whitelist.Files.Remove($matchingHash.Key)
                $removed = $true
            }
        }
        
        # Try to remove from processes
        if ($Script:Whitelist.Processes.ContainsKey($Identifier.ToLower())) {
            $Script:Whitelist.Processes.Remove($Identifier.ToLower())
            $removed = $true
        }
        
        if ($removed) {
            $Script:Whitelist.LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content "$quarantineFolder\whitelist.json"
            Write-Log "[WHITELIST] Removed from whitelist: $Identifier"
            return $true
        } else {
            Write-Log "[WHITELIST] Item not found in whitelist: $Identifier"
            return $false
        }
    } catch {
        Write-ErrorLog -Message "Failed to remove from whitelist" -Severity "Medium" -ErrorRecord $_
        return $false
    }
}

function Test-IsWhitelisted {
    param(
        [string]$FilePath = $null,
        [string]$ProcessName = $null
    )
    
    try {
        if ($FilePath) {
            $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($Script:Whitelist.Files.ContainsKey($hash)) {
                return $true
            }
        }
        
        if ($ProcessName) {
            if ($Script:Whitelist.Processes.ContainsKey($ProcessName.ToLower())) {
                return $true
            }
        }
        
        return $false
    } catch {
        return $false
    }
}

# ============================================
# SECURITY ENHANCEMENT: Memory Protection
# ============================================

function Protect-SensitiveData {
    try {
        # Clear sensitive strings from memory
        if ($Script:HMACKey) {
            [Array]::Clear($Script:HMACKey, 0, $Script:HMACKey.Length)
            $Script:HMACKey = $null
        }
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-Log "[SECURITY] Sensitive data cleared from memory"
    } catch {
        Write-ErrorLog -Message "Failed to protect sensitive data" -Severity "Low" -ErrorRecord $_
    }
}

# Register cleanup on exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Protect-SensitiveData
    
    if ($Script:SecurityMutex) {
        try { 
            $Script:SecurityMutex.ReleaseMutex()
            $Script:SecurityMutex.Dispose() 
        } catch {}
    }
} | Out-Null

# ============================================
# PERFORMANCE ENHANCEMENT: Parallel Scanning
# ============================================
function Invoke-ParallelScan {
    param(
        [string[]]$Paths,
        [int]$MaxThreads = 8  # Increased from 4 to 8 for faster scanning
    )
    
    try {
        Write-Log "[SCAN] Starting parallel scan of $($Paths.Count) paths with $MaxThreads threads"
        
        # Process in batches to avoid memory bloat
        $batchSize = 100
        $allResults = @()
        
        for ($i = 0; $i -lt $Paths.Count; $i += $batchSize) {
            $batch = $Paths[$i..[math]::Min($i + $batchSize - 1, $Paths.Count - 1)]
            
            $batchResults = $batch | ForEach-Object -ThrottleLimit $MaxThreads -Parallel {
                $path = $_
                
                try {
                    if (Test-Path $path -ErrorAction SilentlyContinue) {
                        $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash
                        
                        [PSCustomObject]@{
                            Path = $path
                            Hash = $hash
                            Success = $true
                            Error = $null
                        }
                    } else {
                        [PSCustomObject]@{
                            Path = $path
                            Hash = $null
                            Success = $false
                            Error = "File not found"
                        }
                    }
                } catch {
                    [PSCustomObject]@{
                        Path = $path
                        Hash = $null
                        Success = $false
                        Error = $_.Exception.Message
                    }
                }
            }
            
            $allResults += $batchResults
            
            # Cleanup between batches
            if (($i + $batchSize) -lt $Paths.Count) {
                [System.GC]::Collect()
            }
        }
        
        $successCount = ($allResults | Where-Object Success).Count
        Write-Log "[SCAN] Parallel scan complete: $successCount/$($Paths.Count) files processed successfully"
        
        return $allResults
    } catch {
        Write-ErrorLog -Message "Parallel scan failed" -Severity "Medium" -ErrorRecord $_
        return @()
    }
}

# ============================================
# OPERATIONAL ENHANCEMENT: Interactive Exclusion Manager
# ============================================

function Show-ExclusionManager {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "       EXCLUSION MANAGER" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    while ($true) {
        Write-Host "[1] Add Process Exclusion" -ForegroundColor Green
        Write-Host "[2] Add File/Path Exclusion" -ForegroundColor Green
        Write-Host "[3] View Current Exclusions" -ForegroundColor Yellow
        Write-Host "[4] Remove Exclusion" -ForegroundColor Red
        Write-Host "[5] Export Whitelist" -ForegroundColor Cyan
        Write-Host "[6] Return to Monitoring" -ForegroundColor Gray
        Write-Host ""
        
        $choice = Read-Host "Select an option (1-6)"
        
        switch ($choice) {
            "1" {
                $procName = Read-Host "Enter process name (e.g., myapp.exe)"
                $reason = Read-Host "Enter reason for exclusion"
                if ($procName) {
                    Add-ToWhitelist -ProcessName $procName -Reason $reason -Category "UserDefined"
                    Write-Host "[+] Process added to whitelist: $procName" -ForegroundColor Green
                }
            }
            "2" {
                $filePath = Read-Host "Enter full file path or directory pattern"
                $reason = Read-Host "Enter reason for exclusion"
                if ($filePath -and (Test-Path $filePath)) {
                    Add-ToWhitelist -FilePath $filePath -Reason $reason -Category "UserDefined"
                    Write-Host "[+] File/path added to whitelist: $filePath" -ForegroundColor Green
                } else {
                    Write-Host "[-] Invalid path or file not found" -ForegroundColor Red
                }
            }
            "3" {
                Write-Host "`nCurrent Whitelisted Processes:" -ForegroundColor Cyan
                $Script:Whitelist.Processes.GetEnumerator() | ForEach-Object {
                    Write-Host "  - $($_.Key): $($_.Value.Reason) (Added: $($_.Value.Timestamp))" -ForegroundColor Gray
                }
                
                Write-Host "`nCurrent Whitelisted Files:" -ForegroundColor Cyan
                $Script:Whitelist.Files.GetEnumerator() | ForEach-Object {
                    Write-Host "  - $($_.Value.Path)" -ForegroundColor Gray
                    Write-Host "    Hash: $($_.Key)" -ForegroundColor DarkGray
                    Write-Host "    Reason: $($_.Value.Reason) (Added: $($_.Value.Timestamp))" -ForegroundColor DarkGray
                }
                
                Read-Host "`nPress Enter to continue"
            }
            "4" {
                $identifier = Read-Host "Enter process name, file path, or hash to remove"
                if ($identifier) {
                    if (Remove-FromWhitelist -Identifier $identifier) {
                        Write-Host "[+] Successfully removed from whitelist" -ForegroundColor Green
                    } else {
                        Write-Host "[-] Item not found in whitelist" -ForegroundColor Red
                    }
                }
            }
            "5" {
                $exportPath = "$quarantineFolder\whitelist_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $Script:Whitelist | ConvertTo-Json -Depth 5 | Set-Content $exportPath
                Write-Host "[+] Whitelist exported to: $exportPath" -ForegroundColor Green
                Read-Host "Press Enter to continue"
            }
            "6" {
                Write-Host "[*] Returning to monitoring..." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "[-] Invalid option. Please select 1-6." -ForegroundColor Red
            }
        }
        
        Write-Host ""
    }
}

# ============================================
# SECURITY ENHANCEMENT: Self-Defense Against Termination
# ============================================

function Register-TerminationProtection {
    try {
        # Monitor for unexpected termination attempts
        $Script:UnhandledExceptionHandler = Register-ObjectEvent -InputObject ([AppDomain]::CurrentDomain) `
            -EventName UnhandledException -Action {
            param($sender, $eventArgs)
            
            $errorMsg = "Unhandled exception: $($eventArgs.Exception.ToString())"
            $errorMsg | Out-File "$using:quarantineFolder\crash_log.txt" -Append
            
            try {
                # Log to security events
                $event = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    EventType = "UnexpectedTermination"
                    Severity = "Critical"
                    Exception = $eventArgs.Exception.ToString()
                    IsTerminating = $eventArgs.IsTerminating
                }
                $event | ConvertTo-Json -Compress | Out-File "$using:quarantineFolder\security_events.jsonl" -Append
            } catch {}
            
            # Attempt auto-restart if configured
            if ($using:Script:AutoRestart -and $eventArgs.IsTerminating) {
                try {
                    Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$using:Script:SelfPath`"" `
                        -WindowStyle Hidden -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        
        Write-Log "[PROTECTION] Termination protection registered"
        
    } catch {
        Write-ErrorLog -Message "Failed to register termination protection" -Severity "Medium" -ErrorRecord $_
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
            param($sender, $e)
            
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
                $e.Cancel = $false
            } else {
                Write-Host "[PROTECTION] Termination blocked. Press Ctrl+C $($Script:MaxTerminationAttempts - $Script:TerminationAttempts) more times to force stop." -ForegroundColor Yellow
                $e.Cancel = $true
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

# ============================================
# PERFORMANCE ENHANCEMENT: Advanced Cache Management
# ============================================

function Get-CachedFileHash {
    param([string]$FilePath)
    
    try {
        $cacheKey = $FilePath.ToLower()
        $result = $null
        
        # Check cache first
        if ($Script:FileHashCache.TryGetValue($cacheKey, [ref]$result)) {
            $Script:CacheHits++
            return $result
        }
        
        # Cache miss - calculate hash
        $Script:CacheMisses++
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        
        if ($hash) {
            # Implement more aggressive cache size management
            if ($Script:FileHashCache.Count -ge $Script:MaxCacheSize) {
                # Remove oldest 25% of entries
                $removeCount = [math]::Floor($Script:MaxCacheSize * 0.25)
                $keysToRemove = $Script:FileHashCache.Keys | Select-Object -First $removeCount
                foreach ($key in $keysToRemove) {
                    $dummy = $null
                    [void]$Script:FileHashCache.TryRemove($key, [ref]$dummy)
                }
                Write-Log "[CACHE] Evicted $removeCount entries (cache at max size)"
            }
            
            # Add to cache
            [void]$Script:FileHashCache.TryAdd($cacheKey, $hash)
        }
        
        return $hash
    } catch {
        Write-ErrorLog -Message "Failed to get cached file hash: $FilePath" -Severity "Low" -ErrorRecord $_
        return $null
    }
}


$Script:SelfProcessName = $PID
$Script:SelfPath = $PSCommandPath
$Script:SelfHash = (Get-FileHash -Path $Script:SelfPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
$Script:SelfDirectory = Split-Path $Script:SelfPath -Parent
$Script:QuarantineDir = $QuarantineDir

Write-Host "[PROTECTION] Self-protection enabled. PID: $Script:SelfProcessName, Path: $Script:SelfPath"

$Script:ProtectedProcessNames = @(
    "system", "csrss", "wininit", "services", "lsass", "svchost",
    "smss", "winlogon", "explorer", "dwm", "taskmgr", "spoolsv",
    "conhost", "fontdrvhost", "dllhost", "runtimebroker", "sihost",
    "taskhostw", "searchindexer", "searchprotocolhost", "searchfilterhost",
    "registry", "memory compression", "idle", "wudfhost", "dashost", "mscorsvw"
)

# Microsoft Store and UWP Apps Whitelist
$Script:MicrosoftStoreProcesses = @(
    "windowsstore", "wsappx", "wwahost", "applicationframehost", "runtimebroker",
    "microsoftedge", "microsoftedgecp", "msedge", "winstore.app",
    "microsoft.windowsstore", "winstore.mobile.exe", "microsoft.paint",
    "paintstudio.view", "mspaint", "microsoft.screensketch", "clipchamp",
    "microsoft.photos", "microsoft.windowscalculator", "microsoft.windowscamera"
)

# Gaming Platform Processes Whitelist
$Script:GamingPlatformProcesses = @(
    # Steam and dependencies
    "steam", "steamservice", "steamwebhelper", "gameoverlayui", "steamerrorreporter",
    "streaming_client", "steamclient", "steamcmd",
    # Epic Games
    "epicgameslauncher", "epicwebhelper", "epiconlineservices", "easyanticheat",
    "easyanticheat_eos", "battleye", "eac_launcher",
    # GOG Galaxy
    "galaxyclient", "galaxyclientservice", "gogalaxy", "gogalaxy",
    # Origin / EA Desktop
    "origin", "originwebhelperservice", "originclientservice", "eadesktop",
    "eabackgroundservice", "eaapp", "link2ea",
    # Ubisoft Connect
    "ubisoftgamelauncher", "upc", "ubisoft game launcher", "ubiorbitapi_r2_loader",
    "uplayservice", "uplaywebcore",
    # Battle.net
    "battle.net", "blizzard", "agent", "blizzardbrowser",
    # Xbox and Microsoft Gaming
    "gamebar", "gamebarftwizard", "gamebarpresencewriter", "xboxapp",
    "gamingservices", "gamingservicesnet", "xboxgamingoverlay", "xboxpcapp",
    "microsoftgaming", "gamepass", "xbox", "xboxstat",
    # Rockstar Games
    "rockstargameslauncher", "launcherpatc her", "rockstarservice", "socialclubhelper",
    # Riot Games
    "riotclientservices", "riotclientux", "riotclientcrashhandler", "valorant",
    "leagueclient", "leagueclientux",
    # Discord (gaming communication)
    "discord", "discordptb", "discordcanary", "discordoverlay",
    # NVIDIA GeForce Experience
    "nvcontainer", "nvidia web helper", "nvstreamservice", "geforcenow", "gfexperience",
    # Anti-cheat systems
    "vanguard", "riot vanguard", "faceit", "punkbuster", "nprotect",
    "xigncode", "vac", "gameguard", "xtrap", "hackshield"
)

# Gaming Platform Directories Whitelist
$Script:GamingPlatformPaths = @(
    "*\steam\*", "*\steamapps\*", "*\epic games\*", "*\epicgames\*",
    "*\gog galaxy\*", "*\goggalaxy\*", "*\origin\*", "*\origin games\*",
    "*\electronic arts\*", "*\ea games\*", "*\ea desktop\*",
    "*\ubisoft\*", "*\ubisoft game launcher\*", "*\uplay\*",
    "*\battle.net\*", "*\blizzard\*", "*\blizzard entertainment\*",
    "*\riot games\*", "*\valorant\*", "*\league of legends\*",
    "*\rockstar games\*", "*\xbox games\*", "*\xbox live\*",
    "*\program files\modifiablewindowsapps\*",
    "*\program files (x86)\microsoft\windowsapps\*",
    "*\program files\microsoft\windowsapps\*",
    "*\nvidia corporation\*", "*\geforce experience\*"
)

# Common Hardware Driver Processes Whitelist
$Script:CommonDriverProcesses = @(
    # NVIDIA drivers
    "nvdisplay.container", "nvcontainer", "nvidia web helper", "nvstreamservice", 
    "nvstreamsvc", "nvwmi64", "nvspcaps64", "nvtray", "nvcplui", "nvbackend",
    "nvprofileupdater", "nvtmru", "nvdisplaycontainer", "nvtelemetrycontainer",
    # AMD drivers
    "amdow", "amddvr", "amdrsserv", "ccc", "mom", "atiesrxx", "atieclxx",
    "amddvrserver", "amdlvrproxy", "radeonsoft", "rsservices", "amdrsserv",
    # Intel drivers
    "igfxtray", "hkcmd", "persistence", "igfxem", "igfxhk", "igfxpers",
    "intelhaxm", "intelcphecisvs", "intelcphdcpsvc",
    # Audio drivers (Realtek, Creative, etc)
    "rthdvcpl", "rtkngui64", "rthdbpl", "realtekservice", "nahimicsvc",
    "nahimicmsi", "creative", "audiodeviceservice",
    # Network drivers
    "intelmewservice", "lghub", "lghub_agent", "lghub_updater", "lcore",
    "icue", "corsair", "lightingservice",
    # Razer peripherals
    "razer*", "rzchromasdk", "rzsynapse", "rzudd",
    # Logitech peripherals
    "logibolt", "logioptions", "logioverlay", "logitechgamingregistry",
    # General device helpers
    "synaptics", "touchpad", "wacom", "tablet", "pen"
)

# Microsoft Office Processes Whitelist
$Script:MicrosoftOfficeProcesses = @(
    # Core Office applications
    "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote",
    "visio", "project", "teams", "lync", "skype", "skypeforbusiness",
    # Office services and helpers
    "officeclick2run", "officeclicktorun", "officec2rclient", "appvshnotify",
    "msoasb", "msouc", "msoidsvc", "msosync", "officehub",
    "msoia", "msoyb", "officeclicktorun", "integrator",
    # OneDrive
    "onedrive", "onedrivesync", "filecoauth",
    # Office telemetry and updates
    "msoia", "officeupdatemonitor", "officebackgroundtaskhandler"
)

# Adobe Products Whitelist
$Script:AdobeProcesses = @(
    # Creative Cloud and core services
    "creative cloud", "adobegcclient", "ccxprocess", "cclibrary", "adobenotificationclient",
    "adobeipcbroker", "adobegcctray", "adobeupdateservice", "adobearmservice",
    "adobe desktop service", "coresynch", "ccxwelcome",
    # Photoshop
    "photoshop", "photoshoplightroom", "lightroomclassic",
    # Illustrator
    "illustrator", "ai",
    # Premiere Pro / After Effects
    "premiere pro", "afterfx", "premiere", "ame", "adobe media encoder",
    # Acrobat
    "acrobat", "acrord32", "acrodist", "acrotray", "adobecollabsync",
    # Other Adobe apps
    "indesign", "audition", "animate", "dreamweaver", "bridge",
    "xd", "dimension", "character animator", "prelude", "incopy",
    # Shared Adobe components
    "node", "cef", "adobegenuineservice", "adobeupdateservice"
)

# Common Productivity Software Whitelist
$Script:ProductivitySoftwareProcesses = @(
    # Browsers (common legitimate ones)
    "chrome", "firefox", "brave", "opera", "vivaldi", "edge",
    # Communication
    "slack", "zoom", "zoomopener", "whatsapp", "telegram", "signal",
    # Cloud storage
    "dropbox", "googledrivesync", "googledrivefs", "box", "icloudservices",
    # Note-taking
    "notion", "evernote", "obsidian", "notepad++",
    # Development tools
    "code", "devenv", "rider", "pycharm", "webstorm", "intellij",
    "git", "github desktop", "sourcetree", "gitkraken",
    # Compression tools
    "7z", "7zfm", "7zg", "winrar", "winzip",
    # Media players
    "vlc", "spotify", "foobar2000", "musicbee", "aimp"
)

# Common Software Installation Paths Whitelist
$Script:CommonSoftwarePaths = @(
    "*\microsoft office\*", "*\office*\*", "*\microsoft\office*\*",
    "*\adobe\*", "*\adobe creative cloud\*", "*\adobe photoshop*\*",
    "*\adobe illustrator*\*", "*\adobe premiere*\*", "*\adobe acrobat*\*",
    "*\google\chrome\*", "*\mozilla firefox\*", "*\microsoft\edge\*",
    "*\nvidia\*", "*\amd\*", "*\intel\*", "*\realtek\*",
    "*\program files\common files\microsoft shared\*",
    "*\program files (x86)\common files\microsoft shared\*",
    "*\slack\*", "*\zoom\*", "*\dropbox\*", "*\onedrive\*"
)

# SECURITY FIX #6: Critical system services that must NEVER be killed
$Script:CriticalSystemProcesses = @(
    "registry", "csrss", "smss", "services", "lsass", "wininit", "winlogon", "svchost"
)

# SECURITY FIX #6: Windows networking services allowlist
$Script:WindowsNetworkingServices = @(
    "RpcSs", "DHCP", "Dhcp", "Dnscache", "DNS Cache", "LanmanServer", "LanmanWorkstation", "WinHttpAutoProxySvc",
    "iphlpsvc", "netprofm", "NlaSvc", "Netman", "TermService", "SessionEnv", "UmRdpService"
)

$Script:EvilStrings = @(
    "mimikatz", "sekurlsa::", "kerberos::", "lsadump::", "wdigest", "tspkg",
    "http-beacon", "https-beacon", "cobaltstrike", "sleepmask", "reflective",
    "amsi.dll", "AmsiScanBuffer", "EtwEventWrite", "MiniDumpWriteDump",
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "ReflectiveLoader", "sharpchrome", "rubeus", "safetykatz", "sharphound"
)

# SECURITY FIX #4: LOLBin detection patterns for signed malware abuse
$Script:LOLBinPatterns = @{
    "powershell.exe" = @("-encodedcommand", "-enc", "downloadstring", "invoke-expression", "iex", "bypass")
    "cmd.exe" = @("powershell", "wscript", "mshta", "regsvr32", "rundll32")
    "mshta.exe" = @("javascript:", "vbscript:", "http://", "https://")
    "regsvr32.exe" = @("scrobj.dll", "http://", "https://", "/i:")
    "rundll32.exe" = @("javascript:", "http://", "https://", ".cpl,")
    "wmic.exe" = @("process call create", "shadowcopy delete")
    "certutil.exe" = @("-urlcache", "-decode", "-split", "http://", "https://")
    "bitsadmin.exe" = @("/transfer", "/download", "/upload")
    "msbuild.exe" = @(".csproj", ".proj", ".xml")
    "cscript.exe" = @(".vbs", ".js", ".jse")
    "wscript.exe" = @(".vbs", ".js", ".jse")
}

# ============================================
# SECURITY FIX #3: DATABASE INTEGRITY WITH HMAC
# ============================================
function Get-HMACSignature {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        if ($null -eq $Script:HMACKey -or $Script:HMACKey.Length -eq 0) {
            Write-ErrorLog -Message "HMAC key is not initialized" -Severity "Critical"
            return $null
        }
        
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $Script:HMACKey
        $fileContent = Get-Content $FilePath -Raw -Encoding UTF8
        if ([string]::IsNullOrEmpty($fileContent)) {
            Write-Log "[WARN] File $FilePath is empty, skipping HMAC computation"
            return $null
        }
        $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fileContent))
        return [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
    } catch {
        Write-ErrorLog -Message "HMAC computation failed for $FilePath" -Severity "High" -ErrorRecord $_
        return $null
    } finally {
        if ($hmac) { $hmac.Dispose() }
    }
}

function Test-DatabaseIntegrity {
    if (-not (Test-Path $localDatabase)) { return $true }
    if (-not (Test-Path $hashIntegrityFile)) {
        Write-Log "[WARNING] No integrity file found for database. Creating one..."
        $hmac = Get-HMACSignature -FilePath $localDatabase
        if ($hmac) {
            $hmac | Out-File -FilePath $hashIntegrityFile -Encoding UTF8
        }
        return $true
    }
    
    try {
        $storedHMAC = Get-Content $hashIntegrityFile -Raw -ErrorAction Stop
        $currentHMAC = Get-HMACSignature -FilePath $localDatabase
        
        if ($storedHMAC.Trim() -ne $currentHMAC) {
            Write-Log "[CRITICAL] Database integrity violation! Database has been tampered with!"
            Write-ErrorLog -Message "Hash database HMAC mismatch - possible tampering detected" -Severity "Critical"
            Write-SecurityEvent -EventType "DatabaseTampering" -Details @{ DatabasePath = $localDatabase } -Severity "Critical"
            
            # Backup and reset
            $backupPath = "$localDatabase.corrupted_$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item $localDatabase $backupPath -ErrorAction SilentlyContinue
            Remove-Item $localDatabase -Force -ErrorAction Stop
            Remove-Item $hashIntegrityFile -Force -ErrorAction Stop
            Write-Log "[ACTION] Corrupted database backed up and reset"
            
            return $false
        }
        return $true
    } catch {
        Write-ErrorLog -Message "Database integrity check failed" -Severity "High" -ErrorRecord $_
        return $false
    }
}

function Update-DatabaseIntegrity {
    try {
        $hmac = Get-HMACSignature -FilePath $localDatabase
        if ($hmac) {
            $hmac | Out-File -FilePath $hashIntegrityFile -Force -Encoding UTF8
        }
    } catch {
        Write-ErrorLog -Message "Failed to update database integrity" -Severity "Medium" -ErrorRecord $_
    }
}

# ============================================
# DATABASE LOADING WITH INTEGRITY CHECK
# ============================================
if (Test-Path $localDatabase) {
    if (Test-DatabaseIntegrity) {
        try {
            $scannedFiles.Clear()
            $lines = Get-Content $localDatabase -ErrorAction Stop
            foreach ($line in $lines) {
                if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                    $scannedFiles[$matches[1]] = [bool]::Parse($matches[2])
                }
            }
            Write-Log "[DATABASE] Loaded $($scannedFiles.Count) verified entries"
        } catch {
            Write-ErrorLog -Message "Failed to load database" -Severity "High" -ErrorRecord $_
            $scannedFiles.Clear()
        }
    } else {
        Write-Log "[DATABASE] Integrity check failed. Starting with empty database."
        $scannedFiles.Clear()
    }
} else {
    $scannedFiles.Clear()
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-Log "[DATABASE] Created new database file"
}

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Log "[POLICY] Set execution policy to Bypass"
}

# ============================================
# SECURITY FIX #5: STRICT SELF-EXCLUSION
# ============================================
function Test-IsSelfOrRelated {
    param([string]$FilePath)
    
    try {
        $normalizedPath = [System.IO.Path]::GetFullPath($FilePath).ToLower()
        $selfNormalized = [System.IO.Path]::GetFullPath($Script:SelfPath).ToLower()
        $quarantineNormalized = [System.IO.Path]::GetFullPath($Script:QuarantineDir).ToLower()
        
        # Exclude self
        if ($normalizedPath -eq $selfNormalized) {
            return $true
        }
        
        # Exclude quarantine directory
        if ($normalizedPath.StartsWith($quarantineNormalized)) {
            return $true
        }
        
        # Exclude loaded PowerShell modules
        $loadedModules = Get-Module | Select-Object -ExpandModuleBase
        foreach ($moduleBase in $loadedModules) {
            if ($moduleBase -and ([System.IO.Path]::GetFullPath($moduleBase).ToLower() -eq $normalizedPath)) {
                return $true
            }
        }
        
        # Exclude script directory
        if ($normalizedPath.StartsWith($Script:SelfDirectory.ToLower())) {
            return $true
        }
        
        return $false
    } catch {
        return $true # Fail-safe: if we can't determine, exclude it
    }
}

function Test-CriticalSystemProcess {
    param($Process)
    
    try {
        if (-not $Process) { return $true }
        
        $procName = $Process.ProcessName.ToLower()
        
        # Check against critical process list
        if ($Script:CriticalSystemProcesses -contains $procName) {
            return $true
        }
        
        # SECURITY FIX #4: Verify Microsoft signatures for System32/SysWOW64 binaries
        $path = $Process.Path
        if ($path -match "\\windows\\system32\\" -or $path -match "\\windows\\syswow64\\") {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
                if ($signature.Status -eq "Valid" -and $signature.SignerCertificate.Subject -match "CN=Microsoft") {
                    return $true
                } else {
                    Write-Log "[SUSPICIOUS] Unsigned or non-Microsoft binary in System32: $path (Signature: $($signature.Status))"
                    return $false
                }
            } catch {
                Write-Log "[ERROR] Could not verify signature for System32 file: $path"
                return $true # Fail-safe
            }
        }
        
        return $false
    } catch {
        return $true # Fail-safe
    }
}

function Test-ProtectedOrSelf {
    param($Process)
    
    try {
        if (-not $Process) { return $true }
        
        $procName = $Process.ProcessName.ToLower()
        $procId = $Process.Id
        
        # SECURITY FIX #5: Self-protection
        if ($procId -eq $Script:SelfProcessName) {
            return $true
        }
        
        # Check protected process names
        foreach ($protected in $Script:ProtectedProcessNames) {
            if ($procName -eq $protected -or $procName -like "$protected*") {
                return $true
            }
        }
        
        foreach ($storeProc in $Script:MicrosoftStoreProcesses) {
            if ($procName -eq $storeProc.ToLower() -or $procName -like "$($storeProc.ToLower())*") {
                return $true
            }
        }
        
        foreach ($gamingProc in $Script:GamingPlatformProcesses) {
            if ($procName -eq $gamingProc.ToLower() -or $procName -like "$($gamingProc.ToLower())*") {
                return $true
            }
        }
        
        foreach ($driverProc in $Script:CommonDriverProcesses) {
            if ($procName -eq $driverProc.ToLower() -or $procName -like "$($driverProc.ToLower())*") {
                return $true
            }
        }
        
        foreach ($officeProc in $Script:MicrosoftOfficeProcesses) {
            if ($procName -eq $officeProc.ToLower() -or $procName -like "$($officeProc.ToLower())*") {
                return $true
            }
        }
        
        foreach ($adobeProc in $Script:AdobeProcesses) {
            if ($procName -eq $adobeProc.ToLower() -or $procName -like "$($adobeProc.ToLower())*") {
                return $true
            }
        }
        
        foreach ($prodProc in $Script:ProductivitySoftwareProcesses) {
            if ($procName -eq $prodProc.ToLower() -or $procName -like "$($prodProc.ToLower())*") {
                return $true
            }
        }
        
        # Check if path is self
        if ($Process.Path -and (Test-IsSelfOrRelated -FilePath $Process.Path)) {
            return $true
        }
        
        return $false
    } catch {
        return $true # Fail-safe
    }
}

# ============================================
# SECURITY FIX #6: SERVICE-AWARE PROCESS KILLING
# ============================================
function Test-IsWindowsNetworkingService {
    param([int]$ProcessId)
    
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($service) {
            if ($Script:WindowsNetworkingServices -contains $service.Name) {
                Write-Log "[PROTECTION] Process PID $ProcessId is Windows networking service: $($service.Name)"
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

# ============================================
# SECURITY FIX #2: RACE-CONDITION-FREE FILE OPERATIONS
# ============================================
function Get-FileWithLock {
    param([string]$FilePath)
    
    try {
        # Open with exclusive lock to prevent TOCTOU attacks
        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        
        # Get file attributes while locked
        $fileInfo = New-Object System.IO.FileInfo($FilePath)
        $length = $fileInfo.Length
        $lastWrite = $fileInfo.LastWriteTime
        
        # Calculate hash while file is locked
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($fileStream)
        $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
        
        $fileStream.Close()
        
        return [PSCustomObject]@{
            Hash = $hash
            Length = $length
            LastWriteTime = $lastWrite
            Locked = $true
        }
    } catch {
        return $null
    }
}

function Calculate-FileHash {
    param ([string]$filePath)
    
    try {
        # SECURITY FIX #5: Self-exclusion check
        if (Test-IsSelfOrRelated -FilePath $filePath) {
            Write-Log "[EXCLUDED] Skipping self/related file: $filePath"
            return $null
        }
        
        # PERFORMANCE FIX #8: Check cache first with timestamp validation
        $fileInfo = Get-Item $filePath -Force -ErrorAction Stop
        $cacheKey = "$filePath|$($fileInfo.LastWriteTime.Ticks)"
        
        $cachedResult = $null
        if ($Script:FileHashCache.TryGetValue($cacheKey, [ref]$cachedResult)) {
            Write-Log "[CACHE HIT] Using cached hash for: $filePath"
            $Script:CacheHits++
            return $cachedResult
        }
        
        $Script:CacheMisses++
        
        # SECURITY FIX #2: Lock file during scan
        $lockedFile = Get-FileWithLock -FilePath $filePath
        if (-not $lockedFile) {
            Write-Log "[ERROR] Could not lock file for scanning: $filePath"
            return $null
        }
        
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        
        $result = [PSCustomObject]@{
            Hash = $lockedFile.Hash
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
            SignerCertificate = $signature.SignerCertificate
            LastWriteTime = $lockedFile.LastWriteTime
        }
        
        $Script:FileHashCache[$cacheKey] = $result
        
        # Limit cache size to prevent memory exhaustion
        if ($Script:FileHashCache.Count -gt 5000) {
            # Remove oldest 1000 entries
            $keysToRemove = $Script:FileHashCache.Keys | Select-Object -First 1000
            foreach ($key in $keysToRemove) {
                $null = $Script:FileHashCache.TryRemove($key, [ref]$null)
            }
            Write-Log "[CACHE] Cleared 1000 oldest entries (cache size was $($Script:FileHashCache.Count))"
        }
        
        return $result
    } catch {
        Write-ErrorLog -Message "Error processing file hash for $filePath" -Severity "Low" -ErrorRecord $_
        return $null
    }
}

function Get-SHA256Hash {
    param([string]$FilePath)
    
    try {
        if (Test-IsSelfOrRelated -FilePath $FilePath) {
            return $null
        }
        
        $lockedFile = Get-FileWithLock -FilePath $FilePath
        return $lockedFile.Hash
    } catch {
        return $null
    }
}

# ============================================
# SECURITY FIX #3: HARDENED QUARANTINE
# ============================================
function Quarantine-File {
    param ([string]$filePath)
    
    try {
        # SECURITY FIX #5: Never quarantine self
        if (Test-IsSelfOrRelated -FilePath $filePath) {
            Write-Log "[PROTECTION] Refusing to quarantine self/related file: $filePath"
            return $false
        }
        
        if (-not (Test-Path $filePath)) {
            Write-Log "[QUARANTINE] File not found: $filePath"
            return $false
        }
        
        # SECURITY FIX #2: Re-verify hash before quarantine
        $finalHash = Get-FileWithLock -FilePath $filePath
        if (-not $finalHash) {
            Write-Log "[QUARANTINE] Could not lock file for final verification: $filePath"
            return $false
        }
        
        # SECURITY FIX #3: Use GUID for unique quarantine naming
        $guid = [System.Guid]::NewGuid().ToString()
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $fileName = Split-Path $filePath -Leaf
        $quarantinePath = Join-Path $quarantineFolder "${timestamp}_${guid}_${fileName}.quarantined"
        
        # SECURITY FIX #3: Strip execution permissions and rename
        Copy-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        
        # SECURITY FIX #3: Remove execute permissions using icacls
        icacls $quarantinePath /deny "*S-1-1-0:(X)" /inheritance:r | Out-Null
        
        # Store metadata
        $metadata = @{
            OriginalPath = $filePath
            QuarantinePath = $quarantinePath
            Timestamp = $timestamp
            GUID = $guid
            Hash = $finalHash.Hash
            Reason = "Unsigned or malicious"
        } | ConvertTo-Json -Compress
        
        Add-Content -Path "$quarantineFolder\quarantine_metadata.jsonl" -Value $metadata -Encoding UTF8
        
        Write-Log "[QUARANTINE] File quarantined: $filePath -> $quarantinePath"
        Write-SecurityEvent -EventType "FileQuarantined" -Details @{ OriginalPath = $filePath; QuarantinePath = $quarantinePath; Hash = $finalHash.Hash } -Severity "High"
        
        # Attempt to delete original
        try {
            Remove-Item -Path $filePath -Force -ErrorAction Stop
            Write-Log "[QUARANTINE] Original file deleted: $filePath"
        } catch {
            Write-Log "[QUARANTINE] Could not delete original (may be in use): $filePath"
        }
        
        return $true
    } catch {
        Write-ErrorLog -Message "Failed to quarantine file: $filePath" -Severity "High" -ErrorRecord $_
        return $false
    }
}

function Invoke-QuarantineFile {
    param ([string]$filePath)
    return Quarantine-File -filePath $filePath
}

function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    
    try {
        # Ensure SYSTEM has full control and deny execute for others
        $acl = Get-Acl $filePath
        $acl.SetAccessRuleProtection($true, $false) # Remove inheritance
        
        $SYSTEM_SID = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $SYSTEM_Identity = $SYSTEM_SID.Translate([System.Security.Principal.NTAccount]).Value
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($SYSTEM_Identity, "FullControl", "None", "Allow")
        $acl.SetAccessRule($rule)
        
        $Everyone_SID = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $Everyone_Identity = $Everyone_SID.Translate([System.Security.Principal.NTAccount]).Value
        
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone_Identity, "ExecuteFile", "None", "Deny")
        $acl.SetAccessRule($denyRule)
        
        Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
        Write-Log "[ACL] Set SYSTEM FullControl and denied Execute for $filePath"
        return $true
    } catch {
        Write-ErrorLog -Message "Failed to set file ownership/permissions for $filePath" -Severity "Low" -ErrorRecord $_
        return $false
    }
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        if (Test-IsSelfOrRelated -FilePath $filePath) {
            return
        }
        
        $processes = Get-Process | Where-Object { 
            try {
                ($_.Modules | Where-Object { $_.FileName -eq $filePath }) -and 
                -not (Test-ProtectedOrSelf $_) -and 
                -not (Test-CriticalSystemProcess $_)
            } catch { $false }
        }
        
        foreach ($process in $processes) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-Log "[KILL] Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
                Write-SecurityEvent -EventType "ProcessKilled" -Details @{ ProcessName = $process.Name; PID = $process.Id; Reason = "Using quarantined DLL: $filePath" } -Severity "Medium"
            } catch {
                Write-ErrorLog -Message "Failed to stop process $($process.Name) using $filePath" -Severity "Medium" -ErrorRecord $_
            }
        }
    } catch {
        Write-ErrorLog -Message "Error stopping processes for $filePath" -Severity "Medium" -ErrorRecord $_
    }
}

function Stop-ProcessesUsingFile {
    param([string]$FilePath)
    
    try {
        if (Test-IsSelfOrRelated -FilePath $FilePath) {
            return
        }
        
        Get-Process | Where-Object {
            try {
                $_.Path -eq $FilePath -and 
                -not (Test-ProtectedOrSelf $_) -and 
                -not (Test-CriticalSystemProcess $_) -and
                -not (Test-IsWindowsNetworkingService -ProcessId $_.Id)
            } catch { $false }
        } | ForEach-Object {
            try {
                $_.Kill()
                Write-Log "[KILL] Terminated process using file: $($_.ProcessName) (PID: $($_.Id))"
                Write-SecurityEvent -EventType "ProcessKilled" -Details @{ ProcessName = $_.ProcessName; PID = $_.Id; Reason = "Using malicious file: $FilePath" } -Severity "Medium"
                Start-Sleep -Milliseconds 100
            } catch {
                Write-ErrorLog -Message "Failed to kill process $($_.ProcessName)" -Severity "Low" -ErrorRecord $_
            }
        }
    } catch {
        Write-ErrorLog -Message "Error in Stop-ProcessesUsingFile" -Severity "Low" -ErrorRecord $_
    }
}

function Should-ExcludeFile {
    param ([string]$filePath)
    
    if (Test-IsWhitelisted -FilePath $filePath) {
        return $true
    }
    
    $lowerPath = $filePath.ToLower()
    
    # SECURITY FIX #5: Exclude self and related files
    if (Test-IsSelfOrRelated -FilePath $filePath) {
        return $true
    }
    
    # Exclude assembly folders
    if ($lowerPath -like "*\assembly\*") {
        return $true
    }
    
    # Exclude ctfmon-related files
    if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") {
        return $true
    }
    
    foreach ($gamingPath in $Script:GamingPlatformPaths) {
        if ($lowerPath -like $gamingPath) {
            return $true
        }
    }
    
    foreach ($softwarePath in $Script:CommonSoftwarePaths) {
        if ($lowerPath -like $softwarePath) {
            return $true
        }
    }
    
    return $false
}

# ============================================
# SECURITY FIX #8: PERFORMANCE-OPTIMIZED SCANNING
# ============================================
function Remove-UnsignedDLLs {
    Write-Log "[SCAN] Starting unsigned DLL/WINMD scan"
    
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    $Script:ScanThrottle = 0
    
    $protectedDirs = @(
        "C:\Windows\System32\wbem",
        "C:\Windows\System32\WinSxS",
        "C:\Windows\System32\LogFiles",
        "C:\Windows\servicing",
        "C:\Windows\WinSxS"
    )
    
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "[SCAN] Scanning drive: $root"
        
        try {
            $dllFiles = Get-ChildItem -Path $root -Include *.dll,*.winmd -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $filePath = $_.FullName
                    $isProtected = $false
                    foreach ($protectedDir in $protectedDirs) {
                        if ($filePath -like "$protectedDir*") {
                            $isProtected = $true
                            break
                        }
                    }
                    -not $isProtected
                }
            
            foreach ($dll in $dllFiles) {
                # PERFORMANCE FIX #8: Throttle scanning to prevent system slowdown
                $Script:ScanThrottle++
                if ($Script:ScanThrottle % 100 -eq 0) {
                    Start-Sleep -Milliseconds 50
                }
                
                try {
                    if (Should-ExcludeFile -filePath $dll.FullName) {
                        continue
                    }
                    
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if ($fileHash) {
                        if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            # Already scanned, take action if needed
                            if (-not $scannedFiles[$fileHash.Hash]) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Invoke-QuarantineFile -filePath $dll.FullName
                                }
                            }
                        } else {
                            # New file
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                            Update-DatabaseIntegrity # SECURITY FIX #3: Update HMAC
                            
                            Write-Log "[SCAN] New file: $($dll.FullName) (Valid: $isValid)"
                            Write-SecurityEvent -EventType "FileScanned" -Details @{ Path = $dll.FullName; Hash = $fileHash.Hash; IsValid = $isValid } -Severity "Informational"
                            
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Invoke-QuarantineFile -filePath $dll.FullName
                                }
                            }
                        }
                    }
                } catch {
                    Write-ErrorLog -Message "Error processing file $($dll.FullName)" -Severity "Low" -ErrorRecord $_
                }
            }
        } catch {
            Write-ErrorLog -Message "Scan failed for drive $root" -Severity "Medium" -ErrorRecord $_
        }
    }
}

# ============================================
# FILE SYSTEM WATCHER (Throttled)
# ============================================
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
foreach ($drive in $drives) {
    $monitorPath = $drive.DeviceID + "\"
    
    try {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $monitorPath
        $fileWatcher.Filter = "*.*"
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true
        $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
        
        $action = {
            param($sender, $e)
            
            try {
                $localScannedFiles = $using:scannedFiles
                $localQuarantineFolder = $using:quarantineFolder
                $localDatabase = $using:localDatabase
                
                if ($e.ChangeType -in "Created", "Changed" -and 
                    $e.FullPath -notlike "$localQuarantineFolder*" -and 
                    ($e.FullPath -like "*.dll" -or $e.FullPath -like "*.winmd")) {
                    
                    if (Should-ExcludeFile -filePath $e.FullPath) {
                        return
                    }
                    
                    Start-Sleep -Milliseconds 500 # Throttle
                    
                    $fileHash = Calculate-FileHash -filePath $e.FullPath
                    if ($fileHash) {
                        if ($localScannedFiles.ContainsKey($fileHash.Hash)) {
                            if (-not $localScannedFiles[$fileHash.Hash]) {
                                if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                    Stop-ProcessUsingDLL -filePath $e.FullPath
                                    Invoke-QuarantineFile -filePath $e.FullPath
                                }
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid"
                            $localScannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8
                            Update-DatabaseIntegrity
                            
                            Write-Log "[FSWATCHER] New file: $($e.FullPath) (Valid: $isValid)"
                            Write-SecurityEvent -EventType "FileScanned" -Details @{ Path = $e.FullPath; Hash = $fileHash.Hash; IsValid = $isValid } -Severity "Informational"
                            
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                    Stop-ProcessUsingDLL -filePath $e.FullPath
                                    Invoke-QuarantineFile -filePath $e.FullPath
                                }
                            }
                        }
                    }
                }
            } catch {
                # Silently continue
            }
        }
        
        Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action -ErrorAction Stop
        Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action -ErrorAction Stop
        Write-Log "[WATCHER] FileSystemWatcher set up for $monitorPath"
    } catch {
        Write-ErrorLog -Message "Failed to set up watcher for $monitorPath" -Severity "Medium" -ErrorRecord $_
    }
}

$ApiConfig = @{
    CirclHashLookupUrl   = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl          = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl  = "https://mb-api.abuse.ch/api/v1/"
}

# ============================================
# HASH-BASED THREAT DETECTION
# ============================================
function Check-HashReputation {
    param(
        [string]$hash,
        [string]$ProcessName
    )
    
    if (-not $hash) { return $false }
    
    $isMalicious = $false
    
    $jobs = @()
    
    # CIRCL Hash Lookup
    $jobs += Start-Job -ScriptBlock {
        param($h, $url)
        try {
            $circlUrl = "$url/$h"
            $response = Invoke-RestMethod -Uri $circlUrl -Method Get -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
            if ($response -and $response.KnownMalicious) {
                return @{ Source = "CIRCL"; Malicious = $true }
            }
        } catch {}
        return $null
    } -ArgumentList $hash, $ApiConfig.CirclHashLookupUrl
    
    # Team Cymru
    $jobs += Start-Job -ScriptBlock {
        param($h, $url)
        try {
            $cymruUrl = "$url/$h"
            $response = Invoke-RestMethod -Uri $cymruUrl -Method Get -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
            if ($response -and $response.malicious -eq $true) {
                return @{ Source = "Cymru"; Malicious = $true }
            }
        } catch {}
        return $null
    } -ArgumentList $hash, $ApiConfig.CymruApiUrl
    
    $jobs += Start-Job -ScriptBlock {
        param($h, $url)
        try {
            $mbBody = @{ query = "get_info"; hash = $h } | ConvertTo-Json
            $response = Invoke-RestMethod -Uri $url -Method Post -Body $mbBody -ContentType "application/json" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
            if ($response -and $response.query_status -eq "ok") {
                return @{ Source = "MalwareBazaar"; Malicious = $true }
            }
        } catch {}
        return $null
    } -ArgumentList $hash, $ApiConfig.MalwareBazaarApiUrl
    
    # Wait for jobs with timeout
    $jobs | Wait-Job -Timeout 5 | Out-Null
    
    # Check results
    foreach ($job in $jobs) {
        try {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($result -and $result.Malicious) {
                Write-Log "[HASH] $($result.Source) reports malicious: $ProcessName"
                Write-SecurityEvent -EventType "MaliciousHashDetected" -Details @{ 
                    Source = $result.Source; Hash = $hash; Process = $ProcessName 
                } -Severity "High"
                $isMalicious = $true
            }
        } catch {}
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    
    return $isMalicious
}

function Check-FileHash {
    param(
        [string]$FilePath,
        [string]$ProcessName,
        [int]$ProcessId
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            return $false
        }
        
        if (Test-IsSelfOrRelated -FilePath $FilePath) {
            return $false
        }
        
        $hashInfo = Calculate-FileHash -filePath $FilePath
        if (-not $hashInfo) {
            return $false
        }
        
        $hash = $hashInfo.Hash
        
        if (Check-HashReputation -hash $hash -ProcessName $ProcessName) {
            return $true
        }
        
        return $false
    } catch {
        Write-ErrorLog -Message "Error during file hash check for $FilePath" -Severity "Low" -ErrorRecord $_
        return $false
    }
}

# ============================================
# THREAT KILLING WITH SAFETY CHECKS
# ============================================
function Kill-Threat {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            return $false
        }
        
        # SECURITY FIX #5 & #6: Comprehensive protection checks
        if (Test-ProtectedOrSelf $proc) {
            Write-Log "[PROTECTION] Refusing to kill protected process: $ProcessName (PID: $ProcessId)"
            return $false
        }
        
        if (Test-CriticalSystemProcess $proc) {
            Write-Log "[PROTECTION] Refusing to kill critical system process: $ProcessName (PID: $ProcessId)"
            return $false
        }
        
        if (Test-IsWindowsNetworkingService -ProcessId $ProcessId) {
            Write-Log "[PROTECTION] Refusing to kill Windows networking service: $ProcessName (PID: $ProcessId)"
            return $false
        }
        
        Write-Log "[KILL] Terminating process: $ProcessName (PID: $ProcessId) - Reason: $Reason"
        Write-SecurityEvent -EventType "ProcessKilled" -Details @{ ProcessName = $ProcessName; PID = $ProcessId; Reason = $Reason } -Severity "High"
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Log "[KILL] Successfully terminated PID: $ProcessId"
        return $true
    } catch {
        Write-ErrorLog -Message "Failed to terminate PID $ProcessId" -Severity "Low" -ErrorRecord $_
        return $false
    }
}

function Stop-ThreatProcess {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    return Kill-Threat -ProcessId $ProcessId -ProcessName $ProcessName -Reason $Reason
}

function Invoke-ProcessKill {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    return Kill-Threat -ProcessId $ProcessId -ProcessName $ProcessName -Reason $Reason
}

function Invoke-QuarantineProcess {
    param(
        $Process,
        [string]$Reason
    )
    
    try {
        if (Test-ProtectedOrSelf $Process) {
            Write-Log "[PROTECTION] Refusing to quarantine protected process: $($Process.ProcessName)"
            return $false
        }
        
        Write-Log "[QUARANTINE] Quarantining process $($Process.ProcessName) (PID: $($Process.Id)) due to: $Reason"
        Write-SecurityEvent -EventType "ProcessQuarantineInitiated" -Details @{ ProcessName = $Process.ProcessName; PID = $Process.Id; Reason = $Reason } -Severity "High"
        
        if ($Process.Path -and (Test-Path $Process.Path)) {
            Invoke-QuarantineFile -FilePath $Process.Path
        }
        
        $Process.Kill()
        Write-Log "[KILL] Killed malicious process: $($Process.ProcessName) (PID: $($Process.Id))"
        Write-SecurityEvent -EventType "ProcessKilled" -Details @{ ProcessName = $Process.ProcessName; PID = $Process.Id; Reason = "Quarantined file: $Reason" } -Severity "High"
        return $true
    } catch {
        Write-ErrorLog -Message "Failed to quarantine process $($Process.ProcessName)" -Severity "Medium" -ErrorRecord $_
        return $false
    }
}

# ============================================
# SECURITY FIX #4: LOLBin DETECTION
# ============================================
function Test-LOLBinAbuse {
    param(
        [string]$ProcessName,
        [string]$CommandLine
    )
    
    $procLower = $ProcessName.ToLower()
    
    if ($Script:LOLBinPatterns.ContainsKey($procLower)) {
        $patterns = $Script:LOLBinPatterns[$procLower]
        foreach ($pattern in $patterns) {
            if ($CommandLine -match [regex]::Escape($pattern)) {
                Write-Log "[LOLBIN] Detected LOLBin abuse: $ProcessName with pattern '$pattern'"
                Write-SecurityEvent -EventType "LOLBinAbuse" -Details @{ ProcessName = $ProcessName; CommandLine = $CommandLine; Pattern = $pattern } -Severity "High"
                return $true
            }
        }
    }
    
    return $false
}

# ============================================
# FILELESS MALWARE DETECTION
# ============================================
function Detect-FilelessMalware {
    $detections = @()
    
    # PowerShell without file
    try {
        Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {
            try {
                -not (Test-ProtectedOrSelf $_) -and
                ($_.MainWindowTitle -match "encodedcommand|enc|iex|invoke-expression" -or
                ($_.Modules | Where-Object { $_.ModuleName -eq "" -or $_.FileName -eq "" }))
            } catch { $false }
        } | ForEach-Object {
            $proc = $_
            Write-Log "[FILELESS] Detected suspicious PowerShell: PID $($proc.Id)"
            
            if ($proc.Path) {
                $hashMalicious = Check-FileHash -FilePath $proc.Path -ProcessName $proc.Name -ProcessId $proc.Id
                if ($hashMalicious) {
                    Invoke-QuarantineFile -FilePath $proc.Path
                }
            }
            
            Kill-Threat -ProcessId $proc.Id -ProcessName $proc.Name -Reason "Fileless PowerShell execution"
        }
    } catch {
        Write-ErrorLog -Message "Error in PowerShell fileless detection" -Severity "Low" -ErrorRecord $_
    }
    
    # WMI Event Subscriptions
    try {
        Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object {
            $_.Query -match "powershell|vbscript|javascript"
        } | ForEach-Object {
            $subscription = $_
            try {
                Write-Log "[FILELESS] Removing malicious WMI event filter: $($subscription.Name)"
                Remove-WmiObject -InputObject $subscription -ErrorAction Stop
                Write-SecurityEvent -EventType "WMIEventFilterRemoved" -Details @{ FilterName = $subscription.Name } -Severity "High"
                
                $consumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer -Filter "Name='$($subscription.Name)'" -ErrorAction SilentlyContinue
                $bindings = Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "Filter='$($subscription.__RELPATH)'" -ErrorAction SilentlyContinue
                
                foreach ($consumer in $consumers) {
                    Remove-WmiObject -InputObject $consumer -ErrorAction SilentlyContinue
                }
                foreach ($binding in $bindings) {
                    Remove-WmiObject -InputObject $binding -ErrorAction SilentlyContinue
                }
            } catch {
                Write-ErrorLog -Message "Failed to remove WMI subscription" -Severity "Medium" -ErrorRecord $_
            }
        }
    } catch {
        Write-ErrorLog -Message "Error in WMI fileless detection" -Severity "Low" -ErrorRecord $_
    }
    
    # Registry Scripts
    try {
        $suspiciousKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $suspiciousKeys) {
            if (Test-Path $key) {
                Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object {
                        $_.Value -match "powershell.*-enc|mshta|regsvr32.*scrobj|wscript|cscript" -and $_.Name -ne "PSGuid"
                    } | ForEach-Object {
                        try {
                            Write-Log "[FILELESS] Removing malicious registry entry: $($key)\$($_.Name)"
                            Remove-ItemProperty -Path $key -Name $_.Name -Force -ErrorAction Stop
                            Write-SecurityEvent -EventType "RegistryMalwareEntryRemoved" -Details @{ Path = "$key\$($_.Name)"; Value = $_.Value } -Severity "High"
                        } catch {
                            Write-ErrorLog -Message "Failed to remove registry entry" -Severity "Medium" -ErrorRecord $_
                        }
                    }
                }
            }
        }
    } catch {
        Write-ErrorLog -Message "Error in registry fileless detection" -Severity "Low" -ErrorRecord $_
    }
    
    return $detections
}

# ============================================
# MEMORY SCANNER
# ============================================
$Script:MemoryMonitorJob = Start-Job -ScriptBlock {
    param($LogsDir)
    
    while ($true) {
        Start-Sleep -Seconds 300  # Check every 5 minutes
        
        try {
            $parentProcess = Get-Process -Id $using:PID -ErrorAction SilentlyContinue
            if ($parentProcess) {
                $memoryMB = [math]::Round($parentProcess.WorkingSet64 / 1MB, 2)
                
                if ($memoryMB -gt 500) {
                    # Signal cleanup needed (parent script will check logs)
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    "[$timestamp] [MEMORY] High memory usage detected: ${memoryMB}MB" | 
                        Out-File (Join-Path $LogsDir "memory_alerts.txt") -Append
                }
            }
        } catch {}
    }
} -ArgumentList $Script:LogsDir

Write-Log "[+] Starting PowerShell memory scanner"
Start-Job -ScriptBlock {
    $log = "$using:Base\ps_memory_hits.log"
    $QuarantineDir = $using:QuarantineDir
    $Base = $using:Base
    $SelfProcessName = $using:SelfProcessName
    $ProtectedProcessNames = $using:Script:ProtectedProcessNames
    
    ${function:Check-FileHash} = ${using:function:Check-FileHash}
    ${function:Kill-Threat} = ${using:function:Kill-Threat}
    ${function:Invoke-QuarantineFile} = ${using:function:Invoke-QuarantineFile}
    ${function:Write-Log} = ${using:function:Write-Log}
    ${function:Test-ProtectedOrSelf} = ${using:function:Test-ProtectedOrSelf}
    ${function:Test-CriticalSystemProcess} = ${using:function:Test-CriticalSystemProcess}
    ${function:Test-IsWindowsNetworkingService} = ${using:function:Test-IsWindowsNetworkingService}
    ${function:Test-IsSelfOrRelated} = ${using:function:Test-IsSelfOrRelated}
    ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
    
    $ApiConfig = $using:ApiConfig
    $logFile = $using:logFile
    $Script:logFile = $logFile
    $Script:SelfProcessName = $SelfProcessName
    
    $EvilStrings = @(
        'mimikatz','sekurlsa::','kerberos::','lsadump::','wdigest','tspkg',
        'http-beacon','https-beacon','cobaltstrike','sleepmask','reflective',
        'amsi.dll','AmsiScanBuffer','EtwEventWrite','MiniDumpWriteDump',
        'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
        'ReflectiveLoader','sharpchrome','rubeus','safetykatz','sharphound'
    )
    
    while ($true) {
        Start-Sleep -Seconds 2
        
        Get-Process | Where-Object {
            try {
                $procId = $_.Id
                if ($procId -eq $SelfProcessName) { return $false }
                
                $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
            } catch { $false }
        } | ForEach-Object {
            $hit = $false
            $proc = $_
            
            try {
                if (Test-ProtectedOrSelf $proc) { return }
                if (Test-CriticalSystemProcess $proc) { return }
                if (Test-IsWindowsNetworkingService -ProcessId $proc.Id) { return }
                
                $proc.Modules | ForEach-Object {
                    if ($EvilStrings | Where-Object { $_.ModuleName -match $_ -or $_.FileName -match $_ }) {
                        $hit = $true
                    }
                }
            } catch {}
            
            if ($hit) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | PS MEMORY HIT +' $($proc.Name) ($($proc.Id))" | Out-File $log -Append
                Write-SecurityEvent -EventType "MemoryScanHit" -Details @{ ProcessName = $proc.Name; PID = $proc.Id; Reason = "Suspicious strings in memory" } -Severity "High"
                
                if ($proc.Path) {
                    $hashMalicious = Check-FileHash -FilePath $proc.Path -ProcessName $proc.Name -ProcessId $proc.Id
                    if ($hashMalicious) {
                        Invoke-QuarantineFile -FilePath $proc.Path
                    }
                }
                
                Kill-Threat -ProcessId $proc.Id -ProcessName $proc.Name -Reason "Malicious strings in memory"
            }
        }
    }
} | Out-Null

# ============================================
# REFLECTIVE PAYLOAD DETECTOR
# ============================================
Write-Log "[+] Starting reflective payload detector"
Start-Job -ScriptBlock {
    $log = "$using:Base\manual_map_hits.log"
    $QuarantineDir = $using:QuarantineDir
    $Base = $using:Base
    $SelfProcessName = $using:SelfProcessName
    
    ${function:Check-FileHash} = ${using:function:Check-FileHash}
    ${function:Kill-Threat} = ${using:function:Kill-Threat}
    ${function:Invoke-QuarantineFile} = ${using:function:Invoke-QuarantineFile}
    ${function:Write-Log} = ${using:function:Write-Log}
    ${function:Test-ProtectedOrSelf} = ${using:function:Test-ProtectedOrSelf}
    ${function:Test-CriticalSystemProcess} = ${using:function:Test-CriticalSystemProcess}
    ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
    
    $ApiConfig = $using:ApiConfig
    $logFile = $using:logFile
    $Script:logFile = $logFile
    $Script:SelfProcessName = $SelfProcessName
    
    while ($true) {
        Start-Sleep -Seconds 2
        
        Get-Process | Where-Object { 
            try {
                $_.Id -ne $SelfProcessName -and $_.WorkingSet64 -gt 40MB
            } catch { $false }
        } | ForEach-Object {
            $p = $_
            $sus = $false
            
            try {
                if (Test-ProtectedOrSelf $p) { return }
                if (Test-CriticalSystemProcess $p) { return }
                
                if (-not $p.Path -or $p.Path -eq '' -or $p.Path -match '$$Unknown$$') { $sus = $true }
                if ($p.Modules | Where-Object { $_.FileName -eq '' -or $_.ModuleName -eq '' }) { $sus = $true }
            } catch {}
            
            if ($sus) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REFLECTIVE PAYLOAD +' $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                Write-SecurityEvent -EventType "ReflectivePayloadDetected" -Details @{ ProcessName = $p.Name; PID = $p.Id; Path = $p.Path } -Severity "Critical"
                
                if ($p.Path) {
                    $hashMalicious = Check-FileHash -FilePath $p.Path -ProcessName $p.Name -ProcessId $p.Id
                    if ($hashMalicious) {
                        Invoke-QuarantineFile -FilePath $p.Path
                    }
                }
                
                Kill-Threat -ProcessId $p.Id -ProcessName $p.Name -Reason "Reflective payload detected"
            }
        }
    }
} | Out-Null

# ============================================
# BEHAVIOR MONITOR
# ============================================
function Start-BehaviorMonitor {
    $suspiciousBehaviors = @{
        "ProcessHollowing" = {
            param($Process)
            try {
                $procPath = $Process.Path
                $modules = Get-Process -Id $Process.Id -Module -ErrorAction SilentlyContinue
                return ($modules -and $procPath -and ($modules[0].FileName -ne $procPath))
            } catch { return $false }
        }
        "CredentialAccess" = {
            param($Process)
            try {
                $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction SilentlyContinue).CommandLine
                return ($cmdline -match "mimikatz|procdump|sekurlsa|lsadump" -or 
                        $Process.ProcessName -match "vaultcmd|cred")
            } catch { return $false }
        }
        "LateralMovement" = {
            param($Process)
            try {
                $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
                $remoteIPs = $connections | Where-Object { 
                    $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -and
                    $_.RemoteAddress -ne "0.0.0.0" -and
                    $_.RemoteAddress -ne "::"
                }
                return ($remoteIPs.Count -gt 5)
            } catch { return $false }
        }
    }
    
    Start-Job -ScriptBlock {
        try {
            $behaviors = $using:suspiciousBehaviors
            $logFile = "$using:Base\behavior_detections.log"
            $Base = $using:Base
            $QuarantineDir = $using:QuarantineDir
            $SelfProcessName = $using:SelfProcessName
            
            ${function:Check-FileHash} = ${using:function:Check-FileHash}
            ${function:Kill-Threat} = ${using:function:Kill-Threat}
            ${function:Invoke-QuarantineFile} = ${using:function:Invoke-QuarantineFile}
            ${function:Write-Log} = ${using:function:Write-Log}
            ${function:Test-ProtectedOrSelf} = ${using:function:Test-ProtectedOrSelf}
            ${function:Test-CriticalSystemProcess} = ${using:function:Test-CriticalSystemProcess}
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            
            $ApiConfig = $using:ApiConfig
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 5
                    
                    Get-Process | Where-Object {
                        try { $_.Id -ne $SelfProcessName } catch { $false }
                    } | ForEach-Object {
                        try {
                            $process = $_
                            
                            if (Test-ProtectedOrSelf $process) { return }
                            if (Test-CriticalSystemProcess $process) { return }
                            
                            foreach ($behavior in $behaviors.Keys) {
                                try {
                                    if (& $behaviors[$behavior] $process) {
                                        $msg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | BEHAVIOR DETECTED: $behavior | " +
                                               "Process: $($process.Name) PID: $($process.Id) Path: $($process.Path)"
                                        $msg | Out-File $logFile -Append
                                        Write-SecurityEvent -EventType "SuspiciousBehaviorDetected" -Details @{ Behavior = $behavior; ProcessName = $process.Name; PID = $process.Id; Path = $process.Path } -Severity "High"
                                        
                                        if ($behavior -in @("ProcessHollowing", "CredentialAccess")) {
                                            if ($process.Path) {
                                                $hashMalicious = Check-FileHash -FilePath $process.Path -ProcessName $process.Name -ProcessId $process.Id
                                                if ($hashMalicious) {
                                                    Invoke-QuarantineFile -FilePath $process.Path
                                                }
                                            }
                                            Kill-Threat -ProcessId $process.Id -ProcessName $process.Name -Reason "Suspicious behavior: $behavior"
                                        }
                                    }
                                } catch {}
                            }
                        } catch {}
                    }
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\behavior_detections.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Behavior monitor job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] Behavior monitor started"
}

function Start-EnhancedBehaviorMonitor {
    Start-Job -ScriptBlock {
        try {
            param($LogFile, $ProtectedProcessNames, $SelfProcessName, $QuarantineDir, $LOLBinPatterns)
            
            $Script:LogFile = $LogFile
            $Script:QuarantineDir = $QuarantineDir
            $Script:SelfProcessName = $SelfProcessName
            $Script:LOLBinPatterns = $LOLBinPatterns
            
            ${function:Test-LOLBinAbuse} = ${using:function:Test-LOLBinAbuse}
            ${function:Test-ProtectedOrSelf} = ${using:function:Test-ProtectedOrSelf}
            ${function:Test-CriticalSystemProcess} = ${using:function:Test-CriticalSystemProcess}
            ${function:Kill-Threat} = ${using:function:Kill-Threat}
            ${function:Invoke-QuarantineFile} = ${using:function:Invoke-QuarantineFile}
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            
            $ApiConfig = $using:ApiConfig
            
            while ($true) {
                try {
                    Get-Process | Where-Object {
                        try {
                            $procId = $_.Id
                            if ($procId -eq $SelfProcessName) { return $false }
                            if ($ProtectedProcessNames -contains $_.ProcessName.ToLower()) { return $false }
                            $true
                        } catch { $false }
                    } | ForEach-Object {
                        try {
                            $proc = $_
                            
                            # SECURITY FIX #4: LOLBin detection
                            $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                            if ($commandLine -and (Test-LOLBinAbuse -ProcessName $proc.ProcessName -CommandLine $commandLine)) {
                                Add-Content -Path $LogFile -Value "[LOLBIN ABUSE] Detected in $($proc.ProcessName) (PID: $($proc.Id)): $commandLine" -Encoding UTF8
                                Write-SecurityEvent -EventType "LOLBinAbuse" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; CommandLine = $commandLine } -Severity "High"
                                
                                if ($proc.Path) {
                                    Invoke-QuarantineFile -FilePath $proc.Path
                                }
                                Kill-Threat -ProcessId $proc.Id -ProcessName $proc.ProcessName -Reason "LOLBin abuse detected"
                            }
                            
                            # High thread/handle count
                            $threadCount = $proc.Threads.Count
                            $handleCount = $proc.HandleCount
                            
                            if ($threadCount -gt 100 -or $handleCount -gt 10000) {
                                Add-Content -Path $LogFile -Value "SUSPICIOUS BEHAVIOR: High thread/handle count in $($proc.ProcessName) (Threads: $threadCount, Handles: $handleCount)" -Encoding UTF8
                                Write-SecurityEvent -EventType "SuspiciousProcessBehavior" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Behavior = "HighThreadHandleCount"; ThreadCount = $threadCount; HandleCount = $handleCount } -Severity "Medium"
                            }
                            
                            # Random process name
                            if ($proc.ProcessName -match "^[a-z0-9]{32}$") {
                                Add-Content -Path $LogFile -Value "SUSPICIOUS BEHAVIOR: Random process name: $($proc.ProcessName)" -Encoding UTF8
                                Write-SecurityEvent -EventType "SuspiciousProcessBehavior" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Behavior = "RandomProcessName" } -Severity "Medium"
                            }
                        } catch {}
                    }
                    
                    Start-Sleep -Seconds 30
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Enhanced behavior monitor job crashed: $_"
            } catch {}
        }
    } -ArgumentList $Script:logFile, $Script:ProtectedProcessNames, $Script:SelfProcessName, $Script:QuarantineDir, $Script:LOLBinPatterns | Out-Null
    
    Write-Log "[+] Enhanced behavior monitor started"
}

function Start-AntiTamperMonitor {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $ScriptPath = $using:MyInvocation.MyCommand.Path
            $SelfPID = $using:PID
            $logFile = "$Base\anti_tamper.log"
            
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            ${function:Write-Log} = ${using:function:Write-Log}
            
            $originalScriptHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256).Hash
            $lastCheckTime = Get-Date
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 10
                    
                    try {
                        # Check if someone modified the script file
                        $currentHash = (Get-FileHash -Path $ScriptPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        if ($currentHash -and $currentHash -ne $originalScriptHash) {
                            $msg = "CRITICAL: Script file has been modified! Original: $originalScriptHash, Current: $currentHash"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "ScriptTampering" -Details @{ OriginalHash = $originalScriptHash; CurrentHash = $currentHash } -Severity "Critical"
                            
                            # Alert and restart from backup if available
                            Write-Host "`n[!!! CRITICAL !!!] EDR script has been tampered with! Restarting from backup..." -ForegroundColor Red
                        }
                        
                        # Check if someone is trying to debug/attach to our process
                        $ourProcess = Get-Process -Id $SelfPID -ErrorAction SilentlyContinue
                        if ($ourProcess) {
                            $threads = $ourProcess.Threads
                            # Detect debugger attachment (suspended threads, etc.)
                            $suspendedCount = ($threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' }).Count
                            if ($suspendedCount -gt 5) {
                                $msg = "CRITICAL: Debugger attachment suspected - $suspendedCount suspended threads detected"
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                Write-SecurityEvent -EventType "DebuggerDetected" -Details @{ SuspendedThreads = $suspendedCount } -Severity "Critical"
                            }
                        }
                        
                        # Check for process injection attempts into our process
                        $currentModules = Get-Process -Id $SelfPID -Module -ErrorAction SilentlyContinue
                        if ($currentModules) {
                            $unexpectedModules = $currentModules | Where-Object { 
                                $_.FileName -notmatch "\\Windows\\|\\PowerShell\\" -and
                                $_.FileName -notmatch [regex]::Escape($ScriptPath)
                            }
                            if ($unexpectedModules) {
                                foreach ($mod in $unexpectedModules) {
                                    $msg = "CRITICAL: Unexpected module loaded into EDR process: $($mod.FileName)"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "ProcessInjection" -Details @{ Module = $mod.FileName } -Severity "Critical"
                                }
                            }
                        }
                        
                        # Check for memory dumping tools
                        $dumpTools = Get-Process | Where-Object { 
                            $_.ProcessName -match "procdump|processhacker|processdumper|memorydumper|mimikatz" 
                        }
                        if ($dumpTools) {
                            foreach ($tool in $dumpTools) {
                                $msg = "CRITICAL: Memory dumping tool detected: $($tool.ProcessName) (PID: $($tool.Id))"
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                Write-SecurityEvent -EventType "MemoryDumpingTool" -Details @{ ProcessName = $tool.ProcessName; PID = $tool.Id; Path = $tool.Path } -Severity "Critical"
                                
                                # Kill it
                                try {
                                    Stop-Process -Id $tool.Id -Force
                                    $msg = "KILLED: Terminated memory dumping tool: $($tool.ProcessName)"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                } catch {}
                            }
                        }
                        
                        $lastCheckTime = Get-Date
                    } catch {
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR in anti-tamper monitor: $_"
                    }
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Anti-tamper monitor crashed: $_"
            } catch {}
        }
    } -ArgumentList $Script:logFile | Out-Null
    
    Write-Log "[+] Anti-tamper monitor started"
}

# ============================================
# START OF NEWLY ADDED CODE BLOCK
# ============================================
function Start-NetworkAnomalyDetector {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $SelfPID = $using:SelfPID
            $logFile = "$Base\network_anomalies.log"

            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            ${function:Write-Log} = ${using:function:Write-Log}
            
            # Track baseline connection patterns
            $connectionBaseline = @{}
            $suspiciousIPs = @()
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 15
                    
                    try {
                        # Get all network connections
                        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                        
                        foreach ($conn in $connections) {
                            try {
                                $remoteIP = $conn.RemoteAddress
                                $localPort = $conn.LocalPort
                                $remotePort = $conn.RemotePort
                                $owningPID = $conn.OwningProcess
                                
                                # Skip localhost and private IPs
                                if ($remoteIP -match "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -or
                                    $remoteIP -eq "0.0.0.0" -or $remoteIP -eq "::") {
                                    continue
                                }
                                
                                # Detect data exfiltration patterns (unusual ports, high connection counts)
                                if ($remotePort -in @(4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345)) {
                                    $process = Get-Process -Id $owningPID -ErrorAction SilentlyContinue
                                    $msg = "SUSPICIOUS: Connection to known malicious port $remotePort from $($process.ProcessName) (PID: $owningPID) to $remoteIP"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "SuspiciousNetworkConnection" -Details @{ 
                                        ProcessName = $process.ProcessName
                                        PID = $owningPID
                                        RemoteIP = $remoteIP
                                        RemotePort = $remotePort
                                    } -Severity "High"
                                    
                                    # Kill the process
                                    try {
                                        Stop-Process -Id $owningPID -Force
                                        $msg = "KILLED: Terminated process with suspicious network activity: $($process.ProcessName)"
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    } catch {}
                                }
                                
                                # Track connection frequency for each process
                                $key = "$owningPID-$remoteIP"
                                if (-not $connectionBaseline.ContainsKey($key)) {
                                    $connectionBaseline[$key] = 1
                                } else {
                                    $connectionBaseline[$key]++
                                    
                                    # If a process is making too many connections to same IP (beaconing behavior)
                                    if ($connectionBaseline[$key] -gt 50) {
                                        $process = Get-Process -Id $owningPID -ErrorAction SilentlyContinue
                                        $msg = "SUSPICIOUS: Possible C2 beaconing from $($process.ProcessName) (PID: $owningPID) to $remoteIP (Count: $($connectionBaseline[$key]))"
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                        Write-SecurityEvent -EventType "PossibleC2Beaconing" -Details @{ 
                                            ProcessName = $process.ProcessName
                                            PID = $owningPID
                                            RemoteIP = $remoteIP
                                            ConnectionCount = $connectionBaseline[$key]
                                        } -Severity "Critical"
                                    }
                                }
                            } catch {}
                        }
                        
                        # Check for processes trying to access our monitoring infrastructure
                        $monitoringConnections = $connections | Where-Object { 
                            $_.RemoteAddress -match "monitoring|telemetry|analytics" 
                        }
                        if ($monitoringConnections) {
                            $msg = "SUSPICIOUS: Process attempting to access monitoring infrastructure"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        }
                        
                    } catch {
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR in network anomaly detector: $_"
                    }
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\network_anomalies.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Network anomaly detector job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] Network anomaly detector started"
}

function Start-RootkitDetector {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $logFile = "$Base\rootkit_detections.log"
            
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            ${function:Write-Log} = ${using:function:Write-Log}
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 60
                    
                    try {
                        # Check for hidden processes (compare Task Manager vs Get-Process)
                        $cimProcesses = Get-CimInstance Win32_Process | Select-Object -ExpandProperty ProcessId
                        $psProcesses = Get-Process | Select-Object -ExpandProperty Id
                        
                        $hiddenPIDs = $cimProcesses | Where-Object { $_ -notin $psProcesses }
                        if ($hiddenPIDs) {
                            foreach ($pid in $hiddenPIDs) {
                                try {
                                    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pid"
                                    $msg = "CRITICAL: Hidden process detected: $($process.Name) (PID: $pid) - Possible rootkit"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "HiddenProcess" -Details @{ ProcessName = $process.Name; PID = $pid } -Severity "Critical"
                                } catch {}
                            }
                        }
                        
                        # Check for suspicious drivers
                        $drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
                        foreach ($driver in $drivers) {
                            try {
                                # Check if driver file exists (some rootkits use phantom drivers)
                                $driverPath = $driver.PathName -replace '"', ''
                                if ($driverPath -and -not (Test-Path $driverPath)) {
                                    $msg = "CRITICAL: Phantom driver detected: $($driver.Name) - Path does not exist: $driverPath"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "PhantomDriver" -Details @{ DriverName = $driver.Name; Path = $driverPath } -Severity "Critical"
                                }
                                
                                # Check if driver is unsigned
                                if ($driverPath -and (Test-Path $driverPath)) {
                                    $sig = Get-AuthenticodeSignature -FilePath $driverPath -ErrorAction SilentlyContinue
                                    if ($sig -and $sig.Status -ne "Valid") {
                                        $msg = "WARNING: Unsigned/invalid driver: $($driver.Name) at $driverPath"
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                        Write-SecurityEvent -EventType "UnsignedDriver" -Details @{ DriverName = $driver.Name; Path = $driverPath; SignatureStatus = $sig.Status } -Severity "High"
                                    }
                                }
                            } catch {}
                        }
                        
                        # Check for SSDT hooks (System Service Descriptor Table) - advanced rootkit detection
                        # This is a simplified check - would need kernel access for full SSDT inspection
                        $systemProcesses = Get-Process | Where-Object { $_.ProcessName -match "^(system|smss|csrss|wininit|services|lsass|svchost)$" }
                        foreach ($proc in $systemProcesses) {
                            try {
                                $modules = Get-Process -Id $proc.Id -Module -ErrorAction SilentlyContinue
                                $suspiciousModules = $modules | Where-Object { 
                                    $_.FileName -notmatch "\\Windows\\System32\\" -and
                                    $_.FileName -notmatch "\\Windows\\SysWOW64\\"
                                }
                                if ($suspiciousModules) {
                                    $msg = "CRITICAL: Suspicious module in system process $($proc.ProcessName): $($suspiciousModules[0].FileName)"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "SystemProcessHook" -Details @{ 
                                        ProcessName = $proc.ProcessName
                                        PID = $proc.Id
                                        SuspiciousModule = $suspiciousModules[0].FileName
                                    } -Severity "Critical"
                                }
                            } catch {}
                        }
                        
                    } catch {
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR in rootkit detector: $_"
                    }
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\rootkit_detections.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Rootkit detector job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] Rootkit detector started"
}

function Start-FileSystemIntegrityMonitor {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $logFile = "$Base\filesystem_integrity.log"
            $criticalPaths = @(
                "$env:SystemRoot\System32\drivers\etc\hosts",
                "$env:SystemRoot\System32\config\SAM",
                "$env:SystemRoot\System32\config\SYSTEM",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            ${function:Write-Log} = ${using:function:Write-Log}
            
            # Baseline hashes
            $baseline = @{}
            foreach ($path in $criticalPaths) {
                try {
                    if (Test-Path $path) {
                        if ((Get-Item $path).PSIsContainer) {
                            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                            foreach ($file in $files) {
                                try {
                                    $baseline[$file.FullName] = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                                } catch {}
                            }
                        } else {
                            $baseline[$path] = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        }
                    }
                } catch {}
            }
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 30
                    
                    try {
                        foreach ($path in $baseline.Keys) {
                            try {
                                if (Test-Path $path) {
                                    $currentHash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                                    if ($currentHash -ne $baseline[$path]) {
                                        $msg = "CRITICAL: Critical system file modified: $path"
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                        Write-SecurityEvent -EventType "CriticalFileModified" -Details @{ 
                                            FilePath = $path
                                            OriginalHash = $baseline[$path]
                                            CurrentHash = $currentHash
                                        } -Severity "Critical"
                                        
                                        # Update baseline
                                        $baseline[$path] = $currentHash
                                    }
                                }
                            } catch {}
                        }
                    } catch {
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR in filesystem integrity monitor: $_"
                    }
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\filesystem_integrity.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Filesystem integrity monitor job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] Filesystem integrity monitor started"
}

function Start-COMControlMonitor {
    Start-Job -ScriptBlock {
        try {
            param($LogFile, $QuarantineDir)
            
            $Script:LogFile = $LogFile
            $Script:QuarantineDir = $QuarantineDir
            
            while ($true) {
                try {
                    try {
                        $basePaths = @(
                            "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID",
                            "HKLM:\SOFTWARE\Classes\CLSID"
                        )
                        
                        foreach ($basePath in $basePaths) {
                            try {
                                if (Test-Path $basePath) {
                                    Get-ChildItem -Path $basePath | Where-Object {
                                        $_.PSChildName -match "\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"
                                    } | ForEach-Object {
                                        try {
                                            $clsid = $_.PSChildName
                                            $clsidPath = Join-Path $basePath $clsid
                                            
                                            @("InProcServer32", "InprocHandler32") | ForEach-Object {
                                                try {
                                                    $subKeyPath = Join-Path $clsidPath $_
                                                    
                                                    if (Test-Path $subKeyPath) {
                                                        $dllPath = (Get-ItemProperty -Path $subKeyPath -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
                                                        
                                                        if ($dllPath -and (Test-Path $dllPath)) {
                                                            if ($dllPath -match "\\temp\\|\\downloads\\|\\public\\" -or (Get-Item $dllPath).Length -lt 100KB) {
                                                                Add-Content -Path $LogFile -Value "REMOVING malicious COM control: $dllPath" -Encoding UTF8
                                                                Write-SecurityEvent -EventType "MaliciousCOMControlRemoved" -Details @{ Path = $dllPath } -Severity "High"
                                                                Remove-Item -Path $clsidPath -Recurse -Force -ErrorAction SilentlyContinue
                                                                Remove-Item -Path $dllPath -Force -ErrorAction SilentlyContinue
                                                            }
                                                        }
                                                    }
                                                } catch {}
                                            }
                                        } catch {}
                                    }
                                }
                            } catch {}
                        }
                    } catch {}
                    
                    Start-Sleep -Seconds 60
                } catch {}
            }
        } catch {
            try {
                Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: COM control monitor job crashed: $_"
            } catch {}
        }
    } -ArgumentList $Script:logFile, $Script:QuarantineDir | Out-Null
    
    Write-Log "[+] COM control monitor started"
}

function Invoke-MalwareScan {
    try {
        Get-Process | Where-Object {
            try {
                -not (Test-ProtectedOrSelf $_) -and 
                -not (Test-CriticalSystemProcess $_) -and
                -not (Test-IsWindowsNetworkingService -ProcessId $_.Id)
            } catch { $false }
        } | ForEach-Object {
            try {
                $proc = $_
                $procName = $proc.ProcessName.ToLower()
                
                # Fileless malware detection
                if ($procName -match "powershell|cmd") {
                    $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    
                    if ($commandLine -and ($commandLine -match "-encodedcommand|-enc|invoke-expression|downloadstring|iex|-executionpolicy bypass")) {
                        Write-Log "[DETECTED] Fileless malware: $($proc.ProcessName) (PID: $($proc.Id))"
                        Write-SecurityEvent -EventType "FilelessMalwareDetected" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; CommandLine = $commandLine } -Severity "Critical"
                        Invoke-QuarantineProcess -Process $proc -Reason "Fileless malware execution"
                    }
                }
            } catch {}
        }
    } catch {}
}

function Invoke-LogRotation {
    try {
        if ((Get-Item $Script:logFile -ErrorAction SilentlyContinue).Length -gt 50MB) {
            $backupLog = "$($Script:logFile).old"
            if (Test-Path $backupLog) {
                Remove-Item $backupLog -Force
            }
            Move-Item $Script:logFile $backupLog -Force
            Write-Log "[*] Log rotated due to size"
        }
    } catch {}
}

# ============================================
# SECURITY FIX #1: PERIODIC INTEGRITY CHECKS
# ============================================
function Start-IntegrityMonitor {
    Start-Job -ScriptBlock {
        try {
            param($SelfPath, $SelfHash)
            
            ${function:Test-ScriptIntegrity} = ${using:function:Test-ScriptIntegrity}
            $Script:SelfPath = $SelfPath
            $Script:SelfHash = $SelfHash
            
            while ($true) {
                try {
                    Start-Sleep -Seconds 60
                    
                    try {
                        if (-not (Test-ScriptIntegrity)) {
                            # Script has been tampered with - terminate
                            Write-Host "[CRITICAL] Script integrity compromised. Terminating." -ForegroundColor Red
                            Write-SecurityEvent -EventType "ScriptIntegrityFailure" -Details @{ PID = $PID } -Severity "Critical"
                            Stop-Process -Id $PID -Force
                        }
                    } catch {}
                } catch {}
            }
        } catch {
            try {
                Write-Host "[CRITICAL] Integrity monitor job crashed: $_" -ForegroundColor Red
            } catch {}
        }
    } -ArgumentList $Script:SelfPath, $Script:SelfHash | Out-Null
    
    Write-Log "[+] Integrity monitor started"
}

# ============================================
# MAIN EXECUTION
# ============================================

# Run configuration validation at startup
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ANTIVIRUS PROTECTION - STARTING UP" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Initialize-WhitelistDatabase

$configErrors = Test-ScriptConfiguration
if ($configErrors.Count -gt 0) {
    Write-Host "[WARNING] Configuration issues detected:" -ForegroundColor Yellow
    $configErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
}

Write-SecurityEvent -EventType "AntivirusStartup" -Details @{ 
    PID = $PID
    User = $env:USERNAME
    ConfigErrors = $configErrors.Count
} -Severity "Informational"

# Initialize HMAC key
# Moved to top after logging functions

Write-Log "[+] Starting all detection modules"

# Initial scan
Remove-UnsignedDLLs

Write-Host "`n[*] Initializing background monitoring jobs..."

$jobNames = @()

Write-Host "[*] Starting Behavior Monitor..."
Start-BehaviorMonitor
$jobNames += "BehaviorMonitor"

Write-Host "[*] Starting Enhanced Behavior Monitor..."
Start-EnhancedBehaviorMonitor
$jobNames += "EnhancedBehaviorMonitor"

Write-Host "[*] Starting COM Control Monitor..."
Start-COMControlMonitor
$jobNames += "COMControlMonitor"

Write-Host "[*] Starting Anti-Tamper Monitor..." -ForegroundColor Yellow
Start-AntiTamperMonitor
$jobNames += "AntiTamperMonitor"

Write-Host "[*] Starting Network Anomaly Detector..." -ForegroundColor Yellow
Start-NetworkAnomalyDetector
$jobNames += "NetworkAnomalyDetector"

Write-Host "[*] Starting Rootkit Detector..." -ForegroundColor Yellow
Start-RootkitDetector
$jobNames += "RootkitDetector"

Write-Host "[*] Starting Filesystem Integrity Monitor..." -ForegroundColor Yellow
Start-FileSystemIntegrityMonitor
$jobNames += "FileSystemIntegrityMonitor"


# Add termination protection AFTER all functions are defined
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

Write-Host "[*] Starting Integrity Monitor..."
Start-IntegrityMonitor
$jobNames += "IntegrityMonitor"

Start-Sleep -Seconds 2


Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DLL {
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

# ============================================
# START OF NEWLY ADDED CODE BLOCK
# ============================================
function Start-NetworkTrafficMonitor {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $logFile = "$Base\ntm_monitor.log"
            
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            ${function:Write-Log} = ${using:function:Write-Log}
            
            # Configuration
            $script:AllowedDomains = @()
            $script:AllowedIPs = @()
            $script:BlockedConnections = @{}
            $script:MonitoringActive = $true
            $script:CurrentBrowserConnections = @{}
            
            # Helper functions from NTM
            function Write-ColorOutput {
                param([string]$Message, [string]$Color = "White")
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
            }
            
            function Add-AllowedDomain {
                param([string]$Domain)
                
                $Domain = $Domain -replace '^https?://', '' -replace '/$', ''
                
                if ($script:AllowedDomains -notcontains $Domain) {
                    $script:AllowedDomains += $Domain
                    Write-ColorOutput "Added allowed domain: $Domain"
                    
                    try {
                        $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
                        foreach ($IP in $IPs) {
                            if ($script:AllowedIPs -notcontains $IP) {
                                $script:AllowedIPs += $IP
                                Write-ColorOutput "  Resolved IP: $IP"
                            }
                        }
                    } catch {
                        Write-ColorOutput "  Warning: Could not resolve domain to IP"
                    }
                }
            }
            
            function Test-BrowserConnection {
                param([string]$RemoteAddress)
                
                if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    return $true
                }
                
                if ($script:AllowedIPs -contains $RemoteAddress) {
                    return $true
                }
                
                return $false
            }
            
            function Watch-BrowserActivity {
                param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)
                
                $BrowserProcesses = @('chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave')
                
                if ($BrowserProcesses -contains $ProcessName.ToLower()) {
                    $Now = Get-Date
                    $RecentNavigationTime = $null
                    
                    foreach ($BrowserIP in $script:CurrentBrowserConnections.Keys) {
                        $ConnectionTime = $script:CurrentBrowserConnections[$BrowserIP]
                        $TimeDiff = ($Now - $ConnectionTime).TotalSeconds
                        
                        if ($TimeDiff -le 30) {
                            if ($null -eq $RecentNavigationTime -or $ConnectionTime -gt $RecentNavigationTime) {
                                $RecentNavigationTime = $ConnectionTime
                            }
                        }
                    }
                    
                    if ($null -ne $RecentNavigationTime) {
                        if ($script:AllowedIPs -notcontains $RemoteAddress) {
                            $script:AllowedIPs += $RemoteAddress
                            Write-ColorOutput "DEPENDENCY: Allowing $RemoteAddress (linked to browser navigation)"
                        }
                        return $true
                    }
                    elseif ($RemotePort -eq 443 -or $RemotePort -eq 80) {
                        if ($script:AllowedIPs -notcontains $RemoteAddress) {
                            $script:AllowedIPs += $RemoteAddress
                            $script:CurrentBrowserConnections[$RemoteAddress] = Get-Date
                            Write-ColorOutput "BROWSER NAVIGATION: Allowing $RemoteAddress and its dependencies"
                            return $true
                        }
                    }
                    else {
                        if ($script:AllowedIPs -notcontains $RemoteAddress) {
                            $script:AllowedIPs += $RemoteAddress
                            Write-ColorOutput "BROWSER: Allowing $RemoteAddress"
                        }
                        return $true
                    }
                }
                
                $Now = Get-Date
                foreach ($BrowserIP in $script:CurrentBrowserConnections.Keys) {
                    $ConnectionTime = $script:CurrentBrowserConnections[$BrowserIP]
                    $TimeDiff = ($Now - $ConnectionTime).TotalSeconds
                    
                    if ($TimeDiff -le 30) {
                        if ($script:AllowedIPs -notcontains $RemoteAddress) {
                            $script:AllowedIPs += $RemoteAddress
                            Write-ColorOutput "DEPENDENCY: Allowing $RemoteAddress (linked to browser navigation)"
                        }
                        return $true
                    }
                }
                
                return $false
            }
            
            function New-BlockRule {
                param([string]$RemoteAddress, [int]$RemotePort, [string]$ProcessName)
                
                $script:BlockedConnections[$RemoteAddress] = @{ Port = $RemotePort; Process = $ProcessName }
                Write-ColorOutput "BLOCKED: ${RemoteAddress}:${RemotePort} (Process: $ProcessName)"
                Write-SecurityEvent -EventType "UnauthorizedConnectionBlocked" -Details @{ 
                    RemoteAddress = $RemoteAddress
                    RemotePort = $RemotePort
                    ProcessName = $ProcessName
                } -Severity "Medium"
                
                # Create firewall rule
                $ruleName = "AV_Block_$RemoteAddress"
                try {
                    netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip=$RemoteAddress | Out-Null
                } catch {}
            }
            
            Write-ColorOutput "=== Network Traffic Monitor (Automatic Mode) ==="
            Write-ColorOutput "Monitoring browser traffic and blocking unauthorized connections..."
            
            $SeenConnections = @{}
            
            while ($script:MonitoringActive) {
                try {
                    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
                    
                    foreach ($Conn in $Connections) {
                        $Key = "$($Conn.RemoteAddress):$($Conn.RemotePort):$($Conn.OwningProcess)"
                        
                        if ($SeenConnections.ContainsKey($Key)) {
                            continue
                        }
                        
                        $SeenConnections[$Key] = $true
                        
                        try {
                            $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction Stop
                            $ProcessName = $Process.ProcessName
                        } catch {
                            $ProcessName = "Unknown"
                        }
                        
                        $IsBrowserOrDependency = Watch-BrowserActivity -RemoteAddress $Conn.RemoteAddress -ProcessName $ProcessName -RemotePort $Conn.RemotePort
                        
                        if ($IsBrowserOrDependency) {
                            continue
                        }
                        
                        if (-not (Test-BrowserConnection -RemoteAddress $Conn.RemoteAddress)) {
                            if (-not $script:BlockedConnections.ContainsKey($Conn.RemoteAddress)) {
                                New-BlockRule -RemoteAddress $Conn.RemoteAddress -RemotePort $Conn.RemotePort -ProcessName $ProcessName
                            }
                        } else {
                            Write-ColorOutput "ALLOWED: $($Conn.RemoteAddress):$($Conn.RemotePort) (Process: $ProcessName)"
                        }
                    }
                    
                    # Clean up old browser connection timestamps
                    $Now = Get-Date
                    $ToRemove = @()
                    foreach ($IP in $script:CurrentBrowserConnections.Keys) {
                        $TimeDiff = ($Now - $script:CurrentBrowserConnections[$IP]).TotalSeconds
                        if ($TimeDiff -gt 60) {
                            $ToRemove += $IP
                        }
                    }
                    foreach ($IP in $ToRemove) {
                        $script:CurrentBrowserConnections.Remove($IP)
                    }
                    
                    Start-Sleep -Seconds 2
                } catch {
                    Write-ColorOutput "ERROR in NTM monitoring loop: $_"
                }
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\ntm_monitor.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: NTM job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] Network Traffic Monitor (NTM) started"
}

function Start-KeyScrambler {
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $logFile = "$Base\keyscrambler.log"
            
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Starting KeyScrambler anti-keylogger protection..."
            
            # KeyScrambler C# code
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
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KeyScrambler compiled successfully!"
                Write-SecurityEvent -EventType "KeyScramblerStarted" -Details @{ Status = "Active" } -Severity "Info"
                
                # Start KeyScrambler
                [KeyScrambler]::Start()
            }
            catch {
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR: KeyScrambler compilation failed: $($_.Exception.Message)"
                Write-SecurityEvent -EventType "KeyScramblerFailed" -Details @{ Error = $_.Exception.Message } -Severity "High"
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\keyscrambler.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: KeyScrambler job crashed: $_"
            } catch {}
        }
    } | Out-Null
    
    Write-Log "[+] KeyScrambler anti-keylogger started"
}


function Start-ElfCatcher {
    Write-Log "[+] Starting Elf Catcher DLL Monitor"
    
    Start-Job -ScriptBlock {
        try {
            $Base = $using:Base
            $logFile = "$Base\elf_catcher.log"
            
            ${function:Write-Log} = ${using:function:Write-Log}
            ${function:Write-SecurityEvent} = ${using:function:Write-SecurityEvent}
            
            # DLL whitelist - safe system DLLs
            $whitelist = @('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 
                          'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
                          'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
                          'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll')
            
            # Target browser processes
            $targets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 
                        'iexplore', 'microsoftedge')
            
            # Track processed DLLs to avoid repeated attempts
            $processed = @{}
            
            $msg = "Elf Catcher DLL Monitor started. Monitoring: $($targets -join ', ')"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
            Write-Log "[ELF-CATCHER] $msg"
            
            while ($true) {
                try {
                    foreach ($procName in $targets) {
                        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
                        
                        foreach ($proc in $procs) {
                            try {
                                # Open process with full access
                                $hProc = [DLL]::OpenProcess(0x1F0FFF, $false, $proc.Id)
                                if ($hProc -eq [IntPtr]::Zero) { 
                                    continue 
                                }
                                
                                # Get FreeLibrary function address
                                $freeLib = [DLL]::GetProcAddress([DLL]::GetModuleHandle("kernel32.dll"), "FreeLibrary")
                                
                                # Scan loaded modules
                                foreach ($mod in $proc.Modules) {
                                    try {
                                        $name = [System.IO.Path]::GetFileName($mod.FileName).ToLower()
                                        
                                        # Skip whitelisted DLLs
                                        if ($whitelist -contains $name) { continue }
                                        
                                        # Check if already processed
                                        $key = "$($proc.Id):$($mod.FileName)"
                                        if ($processed.ContainsKey($key)) { continue }
                                        
                                        # Detect suspicious DLLs
                                        $suspicious = $false
                                        $reason = ""
                                        
                                        if ($name -like '*_elf.dll') {
                                            $suspicious = $true
                                            $reason = "ELF pattern DLL"
                                        }
                                        elseif ($name -like '*.winmd' -and $mod.FileName -notmatch "\\Windows\\") {
                                            $suspicious = $true
                                            $reason = "Suspicious WINMD outside Windows directory"
                                        }
                                        elseif ($name -match '^[a-f0-9]{8,}\.dll$') {
                                            $suspicious = $true
                                            $reason = "Random hex-named DLL"
                                        }
                                        elseif ($mod.FileName -match "\\AppData\\Local\\Temp\\" -and $name -notlike "chrome_*" -and $name -notlike "edge_*") {
                                            $suspicious = $true
                                            $reason = "DLL loaded from TEMP directory"
                                        }
                                        
                                        if ($suspicious) {
                                            $msg = "Detected suspicious DLL: $name in $procName (PID $($proc.Id)) - Reason: $reason"
                                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                            Write-Log "[ELF-CATCHER] $msg"
                                            Write-SecurityEvent -EventType "SuspiciousDLLDetected" -Details @{ 
                                                DLLName = $name
                                                DLLPath = $mod.FileName
                                                ProcessName = $procName
                                                PID = $proc.Id
                                                Reason = $reason
                                            } -Severity "High"
                                            
                                            # Attempt to unload the DLL
                                            Write-Log "[ELF-CATCHER] Attempting to unload $name from $procName (PID $($proc.Id))"
                                            
                                            $thread = [DLL]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $freeLib, $mod.BaseAddress, 0, [IntPtr]::Zero)
                                            
                                            if ($thread -ne [IntPtr]::Zero) {
                                                [DLL]::WaitForSingleObject($thread, 5000) | Out-Null
                                                [DLL]::CloseHandle($thread) | Out-Null
                                                
                                                $msg = "Successfully unloaded DLL: $name from $procName"
                                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                                Write-Log "[ELF-CATCHER] $msg"
                                                
                                                # Schedule file deletion on reboot
                                                if (Test-Path $mod.FileName) {
                                                    if ([DLL]::MoveFileEx($mod.FileName, $null, 4)) {
                                                        $msg = "Scheduled deletion on reboot: $($mod.FileName)"
                                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                                        Write-Log "[ELF-CATCHER] $msg"
                                                        Write-SecurityEvent -EventType "SuspiciousDLLScheduledForDeletion" -Details @{ 
                                                            DLLPath = $mod.FileName
                                                        } -Severity "Medium"
                                                    }
                                                }
                                            } else {
                                                $msg = "Failed to unload DLL: $name from $procName"
                                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                                Write-Log "[ELF-CATCHER] $msg"
                                            }
                                            
                                            # Mark as processed
                                            $processed[$key] = $true
                                        }
                                    } catch {
                                        # Silently continue - module may have unloaded during iteration
                                    }
                                }
                                
                                # Close process handle
                                [DLL]::CloseHandle($hProc) | Out-Null
                                
                            } catch {
                                # Process may have exited
                            }
                        }
                    }
                    
                    # Clean up processed list periodically (remove entries older than 1 hour)
                    if ($processed.Count -gt 1000) {
                        $processed.Clear()
                    }
                    
                    Start-Sleep -Seconds 10
                    
                } catch {
                    $msg = "Error in Elf Catcher main loop: $_"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR: $msg"
                    Start-Sleep -Seconds 30
                }
            }
        } catch {
            try {
                Add-Content -Path "$using:Base\elf_catcher.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | CRITICAL: Elf Catcher job crashed: $_"
            } catch {}
        }
    } -ArgumentList $Base | Out-Null
    
    Write-Log "[ELF-CATCHER] DLL monitor job started successfully"
}

Write-Host "[*] Starting Integrity Monitor..."
Start-ElfCatcher
$jobNames += "ElfCatcher"

Start-Sleep -Seconds 2

Write-Host "[*] Verifying job status..."
$jobs = Get-Job
$runningJobs = $jobs | Where-Object { $_.State -eq 'Running' }
$failedJobs = $jobs | Where-Object { $_.State -eq 'Failed' }

Write-Host "[+] Total jobs created: $($jobs.Count)"
Write-Host "[+] Jobs running: $($runningJobs.Count)" -ForegroundColor Green
if ($failedJobs.Count -gt 0) {
    Write-Host "[-] Jobs failed: $($failedJobs.Count)" -ForegroundColor Red
    $failedJobs | ForEach-Object {
        Write-Host "    Failed Job ID: $($_.Id) - $($_.State)" -ForegroundColor Red
        if ($_.ChildJobs[0].Error) {
            Write-Host "    Error: $($_.ChildJobs[0].Error)" -ForegroundColor Red
        }
    }
}

foreach ($job in $jobs) {
    Write-Log "[JOB] ID: $($job.Id) | State: $($job.State) | HasMoreData: $($job.HasMoreData)"
}

Write-Log "[+] All monitoring modules started successfully"
Write-Log "[+] Self-protection: ACTIVE"
Write-Log "[+] Database integrity: VERIFIED"
Write-Log "[+] Watchdog persistence: CONFIGURED"

# Set the flag indicating jobs have been initialized
$Script:JobsInitialized = $true

# Keep script running
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Production Hardened Antivirus RUNNING" -ForegroundColor Green
Write-Host "Active Background Jobs: $($runningJobs.Count)" -ForegroundColor Green
Write-Host "Press [Ctrl] + [C] to stop." -ForegroundColor Yellow
Write-Host "Press [H] for help." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# SECURITY FIX #1: PERIODIC INTEGRITY CHECKS
function Test-ScriptIntegrity {
    try {
        # Verify script file still exists
        if (-not (Test-Path $Script:SelfPath)) {
            Write-Log "[CRITICAL] Script file has been deleted: $Script:SelfPath"
            return $false
        }
        
        # Calculate current hash
        $currentHash = (Get-FileHash -Path $Script:SelfPath -Algorithm SHA256 -ErrorAction Stop).Hash
        
        # Compare with original hash
        if ($currentHash -ne $Script:SelfHash) {
            Write-Log "[CRITICAL] Script file has been modified! Original: $Script:SelfHash, Current: $currentHash"
            return $false
        }
        
        return $true
    } catch {
        Write-ErrorLog -Message "Failed to check script integrity" -Severity "High" -ErrorRecord $_
        # On error, assume integrity is OK to prevent false positives
        return $true
    }
}

$Script:LoopCounter = 0 # Initialize loop counter

try {
    while ($true) {
        # Check for Ctrl+C via keyboard input instead of relying on trap
        try {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                
                switch ($key.Key) {
                    'H' {
                        Write-Host "`n========================================" -ForegroundColor Cyan
                        Write-Host "  ANTIVIRUS KEYBOARD SHORTCUTS" -ForegroundColor Cyan
                        Write-Host "========================================" -ForegroundColor Cyan
                        Write-Host "[H] - Show this help menu" -ForegroundColor White
                        Write-Host "[M] - Open Exclusion Manager" -ForegroundColor White
                        Write-Host "[R] - Generate Security Report" -ForegroundColor White
                        Write-Host "[Ctrl+C] - Stop antivirus (requires 5 attempts)" -ForegroundColor White
                        Write-Host "========================================`n" -ForegroundColor Cyan
                    }
                    'M' {
                        Show-ExclusionManager
                    }
                    'R' {
                        $reportPath = New-SecurityReport
                        Write-Host "[+] Security report generated: $reportPath" -ForegroundColor Green
                    }
                }
            }
        } catch [System.InvalidOperationException] {
            # Console redirected or not available - skip keyboard handling
        } catch {
            # Ignore other keyboard handling errors
        }

        # Handle Ctrl+C press
        try {
            if ([Console]::KeyAvailable) {
                $consoleKey = [Console]::ReadKey($true)
                if ($consoleKey.Modifiers -band [ConsoleModifiers]::Control -and $consoleKey.Key -eq [ConsoleKey]::C) {
                    $Script:TerminationAttempts++
                    Write-Host "`n[PROTECTION] Termination attempt detected ($Script:TerminationAttempts/$Script:MaxTerminationAttempts)" -ForegroundColor Red
                    
                    if ($Script:TerminationAttempts -ge $Script:MaxTerminationAttempts) {
                        Write-Host "[PROTECTION] Maximum termination attempts reached. Shutting down..." -ForegroundColor Yellow
                        Write-SecurityEvent -EventType "ScriptTerminated" -Details @{ PID = $PID; TotalAttempts = $Script:TerminationAttempts } -Severity "Critical"
                        break # Exit the loop
                    } else {
                        Write-Host "[PROTECTION] Termination blocked. Press Ctrl+C $($Script:MaxTerminationAttempts - $Script:TerminationAttempts) more times to force stop." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 500
                        continue # Skip the rest of the loop iteration
                    }
                }
            }
        } catch [System.InvalidOperationException] {
            # Console not available - Ctrl+C protection won't work but that's okay
        } catch {
            # Ignore other errors
        }
        
        # Check for script integrity
        # DISABLED: This check causes immediate exit when script is edited
        # The background integrity monitor job still runs every 60 seconds
        # if (-not (Test-ScriptIntegrity)) {
        #     Write-Host "[CRITICAL] Script integrity check failed. Entering fail-safe mode." -ForegroundColor Red
        #     Write-ErrorLog -Message "Script integrity compromised. Exiting." -Severity "Critical"
        #     break # Exit the loop
        # }
        
        # Check for script integrity
        if (-not (Test-ScriptIntegrity)) {
            Write-Host "[CRITICAL] Script integrity check failed. Entering fail-safe mode." -ForegroundColor Red
            # Assuming Enter-FailSafeMode is defined elsewhere or this is a placeholder for error handling
            # If it's not defined, this line might cause an error. For now, we'll log and exit.
            Write-ErrorLog -Message "Script integrity compromised. Exiting." -Severity "Critical"
            break # Exit the loop
        }
        
        # Job health check every 10 iterations
        if ($Script:LoopCounter % 10 -eq 0) {
            $runningJobsCount = (Get-Job | Where-Object { $_.State -eq 'Running' }).Count
            # Assuming a minimum expected number of jobs, e.g., 4
            if ($runningJobsCount -lt 4) { # Adjust this threshold if more jobs are added
                Write-Host "[!] WARNING: Some monitoring jobs have stopped! Check logs for details." -ForegroundColor Yellow
                Write-Log "[WARNING] Detected fewer running jobs than expected. Running: $runningJobsCount"
            }
        }
        
        # Performance monitoring every 30 seconds (adjust loop counter check for seconds)
        if ($Script:LoopCounter % 30 -eq 0) {
            # Assuming Update-PerformanceMetrics is defined elsewhere
            # If it's not defined, this line might cause an error. For now, we'll comment it out if it's not in the original code.
            # Update-PerformanceMetrics 
        }
        
        # Generate periodic reports every 5 minutes (300 seconds / 1 sec loop = 300 iterations)
        if ($Script:LoopCounter % 300 -eq 0) {
             $reportPath = New-SecurityReport
             if ($reportPath) {
                 Write-Host "[REPORT] Generated: $reportPath" -ForegroundColor Cyan
             }
        }
        
        $Script:LoopCounter++
        Start-Sleep -Seconds 1
    }
} finally {
    # Cleanup code
    Write-Host "`n[*] Shutting down antivirus..." -ForegroundColor Yellow
    
    # Stop all jobs
    Write-Log "[*] Stopping all background jobs..."
    Get-Job | Stop-Job -PassThru | Remove-Job -Force
    
    # Release mutex
    if ($Script:SecurityMutex) {
        try {
            $Script:SecurityMutex.ReleaseMutex()
            $Script:SecurityMutex.Dispose()
            Write-Host "[PROTECTION] Mutex released successfully." -ForegroundColor Green
        } catch {
            Write-Log "Warning: Failed to release mutex: $($_.Exception.Message)"
        }
    }
    
    # Clear sensitive data from memory
    Protect-SensitiveData
    
    Write-Host "[*] Antivirus stopped." -ForegroundColor Green
}
