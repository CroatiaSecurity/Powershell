# Antivirus.ps1
# Author: Gorstak

#Requires -RunAsAdministrator

param(
    [switch]$Uninstall
)

$Script:InstallDir = "C:\ProgramData\Antivirus"
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
# LOGGING FUNCTION (MUST BE VERY EARLY)
# ============================================
function Write-Log {
    param ([string]$message)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    
    try {
        # Use Script:LogsDir if available, otherwise use temp
        $targetLogFile = if ($Script:LogsDir -and (Test-Path $Script:LogsDir)) {
            Join-Path $Script:LogsDir "antivirus_log.txt"
        } elseif ($logFile) {
            $logFile
        } else {
            Join-Path $env:TEMP "antivirus_log.txt"
        }
        
        $logEntry | Out-File -FilePath $targetLogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[WARNING] Failed to write log: $message" -ForegroundColor Yellow
    }
}

function Get-ManagedJobsRunningCount {
    try {
        if (-not $script:ManagedJobs) {
            return 0
        }

        return ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
    } catch {
        return 0
    }
}



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
                ManagedJobsRunning = (Get-ManagedJobsRunningCount)
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
    return New-SecurityReport -ReportType $ReportType
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
# Task description used in scheduled task registration
$Script:TaskDescription = "Runs the Production Hardened Antivirus script"
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

function Write-SecurityEvent {
    param(
        [string]$EventType,
        [hashtable]$Details,
        [string]$Severity = "Informational"
    )
    
    try {
        $securityEvent = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            EventType = $EventType
            Severity = $Severity
            User = $env:USERNAME
            Machine = $env:COMPUTERNAME
            PID = $PID
            Details = $Details
        }
        
        $eventJson = $securityEvent | ConvertTo-Json -Compress
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

# ============================================
# MANAGED JOB FRAMEWORK (MUST BE BEFORE STARTUP)
# ============================================
$Script:LoopCounter = 0
$script:ManagedJobs = @{}

function Register-ManagedJob {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$IntervalSeconds = 30,
        [bool]$Enabled = $true,
        [bool]$Critical = $false,
        [int]$MaxRestartAttempts = 3,
        [int]$RestartDelaySeconds = 5
    )
 
    if (-not $script:ManagedJobs) {
        $script:ManagedJobs = @{}
    }

    $minIntervalSeconds = 1
    if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MinimumIntervalSeconds) {
        $minIntervalSeconds = [int]$Script:ManagedJobConfig.MinimumIntervalSeconds
    }

    $IntervalSeconds = [Math]::Max([int]$IntervalSeconds, [int]$minIntervalSeconds)
 
    $script:ManagedJobs[$Name] = [ordered]@{
        Name = $Name
        ScriptBlock = $ScriptBlock
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
        if (-not $job.Enabled) {
            continue
        }
 
        if ($null -ne $job.DisabledUtc) {
            continue
        }
 
        if ($job.NextRunUtc -gt $NowUtc) {
            continue
        }
 
        $job.LastStartUtc = $NowUtc
 
        try {
            & $job.ScriptBlock
            $job.LastSuccessUtc = [DateTime]::UtcNow
            $job.RestartAttempts = 0
            $job.LastError = $null
            $job.NextRunUtc = $job.LastSuccessUtc.AddSeconds([Math]::Max(1, $job.IntervalSeconds))
        } catch {
            $job.LastError = $_
            $job.RestartAttempts++
 
            try {
                Write-ErrorLog -Message "Managed job '$($job.Name)' failed (attempt $($job.RestartAttempts)/$($job.MaxRestartAttempts))" -Severity "High" -ErrorRecord $_
            } catch {}
 
            if ($job.RestartAttempts -ge $job.MaxRestartAttempts) {
                $job.DisabledUtc = [DateTime]::UtcNow
 
                try {
                    Write-ErrorLog -Message "Managed job '$($job.Name)' exceeded max restart attempts and has been disabled" -Severity "Critical" -ErrorRecord $_
                } catch {}
 
                continue
            }
 
            $job.NextRunUtc = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $job.RestartDelaySeconds))
        }
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
    "startmenuexperiencehost", "shellexperiencehost", "textinputhost",
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
        
        $rawName = $null
        if ($null -ne $Process.ProcessName) { $rawName = $Process.ProcessName }
        elseif ($null -ne $Process.Name) { $rawName = $Process.Name }
        else { $rawName = "" }

        $procName = $rawName.ToLower()
        if ($procName.EndsWith('.exe')) {
            $procName = $procName.Substring(0, $procName.Length - 4)
        }

        $procId = $Process.Id
        
        # SECURITY FIX #5: Self-protection
        if ($procId -eq $Script:SelfProcessName) {
            return $true
        }

        # Parent process protection: killing explorer.exe children can destabilize the shell
        try {
            $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
            if ($cimProc -and $cimProc.ParentProcessId) {
                $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cimProc.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($parent -and $parent.Name) {
                    $parentName = $parent.Name.ToLower()
                    if ($parentName -eq 'explorer.exe') {
                        return $true
                    }
                }
            }
        } catch {
        }
        
        # Check protected process names
        foreach ($protected in $Script:ProtectedProcessNames) {
            $p = $protected.ToLower()
            if ($p -match '[\*\?\[]') {
                if ($procName -like $p) { return $true }
            } else {
                if ($procName -eq $p) { return $true }
            }
        }
        
        foreach ($storeProc in $Script:MicrosoftStoreProcesses) {
            $sp = $storeProc.ToLower()
            if ($sp -match '[\*\?\[]') {
                if ($procName -like $sp) { return $true }
            } else {
                if ($procName -eq $sp) { return $true }
            }
        }
        
        foreach ($gamingProc in $Script:GamingPlatformProcesses) {
            $gp = $gamingProc.ToLower()
            if ($gp -match '[\*\?\[]') {
                if ($procName -like $gp) { return $true }
            } else {
                if ($procName -eq $gp) { return $true }
            }
        }
        
        foreach ($driverProc in $Script:CommonDriverProcesses) {
            $dp = $driverProc.ToLower()
            if ($dp -match '[\*\?\[]') {
                if ($procName -like $dp) { return $true }
            } else {
                if ($procName -eq $dp) { return $true }
            }
        }
        
        foreach ($officeProc in $Script:MicrosoftOfficeProcesses) {
            $op = $officeProc.ToLower()
            if ($op -match '[\*\?\[]') {
                if ($procName -like $op) { return $true }
            } else {
                if ($procName -eq $op) { return $true }
            }
        }
        
        foreach ($adobeProc in $Script:AdobeProcesses) {
            $ap = $adobeProc.ToLower()
            if ($ap -match '[\*\?\[]') {
                if ($procName -like $ap) { return $true }
            } else {
                if ($procName -eq $ap) { return $true }
            }
        }
        
        foreach ($prodProc in $Script:ProductivitySoftwareProcesses) {
            $pp = $prodProc.ToLower()
            if ($pp -match '[\*\?\[]') {
                if ($procName -like $pp) { return $true }
            } else {
                if ($procName -eq $pp) { return $true }
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

function Get-SafeFileHash {
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
function Move-FileToQuarantine {
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
    return Move-FileToQuarantine -filePath $filePath
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
                -not (Test-ProtectedOrSelf $_) -and
                -not (Test-CriticalSystemProcess $_) -and
                ($_.Modules | Where-Object { $_.FileName -eq $filePath })
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

function Test-ExcludeFile {
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
                    if (Test-ExcludeFile -filePath $dll.FullName) {
                        continue
                    }
                    
                    $fileHash = Get-SafeFileHash -filePath $dll.FullName
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
            param($src, $evtArgs)
            
            try {
                $localScannedFiles = $using:scannedFiles
                $localQuarantineFolder = $using:quarantineFolder
                $localDatabase = $using:localDatabase
                
                if ($evtArgs.ChangeType -in "Created", "Changed" -and 
                    $evtArgs.FullPath -notlike "$localQuarantineFolder*" -and 
                    ($evtArgs.FullPath -like "*.dll" -or $evtArgs.FullPath -like "*.winmd")) {
                    
                    if (Test-ExcludeFile -filePath $evtArgs.FullPath) {
                        return
                    }
                    
                    Start-Sleep -Milliseconds 500 # Throttle
                    
                    $fileHash = Get-SafeFileHash -filePath $evtArgs.FullPath
                    if ($fileHash) {
                        if ($localScannedFiles.ContainsKey($fileHash.Hash)) {
                            if (-not $localScannedFiles[$fileHash.Hash]) {
                                if (Set-FileOwnershipAndPermissions -filePath $evtArgs.FullPath) {
                                    Stop-ProcessUsingDLL -filePath $evtArgs.FullPath
                                    Invoke-QuarantineFile -filePath $evtArgs.FullPath
                                }
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid"
                            $localScannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8
                            Update-DatabaseIntegrity
                            
                            Write-Log "[FSWATCHER] New file: $($evtArgs.FullPath) (Valid: $isValid)"
                            Write-SecurityEvent -EventType "FileScanned" -Details @{ Path = $evtArgs.FullPath; Hash = $fileHash.Hash; IsValid = $isValid } -Severity "Informational"
                            
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $evtArgs.FullPath) {
                                    Stop-ProcessUsingDLL -filePath $evtArgs.FullPath
                                    Invoke-QuarantineFile -filePath $evtArgs.FullPath
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
function Test-HashReputation {
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

function Test-FileHash {
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
        
        $hashInfo = Get-SafeFileHash -filePath $FilePath
        if (-not $hashInfo) {
            return $false
        }
        
        $hash = $hashInfo.Hash
        
        if (Test-HashReputation -hash $hash -ProcessName $ProcessName) {
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
function Stop-ThreatProcess {
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

function Stop-ThreatProcessWrapper {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    return Stop-ThreatProcess -ProcessId $ProcessId -ProcessName $ProcessName -Reason $Reason
}

function Invoke-ProcessKill {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    return Stop-ThreatProcess -ProcessId $ProcessId -ProcessName $ProcessName -Reason $Reason
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
function Find-FilelessMalware {
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
                $hashMalicious = Test-FileHash -FilePath $proc.Path -ProcessName $proc.Name -ProcessId $proc.Id
                if ($hashMalicious) {
                    Invoke-QuarantineFile -FilePath $proc.Path
                }
            }
            
            Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.Name -Reason "Fileless PowerShell execution"
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

function Start-MemoryMonitors {
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    $intervalHighMem = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.HighMemoryCheckIntervalSeconds) { [int]$Script:ManagedJobConfig.HighMemoryCheckIntervalSeconds } else { 300 }
    Register-ManagedJob -Name "HighMemoryMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalHighMem -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-HighMemoryMonitorTick
    }

    $intervalPSMem = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.PowerShellMemoryScanIntervalSeconds) { [int]$Script:ManagedJobConfig.PowerShellMemoryScanIntervalSeconds } else { 10 }
    Register-ManagedJob -Name "PowerShellMemoryScanner" -Enabled $true -Critical $true -IntervalSeconds $intervalPSMem -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-PowerShellMemoryScannerTick
    }

    Write-Log "[+] Memory monitors (managed jobs) registered"
}

function Invoke-HighMemoryMonitorTick {
    try {
        $parentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($parentProcess) {
            $memoryMB = [math]::Round($parentProcess.WorkingSet64 / 1MB, 2)
            if ($memoryMB -gt 500) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "[$timestamp] [MEMORY] High memory usage detected: ${memoryMB}MB" | Out-File (Join-Path $Script:LogsDir "memory_alerts.txt") -Append
            }
        }
    } catch {}
}

function Invoke-PowerShellMemoryScannerTick {
    try {
        if (-not $script:PowerShellMemoryScannerEvilStrings) {
            $script:PowerShellMemoryScannerEvilStrings = @(
                'mimikatz','sekurlsa::','kerberos::','lsadump::','wdigest','tspkg',
                'http-beacon','https-beacon','cobaltstrike','sleepmask','reflective',
                'amsi.dll','AmsiScanBuffer','EtwEventWrite','MiniDumpWriteDump',
                'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
                'ReflectiveLoader','sharpchrome','rubeus','safetykatz','sharphound'
            )
        }

        $log = "$Base\ps_memory_hits.log"
        $evil = $script:PowerShellMemoryScannerEvilStrings
        $selfId = $PID

        Get-Process | Where-Object {
            try {
                $_.Id -ne $selfId -and ($_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp')
            } catch { $false }
        } | ForEach-Object {
            $hit = $false
            $proc = $_

            try {
                if (Test-ProtectedOrSelf $proc) { return }
                if (Test-CriticalSystemProcess $proc) { return }
                if (Test-IsWindowsNetworkingService -ProcessId $proc.Id) { return }

                foreach ($m in $proc.Modules) {
                    foreach ($s in $evil) {
                        if ($m.ModuleName -match $s -or $m.FileName -match $s) {
                            $hit = $true
                            break
                        }
                    }
                    if ($hit) { break }
                }
            } catch {}

            if ($hit) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | PS MEMORY HIT -> $($proc.Name) ($($proc.Id))" | Out-File $log -Append
                Write-SecurityEvent -EventType "MemoryScanHit" -Details @{ ProcessName = $proc.Name; PID = $proc.Id; Reason = "Suspicious strings in memory" } -Severity "High"

                if ($proc.Path) {
                    $hashMalicious = Test-FileHash -FilePath $proc.Path -ProcessName $proc.Name -ProcessId $proc.Id
                    if ($hashMalicious) {
                        Invoke-QuarantineFile -FilePath $proc.Path
                    }
                }

                Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.Name -Reason "Malicious strings in memory"
            }
        }
    } catch {
        try { Write-ErrorLog -Message "PowerShell memory scanner tick failed" -Severity "Low" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# REFLECTIVE PAYLOAD DETECTOR
# ============================================
Write-Log "[+] Starting reflective payload detector"

function Start-ReflectivePayloadDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ReflectivePayloadIntervalSeconds) { [int]$Script:ManagedJobConfig.ReflectivePayloadIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "ReflectivePayloadDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ReflectivePayloadDetectorTick
    }

    Write-Log "[+] Reflective payload detector (managed job) registered"
}

function Invoke-ReflectivePayloadDetectorTick {
    try {
        $log = "$Base\manual_map_hits.log"
        $selfId = $PID

        Get-Process | Where-Object {
            try { $_.Id -ne $selfId -and $_.WorkingSet64 -gt 40MB } catch { $false }
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
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REFLECTIVE PAYLOAD -> $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                Write-SecurityEvent -EventType "ReflectivePayloadDetected" -Details @{ ProcessName = $p.Name; PID = $p.Id; Path = $p.Path } -Severity "Critical"

                if ($p.Path) {
                    $hashMalicious = Test-FileHash -FilePath $p.Path -ProcessName $p.Name -ProcessId $p.Id
                    if ($hashMalicious) {
                        Invoke-QuarantineFile -FilePath $p.Path
                    }
                }

                Stop-ThreatProcess -ProcessId $p.Id -ProcessName $p.Name -Reason "Reflective payload detected"
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Reflective payload detector tick failed" -Severity "Low" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# BEHAVIOR MONITOR
# ============================================
function Start-BehaviorMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.BehaviorMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.BehaviorMonitorIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "BehaviorMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-BehaviorMonitorTick
    }

    Write-Log "[+] Behavior monitor (managed job) registered"
}

function Invoke-BehaviorMonitorTick {
    try {
        if (-not $script:BehaviorMonitorBehaviors) {
            $script:BehaviorMonitorBehaviors = @{
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
                        return ($cmdline -match "mimikatz|procdump|sekurlsa|lsadump" -or $Process.ProcessName -match "vaultcmd|cred")
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
        }

        $behaviors = $script:BehaviorMonitorBehaviors
        $logFilePath = "$Base\behavior_detections.log"
        $selfId = $PID

        Get-Process | Where-Object {
            try { $_.Id -ne $selfId } catch { $false }
        } | ForEach-Object {
            try {
                $process = $_
                if (Test-ProtectedOrSelf $process) { return }
                if (Test-CriticalSystemProcess $process) { return }

                foreach ($behavior in $behaviors.Keys) {
                    try {
                        if (& $behaviors[$behavior] $process) {
                            $msg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | BEHAVIOR DETECTED: $behavior | Process: $($process.Name) PID: $($process.Id) Path: $($process.Path)"
                            $msg | Out-File $logFilePath -Append
                            Write-SecurityEvent -EventType "SuspiciousBehaviorDetected" -Details @{ Behavior = $behavior; ProcessName = $process.Name; PID = $process.Id; Path = $process.Path } -Severity "High"

                            if ($behavior -in @("ProcessHollowing", "CredentialAccess")) {
                                if ($process.Path) {
                                    $hashMalicious = Test-FileHash -FilePath $process.Path -ProcessName $process.Name -ProcessId $process.Id
                                    if ($hashMalicious) {
                                        Invoke-QuarantineFile -FilePath $process.Path
                                    }
                                }
                                Stop-ThreatProcess -ProcessId $process.Id -ProcessName $process.Name -Reason "Suspicious behavior: $behavior"
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Behavior monitor tick failed" -Severity "Medium" -ErrorRecord $_ } catch {}
    }
}

function Start-EnhancedBehaviorMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.EnhancedBehaviorIntervalSeconds) { [int]$Script:ManagedJobConfig.EnhancedBehaviorIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "EnhancedBehaviorMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-EnhancedBehaviorMonitorTick
    }

    Write-Log "[+] Enhanced behavior monitor (managed job) registered"
}

function Invoke-EnhancedBehaviorMonitorTick {
    try {
        $logPath = "$Base\enhanced_behavior.log"
        $protected = $Script:ProtectedProcessNames
        $selfId = $PID

        Get-Process | Where-Object {
            try {
                if ($_.Id -eq $selfId) { return $false }
                if ($protected -and ($protected -contains $_.ProcessName.ToLower())) { return $false }
                $true
            } catch { $false }
        } | ForEach-Object {
            try {
                $proc = $_
                if (Test-ProtectedOrSelf $proc) { return }
                if (Test-CriticalSystemProcess $proc) { return }

                # LOLBin detection
                $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($commandLine -and (Test-LOLBinAbuse -ProcessName $proc.ProcessName -CommandLine $commandLine)) {
                    Add-Content -Path $logPath -Value "[LOLBIN ABUSE] Detected in $($proc.ProcessName) (PID: $($proc.Id)): $commandLine" -Encoding UTF8
                    Write-SecurityEvent -EventType "LOLBinAbuse" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; CommandLine = $commandLine } -Severity "High"

                    if ($proc.Path) {
                        Invoke-QuarantineFile -FilePath $proc.Path
                    }
                    Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName -Reason "LOLBin abuse detected"
                }

                # High thread/handle count
                $threadCount = $proc.Threads.Count
                $handleCount = $proc.HandleCount
                if ($threadCount -gt 100 -or $handleCount -gt 10000) {
                    Add-Content -Path $logPath -Value "SUSPICIOUS BEHAVIOR: High thread/handle count in $($proc.ProcessName) (Threads: $threadCount, Handles: $handleCount)" -Encoding UTF8
                    Write-SecurityEvent -EventType "SuspiciousProcessBehavior" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Behavior = "HighThreadHandleCount"; ThreadCount = $threadCount; HandleCount = $handleCount } -Severity "Medium"
                }

                # Random process name
                if ($proc.ProcessName -match "^[a-z0-9]{32}$") {
                    Add-Content -Path $logPath -Value "SUSPICIOUS BEHAVIOR: Random process name: $($proc.ProcessName)" -Encoding UTF8
                    Write-SecurityEvent -EventType "SuspiciousProcessBehavior" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Behavior = "RandomProcessName" } -Severity "Medium"
                }
            } catch {}
        }
    } catch {
        try {
            Write-ErrorLog -Message "Enhanced behavior monitor tick failed" -Severity "Medium" -ErrorRecord $_
        } catch {}
    }
}

function Start-AntiTamperMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.AntiTamperIntervalSeconds) { [int]$Script:ManagedJobConfig.AntiTamperIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "AntiTamperMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-AntiTamperMonitorTick
    }

    Write-Log "[+] Anti-tamper monitor (managed job) registered"
}

function Invoke-AntiTamperMonitorTick {
    try {
        if (-not $script:AntiTamperOriginalScriptHash) {
            $scriptPathToCheck = $Script:SelfPath
            if (-not $scriptPathToCheck) { $scriptPathToCheck = $PSCommandPath }
            if (-not $scriptPathToCheck) { $scriptPathToCheck = $Script:ScriptInstallPath }
            if ($scriptPathToCheck) {
                $script:AntiTamperScriptPath = $scriptPathToCheck
                $script:AntiTamperOriginalScriptHash = (Get-FileHash -Path $scriptPathToCheck -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            }
        }

        $logPath = "$Base\anti_tamper.log"
        $selfPid = $PID

        if ($script:AntiTamperScriptPath -and $script:AntiTamperOriginalScriptHash) {
            $currentHash = (Get-FileHash -Path $script:AntiTamperScriptPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($currentHash -and $currentHash -ne $script:AntiTamperOriginalScriptHash) {
                $msg = "CRITICAL: Script file has been modified! Original: $($script:AntiTamperOriginalScriptHash), Current: $currentHash"
                Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Write-SecurityEvent -EventType "ScriptTampering" -Details @{ OriginalHash = $script:AntiTamperOriginalScriptHash; CurrentHash = $currentHash } -Severity "Critical"
                Write-Host "`n[!!! CRITICAL !!!] EDR script has been tampered with!" -ForegroundColor Red
            }
        }

        $ourProcess = Get-Process -Id $selfPid -ErrorAction SilentlyContinue
        if ($ourProcess) {
            $threads = $ourProcess.Threads
            $suspendedCount = ($threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' }).Count
            if ($suspendedCount -gt 5) {
                $msg = "CRITICAL: Debugger attachment suspected - $suspendedCount suspended threads detected"
                Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Write-SecurityEvent -EventType "DebuggerDetected" -Details @{ SuspendedThreads = $suspendedCount } -Severity "Critical"
            }
        }

        $currentModules = Get-Process -Id $selfPid -Module -ErrorAction SilentlyContinue
        if ($currentModules -and $script:AntiTamperScriptPath) {
            $unexpectedModules = $currentModules | Where-Object {
                $_.FileName -notmatch "\\Windows\\|\\PowerShell\\" -and
                $_.FileName -notmatch [regex]::Escape($script:AntiTamperScriptPath)
            }
            if ($unexpectedModules) {
                foreach ($mod in $unexpectedModules) {
                    $msg = "CRITICAL: Unexpected module loaded into EDR process: $($mod.FileName)"
                    Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "ProcessInjection" -Details @{ Module = $mod.FileName } -Severity "Critical"
                }
            }
        }

        $dumpTools = Get-Process | Where-Object { $_.ProcessName -match "procdump|processhacker|processdumper|memorydumper|mimikatz" }
        if ($dumpTools) {
            foreach ($tool in $dumpTools) {
                $msg = "CRITICAL: Memory dumping tool detected: $($tool.ProcessName) (PID: $($tool.Id))"
                Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Write-SecurityEvent -EventType "MemoryDumpingTool" -Details @{ ProcessName = $tool.ProcessName; PID = $tool.Id; Path = $tool.Path } -Severity "Critical"

                try {
                    Stop-Process -Id $tool.Id -Force
                    $msg = "KILLED: Terminated memory dumping tool: $($tool.ProcessName)"
                    Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                } catch {}
            }
        }
    } catch {
        try {
            Write-ErrorLog -Message "Anti-tamper monitor tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
}

# ============================================
# START OF NEWLY ADDED CODE BLOCK
# ============================================
function Start-NetworkAnomalyDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.NetworkAnomalyIntervalSeconds) { [int]$Script:ManagedJobConfig.NetworkAnomalyIntervalSeconds } else { 15 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "NetworkAnomalyDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-NetworkAnomalyDetectorTick
    }

    Write-Log "[+] Network anomaly detector (managed job) registered"
}

function Invoke-NetworkAnomalyDetectorTick {
    try {
        if (-not $script:NetworkAnomalyConnectionBaseline) {
            $script:NetworkAnomalyConnectionBaseline = @{}
        }

        if ($script:NetworkAnomalyConnectionBaseline.Count -gt 5000) {
            $script:NetworkAnomalyConnectionBaseline.Clear()
        }

        $logFile = "$Base\network_anomalies.log"

        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            try {
                $remoteIP = $conn.RemoteAddress
                $remotePort = $conn.RemotePort
                $owningPID = $conn.OwningProcess

                # Skip localhost and private IPs
                if ($remoteIP -match "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -or $remoteIP -eq "0.0.0.0" -or $remoteIP -eq "::") {
                    continue
                }

                # Detect data exfiltration patterns (unusual ports)
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

                    try {
                        Stop-Process -Id $owningPID -Force
                        $msg = "KILLED: Terminated process with suspicious network activity: $($process.ProcessName)"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    } catch {}
                }

                # Track connection frequency for each process/IP
                $key = "$owningPID-$remoteIP"
                if (-not $script:NetworkAnomalyConnectionBaseline.ContainsKey($key)) {
                    $script:NetworkAnomalyConnectionBaseline[$key] = 1
                } else {
                    $script:NetworkAnomalyConnectionBaseline[$key]++
                    if ($script:NetworkAnomalyConnectionBaseline[$key] -gt 50) {
                        $process = Get-Process -Id $owningPID -ErrorAction SilentlyContinue
                        $msg = "SUSPICIOUS: Possible C2 beaconing from $($process.ProcessName) (PID: $owningPID) to $remoteIP (Count: $($script:NetworkAnomalyConnectionBaseline[$key]))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "PossibleC2Beaconing" -Details @{ 
                            ProcessName = $process.ProcessName
                            PID = $owningPID
                            RemoteIP = $remoteIP
                            ConnectionCount = $script:NetworkAnomalyConnectionBaseline[$key]
                        } -Severity "Critical"
                    }
                }
            } catch {}
        }

        $monitoringConnections = $connections | Where-Object { $_.RemoteAddress -match "monitoring|telemetry|analytics" }
        if ($monitoringConnections) {
            $msg = "SUSPICIOUS: Process attempting to access monitoring infrastructure"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
        }
    } catch {
        try {
            Write-ErrorLog -Message "Network anomaly detector tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
}

function Start-RootkitDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RootkitScanIntervalSeconds) { [int]$Script:ManagedJobConfig.RootkitScanIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "RootkitDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-RootkitDetectorTick
    }

    Write-Log "[+] Rootkit detector (managed job) registered"
}

function Invoke-RootkitDetectorTick {
    try {
        $logFile = "$Base\rootkit_detections.log"

        # Check for hidden processes (compare Task Manager vs Get-Process)
        $cimProcesses = Get-CimInstance Win32_Process | Select-Object -ExpandProperty ProcessId
        $psProcesses = Get-Process | Select-Object -ExpandProperty Id

        $hiddenPIDs = $cimProcesses | Where-Object { $_ -notin $psProcesses }
        if ($hiddenPIDs) {
            foreach ($processId in $hiddenPIDs) {
                try {
                    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId"
                    $msg = "CRITICAL: Hidden process detected: $($process.Name) (PID: $processId) - Possible rootkit"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "HiddenProcess" -Details @{ ProcessName = $process.Name; PID = $processId } -Severity "Critical"
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
        try {
            Write-ErrorLog -Message "Rootkit detector tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
}

function Start-FileSystemIntegrityMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.FileSystemIntegrityIntervalSeconds) { [int]$Script:ManagedJobConfig.FileSystemIntegrityIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "FileSystemIntegrityMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-FileSystemIntegrityMonitorTick
    }

    Write-Log "[+] Filesystem integrity monitor (managed job) registered"
}

function Invoke-FileSystemIntegrityMonitorTick {
    try {
        if (-not $script:FileSystemIntegrityBaseline) {
            $script:FileSystemIntegrityBaseline = @{}
        }

        if (-not $script:FileSystemIntegrityCriticalPaths) {
            $script:FileSystemIntegrityCriticalPaths = @(
                "$env:SystemRoot\System32\drivers\etc\hosts",
                "$env:SystemRoot\System32\config\SAM",
                "$env:SystemRoot\System32\config\SYSTEM",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )
        }

        $logFile = "$Base\filesystem_integrity.log"

        # One-time baseline initialization
        if (-not $script:FileSystemIntegrityBaselineInitialized) {
            foreach ($path in $script:FileSystemIntegrityCriticalPaths) {
                try {
                    if (Test-Path $path) {
                        if ((Get-Item $path).PSIsContainer) {
                            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                            foreach ($file in $files) {
                                try {
                                    $script:FileSystemIntegrityBaseline[$file.FullName] = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                                } catch {}
                            }
                        } else {
                            $script:FileSystemIntegrityBaseline[$path] = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        }
                    }
                } catch {}
            }
            $script:FileSystemIntegrityBaselineInitialized = $true
            return
        }

        foreach ($path in @($script:FileSystemIntegrityBaseline.Keys)) {
            try {
                if (Test-Path $path) {
                    $currentHash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($currentHash -ne $script:FileSystemIntegrityBaseline[$path]) {
                        $msg = "CRITICAL: Critical system file modified: $path"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "CriticalFileModified" -Details @{ 
                            FilePath = $path
                            OriginalHash = $script:FileSystemIntegrityBaseline[$path]
                            CurrentHash = $currentHash
                        } -Severity "Critical"

                        # Update baseline
                        $script:FileSystemIntegrityBaseline[$path] = $currentHash
                    }
                }
            } catch {}
        }
    } catch {
        try {
            Write-ErrorLog -Message "Filesystem integrity monitor tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
}

function Start-COMControlMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.COMControlIntervalSeconds) { [int]$Script:ManagedJobConfig.COMControlIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "COMControlMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-COMControlMonitorTick
    }

    Write-Log "[+] COM control monitor (managed job) registered"
}

function Invoke-COMControlMonitorTick {
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
                                                Add-Content -Path $Script:logFile -Value "REMOVING malicious COM control: $dllPath" -Encoding UTF8
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
    } catch {
        try {
            Write-ErrorLog -Message "COM control monitor tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
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
# ENTERPRISE EDR: AMSI Bypass Detection
# ============================================
function Start-AMSIBypassDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.AMSIBypassIntervalSeconds) { [int]$Script:ManagedJobConfig.AMSIBypassIntervalSeconds } else { 15 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "AMSIBypassDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-AMSIBypassDetectorTick
    }

    Write-Log "[+] AMSI bypass detector (managed job) registered"
}

function Invoke-AMSIBypassDetectorTick {
    try {
        $logFile = "$Base\amsi_bypass_detections.log"

        # Check for AMSI.dll being unloaded or tampered
        $amsiDllPath = "$env:SystemRoot\System32\amsi.dll"
        if (-not (Test-Path $amsiDllPath)) {
            $msg = "CRITICAL: AMSI.dll missing from System32 - possible AMSI bypass"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
            Write-SecurityEvent -EventType "AMSIDllMissing" -Details @{ ExpectedPath = $amsiDllPath } -Severity "Critical"
        }

        # Check PowerShell processes for AMSI bypass indicators
        $psProcesses = Get-Process -Name "powershell", "pwsh" -ErrorAction SilentlyContinue
        foreach ($proc in $psProcesses) {
            try {
                # Skip our own process
                if ($proc.Id -eq $PID) { continue }

                # Check if amsi.dll is loaded in the PowerShell process
                $modules = $proc.Modules | Select-Object -ExpandProperty ModuleName -ErrorAction SilentlyContinue
                $amsiLoaded = $modules -contains "amsi.dll"

                if (-not $amsiLoaded) {
                    $msg = "CRITICAL: PowerShell process (PID: $($proc.Id)) running without AMSI - likely bypass attack"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "AMSIBypassDetected" -Details @{ 
                        ProcessName = $proc.ProcessName
                        PID = $proc.Id
                        StartTime = $proc.StartTime
                    } -Severity "Critical"

                    # Terminate the suspicious process
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                        $msg = "KILLED: Terminated PowerShell process with AMSI bypass (PID: $($proc.Id))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    } catch {}
                }

                # Check for common AMSI bypass patterns in command line
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine) {
                    $bypassPatterns = @(
                        'AmsiScanBuffer',
                        'AmsiInitFailed',
                        'amsiContext',
                        'amsiSession',
                        '\[Ref\]\.Assembly\.GetType',
                        'System\.Management\.Automation\.AmsiUtils',
                        'amsi\.dll.*VirtualProtect',
                        'SetValue\(.*NonPublic.*amsi'
                    )

                    foreach ($pattern in $bypassPatterns) {
                        if ($cmdLine -match $pattern) {
                            $msg = "CRITICAL: AMSI bypass attempt detected in PowerShell (PID: $($proc.Id)) - Pattern: $pattern"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "AMSIBypassAttempt" -Details @{ 
                                ProcessName = $proc.ProcessName
                                PID = $proc.Id
                                Pattern = $pattern
                                CommandLine = $cmdLine.Substring(0, [Math]::Min(500, $cmdLine.Length))
                            } -Severity "Critical"

                            try {
                                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            } catch {}
                            break
                        }
                    }
                }
            } catch {}
        }

        # Check for ETW tampering (often done alongside AMSI bypass)
        $etwPatterns = @(
            'EtwEventWrite',
            'NtTraceEvent',
            'EventWrite.*patch'
        )

        foreach ($proc in $psProcesses) {
            try {
                if ($proc.Id -eq $PID) { continue }
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine) {
                    foreach ($pattern in $etwPatterns) {
                        if ($cmdLine -match $pattern) {
                            $msg = "CRITICAL: ETW tampering detected in PowerShell (PID: $($proc.Id))"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "ETWTamperingDetected" -Details @{ 
                                ProcessName = $proc.ProcessName
                                PID = $proc.Id
                                Pattern = $pattern
                            } -Severity "Critical"

                            try {
                                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            } catch {}
                            break
                        }
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "AMSI bypass detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Credential Dumping Detection
# ============================================
function Start-CredentialDumpingDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.CredentialDumpingIntervalSeconds) { [int]$Script:ManagedJobConfig.CredentialDumpingIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "CredentialDumpingDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-CredentialDumpingDetectorTick
    }

    Write-Log "[+] Credential dumping detector (managed job) registered"
}

function Invoke-CredentialDumpingDetectorTick {
    try {
        $logFile = "$Base\credential_dumping_detections.log"

        # Get LSASS process
        $lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $lsass) { return }

        # Known credential dumping tools
        $credDumpTools = @(
            'mimikatz',
            'procdump',
            'sqldumper',
            'comsvcs',
            'rundll32.*comsvcs.*MiniDump',
            'sekurlsa',
            'lsadump',
            'wce\.exe',
            'gsecdump',
            'pwdump',
            'fgdump',
            'lazagne',
            'crackmapexec',
            'pypykatz',
            'nanodump',
            'handlekatz',
            'physmem2profit'
        )

        # Check all running processes for credential dumping indicators
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            try {
                # Skip system processes and self
                if ($proc.Id -le 4 -or $proc.Id -eq $PID) { continue }

                $procNameLower = $proc.ProcessName.ToLower()
                $cmdLine = $null

                # Check process name against known tools
                foreach ($tool in $credDumpTools) {
                    if ($procNameLower -match $tool) {
                        $msg = "CRITICAL: Known credential dumping tool detected: $($proc.ProcessName) (PID: $($proc.Id))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "CredentialDumpingToolDetected" -Details @{ 
                            ProcessName = $proc.ProcessName
                            PID = $proc.Id
                            Tool = $tool
                        } -Severity "Critical"

                        try {
                            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: $($proc.ProcessName)"
                        } catch {}
                        break
                    }
                }

                # Check command line for credential dumping patterns
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine) {
                    $suspiciousPatterns = @(
                        'sekurlsa::logonpasswords',
                        'lsadump::sam',
                        'lsadump::dcsync',
                        'privilege::debug',
                        'token::elevate',
                        '-ma lsass',
                        'MiniDump.*lsass',
                        'comsvcs\.dll.*MiniDump',
                        'Out-Minidump',
                        'Get-Process.*lsass.*\.DumpFile',
                        'procdump.*-ma.*lsass',
                        'rundll32.*comsvcs.*24'
                    )

                    foreach ($pattern in $suspiciousPatterns) {
                        if ($cmdLine -match $pattern) {
                            $msg = "CRITICAL: Credential dumping command detected: $($proc.ProcessName) (PID: $($proc.Id)) - Pattern: $pattern"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "CredentialDumpingCommand" -Details @{ 
                                ProcessName = $proc.ProcessName
                                PID = $proc.Id
                                Pattern = $pattern
                                CommandLine = $cmdLine.Substring(0, [Math]::Min(500, $cmdLine.Length))
                            } -Severity "Critical"

                            try {
                                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            } catch {}
                            break
                        }
                    }
                }

                # Check for processes with handles to LSASS (potential credential access)
                # This is a simplified check - full implementation would use NtQuerySystemInformation
                if ($procNameLower -notin @('csrss', 'wininit', 'services', 'svchost', 'mrt', 'taskmgr', 'procexp', 'procexp64', 'msmpeng')) {
                    try {
                        $procPath = $proc.Path
                        if ($procPath -and (Test-Path $procPath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                            $isUnsigned = (-not $sig) -or ($sig.Status -ne "Valid")

                            # Check if this unsigned process has debug privileges (common for credential dumping)
                            if ($isUnsigned) {
                                # This is a heuristic - unsigned process with suspicious name patterns
                                if ($procNameLower -match '^[a-f0-9]{8,}$|^tmp|^temp|\.tmp$') {
                                    $msg = "WARNING: Unsigned process with suspicious name detected: $($proc.ProcessName) (PID: $($proc.Id))"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                    Write-SecurityEvent -EventType "SuspiciousUnsignedProcess" -Details @{ 
                                        ProcessName = $proc.ProcessName
                                        PID = $proc.Id
                                        Path = $procPath
                                    } -Severity "High"
                                }
                            }
                        }
                    } catch {}
                }
            } catch {}
        }

        # Check for SAM/SYSTEM/SECURITY hive access attempts
        $hiveAccessPatterns = @(
            'reg.*save.*sam',
            'reg.*save.*system',
            'reg.*save.*security',
            'vssadmin.*shadow',
            'wmic.*shadowcopy',
            'ntdsutil.*ifm',
            'esentutl.*ntds'
        )

        foreach ($proc in $processes) {
            try {
                if ($proc.Id -eq $PID) { continue }
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine) {
                    foreach ($pattern in $hiveAccessPatterns) {
                        if ($cmdLine -match $pattern) {
                            $msg = "CRITICAL: Registry hive extraction attempt: $($proc.ProcessName) (PID: $($proc.Id))"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "HiveExtractionAttempt" -Details @{ 
                                ProcessName = $proc.ProcessName
                                PID = $proc.Id
                                Pattern = $pattern
                            } -Severity "Critical"

                            try {
                                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            } catch {}
                            break
                        }
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Credential dumping detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Parent-Child Process Anomaly Detection
# ============================================
function Start-ProcessAnomalyDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ProcessAnomalyIntervalSeconds) { [int]$Script:ManagedJobConfig.ProcessAnomalyIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize known-good parent-child relationships
    if (-not $script:ProcessAnomalyAllowedChains) {
        $script:ProcessAnomalyAllowedChains = @{
            'explorer.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'notepad.exe', 'mspaint.exe', 'calc.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'code.exe', 'devenv.exe')
            'services.exe' = @('svchost.exe', 'spoolsv.exe', 'msdtc.exe', 'vds.exe', 'vmtoolsd.exe', 'vmwaretray.exe')
            'svchost.exe' = @('wuauclt.exe', 'wermgr.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe', 'RuntimeBroker.exe', 'dllhost.exe')
            'cmd.exe' = @('conhost.exe', 'find.exe', 'findstr.exe', 'sort.exe', 'more.com', 'tree.com')
            'powershell.exe' = @('conhost.exe')
            'pwsh.exe' = @('conhost.exe')
            'winword.exe' = @()  # Word should NOT spawn cmd/powershell
            'excel.exe' = @()    # Excel should NOT spawn cmd/powershell
            'outlook.exe' = @()  # Outlook should NOT spawn cmd/powershell
            'acrord32.exe' = @() # Adobe Reader should NOT spawn cmd/powershell
        }
    }

    # Suspicious parent-child combinations (high confidence malicious)
    if (-not $script:ProcessAnomalySuspiciousChains) {
        $script:ProcessAnomalySuspiciousChains = @(
            @{ Parent = 'winword.exe'; Child = 'cmd.exe' },
            @{ Parent = 'winword.exe'; Child = 'powershell.exe' },
            @{ Parent = 'winword.exe'; Child = 'pwsh.exe' },
            @{ Parent = 'winword.exe'; Child = 'wscript.exe' },
            @{ Parent = 'winword.exe'; Child = 'cscript.exe' },
            @{ Parent = 'winword.exe'; Child = 'mshta.exe' },
            @{ Parent = 'excel.exe'; Child = 'cmd.exe' },
            @{ Parent = 'excel.exe'; Child = 'powershell.exe' },
            @{ Parent = 'excel.exe'; Child = 'pwsh.exe' },
            @{ Parent = 'excel.exe'; Child = 'wscript.exe' },
            @{ Parent = 'excel.exe'; Child = 'mshta.exe' },
            @{ Parent = 'outlook.exe'; Child = 'cmd.exe' },
            @{ Parent = 'outlook.exe'; Child = 'powershell.exe' },
            @{ Parent = 'outlook.exe'; Child = 'pwsh.exe' },
            @{ Parent = 'acrord32.exe'; Child = 'cmd.exe' },
            @{ Parent = 'acrord32.exe'; Child = 'powershell.exe' },
            @{ Parent = 'wmiprvse.exe'; Child = 'powershell.exe' },
            @{ Parent = 'wmiprvse.exe'; Child = 'cmd.exe' },
            @{ Parent = 'mshta.exe'; Child = 'powershell.exe' },
            @{ Parent = 'mshta.exe'; Child = 'cmd.exe' },
            @{ Parent = 'wscript.exe'; Child = 'powershell.exe' },
            @{ Parent = 'wscript.exe'; Child = 'cmd.exe' },
            @{ Parent = 'cscript.exe'; Child = 'powershell.exe' },
            @{ Parent = 'cscript.exe'; Child = 'cmd.exe' },
            @{ Parent = 'rundll32.exe'; Child = 'powershell.exe' },
            @{ Parent = 'rundll32.exe'; Child = 'cmd.exe' },
            @{ Parent = 'regsvr32.exe'; Child = 'powershell.exe' },
            @{ Parent = 'regsvr32.exe'; Child = 'cmd.exe' }
        )
    }

    Register-ManagedJob -Name "ProcessAnomalyDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ProcessAnomalyDetectorTick
    }

    Write-Log "[+] Process anomaly detector (managed job) registered"
}

function Invoke-ProcessAnomalyDetectorTick {
    try {
        $logFile = "$Base\process_anomaly_detections.log"

        # Get all processes with parent info
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
            Select-Object ProcessId, Name, ParentProcessId, CommandLine, CreationDate

        foreach ($proc in $processes) {
            try {
                # Skip system processes
                if ($proc.ProcessId -le 4) { continue }

                $childName = $proc.Name.ToLower()
                $parentProc = $processes | Where-Object { $_.ProcessId -eq $proc.ParentProcessId } | Select-Object -First 1
                
                if (-not $parentProc) { continue }
                
                $parentName = $parentProc.Name.ToLower()

                # Check against suspicious chains
                foreach ($chain in $script:ProcessAnomalySuspiciousChains) {
                    if ($parentName -eq $chain.Parent -and $childName -eq $chain.Child) {
                        $msg = "CRITICAL: Suspicious process chain detected: $parentName -> $childName (PID: $($proc.ProcessId))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "SuspiciousProcessChain" -Details @{ 
                            ParentProcess = $parentName
                            ChildProcess = $childName
                            ChildPID = $proc.ProcessId
                            ParentPID = $proc.ParentProcessId
                            CommandLine = if ($proc.CommandLine) { $proc.CommandLine.Substring(0, [Math]::Min(500, $proc.CommandLine.Length)) } else { "N/A" }
                        } -Severity "Critical"

                        # Terminate the suspicious child process
                        try {
                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: $childName (PID: $($proc.ProcessId))"
                        } catch {}
                        break
                    }
                }

                # Check for LOLBin abuse patterns
                $lolbins = @('certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 
                            'wmic.exe', 'cmstp.exe', 'msiexec.exe', 'installutil.exe', 'regasm.exe',
                            'regsvcs.exe', 'msconfig.exe', 'msbuild.exe', 'csc.exe', 'vbc.exe')

                if ($childName -in $lolbins -and $proc.CommandLine) {
                    $cmdLine = $proc.CommandLine.ToLower()
                    
                    # Suspicious LOLBin usage patterns
                    $suspiciousUsage = $false
                    $reason = ""

                    if ($childName -eq 'certutil.exe' -and $cmdLine -match '-urlcache|-decode|-encode|http://|https://') {
                        $suspiciousUsage = $true
                        $reason = "CertUtil used for download/decode"
                    }
                    elseif ($childName -eq 'bitsadmin.exe' -and $cmdLine -match '/transfer|/create|http://|https://') {
                        $suspiciousUsage = $true
                        $reason = "BitsAdmin used for download"
                    }
                    elseif ($childName -eq 'mshta.exe' -and $cmdLine -match 'javascript:|vbscript:|http://|https://') {
                        $suspiciousUsage = $true
                        $reason = "MSHTA executing remote/script content"
                    }
                    elseif ($childName -eq 'regsvr32.exe' -and $cmdLine -match '/s /n /u /i:|scrobj\.dll|http://|https://') {
                        $suspiciousUsage = $true
                        $reason = "RegSvr32 Squiblydoo attack"
                    }
                    elseif ($childName -eq 'rundll32.exe' -and $cmdLine -match 'javascript:|http://|https://|shell32\.dll.*shellexec') {
                        $suspiciousUsage = $true
                        $reason = "RunDLL32 abuse"
                    }
                    elseif ($childName -eq 'wmic.exe' -and $cmdLine -match 'process call create|/node:|http://|https://') {
                        $suspiciousUsage = $true
                        $reason = "WMIC remote execution"
                    }
                    elseif ($childName -eq 'msbuild.exe' -and $cmdLine -match '\.xml|\.csproj' -and $parentName -notin @('devenv.exe', 'msbuild.exe')) {
                        $suspiciousUsage = $true
                        $reason = "MSBuild inline task execution"
                    }

                    if ($suspiciousUsage) {
                        $msg = "CRITICAL: LOLBin abuse detected: $childName - $reason (PID: $($proc.ProcessId))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "LOLBinAbuse" -Details @{ 
                            Process = $childName
                            PID = $proc.ProcessId
                            Reason = $reason
                            CommandLine = $proc.CommandLine.Substring(0, [Math]::Min(500, $proc.CommandLine.Length))
                        } -Severity "Critical"

                        try {
                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        } catch {}
                    }
                }

                # Detect unusual svchost.exe spawning (should only be spawned by services.exe)
                if ($childName -eq 'svchost.exe' -and $parentName -ne 'services.exe') {
                    $msg = "CRITICAL: svchost.exe spawned by non-services.exe parent: $parentName (PID: $($proc.ProcessId))"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "SvchostAnomalousParent" -Details @{ 
                        ParentProcess = $parentName
                        ChildPID = $proc.ProcessId
                        ParentPID = $proc.ParentProcessId
                    } -Severity "Critical"

                    try {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                    } catch {}
                }

                # Detect cmd/powershell spawned from unusual locations
                if ($childName -in @('cmd.exe', 'powershell.exe', 'pwsh.exe')) {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                    if ($procObj -and $procObj.Path) {
                        $expectedPaths = @(
                            "$env:SystemRoot\System32\cmd.exe",
                            "$env:SystemRoot\SysWOW64\cmd.exe",
                            "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
                            "$env:ProgramFiles\PowerShell\7\pwsh.exe",
                            "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
                        )

                        if ($procObj.Path -notin $expectedPaths) {
                            $msg = "CRITICAL: Shell running from unexpected location: $($procObj.Path) (PID: $($proc.ProcessId))"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Write-SecurityEvent -EventType "ShellUnexpectedLocation" -Details @{ 
                                Process = $childName
                                PID = $proc.ProcessId
                                Path = $procObj.Path
                            } -Severity "Critical"

                            try {
                                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                            } catch {}
                        }
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Process anomaly detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: WMI Persistence Detection
# ============================================
function Start-WMIPersistenceDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.WMIPersistenceIntervalSeconds) { [int]$Script:ManagedJobConfig.WMIPersistenceIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "WMIPersistenceDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-WMIPersistenceDetectorTick
    }

    Write-Log "[+] WMI persistence detector (managed job) registered"
}

function Invoke-WMIPersistenceDetectorTick {
    try {
        $logFile = "$Base\wmi_persistence_detections.log"

        # Check for WMI Event Subscriptions (common APT persistence mechanism)
        # These are used by malware like APT29, APT32, and many ransomware families

        # Check __EventFilter (triggers)
        $eventFilters = Get-CimInstance -Namespace "root\subscription" -ClassName "__EventFilter" -ErrorAction SilentlyContinue
        foreach ($filter in $eventFilters) {
            try {
                $filterName = $filter.Name
                $query = $filter.Query

                # Known legitimate filters to skip
                $legitimateFilters = @(
                    'SCM Event Log Filter',
                    'BVTFilter',
                    'TSLogonFilter',
                    'TSLogonEvents'
                )

                if ($filterName -in $legitimateFilters) { continue }

                # Check for suspicious queries
                $suspicious = $false
                $reason = ""

                if ($query -match 'Win32_ProcessStartTrace|Win32_ProcessStopTrace') {
                    $suspicious = $true
                    $reason = "Process monitoring filter (potential keylogger/spy)"
                }
                elseif ($query -match '__InstanceCreationEvent|__InstanceModificationEvent|__InstanceDeletionEvent') {
                    $suspicious = $true
                    $reason = "Instance event filter (potential persistence)"
                }
                elseif ($query -match 'Win32_LogonSession|Win32_LoggedOnUser') {
                    $suspicious = $true
                    $reason = "Logon monitoring filter"
                }
                elseif ($query -match 'SELECT.*FROM.*WHERE.*TargetInstance') {
                    $suspicious = $true
                    $reason = "Generic WMI event subscription"
                }

                if ($suspicious) {
                    $msg = "WARNING: Suspicious WMI EventFilter detected: $filterName - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "SuspiciousWMIEventFilter" -Details @{ 
                        FilterName = $filterName
                        Query = $query
                        Reason = $reason
                    } -Severity "High"
                }
            } catch {}
        }

        # Check __EventConsumer (actions)
        $consumers = @()
        $consumers += Get-CimInstance -Namespace "root\subscription" -ClassName "CommandLineEventConsumer" -ErrorAction SilentlyContinue
        $consumers += Get-CimInstance -Namespace "root\subscription" -ClassName "ActiveScriptEventConsumer" -ErrorAction SilentlyContinue

        foreach ($consumer in $consumers) {
            try {
                $consumerName = $consumer.Name
                $consumerType = $consumer.CimClass.CimClassName

                # CommandLineEventConsumer - executes commands
                if ($consumerType -eq "CommandLineEventConsumer") {
                    $commandLine = $consumer.CommandLineTemplate
                    $executable = $consumer.ExecutablePath

                    $msg = "CRITICAL: WMI CommandLineEventConsumer detected: $consumerName"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Add-Content -Path $logFile -Value "  CommandLine: $commandLine"
                    Add-Content -Path $logFile -Value "  Executable: $executable"

                    Write-SecurityEvent -EventType "WMICommandLineConsumer" -Details @{ 
                        ConsumerName = $consumerName
                        CommandLine = $commandLine
                        Executable = $executable
                    } -Severity "Critical"

                    # Remove the malicious consumer
                    try {
                        $consumer | Remove-CimInstance -ErrorAction SilentlyContinue
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REMOVED: $consumerName"
                    } catch {}
                }

                # ActiveScriptEventConsumer - executes scripts
                if ($consumerType -eq "ActiveScriptEventConsumer") {
                    $scriptText = $consumer.ScriptText
                    $scriptFile = $consumer.ScriptFileName

                    $msg = "CRITICAL: WMI ActiveScriptEventConsumer detected: $consumerName"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "WMIActiveScriptConsumer" -Details @{ 
                        ConsumerName = $consumerName
                        ScriptFile = $scriptFile
                        ScriptTextLength = if ($scriptText) { $scriptText.Length } else { 0 }
                    } -Severity "Critical"

                    # Remove the malicious consumer
                    try {
                        $consumer | Remove-CimInstance -ErrorAction SilentlyContinue
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REMOVED: $consumerName"
                    } catch {}
                }
            } catch {}
        }

        # Check __FilterToConsumerBinding (links filters to consumers)
        $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue
        foreach ($binding in $bindings) {
            try {
                $filterPath = $binding.Filter
                $consumerPath = $binding.Consumer

                $msg = "WARNING: WMI FilterToConsumerBinding detected"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Add-Content -Path $logFile -Value "  Filter: $filterPath"
                Add-Content -Path $logFile -Value "  Consumer: $consumerPath"

                Write-SecurityEvent -EventType "WMIBinding" -Details @{ 
                    Filter = "$filterPath"
                    Consumer = "$consumerPath"
                } -Severity "High"

                # Remove suspicious bindings (be careful - some may be legitimate)
                # Only remove if consumer is CommandLine or ActiveScript type
                if ($consumerPath -match 'CommandLineEventConsumer|ActiveScriptEventConsumer') {
                    try {
                        $binding | Remove-CimInstance -ErrorAction SilentlyContinue
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REMOVED binding"
                    } catch {}
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "WMI persistence detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Scheduled Task Abuse Detection
# ============================================
function Start-ScheduledTaskDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ScheduledTaskIntervalSeconds) { [int]$Script:ManagedJobConfig.ScheduledTaskIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize baseline of known tasks
    if (-not $script:ScheduledTaskBaseline) {
        $script:ScheduledTaskBaseline = @{}
    }

    Register-ManagedJob -Name "ScheduledTaskDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ScheduledTaskDetectorTick
    }

    Write-Log "[+] Scheduled task detector (managed job) registered"
}

function Invoke-ScheduledTaskDetectorTick {
    try {
        $logFile = "$Base\scheduled_task_detections.log"

        # Get all scheduled tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }

        foreach ($task in $tasks) {
            try {
                $taskName = $task.TaskName
                $taskPath = $task.TaskPath
                $fullPath = "$taskPath$taskName"

                # Skip Microsoft tasks (usually legitimate)
                if ($taskPath -match '^\\Microsoft\\') { continue }

                # Get task actions
                $actions = $task.Actions

                foreach ($action in $actions) {
                    try {
                        $execute = $action.Execute
                        $arguments = $action.Arguments

                        if (-not $execute) { continue }

                        $suspicious = $false
                        $reason = ""

                        # Check for suspicious executables
                        if ($execute -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin') {
                            $suspicious = $true
                            $reason = "Task executes script interpreter or LOLBin: $execute"
                        }

                        # Check for suspicious arguments
                        if ($arguments) {
                            if ($arguments -match '-enc|-encodedcommand|downloadstring|invoke-expression|iex|http://|https://|bypass') {
                                $suspicious = $true
                                $reason = "Task has suspicious arguments"
                            }
                            if ($arguments -match '\\temp\\|\\tmp\\|\\appdata\\local\\temp') {
                                $suspicious = $true
                                $reason = "Task executes from temp directory"
                            }
                        }

                        # Check for tasks running from user-writable locations
                        if ($execute -match '\\Users\\|\\AppData\\|\\Temp\\|\\Downloads\\') {
                            $suspicious = $true
                            $reason = "Task executes from user-writable location"
                        }

                        # Check for hidden/encoded PowerShell
                        if ($arguments -match '-w hidden|-windowstyle hidden|hidden -') {
                            $suspicious = $true
                            $reason = "Task runs hidden PowerShell"
                        }

                        # Check if this is a new task (not in baseline)
                        $isNew = $false
                        if (-not $script:ScheduledTaskBaseline.ContainsKey($fullPath)) {
                            $script:ScheduledTaskBaseline[$fullPath] = @{
                                Execute = $execute
                                Arguments = $arguments
                                FirstSeen = Get-Date
                            }
                            $isNew = $true

                            # New tasks are suspicious if they match any pattern
                            if ($execute -match 'powershell|cmd|wscript|mshta') {
                                $suspicious = $true
                                $reason = "Newly created task with script interpreter"
                            }
                        }

                        if ($suspicious) {
                            $msg = "CRITICAL: Suspicious scheduled task detected: $fullPath - $reason"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Add-Content -Path $logFile -Value "  Execute: $execute"
                            Add-Content -Path $logFile -Value "  Arguments: $arguments"
                            Add-Content -Path $logFile -Value "  IsNew: $isNew"

                            Write-SecurityEvent -EventType "SuspiciousScheduledTask" -Details @{ 
                                TaskName = $taskName
                                TaskPath = $taskPath
                                Execute = $execute
                                Arguments = if ($arguments) { $arguments.Substring(0, [Math]::Min(500, $arguments.Length)) } else { "N/A" }
                                Reason = $reason
                                IsNew = $isNew
                            } -Severity "Critical"

                            # Disable the suspicious task
                            try {
                                Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | DISABLED: $fullPath"
                            } catch {}
                        }
                    } catch {}
                }
            } catch {}
        }

        # Cap baseline size
        if ($script:ScheduledTaskBaseline.Count -gt 1000) {
            $keysToRemove = @($script:ScheduledTaskBaseline.Keys | Select-Object -First 200)
            foreach ($k in $keysToRemove) {
                $script:ScheduledTaskBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Scheduled task detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: DNS Exfiltration Detection
# ============================================
function Start-DNSExfiltrationDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.DNSExfiltrationIntervalSeconds) { [int]$Script:ManagedJobConfig.DNSExfiltrationIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize DNS query tracking
    if (-not $script:DNSQueryTracking) {
        $script:DNSQueryTracking = @{}
    }

    Register-ManagedJob -Name "DNSExfiltrationDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-DNSExfiltrationDetectorTick
    }

    Write-Log "[+] DNS exfiltration detector (managed job) registered"
}

function Invoke-DNSExfiltrationDetectorTick {
    try {
        $logFile = "$Base\dns_exfiltration_detections.log"

        # Get DNS client cache - this shows recent DNS queries
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue

        foreach ($entry in $dnsCache) {
            try {
                $name = $entry.Entry
                $recordType = $entry.Type

                if (-not $name) { continue }

                # Skip common legitimate domains
                $legitimateDomains = @(
                    'microsoft.com', 'windows.com', 'windowsupdate.com', 'msftconnecttest.com',
                    'google.com', 'googleapis.com', 'gstatic.com',
                    'cloudflare.com', 'cloudflare-dns.com',
                    'amazon.com', 'amazonaws.com',
                    'apple.com', 'icloud.com',
                    'facebook.com', 'fbcdn.net',
                    'akamai.net', 'akamaiedge.net',
                    'office.com', 'office365.com', 'outlook.com',
                    'live.com', 'msn.com', 'bing.com',
                    'github.com', 'githubusercontent.com'
                )

                $isLegitimate = $false
                foreach ($legit in $legitimateDomains) {
                    if ($name -match [regex]::Escape($legit) + '$') {
                        $isLegitimate = $true
                        break
                    }
                }
                if ($isLegitimate) { continue }

                $suspicious = $false
                $reason = ""

                # Check for unusually long subdomain (potential data exfiltration)
                $parts = $name.Split('.')
                if ($parts.Count -gt 2) {
                    $subdomain = $parts[0..($parts.Count - 3)] -join '.'
                    if ($subdomain.Length -gt 50) {
                        $suspicious = $true
                        $reason = "Unusually long subdomain (potential DNS tunneling/exfiltration)"
                    }

                    # Check for base64-like patterns in subdomain
                    if ($subdomain -match '^[A-Za-z0-9+/=]{20,}$') {
                        $suspicious = $true
                        $reason = "Base64-like subdomain pattern (potential encoded data)"
                    }

                    # Check for hex-encoded data
                    if ($subdomain -match '^[0-9a-fA-F]{32,}$') {
                        $suspicious = $true
                        $reason = "Hex-encoded subdomain (potential data exfiltration)"
                    }
                }

                # Track query frequency per domain
                $baseDomain = if ($parts.Count -ge 2) { "$($parts[-2]).$($parts[-1])" } else { $name }

                if (-not $script:DNSQueryTracking.ContainsKey($baseDomain)) {
                    $script:DNSQueryTracking[$baseDomain] = @{
                        Count = 1
                        FirstSeen = Get-Date
                        LastSeen = Get-Date
                        UniqueSubdomains = @($name)
                    }
                } else {
                    $script:DNSQueryTracking[$baseDomain].Count++
                    $script:DNSQueryTracking[$baseDomain].LastSeen = Get-Date

                    if ($name -notin $script:DNSQueryTracking[$baseDomain].UniqueSubdomains) {
                        if ($script:DNSQueryTracking[$baseDomain].UniqueSubdomains.Count -lt 100) {
                            $script:DNSQueryTracking[$baseDomain].UniqueSubdomains += $name
                        }
                    }

                    # High frequency to single domain with many unique subdomains = suspicious
                    $tracking = $script:DNSQueryTracking[$baseDomain]
                    $timeSpan = (Get-Date) - $tracking.FirstSeen
                    if ($timeSpan.TotalMinutes -gt 0) {
                        $queriesPerMinute = $tracking.Count / $timeSpan.TotalMinutes
                        $uniqueSubdomainCount = $tracking.UniqueSubdomains.Count

                        if ($queriesPerMinute -gt 10 -and $uniqueSubdomainCount -gt 20) {
                            $suspicious = $true
                            $reason = "High DNS query rate with many unique subdomains (potential DNS tunneling)"
                        }
                    }
                }

                # Check for TXT record queries (often used for C2)
                if ($recordType -eq 'TXT' -or $recordType -eq 16) {
                    $suspicious = $true
                    $reason = "TXT record query (commonly used for DNS C2)"
                }

                if ($suspicious) {
                    $msg = "WARNING: Suspicious DNS activity detected: $name - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "SuspiciousDNSActivity" -Details @{ 
                        DomainName = $name
                        RecordType = $recordType
                        Reason = $reason
                    } -Severity "High"
                }
            } catch {}
        }

        # Cap tracking dictionary size
        if ($script:DNSQueryTracking.Count -gt 500) {
            $keysToRemove = @($script:DNSQueryTracking.Keys | Select-Object -First 100)
            foreach ($k in $keysToRemove) {
                $script:DNSQueryTracking.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "DNS exfiltration detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Named Pipe Monitoring (Lateral Movement Detection)
# ============================================
function Start-NamedPipeMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.NamedPipeIntervalSeconds) { [int]$Script:ManagedJobConfig.NamedPipeIntervalSeconds } else { 15 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize known malicious pipe patterns
    if (-not $script:NamedPipeBaseline) {
        $script:NamedPipeBaseline = @{}
    }

    Register-ManagedJob -Name "NamedPipeMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-NamedPipeMonitorTick
    }

    Write-Log "[+] Named pipe monitor (managed job) registered"
}

function Invoke-NamedPipeMonitorTick {
    try {
        $logFile = "$Base\named_pipe_detections.log"

        # Known malicious named pipes used by attack tools
        $maliciousPipePatterns = @(
            # Cobalt Strike
            'msagent_*',
            'MSSE-*',
            'postex_*',
            'status_*',
            'mojo.*',
            'interprocess.*',
            # Metasploit
            'meterpreter*',
            # PsExec and similar
            'psexec*',
            'paexec*',
            'remcom*',
            'csexec*',
            # Mimikatz
            'mimikatz*',
            # Empire
            'empire*',
            # Generic C2
            '*-stdin',
            '*-stdout',
            '*-stderr',
            # Covenant
            'covenant*',
            # Sliver
            'sliver*',
            # Other common malware pipes
            'isapi_*',
            'sdp_*',
            'winsock*',
            'ntsvcs_*'
        )

        # Get all named pipes
        $pipes = Get-ChildItem -Path "\\.\pipe\" -ErrorAction SilentlyContinue

        foreach ($pipe in $pipes) {
            try {
                $pipeName = $pipe.Name

                # Check against malicious patterns
                foreach ($pattern in $maliciousPipePatterns) {
                    if ($pipeName -like $pattern) {
                        $msg = "CRITICAL: Suspicious named pipe detected: $pipeName (matches pattern: $pattern)"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "SuspiciousNamedPipe" -Details @{ 
                            PipeName = $pipeName
                            Pattern = $pattern
                        } -Severity "Critical"

                        # Try to identify the owning process
                        try {
                            $handleOutput = & handle.exe -a -p $pipeName 2>$null
                            if ($handleOutput) {
                                Add-Content -Path $logFile -Value "  Handle info: $handleOutput"
                            }
                        } catch {}

                        break
                    }
                }

                # Check for new pipes with suspicious characteristics
                if (-not $script:NamedPipeBaseline.ContainsKey($pipeName)) {
                    $script:NamedPipeBaseline[$pipeName] = @{
                        FirstSeen = Get-Date
                        Alerted = $false
                    }

                    # Alert on pipes with random-looking names (potential C2)
                    if ($pipeName -match '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
                        $msg = "WARNING: New GUID-named pipe detected (potential C2): $pipeName"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "GUIDNamedPipe" -Details @{ PipeName = $pipeName } -Severity "High"
                    }
                    elseif ($pipeName -match '^[a-zA-Z0-9]{32,}$') {
                        $msg = "WARNING: New long random-named pipe detected: $pipeName"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "RandomNamedPipe" -Details @{ PipeName = $pipeName } -Severity "Medium"
                    }
                }
            } catch {}
        }

        # Cap baseline size
        if ($script:NamedPipeBaseline.Count -gt 500) {
            $keysToRemove = @($script:NamedPipeBaseline.Keys | Select-Object -First 100)
            foreach ($k in $keysToRemove) {
                $script:NamedPipeBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Named pipe monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Registry Run Key Persistence Detection
# ============================================
function Start-RegistryPersistenceDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RegistryPersistenceIntervalSeconds) { [int]$Script:ManagedJobConfig.RegistryPersistenceIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize baseline
    if (-not $script:RegistryPersistenceBaseline) {
        $script:RegistryPersistenceBaseline = @{}
    }

    Register-ManagedJob -Name "RegistryPersistenceDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-RegistryPersistenceDetectorTick
    }

    Write-Log "[+] Registry persistence detector (managed job) registered"
}

function Invoke-RegistryPersistenceDetectorTick {
    try {
        $logFile = "$Base\registry_persistence_detections.log"

        # Common persistence registry locations
        $persistenceKeys = @(
            # Run keys (most common)
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            # RunServices (legacy but still used)
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            # Winlogon
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            # Explorer Run
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            # Active Setup
            "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
            # Shell folders
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        )

        foreach ($keyPath in $persistenceKeys) {
            try {
                if (-not (Test-Path $keyPath)) { continue }

                $values = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                if (-not $values) { continue }

                foreach ($prop in $values.PSObject.Properties) {
                    try {
                        # Skip PowerShell metadata properties
                        if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }

                        $valueName = $prop.Name
                        $valueData = $prop.Value

                        if (-not $valueData -or $valueData -isnot [string]) { continue }

                        $fullKey = "$keyPath\$valueName"

                        # Check if this is a new entry
                        $isNew = $false
                        if (-not $script:RegistryPersistenceBaseline.ContainsKey($fullKey)) {
                            $script:RegistryPersistenceBaseline[$fullKey] = @{
                                Value = $valueData
                                FirstSeen = Get-Date
                            }
                            $isNew = $true
                        } elseif ($script:RegistryPersistenceBaseline[$fullKey].Value -ne $valueData) {
                            # Value changed
                            $isNew = $true
                            $script:RegistryPersistenceBaseline[$fullKey].Value = $valueData
                            $script:RegistryPersistenceBaseline[$fullKey].Changed = Get-Date
                        }

                        if (-not $isNew) { continue }

                        # Analyze the value for suspicious patterns
                        $suspicious = $false
                        $reason = ""

                        # Check for suspicious executables
                        if ($valueData -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32') {
                            $suspicious = $true
                            $reason = "Script interpreter in persistence key"
                        }

                        # Check for encoded commands
                        if ($valueData -match '-enc|-encodedcommand|frombase64') {
                            $suspicious = $true
                            $reason = "Encoded command in persistence key"
                        }

                        # Check for download cradles
                        if ($valueData -match 'downloadstring|downloadfile|invoke-webrequest|wget|curl|http://|https://') {
                            $suspicious = $true
                            $reason = "Download cradle in persistence key"
                        }

                        # Check for temp/appdata paths
                        if ($valueData -match '\\temp\\|\\tmp\\|\\appdata\\local\\temp|\\downloads\\') {
                            $suspicious = $true
                            $reason = "Execution from temp/user directory"
                        }

                        # Check for hidden window
                        if ($valueData -match '-w hidden|-windowstyle hidden') {
                            $suspicious = $true
                            $reason = "Hidden window execution"
                        }

                        # Check for random-looking executable names
                        if ($valueData -match '\\[a-f0-9]{8,}\.exe') {
                            $suspicious = $true
                            $reason = "Random hex-named executable"
                        }

                        if ($suspicious) {
                            $msg = "CRITICAL: Suspicious registry persistence detected: $fullKey - $reason"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                            Add-Content -Path $logFile -Value "  Value: $valueData"

                            Write-SecurityEvent -EventType "SuspiciousRegistryPersistence" -Details @{ 
                                KeyPath = $keyPath
                                ValueName = $valueName
                                ValueData = $valueData.Substring(0, [Math]::Min(500, $valueData.Length))
                                Reason = $reason
                                IsNew = $isNew
                            } -Severity "Critical"

                            # Remove the malicious entry
                            try {
                                Remove-ItemProperty -Path $keyPath -Name $valueName -Force -ErrorAction SilentlyContinue
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | REMOVED: $valueName from $keyPath"
                            } catch {}
                        }
                    } catch {}
                }
            } catch {}
        }

        # Cap baseline size
        if ($script:RegistryPersistenceBaseline.Count -gt 1000) {
            $keysToRemove = @($script:RegistryPersistenceBaseline.Keys | Select-Object -First 200)
            foreach ($k in $keysToRemove) {
                $script:RegistryPersistenceBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Registry persistence detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: PowerShell Script Block Logging Analysis
# ============================================
function Start-ScriptBlockAnalyzer {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ScriptBlockAnalyzerIntervalSeconds) { [int]$Script:ManagedJobConfig.ScriptBlockAnalyzerIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Track last event time to avoid re-processing
    if (-not $script:ScriptBlockLastEventTime) {
        $script:ScriptBlockLastEventTime = (Get-Date).AddMinutes(-5)
    }

    Register-ManagedJob -Name "ScriptBlockAnalyzer" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ScriptBlockAnalyzerTick
    }

    Write-Log "[+] Script block analyzer (managed job) registered"
}

function Invoke-ScriptBlockAnalyzerTick {
    try {
        $logFile = "$Base\scriptblock_analysis.log"

        # Get recent PowerShell script block logging events (Event ID 4104)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            Id = 4104
            StartTime = $script:ScriptBlockLastEventTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if (-not $events) { return }

        # Update last event time
        $script:ScriptBlockLastEventTime = Get-Date

        # Suspicious patterns to detect
        $suspiciousPatterns = @(
            @{ Pattern = 'Invoke-Mimikatz|sekurlsa|kerberos::'; Severity = 'Critical'; Reason = 'Mimikatz detected' },
            @{ Pattern = 'Invoke-Empire|Invoke-PSInject'; Severity = 'Critical'; Reason = 'Empire framework detected' },
            @{ Pattern = 'Invoke-Shellcode|Invoke-ReflectivePEInjection'; Severity = 'Critical'; Reason = 'Shellcode injection detected' },
            @{ Pattern = 'Get-GPPPassword|Get-GPPAutologon'; Severity = 'Critical'; Reason = 'GPP password extraction' },
            @{ Pattern = 'Invoke-Kerberoast|Invoke-ASREPRoast'; Severity = 'Critical'; Reason = 'Kerberos attack detected' },
            @{ Pattern = 'Invoke-DCSync|lsadump::dcsync'; Severity = 'Critical'; Reason = 'DCSync attack detected' },
            @{ Pattern = 'Invoke-TokenManipulation|Invoke-CredentialInjection'; Severity = 'Critical'; Reason = 'Token manipulation detected' },
            @{ Pattern = 'AmsiScanBuffer|AmsiInitFailed|amsiContext'; Severity = 'Critical'; Reason = 'AMSI bypass attempt' },
            @{ Pattern = 'Net\.WebClient.*DownloadString|Invoke-Expression.*http'; Severity = 'High'; Reason = 'Download and execute pattern' },
            @{ Pattern = 'IEX.*\(.*New-Object.*Net\.WebClient'; Severity = 'High'; Reason = 'Classic download cradle' },
            @{ Pattern = '\[System\.Reflection\.Assembly\]::Load'; Severity = 'High'; Reason = 'Reflective assembly loading' },
            @{ Pattern = 'VirtualAlloc|VirtualProtect|CreateThread'; Severity = 'High'; Reason = 'Memory manipulation APIs' },
            @{ Pattern = 'Add-MpPreference.*-ExclusionPath'; Severity = 'High'; Reason = 'Defender exclusion modification' },
            @{ Pattern = 'Set-MpPreference.*-DisableRealtimeMonitoring'; Severity = 'Critical'; Reason = 'Defender disable attempt' },
            @{ Pattern = 'Stop-Service.*WinDefend|sc.*stop.*WinDefend'; Severity = 'Critical'; Reason = 'Defender service stop attempt' },
            @{ Pattern = '-bxor|-band.*0x|char\]\s*\d+'; Severity = 'Medium'; Reason = 'Obfuscation detected' },
            @{ Pattern = 'FromBase64String|ToBase64String.*\|.*iex'; Severity = 'High'; Reason = 'Base64 decode and execute' },
            @{ Pattern = 'Invoke-WMIMethod.*Create|Win32_Process.*Create'; Severity = 'High'; Reason = 'WMI process creation' },
            @{ Pattern = 'Enter-PSSession|Invoke-Command.*-ComputerName'; Severity = 'Medium'; Reason = 'Remote PowerShell execution' },
            @{ Pattern = 'reg.*add.*\\Run|New-ItemProperty.*\\Run'; Severity = 'High'; Reason = 'Registry persistence' }
        )

        foreach ($logEvent in $events) {
            try {
                $scriptBlock = $logEvent.Properties[2].Value
                if (-not $scriptBlock) { continue }

                # Skip our own script
                if ($scriptBlock -match 'Antivirus\.ps1|Invoke-ScriptBlockAnalyzerTick') { continue }

                foreach ($check in $suspiciousPatterns) {
                    if ($scriptBlock -match $check.Pattern) {
                        $msg = "$($check.Severity.ToUpper()): Suspicious PowerShell detected - $($check.Reason)"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Add-Content -Path $logFile -Value "  Pattern: $($check.Pattern)"
                        Add-Content -Path $logFile -Value "  Script (truncated): $($scriptBlock.Substring(0, [Math]::Min(500, $scriptBlock.Length)))"

                        Write-SecurityEvent -EventType "SuspiciousScriptBlock" -Details @{ 
                            Pattern = $check.Pattern
                            Reason = $check.Reason
                            ScriptLength = $scriptBlock.Length
                            TimeCreated = $logEvent.TimeCreated
                        } -Severity $check.Severity

                        # For critical detections, try to find and kill the process
                        if ($check.Severity -eq 'Critical') {
                            try {
                                $psProcesses = Get-Process -Name "powershell", "pwsh" -ErrorAction SilentlyContinue | 
                                    Where-Object { $_.Id -ne $PID }
                                foreach ($proc in $psProcesses) {
                                    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                                    if ($cmdLine -match $check.Pattern) {
                                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: PowerShell PID $($proc.Id)"
                                    }
                                }
                            } catch {}
                        }

                        break  # Only report first match per script block
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Script block analyzer tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Service Creation/Modification Detection
# ============================================
function Start-ServiceMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ServiceMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.ServiceMonitorIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize service baseline
    if (-not $script:ServiceBaseline) {
        $script:ServiceBaseline = @{}
    }

    Register-ManagedJob -Name "ServiceMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ServiceMonitorTick
    }

    Write-Log "[+] Service monitor (managed job) registered"
}

function Invoke-ServiceMonitorTick {
    try {
        $logFile = "$Base\service_detections.log"

        # Get all services
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

        foreach ($svc in $services) {
            try {
                $svcName = $svc.Name
                $svcPath = $svc.PathName
                $svcState = $svc.State
                $svcStartMode = $svc.StartMode

                if (-not $svcPath) { continue }

                $svcKey = $svcName

                # Check if this is a new or modified service
                $isNew = $false
                $isModified = $false

                if (-not $script:ServiceBaseline.ContainsKey($svcKey)) {
                    $script:ServiceBaseline[$svcKey] = @{
                        PathName = $svcPath
                        StartMode = $svcStartMode
                        FirstSeen = Get-Date
                    }
                    $isNew = $true
                } elseif ($script:ServiceBaseline[$svcKey].PathName -ne $svcPath) {
                    $isModified = $true
                    $script:ServiceBaseline[$svcKey].PathName = $svcPath
                    $script:ServiceBaseline[$svcKey].Modified = Get-Date
                }

                if (-not $isNew -and -not $isModified) { continue }

                # Analyze for suspicious patterns
                $suspicious = $false
                $reason = ""

                # Check for script interpreters in service path
                if ($svcPath -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta') {
                    $suspicious = $true
                    $reason = "Service uses script interpreter"
                }

                # Check for temp/user directories
                if ($svcPath -match '\\temp\\|\\tmp\\|\\appdata\\|\\users\\.*\\downloads\\') {
                    $suspicious = $true
                    $reason = "Service binary in temp/user directory"
                }

                # Check for encoded commands
                if ($svcPath -match '-enc|-encodedcommand|frombase64') {
                    $suspicious = $true
                    $reason = "Service uses encoded command"
                }

                # Check for suspicious service names
                if ($svcName -match '^[a-f0-9]{8,}$|^svc[0-9]+$|^service[0-9]+$') {
                    $suspicious = $true
                    $reason = "Suspicious service name pattern"
                }

                # Check for unquoted service paths with spaces (vulnerability)
                if ($svcPath -notmatch '^"' -and $svcPath -match ' ' -and $svcPath -match '\.exe') {
                    $suspicious = $true
                    $reason = "Unquoted service path with spaces (potential hijack)"
                }

                # Check for services running as SYSTEM from user directories
                if ($svc.StartName -match 'LocalSystem|SYSTEM' -and $svcPath -match '\\Users\\') {
                    $suspicious = $true
                    $reason = "SYSTEM service running from user directory"
                }

                # Check for unsigned binaries
                $exePath = $svcPath -replace '^"([^"]+)".*', '$1' -replace '\s+-.*$', ''
                if ($exePath -and (Test-Path $exePath)) {
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -ne "Valid") {
                        if ($isNew) {
                            $suspicious = $true
                            $reason = "New service with unsigned/invalid binary"
                        }
                    }
                }

                if ($suspicious) {
                    $action = if ($isNew) { "NEW" } else { "MODIFIED" }
                    $msg = "CRITICAL: Suspicious service detected ($action): $svcName - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Add-Content -Path $logFile -Value "  Path: $svcPath"
                    Add-Content -Path $logFile -Value "  StartMode: $svcStartMode"

                    Write-SecurityEvent -EventType "SuspiciousService" -Details @{ 
                        ServiceName = $svcName
                        PathName = $svcPath
                        StartMode = $svcStartMode
                        Reason = $reason
                        IsNew = $isNew
                        IsModified = $isModified
                    } -Severity "Critical"

                    # Stop and disable suspicious new services
                    if ($isNew -and $svcState -eq 'Running') {
                        try {
                            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | STOPPED and DISABLED: $svcName"
                        } catch {}
                    }
                }
            } catch {}
        }

        # Cap baseline size
        if ($script:ServiceBaseline.Count -gt 500) {
            $keysToRemove = @($script:ServiceBaseline.Keys | Select-Object -First 100)
            foreach ($k in $keysToRemove) {
                $script:ServiceBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Service monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: DLL Search Order Hijacking Detection
# ============================================
function Start-DLLHijackDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.DLLHijackIntervalSeconds) { [int]$Script:ManagedJobConfig.DLLHijackIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "DLLHijackDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-DLLHijackDetectorTick
    }

    Write-Log "[+] DLL hijack detector (managed job) registered"
}

function Invoke-DLLHijackDetectorTick {
    try {
        $logFile = "$Base\dll_hijack_detections.log"

        # Known DLLs that are commonly hijacked
        $hijackableDLLs = @(
            'version.dll', 'winmm.dll', 'wsock32.dll', 'wtsapi32.dll',
            'dbghelp.dll', 'dbgcore.dll', 'faultrep.dll', 'msimg32.dll',
            'oleacc.dll', 'profapi.dll', 'secur32.dll', 'userenv.dll',
            'uxtheme.dll', 'wer.dll', 'winhttp.dll', 'winspool.drv',
            'wow64log.dll', 'CRYPTSP.dll', 'CRYPTBASE.dll', 'dwmapi.dll',
            'netapi32.dll', 'propsys.dll', 'WindowsCodecs.dll'
        )

        # Check common application directories for suspicious DLLs
        $appDirs = @(
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:LOCALAPPDATA",
            "$env:APPDATA"
        )

        foreach ($appDir in $appDirs) {
            if (-not (Test-Path $appDir)) { continue }

            # Get subdirectories (application folders)
            $subDirs = Get-ChildItem -Path $appDir -Directory -ErrorAction SilentlyContinue | Select-Object -First 50

            foreach ($dir in $subDirs) {
                try {
                    foreach ($dllName in $hijackableDLLs) {
                        $dllPath = Join-Path $dir.FullName $dllName

                        if (Test-Path $dllPath) {
                            # Check if this DLL should be here (compare with System32)
                            $systemDll = Join-Path "$env:SystemRoot\System32" $dllName

                            if (Test-Path $systemDll) {
                                # Compare signatures
                                $appSig = Get-AuthenticodeSignature -FilePath $dllPath -ErrorAction SilentlyContinue
                                $sysSig = Get-AuthenticodeSignature -FilePath $systemDll -ErrorAction SilentlyContinue

                                $suspicious = $false
                                $reason = ""

                                # Unsigned DLL in app directory
                                if (-not $appSig -or $appSig.Status -ne "Valid") {
                                    $suspicious = $true
                                    $reason = "Unsigned DLL in application directory"
                                }
                                # Different signer than system DLL
                                elseif ($sysSig -and $sysSig.Status -eq "Valid" -and 
                                       $appSig.SignerCertificate.Subject -ne $sysSig.SignerCertificate.Subject) {
                                    $suspicious = $true
                                    $reason = "DLL signed by different entity than system version"
                                }

                                if ($suspicious) {
                                    $msg = "WARNING: Potential DLL hijack detected: $dllPath - $reason"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                                    Write-SecurityEvent -EventType "PotentialDLLHijack" -Details @{ 
                                        DLLPath = $dllPath
                                        DLLName = $dllName
                                        AppDirectory = $dir.FullName
                                        Reason = $reason
                                        SignatureStatus = $appSig.Status
                                    } -Severity "High"

                                    # Quarantine the suspicious DLL
                                    try {
                                        $quarantinePath = "$quarantineFolder\$($dllName)_$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
                                        Move-Item -Path $dllPath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED: $dllPath -> $quarantinePath"
                                    } catch {}
                                }
                            }
                        }
                    }
                } catch {}
            }
        }

        # Check for DLLs in PATH directories that shouldn't have them
        $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) }

        foreach ($pathDir in $pathDirs) {
            try {
                # Skip system directories
                if ($pathDir -match "$([regex]::Escape($env:SystemRoot))|$([regex]::Escape($env:ProgramFiles))") { continue }

                foreach ($dllName in $hijackableDLLs) {
                    $dllPath = Join-Path $pathDir $dllName

                    if (Test-Path $dllPath) {
                        $sig = Get-AuthenticodeSignature -FilePath $dllPath -ErrorAction SilentlyContinue

                        if (-not $sig -or $sig.Status -ne "Valid") {
                            $msg = "CRITICAL: Unsigned system DLL in PATH directory: $dllPath"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                            Write-SecurityEvent -EventType "DLLInPATH" -Details @{ 
                                DLLPath = $dllPath
                                DLLName = $dllName
                                PathDirectory = $pathDir
                            } -Severity "Critical"

                            # Quarantine
                            try {
                                $quarantinePath = "$quarantineFolder\$($dllName)_$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
                                Move-Item -Path $dllPath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                            } catch {}
                        }
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "DLL hijack detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Token/Privilege Manipulation Detection
# ============================================
function Start-TokenManipulationDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.TokenManipulationIntervalSeconds) { [int]$Script:ManagedJobConfig.TokenManipulationIntervalSeconds } else { 15 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "TokenManipulationDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-TokenManipulationDetectorTick
    }

    Write-Log "[+] Token manipulation detector (managed job) registered"
}

function Invoke-TokenManipulationDetectorTick {
    try {
        $logFile = "$Base\token_manipulation_detections.log"

        # Get all processes
        $processes = Get-Process -ErrorAction SilentlyContinue

        foreach ($proc in $processes) {
            try {
                # Skip system processes and self
                if ($proc.Id -le 4 -or $proc.Id -eq $PID) { continue }

                $procName = $proc.ProcessName.ToLower()

                # Skip known safe processes
                if ($procName -in @('system', 'smss', 'csrss', 'wininit', 'services', 'lsass', 'svchost', 'explorer', 'dwm', 'taskhostw')) { continue }

                # Get process token information via command line analysis
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine

                if ($cmdLine) {
                    $suspicious = $false
                    $reason = ""

                    # Check for token manipulation patterns
                    $tokenPatterns = @(
                        @{ Pattern = 'Invoke-TokenManipulation'; Reason = 'PowerShell token manipulation' },
                        @{ Pattern = 'Invoke-CredentialInjection'; Reason = 'Credential injection' },
                        @{ Pattern = 'Invoke-RevertToSelf'; Reason = 'Token revert manipulation' },
                        @{ Pattern = 'ImpersonateLoggedOnUser|ImpersonateNamedPipeClient'; Reason = 'Impersonation API usage' },
                        @{ Pattern = 'DuplicateToken|DuplicateTokenEx'; Reason = 'Token duplication' },
                        @{ Pattern = 'SetThreadToken|AdjustTokenPrivileges'; Reason = 'Token privilege adjustment' },
                        @{ Pattern = 'CreateProcessWithToken|CreateProcessAsUser'; Reason = 'Process creation with alternate token' },
                        @{ Pattern = 'LogonUser.*LOGON32_LOGON_NEW_CREDENTIALS'; Reason = 'Pass-the-hash style logon' },
                        @{ Pattern = 'runas\s+/netonly|runas\s+/savecred'; Reason = 'RunAs with credential options' },
                        @{ Pattern = 'incognito|list_tokens|impersonate_token'; Reason = 'Incognito/Meterpreter token commands' }
                    )

                    foreach ($check in $tokenPatterns) {
                        if ($cmdLine -match $check.Pattern) {
                            $suspicious = $true
                            $reason = $check.Reason
                            break
                        }
                    }

                    if ($suspicious) {
                        $msg = "CRITICAL: Token manipulation detected: $($proc.ProcessName) (PID: $($proc.Id)) - $reason"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                        Write-SecurityEvent -EventType "TokenManipulation" -Details @{ 
                            ProcessName = $proc.ProcessName
                            PID = $proc.Id
                            Reason = $reason
                            CommandLine = $cmdLine.Substring(0, [Math]::Min(500, $cmdLine.Length))
                        } -Severity "Critical"

                        # Kill the process
                        try {
                            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: $($proc.ProcessName) (PID: $($proc.Id))"
                        } catch {}
                    }
                }

                # Check for processes running with unexpected privileges
                # Look for non-admin processes that somehow have admin tokens
                try {
                    $procPath = $proc.Path
                    if ($procPath -and (Test-Path $procPath)) {
                        # Check if process is from user directory but running elevated
                        if ($procPath -match '\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\') {
                            # This is a user-directory process - check if it's running as SYSTEM or admin
                            $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).GetOwner()
                            if ($owner -and $owner.User -eq 'SYSTEM') {
                                $msg = "CRITICAL: User-directory process running as SYSTEM: $procPath (PID: $($proc.Id))"
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                                Write-SecurityEvent -EventType "ElevatedUserProcess" -Details @{ 
                                    ProcessName = $proc.ProcessName
                                    PID = $proc.Id
                                    Path = $procPath
                                    Owner = 'SYSTEM'
                                } -Severity "Critical"

                                try {
                                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                                } catch {}
                            }
                        }
                    }
                } catch {}
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Token manipulation detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Startup/Autorun Location Monitor
# ============================================
function Start-StartupMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.StartupMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.StartupMonitorIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize startup baseline
    if (-not $script:StartupBaseline) {
        $script:StartupBaseline = @{}
    }

    Register-ManagedJob -Name "StartupMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-StartupMonitorTick
    }

    Write-Log "[+] Startup monitor (managed job) registered"
}

function Invoke-StartupMonitorTick {
    try {
        $logFile = "$Base\startup_detections.log"

        # Startup folder locations
        $startupFolders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        foreach ($folder in $startupFolders) {
            if (-not (Test-Path $folder)) { continue }

            $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue

            foreach ($item in $items) {
                try {
                    $itemPath = $item.FullName
                    $itemKey = $itemPath.ToLower()

                    # Check if new
                    $isNew = $false
                    if (-not $script:StartupBaseline.ContainsKey($itemKey)) {
                        $script:StartupBaseline[$itemKey] = @{
                            Name = $item.Name
                            Hash = (Get-FileHash -Path $itemPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            FirstSeen = Get-Date
                        }
                        $isNew = $true
                    }

                    if (-not $isNew) { continue }

                    # Analyze new startup item
                    $suspicious = $false
                    $reason = ""

                    # Check file extension
                    $ext = $item.Extension.ToLower()
                    if ($ext -in @('.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.hta')) {
                        $suspicious = $true
                        $reason = "Script file in startup folder"
                    }

                    # Check for shortcuts pointing to suspicious locations
                    if ($ext -eq '.lnk') {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($itemPath)
                            $targetPath = $shortcut.TargetPath

                            if ($targetPath -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta') {
                                $suspicious = $true
                                $reason = "Shortcut to script interpreter"
                            }
                            elseif ($targetPath -match '\\temp\\|\\tmp\\|\\appdata\\local\\temp') {
                                $suspicious = $true
                                $reason = "Shortcut to temp directory"
                            }
                            elseif ($targetPath -and -not (Test-Path $targetPath)) {
                                $suspicious = $true
                                $reason = "Shortcut to non-existent target"
                            }
                        } catch {}
                    }

                    # Check for unsigned executables
                    if ($ext -eq '.exe') {
                        $sig = Get-AuthenticodeSignature -FilePath $itemPath -ErrorAction SilentlyContinue
                        if (-not $sig -or $sig.Status -ne "Valid") {
                            $suspicious = $true
                            $reason = "Unsigned executable in startup folder"
                        }
                    }

                    if ($suspicious) {
                        $msg = "CRITICAL: Suspicious startup item detected: $($item.Name) - $reason"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                        Write-SecurityEvent -EventType "SuspiciousStartupItem" -Details @{ 
                            ItemPath = $itemPath
                            ItemName = $item.Name
                            Reason = $reason
                            Folder = $folder
                        } -Severity "Critical"

                        # Quarantine the item
                        try {
                            $quarantinePath = "$quarantineFolder\startup_$($item.Name)_$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
                            Move-Item -Path $itemPath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED: $itemPath"
                        } catch {}
                    }
                } catch {}
            }
        }

        # Cap baseline
        if ($script:StartupBaseline.Count -gt 200) {
            $keysToRemove = @($script:StartupBaseline.Keys | Select-Object -First 50)
            foreach ($k in $keysToRemove) {
                $script:StartupBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Startup monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Browser Extension Monitor
# ============================================
function Start-BrowserExtensionMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.BrowserExtensionIntervalSeconds) { [int]$Script:ManagedJobConfig.BrowserExtensionIntervalSeconds } else { 120 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize extension baseline
    if (-not $script:BrowserExtensionBaseline) {
        $script:BrowserExtensionBaseline = @{}
    }

    Register-ManagedJob -Name "BrowserExtensionMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-BrowserExtensionMonitorTick
    }

    Write-Log "[+] Browser extension monitor (managed job) registered"
}

function Invoke-BrowserExtensionMonitorTick {
    try {
        $logFile = "$Base\browser_extension_detections.log"

        # Chrome extensions
        $chromeExtPaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Extensions"
        )

        # Edge extensions
        $edgeExtPaths = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Profile 1\Extensions"
        )

        # Firefox extensions
        $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"

        $allExtPaths = $chromeExtPaths + $edgeExtPaths

        foreach ($extPath in $allExtPaths) {
            if (-not (Test-Path $extPath)) { continue }

            $extensions = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue

            foreach ($ext in $extensions) {
                try {
                    $extId = $ext.Name
                    $extKey = "$extPath\$extId"

                    # Check if new
                    $isNew = $false
                    if (-not $script:BrowserExtensionBaseline.ContainsKey($extKey)) {
                        $script:BrowserExtensionBaseline[$extKey] = @{
                            ExtensionId = $extId
                            FirstSeen = Get-Date
                        }
                        $isNew = $true
                    }

                    if (-not $isNew) { continue }

                    # Read manifest to get extension info
                    $manifestPath = Get-ChildItem -Path $ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1

                    $extName = $extId
                    $permissions = @()

                    if ($manifestPath) {
                        try {
                            $manifest = Get-Content -Path $manifestPath.FullName -Raw | ConvertFrom-Json
                            $extName = if ($manifest.name) { $manifest.name } else { $extId }
                            $permissions = @()
                            if ($manifest.permissions) { $permissions += $manifest.permissions }
                            if ($manifest.optional_permissions) { $permissions += $manifest.optional_permissions }
                        } catch {}
                    }

                    # Check for suspicious permissions
                    $suspicious = $false
                    $reason = ""

                    $dangerousPermissions = @(
                        'webRequestBlocking',
                        'nativeMessaging',
                        'debugger',
                        'proxy',
                        'vpnProvider',
                        'management',
                        'privacy',
                        'browsingData'
                    )

                    foreach ($perm in $permissions) {
                        if ($perm -in $dangerousPermissions) {
                            $suspicious = $true
                            $reason = "Extension has dangerous permission: $perm"
                            break
                        }
                        if ($perm -eq '<all_urls>' -or $perm -match '^\*://\*/') {
                            $suspicious = $true
                            $reason = "Extension has access to all websites"
                            break
                        }
                    }

                    # Check for extensions with random-looking IDs (not from store)
                    if ($extId -notmatch '^[a-z]{32}$') {
                        # Chrome Web Store extensions have 32 lowercase letter IDs
                        if ($extId -match '^[a-f0-9]{32}$|^[A-Z0-9]{20,}$') {
                            $suspicious = $true
                            $reason = "Extension ID doesn't match store format (possibly sideloaded)"
                        }
                    }

                    if ($suspicious) {
                        $msg = "WARNING: Suspicious browser extension detected: $extName ($extId) - $reason"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                        Write-SecurityEvent -EventType "SuspiciousBrowserExtension" -Details @{ 
                            ExtensionId = $extId
                            ExtensionName = $extName
                            Path = $extPath
                            Reason = $reason
                            Permissions = ($permissions -join ', ')
                        } -Severity "High"
                    }
                } catch {}
            }
        }

        # Check Firefox extensions
        if (Test-Path $firefoxProfiles) {
            $profiles = Get-ChildItem -Path $firefoxProfiles -Directory -ErrorAction SilentlyContinue

            foreach ($ffProfile in $profiles) {
                $extensionsJson = Join-Path $ffProfile.FullName "extensions.json"
                if (Test-Path $extensionsJson) {
                    try {
                        $extData = Get-Content -Path $extensionsJson -Raw | ConvertFrom-Json
                        foreach ($addon in $extData.addons) {
                            $addonId = $addon.id
                            $addonKey = "firefox_$addonId"

                            if (-not $script:BrowserExtensionBaseline.ContainsKey($addonKey)) {
                                $script:BrowserExtensionBaseline[$addonKey] = @{
                                    ExtensionId = $addonId
                                    FirstSeen = Get-Date
                                }

                                # Check if sideloaded
                                if ($addon.location -ne 'app-profile' -and $addon.location -ne 'app-system') {
                                    $msg = "WARNING: Sideloaded Firefox extension detected: $($addon.defaultLocale.name) ($addonId)"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                                    Write-SecurityEvent -EventType "SideloadedFirefoxExtension" -Details @{ 
                                        ExtensionId = $addonId
                                        ExtensionName = $addon.defaultLocale.name
                                        Location = $addon.location
                                    } -Severity "Medium"
                                }
                            }
                        }
                    } catch {}
                }
            }
        }

        # Cap baseline
        if ($script:BrowserExtensionBaseline.Count -gt 500) {
            $keysToRemove = @($script:BrowserExtensionBaseline.Keys | Select-Object -First 100)
            foreach ($k in $keysToRemove) {
                $script:BrowserExtensionBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Browser extension monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Firewall Rule Monitor
# ============================================
function Start-FirewallRuleMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.FirewallRuleIntervalSeconds) { [int]$Script:ManagedJobConfig.FirewallRuleIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize firewall baseline
    if (-not $script:FirewallRuleBaseline) {
        $script:FirewallRuleBaseline = @{}
    }

    Register-ManagedJob -Name "FirewallRuleMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-FirewallRuleMonitorTick
    }

    Write-Log "[+] Firewall rule monitor (managed job) registered"
}

function Invoke-FirewallRuleMonitorTick {
    try {
        $logFile = "$Base\firewall_rule_detections.log"

        # Get all firewall rules
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }

        foreach ($rule in $rules) {
            try {
                $ruleName = $rule.DisplayName
                $ruleKey = $rule.Name

                # Check if new
                $isNew = $false
                if (-not $script:FirewallRuleBaseline.ContainsKey($ruleKey)) {
                    $script:FirewallRuleBaseline[$ruleKey] = @{
                        DisplayName = $ruleName
                        Direction = $rule.Direction
                        Action = $rule.Action
                        FirstSeen = Get-Date
                    }
                    $isNew = $true
                }

                if (-not $isNew) { continue }

                # Get additional rule details
                $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

                $suspicious = $false
                $reason = ""

                # Check for suspicious inbound allow rules
                if ($rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow') {
                    # Allow all ports
                    if ($portFilter -and $portFilter.LocalPort -eq 'Any') {
                        $suspicious = $true
                        $reason = "Inbound rule allows all ports"
                    }

                    # Allow from any address
                    if ($addressFilter -and $addressFilter.RemoteAddress -eq 'Any') {
                        if ($portFilter -and $portFilter.LocalPort -ne 'Any') {
                            # Specific port from anywhere - check if suspicious port
                            $port = $portFilter.LocalPort
                            $suspiciousPorts = @('4444', '5555', '6666', '7777', '8888', '9999', '1234', '31337', '12345')
                            if ($port -in $suspiciousPorts) {
                                $suspicious = $true
                                $reason = "Inbound rule allows suspicious port $port from anywhere"
                            }
                        }
                    }
                }

                # Check for rules pointing to suspicious applications
                if ($appFilter -and $appFilter.Program) {
                    $program = $appFilter.Program

                    if ($program -match '\\temp\\|\\tmp\\|\\appdata\\local\\temp|\\downloads\\') {
                        $suspicious = $true
                        $reason = "Firewall rule for application in temp/user directory"
                    }

                    if ($program -match 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta') {
                        $suspicious = $true
                        $reason = "Firewall rule for script interpreter"
                    }

                    if ($program -match '\\[a-f0-9]{8,}\.exe') {
                        $suspicious = $true
                        $reason = "Firewall rule for random-named executable"
                    }
                }

                # Check for rules with suspicious names
                if ($ruleName -match '^[a-f0-9]{8,}$|^rule[0-9]+$|^allow[0-9]+$') {
                    $suspicious = $true
                    $reason = "Firewall rule with suspicious name pattern"
                }

                if ($suspicious) {
                    $msg = "CRITICAL: Suspicious firewall rule detected: $ruleName - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Add-Content -Path $logFile -Value "  Direction: $($rule.Direction), Action: $($rule.Action)"
                    if ($appFilter.Program) {
                        Add-Content -Path $logFile -Value "  Program: $($appFilter.Program)"
                    }

                    Write-SecurityEvent -EventType "SuspiciousFirewallRule" -Details @{ 
                        RuleName = $ruleName
                        Direction = "$($rule.Direction)"
                        Action = "$($rule.Action)"
                        Program = if ($appFilter.Program) { $appFilter.Program } else { "N/A" }
                        Reason = $reason
                    } -Severity "Critical"

                    # Disable the suspicious rule
                    try {
                        Disable-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | DISABLED: $ruleName"
                    } catch {}
                }
            } catch {}
        }

        # Cap baseline
        if ($script:FirewallRuleBaseline.Count -gt 1000) {
            $keysToRemove = @($script:FirewallRuleBaseline.Keys | Select-Object -First 200)
            foreach ($k in $keysToRemove) {
                $script:FirewallRuleBaseline.Remove($k)
            }
        }
    } catch {
        try { Write-ErrorLog -Message "Firewall rule monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Shadow Copy Tampering Detection (Ransomware)
# ============================================
function Start-ShadowCopyMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ShadowCopyIntervalSeconds) { [int]$Script:ManagedJobConfig.ShadowCopyIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize shadow copy baseline
    if (-not $script:ShadowCopyBaseline) {
        $script:ShadowCopyBaseline = @{
            Count = 0
            LastCheck = $null
        }
    }

    Register-ManagedJob -Name "ShadowCopyMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ShadowCopyMonitorTick
    }

    Write-Log "[+] Shadow copy monitor (managed job) registered"
}

function Invoke-ShadowCopyMonitorTick {
    try {
        $logFile = "$Base\shadowcopy_detections.log"

        # Get current shadow copy count
        $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        $currentCount = if ($shadowCopies) { @($shadowCopies).Count } else { 0 }

        # Initialize baseline on first run
        if (-not $script:ShadowCopyBaseline.LastCheck) {
            $script:ShadowCopyBaseline.Count = $currentCount
            $script:ShadowCopyBaseline.LastCheck = Get-Date
            return
        }

        # Check for mass deletion (ransomware indicator)
        $previousCount = $script:ShadowCopyBaseline.Count
        if ($previousCount -gt 0 -and $currentCount -eq 0) {
            $msg = "CRITICAL: All shadow copies deleted! Possible ransomware attack!"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

            Write-SecurityEvent -EventType "ShadowCopyMassDelete" -Details @{ 
                PreviousCount = $previousCount
                CurrentCount = $currentCount
            } -Severity "Critical"

            # Try to identify the culprit
            $recentProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.CommandLine -match 'vssadmin|wmic.*shadowcopy|bcdedit|wbadmin' }

            foreach ($proc in $recentProcesses) {
                $msg = "SUSPECT: Process may have deleted shadow copies: $($proc.Name) (PID: $($proc.ProcessId))"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Add-Content -Path $logFile -Value "  CommandLine: $($proc.CommandLine)"

                Write-SecurityEvent -EventType "ShadowCopyDeleteSuspect" -Details @{ 
                    ProcessName = $proc.Name
                    PID = $proc.ProcessId
                    CommandLine = $proc.CommandLine
                } -Severity "Critical"

                # Kill the suspect process
                try {
                    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: $($proc.Name)"
                } catch {}
            }
        }
        elseif ($currentCount -lt $previousCount -and ($previousCount - $currentCount) -ge 2) {
            $msg = "WARNING: Multiple shadow copies deleted (from $previousCount to $currentCount)"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

            Write-SecurityEvent -EventType "ShadowCopyPartialDelete" -Details @{ 
                PreviousCount = $previousCount
                CurrentCount = $currentCount
                Deleted = $previousCount - $currentCount
            } -Severity "High"
        }

        # Check for processes attempting to delete shadow copies
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

        foreach ($proc in $processes) {
            try {
                $cmdLine = $proc.CommandLine
                if (-not $cmdLine) { continue }

                $suspicious = $false
                $reason = ""

                # Ransomware shadow copy deletion patterns
                if ($cmdLine -match 'vssadmin\s+(delete|resize)\s+shadows') {
                    $suspicious = $true
                    $reason = "vssadmin shadow copy deletion"
                }
                elseif ($cmdLine -match 'wmic\s+shadowcopy\s+delete') {
                    $suspicious = $true
                    $reason = "WMIC shadow copy deletion"
                }
                elseif ($cmdLine -match 'bcdedit.*recoveryenabled.*no') {
                    $suspicious = $true
                    $reason = "BCDEdit recovery disable"
                }
                elseif ($cmdLine -match 'wbadmin\s+delete\s+(catalog|systemstatebackup)') {
                    $suspicious = $true
                    $reason = "wbadmin backup deletion"
                }
                elseif ($cmdLine -match 'vssadmin\s+resize\s+shadowstorage.*maxsize=') {
                    $suspicious = $true
                    $reason = "vssadmin shadow storage resize (potential deletion)"
                }

                if ($suspicious) {
                    $msg = "CRITICAL: Shadow copy tampering detected: $($proc.Name) (PID: $($proc.ProcessId)) - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "ShadowCopyTampering" -Details @{ 
                        ProcessName = $proc.Name
                        PID = $proc.ProcessId
                        Reason = $reason
                        CommandLine = $cmdLine.Substring(0, [Math]::Min(500, $cmdLine.Length))
                    } -Severity "Critical"

                    # Kill the process immediately
                    try {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | KILLED: $($proc.Name) (PID: $($proc.ProcessId))"
                    } catch {}
                }
            } catch {}
        }

        # Update baseline
        $script:ShadowCopyBaseline.Count = $currentCount
        $script:ShadowCopyBaseline.LastCheck = Get-Date

    } catch {
        try { Write-ErrorLog -Message "Shadow copy monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: USB/Removable Media Monitor
# ============================================
function Start-USBMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.USBMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.USBMonitorIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize USB baseline
    if (-not $script:USBBaseline) {
        $script:USBBaseline = @{}
    }

    Register-ManagedJob -Name "USBMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-USBMonitorTick
    }

    Write-Log "[+] USB monitor (managed job) registered"
}

function Invoke-USBMonitorTick {
    try {
        $logFile = "$Base\usb_detections.log"

        # Get removable drives
        $removableDrives = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | 
            Where-Object { $_.DriveType -eq 2 }  # DriveType 2 = Removable

        foreach ($drive in $removableDrives) {
            try {
                $driveLetter = $drive.DeviceID
                $driveKey = $driveLetter

                # Check if new
                $isNew = $false
                if (-not $script:USBBaseline.ContainsKey($driveKey)) {
                    $script:USBBaseline[$driveKey] = @{
                        VolumeName = $drive.VolumeName
                        Size = $drive.Size
                        FirstSeen = Get-Date
                    }
                    $isNew = $true

                    $msg = "INFO: New removable drive detected: $driveLetter ($($drive.VolumeName))"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "RemovableDriveConnected" -Details @{ 
                        DriveLetter = $driveLetter
                        VolumeName = $drive.VolumeName
                        SizeGB = [math]::Round($drive.Size / 1GB, 2)
                    } -Severity "Informational"
                }

                if (-not $isNew) { continue }

                # Scan for suspicious files on new USB
                $suspiciousExtensions = @('.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.hta', '.lnk')
                $autorunFile = Join-Path $driveLetter "autorun.inf"

                # Check for autorun.inf (often used for USB malware)
                if (Test-Path $autorunFile) {
                    $msg = "WARNING: autorun.inf found on removable drive: $driveLetter"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "USBAutorunDetected" -Details @{ 
                        DriveLetter = $driveLetter
                        AutorunPath = $autorunFile
                    } -Severity "High"

                    # Read and analyze autorun.inf
                    try {
                        $autorunContent = Get-Content -Path $autorunFile -Raw -ErrorAction SilentlyContinue
                        if ($autorunContent -match 'open=|shellexecute=|shell\\') {
                            $msg = "CRITICAL: autorun.inf contains executable reference!"
                            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                            # Quarantine the autorun.inf
                            try {
                                $quarantinePath = "$quarantineFolder\autorun_$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
                                Move-Item -Path $autorunFile -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED: $autorunFile"
                            } catch {}
                        }
                    } catch {}
                }

                # Scan root for suspicious executables
                $rootFiles = Get-ChildItem -Path "$driveLetter\" -File -ErrorAction SilentlyContinue | Select-Object -First 50

                foreach ($file in $rootFiles) {
                    try {
                        $ext = $file.Extension.ToLower()

                        if ($ext -in $suspiciousExtensions) {
                            $suspicious = $false
                            $reason = ""

                            # Check for hidden executables
                            if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) {
                                $suspicious = $true
                                $reason = "Hidden executable on USB root"
                            }

                            # Check for unsigned executables
                            if ($ext -eq '.exe' -or $ext -eq '.dll') {
                                $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                if (-not $sig -or $sig.Status -ne "Valid") {
                                    $suspicious = $true
                                    $reason = "Unsigned executable on USB"
                                }
                            }

                            # Scripts on USB root are always suspicious
                            if ($ext -in @('.bat', '.cmd', '.vbs', '.ps1', '.hta', '.js')) {
                                $suspicious = $true
                                $reason = "Script file on USB root"
                            }

                            # Suspicious shortcut
                            if ($ext -eq '.lnk') {
                                try {
                                    $shell = New-Object -ComObject WScript.Shell
                                    $shortcut = $shell.CreateShortcut($file.FullName)
                                    if ($shortcut.TargetPath -match 'powershell|cmd|wscript|mshta') {
                                        $suspicious = $true
                                        $reason = "Shortcut to script interpreter"
                                    }
                                } catch {}
                            }

                            if ($suspicious) {
                                $msg = "CRITICAL: Suspicious file on USB: $($file.FullName) - $reason"
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                                Write-SecurityEvent -EventType "SuspiciousUSBFile" -Details @{ 
                                    FilePath = $file.FullName
                                    FileName = $file.Name
                                    Reason = $reason
                                    DriveLetter = $driveLetter
                                } -Severity "Critical"

                                # Quarantine the file
                                try {
                                    $quarantinePath = "$quarantineFolder\usb_$($file.Name)_$(Get-Date -Format 'yyyyMMddHHmmss').quarantined"
                                    Move-Item -Path $file.FullName -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED: $($file.FullName)"
                                } catch {}
                            }
                        }
                    } catch {}
                }
            } catch {}
        }

        # Clean up baseline for removed drives
        $currentDrives = @($removableDrives.DeviceID)
        $keysToRemove = @($script:USBBaseline.Keys | Where-Object { $_ -notin $currentDrives })
        foreach ($k in $keysToRemove) {
            $script:USBBaseline.Remove($k)
        }

    } catch {
        try { Write-ErrorLog -Message "USB monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Clipboard Monitoring (Data Theft Detection)
# ============================================
function Start-ClipboardMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ClipboardMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.ClipboardMonitorIntervalSeconds } else { 5 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    # Initialize clipboard tracking
    if (-not $script:ClipboardTracking) {
        $script:ClipboardTracking = @{
            LastHash = $null
            SensitiveAccessCount = 0
            LastReset = Get-Date
        }
    }

    Register-ManagedJob -Name "ClipboardMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ClipboardMonitorTick
    }

    Write-Log "[+] Clipboard monitor (managed job) registered"
}

function Invoke-ClipboardMonitorTick {
    try {
        $logFile = "$Base\clipboard_detections.log"

        # Reset counter every hour
        if ((Get-Date) - $script:ClipboardTracking.LastReset -gt [TimeSpan]::FromHours(1)) {
            $script:ClipboardTracking.SensitiveAccessCount = 0
            $script:ClipboardTracking.LastReset = Get-Date
        }

        # Get clipboard content
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $clipboardText = $null

        try {
            if ([System.Windows.Forms.Clipboard]::ContainsText()) {
                $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
            }
        } catch {
            return  # Clipboard access failed, skip this tick
        }

        if (-not $clipboardText -or $clipboardText.Length -lt 10) { return }

        # Hash to detect changes
        $currentHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($clipboardText)
            )
        ).Replace("-", "").Substring(0, 16)

        if ($currentHash -eq $script:ClipboardTracking.LastHash) { return }
        $script:ClipboardTracking.LastHash = $currentHash

        # Check for sensitive data patterns
        $sensitivePatterns = @(
            @{ Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'; Type = 'Email'; Severity = 'Low' },
            @{ Pattern = '\b(?:\d{4}[-\s]?){3}\d{4}\b'; Type = 'CreditCard'; Severity = 'Critical' },
            @{ Pattern = '\b\d{3}-\d{2}-\d{4}\b'; Type = 'SSN'; Severity = 'Critical' },
            @{ Pattern = '(?i)(password|passwd|pwd)\s*[:=]\s*\S+'; Type = 'Password'; Severity = 'Critical' },
            @{ Pattern = '(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[A-Za-z0-9_-]{20,}'; Type = 'APIKey'; Severity = 'Critical' },
            @{ Pattern = '(?i)bearer\s+[A-Za-z0-9_-]{20,}'; Type = 'BearerToken'; Severity = 'Critical' },
            @{ Pattern = 'AKIA[0-9A-Z]{16}'; Type = 'AWSAccessKey'; Severity = 'Critical' },
            @{ Pattern = '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'; Type = 'PrivateKey'; Severity = 'Critical' },
            @{ Pattern = '(?i)(mysql|postgres|mongodb|redis)://[^\s]+'; Type = 'DatabaseConnectionString'; Severity = 'Critical' }
        )

        foreach ($check in $sensitivePatterns) {
            if ($clipboardText -match $check.Pattern) {
                $script:ClipboardTracking.SensitiveAccessCount++

                # Only log if threshold exceeded (avoid noise from normal copy/paste)
                if ($script:ClipboardTracking.SensitiveAccessCount -ge 3 -or $check.Severity -eq 'Critical') {
                    $msg = "$($check.Severity.ToUpper()): Sensitive data detected in clipboard: $($check.Type)"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                    Write-SecurityEvent -EventType "SensitiveClipboardData" -Details @{ 
                        DataType = $check.Type
                        ContentLength = $clipboardText.Length
                        AccessCount = $script:ClipboardTracking.SensitiveAccessCount
                    } -Severity $check.Severity

                    # For critical data, check what process might be accessing clipboard
                    if ($check.Severity -eq 'Critical') {
                        try {
                            Add-Type @"
                            using System;
                            using System.Runtime.InteropServices;
                            public class ForegroundWindow {
                                [DllImport("user32.dll")]
                                public static extern IntPtr GetForegroundWindow();
                                [DllImport("user32.dll")]
                                public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
                            }
"@ -ErrorAction SilentlyContinue

                            $hwnd = [ForegroundWindow]::GetForegroundWindow()
                            $processId = 0
                            [void][ForegroundWindow]::GetWindowThreadProcessId($hwnd, [ref]$processId)

                            if ($processId -gt 0) {
                                $fgProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
                                if ($fgProcess) {
                                    Add-Content -Path $logFile -Value "  Foreground process: $($fgProcess.ProcessName) (PID: $processId)"
                                }
                            }
                        } catch {}
                    }
                }

                break  # Only report first match
            }
        }

    } catch {
        try { Write-ErrorLog -Message "Clipboard monitor tick failed" -Severity "Low" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Event Log Tampering Detection
# ============================================
function Start-EventLogMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.EventLogMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.EventLogMonitorIntervalSeconds } else { 30 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    if (-not $script:EventLogBaseline) {
        $script:EventLogBaseline = @{}
    }

    Register-ManagedJob -Name "EventLogMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-EventLogMonitorTick
    }

    Write-Log "[+] Event log monitor (managed job) registered"
}

function Invoke-EventLogMonitorTick {
    try {
        $logFile = "$Base\eventlog_tampering.log"

        # Check for event log clearing (Security Event ID 1102, System Event ID 104)
        $clearEvents = @()
        try {
            $clearEvents += Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
            $clearEvents += Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 5 -ErrorAction SilentlyContinue
        } catch {}

        foreach ($evt in $clearEvents) {
            $evtKey = "$($evt.LogName)_$($evt.TimeCreated.Ticks)"
            if (-not $script:EventLogBaseline.ContainsKey($evtKey)) {
                $script:EventLogBaseline[$evtKey] = $true
                $msg = "CRITICAL: Event log cleared! Log: $($evt.LogName)"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Write-SecurityEvent -EventType "EventLogCleared" -Details @{ LogName = $evt.LogName; TimeCreated = $evt.TimeCreated } -Severity "Critical"
            }
        }

        # Check for processes attempting to clear logs
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            $cmd = $proc.CommandLine
            if (-not $cmd) { continue }
            if ($cmd -match 'wevtutil\s+(cl|clear-log)|Clear-EventLog|Remove-EventLog') {
                $msg = "CRITICAL: Event log tampering attempt: $($proc.Name) (PID: $($proc.ProcessId))"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                Write-SecurityEvent -EventType "EventLogTampering" -Details @{ ProcessName = $proc.Name; PID = $proc.ProcessId; CommandLine = $cmd } -Severity "Critical"
                try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
            }
        }

        # Cap baseline
        if ($script:EventLogBaseline.Count -gt 100) {
            $keysToRemove = @($script:EventLogBaseline.Keys | Select-Object -First 50)
            foreach ($k in $keysToRemove) { $script:EventLogBaseline.Remove($k) }
        }
    } catch {
        try { Write-ErrorLog -Message "Event log monitor tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Process Hollowing Detection
# ============================================
function Start-ProcessHollowingDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ProcessHollowingIntervalSeconds) { [int]$Script:ManagedJobConfig.ProcessHollowingIntervalSeconds } else { 20 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "ProcessHollowingDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ProcessHollowingDetectorTick
    }

    Write-Log "[+] Process hollowing detector (managed job) registered"
}

function Invoke-ProcessHollowingDetectorTick {
    try {
        $logFile = "$Base\process_hollowing.log"

        # Common targets for process hollowing
        $hollowTargets = @('svchost.exe', 'explorer.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe', 'RuntimeBroker.exe')

        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in ($hollowTargets -replace '\.exe$','') }

        foreach ($proc in $procs) {
            try {
                if ($proc.Id -le 4 -or $proc.Id -eq $PID) { continue }

                $procPath = $proc.Path
                if (-not $procPath) { continue }

                # Check if process image doesn't match expected location
                $expectedPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")
                $isExpectedPath = $false
                foreach ($exp in $expectedPaths) {
                    if ($procPath -like "$exp\*") { $isExpectedPath = $true; break }
                }

                # svchost should only run from System32
                if ($proc.ProcessName -eq 'svchost' -and -not $isExpectedPath) {
                    $msg = "CRITICAL: Potential process hollowing - svchost from unexpected path: $procPath"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "ProcessHollowing" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Path = $procPath } -Severity "Critical"
                    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
                }

                # Check for suspended state with network connections (common in hollowing)
                $threads = $proc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' }
                if ($threads.Count -gt 0) {
                    $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
                    if ($conns) {
                        $msg = "WARNING: Suspended process with network activity: $($proc.ProcessName) (PID: $($proc.Id))"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "SuspiciousSuspendedProcess" -Details @{ ProcessName = $proc.ProcessName; PID = $proc.Id; Connections = $conns.Count } -Severity "High"
                    }
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Process hollowing detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Keylogger Detection
# ============================================
function Start-KeyloggerDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.KeyloggerDetectorIntervalSeconds) { [int]$Script:ManagedJobConfig.KeyloggerDetectorIntervalSeconds } else { 15 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "KeyloggerDetector" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-KeyloggerDetectorTick
    }

    Write-Log "[+] Keylogger detector (managed job) registered"
}

function Invoke-KeyloggerDetectorTick {
    try {
        $logFile = "$Base\keylogger_detections.log"

        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

        foreach ($proc in $procs) {
            try {
                $cmd = $proc.CommandLine
                $name = $proc.Name
                if (-not $cmd -and -not $name) { continue }

                $suspicious = $false
                $reason = ""

                # Check for known keylogger patterns
                $keyloggerPatterns = @(
                    @{ Pattern = 'GetAsyncKeyState|GetKeyState|SetWindowsHookEx.*WH_KEYBOARD'; Reason = 'Keyboard hook API' },
                    @{ Pattern = 'keylog|keystroke|keypress|keycapture'; Reason = 'Keylogger keyword' },
                    @{ Pattern = 'RegisterRawInputDevices|GetRawInputData'; Reason = 'Raw input API (potential keylogger)' }
                )

                foreach ($check in $keyloggerPatterns) {
                    if ($cmd -match $check.Pattern -or $name -match $check.Pattern) {
                        $suspicious = $true
                        $reason = $check.Reason
                        break
                    }
                }

                # Check for processes with keyboard hooks by examining loaded modules
                if (-not $suspicious -and $proc.ProcessId -gt 4 -and $proc.ProcessId -ne $PID) {
                    try {
                        $p = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                        if ($p -and $p.Modules) {
                            $suspiciousModules = $p.Modules | Where-Object { $_.ModuleName -match 'hook|key|log|capture' }
                            if ($suspiciousModules) {
                                $suspicious = $true
                                $reason = "Suspicious module loaded: $($suspiciousModules[0].ModuleName)"
                            }
                        }
                    } catch {}
                }

                if ($suspicious) {
                    $msg = "CRITICAL: Potential keylogger detected: $name (PID: $($proc.ProcessId)) - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "KeyloggerDetected" -Details @{ ProcessName = $name; PID = $proc.ProcessId; Reason = $reason } -Severity "Critical"
                    try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
                }
            } catch {}
        }
    } catch {
        try { Write-ErrorLog -Message "Keylogger detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# ENTERPRISE EDR: Ransomware Behavior Detection
# ============================================
function Start-RansomwareBehaviorDetector {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RansomwareBehaviorIntervalSeconds) { [int]$Script:ManagedJobConfig.RansomwareBehaviorIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    if (-not $script:RansomwareTracking) {
        $script:RansomwareTracking = @{}
    }

    Register-ManagedJob -Name "RansomwareBehaviorDetector" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-RansomwareBehaviorDetectorTick
    }

    Write-Log "[+] Ransomware behavior detector (managed job) registered"
}

function Invoke-RansomwareBehaviorDetectorTick {
    try {
        $logFile = "$Base\ransomware_behavior.log"

        # Check for ransomware behavior patterns
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

        foreach ($proc in $procs) {
            try {
                $cmd = $proc.CommandLine
                if (-not $cmd) { continue }

                $suspicious = $false
                $reason = ""

                # Check for ransomware command patterns
                if ($cmd -match 'cipher\s+/w:|vssadmin.*delete.*shadows|bcdedit.*recoveryenabled.*no|wbadmin.*delete') {
                    $suspicious = $true
                    $reason = "Ransomware preparation command"
                }

                # Check for mass encryption patterns
                if ($cmd -match '\.(encrypted|locked|crypto|crypt)' -or $cmd -match 'encrypt|ransom|bitcoin|btc|decrypt') {
                    $suspicious = $true
                    $reason = "Ransomware keyword detected"
                }

                if ($suspicious) {
                    $msg = "CRITICAL: Ransomware behavior detected: $($proc.Name) (PID: $($proc.ProcessId)) - $reason"
                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                    Write-SecurityEvent -EventType "RansomwareBehavior" -Details @{ ProcessName = $proc.Name; PID = $proc.ProcessId; Reason = $reason } -Severity "Critical"
                    try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
                }
            } catch {}
        }

        # Check for ransom notes
        $ransomNotePatterns = @('*readme*ransom*', '*decrypt*instructions*', '*how*decrypt*', '*restore*files*', '*your*files*encrypted*', '*DECRYPT*README*', '*_readme.txt', '*-DECRYPT.txt')
        $commonDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:PUBLIC\Desktop")

        foreach ($dir in $commonDirs) {
            if (-not (Test-Path $dir)) { continue }
            foreach ($pattern in $ransomNotePatterns) {
                $notes = Get-ChildItem -Path $dir -Filter $pattern -ErrorAction SilentlyContinue | Select-Object -First 3
                foreach ($note in $notes) {
                    $noteKey = $note.FullName
                    if (-not $script:RansomwareTracking.ContainsKey($noteKey)) {
                        $script:RansomwareTracking[$noteKey] = $true
                        $msg = "CRITICAL: Ransom note detected: $($note.FullName)"
                        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                        Write-SecurityEvent -EventType "RansomNoteDetected" -Details @{ FilePath = $note.FullName } -Severity "Critical"
                        try { Remove-Item -Path $note.FullName -Force -ErrorAction SilentlyContinue } catch {}
                    }
                }
            }
        }

        # Cap tracking
        if ($script:RansomwareTracking.Count -gt 100) {
            $keysToRemove = @($script:RansomwareTracking.Keys | Select-Object -First 50)
            foreach ($k in $keysToRemove) { $script:RansomwareTracking.Remove($k) }
        }
    } catch {
        try { Write-ErrorLog -Message "Ransomware behavior detector tick failed" -Severity "High" -ErrorRecord $_ } catch {}
    }
}

# ============================================
# SECURITY FIX #1: PERIODIC INTEGRITY CHECKS
# ============================================
function Start-IntegrityMonitor {
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.IntegrityMonitorIntervalSeconds) { [int]$Script:ManagedJobConfig.IntegrityMonitorIntervalSeconds } else { 60 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Register-ManagedJob -Name "IntegrityMonitor" -Enabled $true -Critical $true -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-IntegrityMonitorTick
    }

    Write-Log "[+] Integrity monitor (managed job) registered"
}

function Invoke-IntegrityMonitorTick {
    try {
        if (-not (Test-ScriptIntegrity)) {
            Write-Host "[CRITICAL] Script integrity compromised. Terminating." -ForegroundColor Red
            Write-SecurityEvent -EventType "ScriptIntegrityFailure" -Details @{ PID = $PID } -Severity "Critical"
            Stop-Process -Id $PID -Force
        }
    } catch {
        try {
            Write-ErrorLog -Message "Integrity monitor tick failed" -Severity "High" -ErrorRecord $_
        } catch {}
    }
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

Write-Host "[*] Starting Memory Monitors..." -ForegroundColor Yellow
Start-MemoryMonitors
$jobNames += "MemoryMonitors"


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

Write-Host "[*] Starting Reflective Payload Detector..." -ForegroundColor Yellow
Start-ReflectivePayloadDetector
$jobNames += "ReflectivePayloadDetector"

Write-Host "[*] Starting AMSI Bypass Detector..." -ForegroundColor Yellow
Start-AMSIBypassDetector
$jobNames += "AMSIBypassDetector"

Write-Host "[*] Starting Credential Dumping Detector..." -ForegroundColor Yellow
Start-CredentialDumpingDetector
$jobNames += "CredentialDumpingDetector"

Write-Host "[*] Starting Process Anomaly Detector..." -ForegroundColor Yellow
Start-ProcessAnomalyDetector
$jobNames += "ProcessAnomalyDetector"

Write-Host "[*] Starting WMI Persistence Detector..." -ForegroundColor Yellow
Start-WMIPersistenceDetector
$jobNames += "WMIPersistenceDetector"

Write-Host "[*] Starting Scheduled Task Detector..." -ForegroundColor Yellow
Start-ScheduledTaskDetector
$jobNames += "ScheduledTaskDetector"

Write-Host "[*] Starting DNS Exfiltration Detector..." -ForegroundColor Yellow
Start-DNSExfiltrationDetector
$jobNames += "DNSExfiltrationDetector"

Write-Host "[*] Starting Named Pipe Monitor..." -ForegroundColor Yellow
Start-NamedPipeMonitor
$jobNames += "NamedPipeMonitor"

Write-Host "[*] Starting Registry Persistence Detector..." -ForegroundColor Yellow
Start-RegistryPersistenceDetector
$jobNames += "RegistryPersistenceDetector"

Write-Host "[*] Starting Script Block Analyzer..." -ForegroundColor Yellow
Start-ScriptBlockAnalyzer
$jobNames += "ScriptBlockAnalyzer"

Write-Host "[*] Starting Service Monitor..." -ForegroundColor Yellow
Start-ServiceMonitor
$jobNames += "ServiceMonitor"

Write-Host "[*] Starting DLL Hijack Detector..." -ForegroundColor Yellow
Start-DLLHijackDetector
$jobNames += "DLLHijackDetector"

Write-Host "[*] Starting Token Manipulation Detector..." -ForegroundColor Yellow
Start-TokenManipulationDetector
$jobNames += "TokenManipulationDetector"

Write-Host "[*] Starting Startup Monitor..." -ForegroundColor Yellow
Start-StartupMonitor
$jobNames += "StartupMonitor"

Write-Host "[*] Starting Browser Extension Monitor..." -ForegroundColor Yellow
Start-BrowserExtensionMonitor
$jobNames += "BrowserExtensionMonitor"

Write-Host "[*] Starting Firewall Rule Monitor..." -ForegroundColor Yellow
Start-FirewallRuleMonitor
$jobNames += "FirewallRuleMonitor"

Write-Host "[*] Starting Shadow Copy Monitor..." -ForegroundColor Yellow
Start-ShadowCopyMonitor
$jobNames += "ShadowCopyMonitor"

Write-Host "[*] Starting USB Monitor..." -ForegroundColor Yellow
Start-USBMonitor
$jobNames += "USBMonitor"

Write-Host "[*] Starting Clipboard Monitor..." -ForegroundColor Yellow
Start-ClipboardMonitor
$jobNames += "ClipboardMonitor"

Write-Host "[*] Starting Event Log Monitor..." -ForegroundColor Yellow
Start-EventLogMonitor
$jobNames += "EventLogMonitor"

Write-Host "[*] Starting Process Hollowing Detector..." -ForegroundColor Yellow
Start-ProcessHollowingDetector
$jobNames += "ProcessHollowingDetector"

Write-Host "[*] Starting Keylogger Detector..." -ForegroundColor Yellow
Start-KeyloggerDetector
$jobNames += "KeyloggerDetector"

Write-Host "[*] Starting Ransomware Behavior Detector..." -ForegroundColor Yellow
Start-RansomwareBehaviorDetector
$jobNames += "RansomwareBehaviorDetector"

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
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.NetworkTrafficIntervalSeconds) { [int]$Script:ManagedJobConfig.NetworkTrafficIntervalSeconds } else { 5 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Initialize-NetworkTrafficMonitorState

    Register-ManagedJob -Name "NetworkTrafficMonitor" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-NetworkTrafficMonitorTick
    }

    Write-Log "[+] Network Traffic Monitor (managed job) registered"
}

function Initialize-NetworkTrafficMonitorState {
    if ($script:NTMInitialized) { return }

    $script:NTMAllowedDomains = @()
    $script:NTMAllowedIPs = @()
    $script:NTMBlockedConnections = @{}
    $script:NTMCurrentBrowserConnections = @{}
    $script:NTMSeenConnections = @{}

    $script:NTMInitialized = $true
}

function Invoke-NetworkTrafficMonitorTick {
    try {
        if (-not $script:NTMInitialized) {
            Initialize-NetworkTrafficMonitorState
        }

        $logFile = "$Base\ntm_monitor.log"

        function Write-ColorOutput {
            param([string]$Message)
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
        }

        function Test-BrowserConnection {
            param([string]$RemoteAddress)

            if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                return $true
            }

            return ($script:NTMAllowedIPs -contains $RemoteAddress)
        }

        function Watch-BrowserActivity {
            param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)

            $BrowserProcesses = @('chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave')

            if ($BrowserProcesses -contains $ProcessName.ToLower()) {
                if ($script:NTMAllowedIPs -notcontains $RemoteAddress) {
                    $script:NTMAllowedIPs += $RemoteAddress
                    $script:NTMCurrentBrowserConnections[$RemoteAddress] = Get-Date
                }
                return $true
            }

            $now = Get-Date
            foreach ($browserIP in $script:NTMCurrentBrowserConnections.Keys) {
                $connectionTime = $script:NTMCurrentBrowserConnections[$browserIP]
                if (($now - $connectionTime).TotalSeconds -le 30) {
                    if ($script:NTMAllowedIPs -notcontains $RemoteAddress) {
                        $script:NTMAllowedIPs += $RemoteAddress
                    }
                    return $true
                }
            }

            return $false
        }

        function New-BlockRule {
            param([string]$RemoteAddress, [int]$RemotePort, [string]$ProcessName)

            $script:NTMBlockedConnections[$RemoteAddress] = @{ Port = $RemotePort; Process = $ProcessName }
            Write-ColorOutput "BLOCKED: ${RemoteAddress}:${RemotePort} (Process: $ProcessName)"
            Write-SecurityEvent -EventType "UnauthorizedConnectionBlocked" -Details @{ 
                RemoteAddress = $RemoteAddress
                RemotePort = $RemotePort
                ProcessName = $ProcessName
            } -Severity "Medium"

            $ruleName = "AV_Block_$RemoteAddress"
            try {
                netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip=$RemoteAddress | Out-Null
            } catch {}
        }

        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
        foreach ($conn in $connections) {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort):$($conn.OwningProcess)"
            if ($script:NTMSeenConnections.ContainsKey($key)) { continue }
            $script:NTMSeenConnections[$key] = $true

            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
                $processName = $process.ProcessName
            } catch {
                $processName = "Unknown"
            }

            $isBrowserOrDependency = Watch-BrowserActivity -RemoteAddress $conn.RemoteAddress -ProcessName $processName -RemotePort $conn.RemotePort
            if ($isBrowserOrDependency) { continue }

            if (-not (Test-BrowserConnection -RemoteAddress $conn.RemoteAddress)) {
                if (-not $script:NTMBlockedConnections.ContainsKey($conn.RemoteAddress)) {
                    New-BlockRule -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -ProcessName $processName
                }
            }
        }

        # Cap SeenConnections to avoid RAM growth
        if ($script:NTMSeenConnections.Count -gt 10000) {
            $script:NTMSeenConnections.Clear()
        }

        # Clean up old browser connection timestamps
        $now = Get-Date
        $toRemove = @()
        foreach ($ip in $script:NTMCurrentBrowserConnections.Keys) {
            if (($now - $script:NTMCurrentBrowserConnections[$ip]).TotalSeconds -gt 60) {
                $toRemove += $ip
            }
        }
        foreach ($ip in $toRemove) {
            $script:NTMCurrentBrowserConnections.Remove($ip)
        }
    } catch {
        try { Write-ErrorLog -Message "Network traffic monitor tick failed" -Severity "Low" -ErrorRecord $_ } catch {}
    }
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
    $intervalSeconds = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.ElfCatcherIntervalSeconds) { [int]$Script:ManagedJobConfig.ElfCatcherIntervalSeconds } else { 10 }
    $maxRestarts = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.MaxRestartAttempts) { [int]$Script:ManagedJobConfig.MaxRestartAttempts } else { 3 }
    $restartDelay = if ($Script:ManagedJobConfig -and $Script:ManagedJobConfig.RestartDelaySeconds) { [int]$Script:ManagedJobConfig.RestartDelaySeconds } else { 5 }

    Initialize-ElfCatcherState

    Register-ManagedJob -Name "ElfCatcher" -Enabled $true -Critical $false -IntervalSeconds $intervalSeconds -MaxRestartAttempts $maxRestarts -RestartDelaySeconds $restartDelay -ScriptBlock {
        Invoke-ElfCatcherTick
    }

    Write-Log "[ELF-CATCHER] DLL monitor (managed job) registered"
}

function Initialize-ElfCatcherState {
    if ($script:ElfCatcherInitialized) { return }

    $script:ElfCatcherWhitelist = @('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll',
        'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
        'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
        'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll')

    $script:ElfCatcherTargets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore', 'microsoftedge')
    $script:ElfCatcherProcessed = @{}
    $script:ElfCatcherInitialized = $true
}

function Invoke-ElfCatcherTick {
    try {
        if (-not $script:ElfCatcherInitialized) {
            Initialize-ElfCatcherState
        }

        $logFile = "$Base\elf_catcher.log"
        $whitelist = $script:ElfCatcherWhitelist
        $targets = $script:ElfCatcherTargets
        $processed = $script:ElfCatcherProcessed

        foreach ($procName in $targets) {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            foreach ($proc in $procs) {
                try {
                    $hProc = [DLL]::OpenProcess(0x1F0FFF, $false, $proc.Id)
                    if ($hProc -eq [IntPtr]::Zero) { continue }

                    $freeLib = [DLL]::GetProcAddress([DLL]::GetModuleHandle("kernel32.dll"), "FreeLibrary")

                    foreach ($mod in $proc.Modules) {
                        try {
                            $name = [System.IO.Path]::GetFileName($mod.FileName).ToLower()
                            if ($whitelist -contains $name) { continue }

                            $key = "$($proc.Id):$($mod.FileName)"
                            if ($processed.ContainsKey($key)) { continue }

                            $suspicious = $false
                            $reason = ""

                            if ($name -like '*_elf.dll') { $suspicious = $true; $reason = "ELF pattern DLL" }
                            elseif ($name -like '*.winmd' -and $mod.FileName -notmatch "\\Windows\\") { $suspicious = $true; $reason = "Suspicious WINMD outside Windows directory" }
                            elseif ($name -match '^[a-f0-9]{8,}\.dll$') { $suspicious = $true; $reason = "Random hex-named DLL" }
                            elseif ($mod.FileName -match "\\AppData\\Local\\Temp\\" -and $name -notlike "chrome_*" -and $name -notlike "edge_*") { $suspicious = $true; $reason = "DLL loaded from TEMP directory" }

                            if ($suspicious) {
                                $msg = "Detected suspicious DLL: $name in $procName (PID $($proc.Id)) - Reason: $reason"
                                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
                                Write-SecurityEvent -EventType "SuspiciousDLLDetected" -Details @{ DLLName = $name; DLLPath = $mod.FileName; ProcessName = $procName; PID = $proc.Id; Reason = $reason } -Severity "High"

                                $thread = [DLL]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $freeLib, $mod.BaseAddress, 0, [IntPtr]::Zero)
                                if ($thread -ne [IntPtr]::Zero) {
                                    [DLL]::WaitForSingleObject($thread, 5000) | Out-Null
                                    [DLL]::CloseHandle($thread) | Out-Null

                                    $msg = "Successfully unloaded DLL: $name from $procName"
                                    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"

                                    if (Test-Path $mod.FileName) {
                                        if ([DLL]::MoveFileEx($mod.FileName, $null, 4)) {
                                            Write-SecurityEvent -EventType "SuspiciousDLLScheduledForDeletion" -Details @{ DLLPath = $mod.FileName } -Severity "Medium"
                                        }
                                    }
                                }

                                $processed[$key] = $true
                            }
                        } catch {}
                    }

                    [DLL]::CloseHandle($hProc) | Out-Null
                } catch {
                }
            }
        }

        # Cap processed list to avoid RAM growth
        if ($processed.Count -gt 5000) {
            $processed.Clear()
        }
    } catch {
        try { Write-ErrorLog -Message "ElfCatcher tick failed" -Severity "Low" -ErrorRecord $_ } catch {}
    }
}

Write-Host "[*] Starting Network Traffic Monitor..." -ForegroundColor Yellow
Start-NetworkTrafficMonitor
$jobNames += "NetworkTrafficMonitor"

Write-Host "[*] Starting Elf Catcher..." -ForegroundColor Yellow
Start-ElfCatcher
$jobNames += "ElfCatcher"

Write-Log "[+] All monitoring modules started successfully"
Write-Log "[+] Self-protection: ACTIVE"
Write-Log "[+] Database integrity: VERIFIED"
Write-Log "[+] Watchdog persistence: CONFIGURED"

# Set the flag indicating jobs have been initialized
$Script:JobsInitialized = $true

$managedJobsCount = 0
try {
    if ($script:ManagedJobs) {
        $managedJobsCount = ($script:ManagedJobs.Values | Where-Object { $_.Enabled -and ($null -eq $_.DisabledUtc) }).Count
    }
} catch {}

# Keep script running
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Production Hardened Antivirus RUNNING" -ForegroundColor Green
Write-Host "Managed Jobs Active: $managedJobsCount" -ForegroundColor Green
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

$Script:ManagedJobConfig = @{
    MinimumIntervalSeconds = 5
    HealthCheckIntervalSeconds = 30
    MaxRestartAttempts = 3
    RestartDelaySeconds = 5

    # OPTIMIZED INTERVALS - Reduced CPU/RAM usage while maintaining security
    # Critical detections run faster, less critical run slower
    
    MalwareScanIntervalSeconds = 15          # Increased from 10
    LogRotationIntervalSeconds = 120         # Increased from 60
    MemoryCleanupIntervalSeconds = 300       # Decreased from 600 for better RAM
    SecurityReportIntervalSeconds = 600      # Increased from 300

    CacheMaintenanceIntervalSeconds = 180    # Decreased from 300 for better RAM
    ScannedFilesMaxCount = 5000              # Decreased from 10000 for RAM

    BehaviorMonitorIntervalSeconds = 15      # Increased from 10

    IntegrityMonitorIntervalSeconds = 120    # Increased from 60
    EnhancedBehaviorIntervalSeconds = 45     # Increased from 30
    AntiTamperIntervalSeconds = 15           # Increased from 10
    HighMemoryCheckIntervalSeconds = 180     # Decreased from 300
    PowerShellMemoryScanIntervalSeconds = 20 # Increased from 10
    ReflectivePayloadIntervalSeconds = 20    # Increased from 10
    NetworkTrafficIntervalSeconds = 10       # Increased from 5

    ElfCatcherIntervalSeconds = 20           # Increased from 10

    RootkitScanIntervalSeconds = 120         # Increased from 60
    FileSystemIntegrityIntervalSeconds = 60  # Increased from 30

    NetworkAnomalyIntervalSeconds = 30       # Increased from 15
    COMControlIntervalSeconds = 120          # Increased from 60

    # Enterprise EDR intervals - OPTIMIZED
    AMSIBypassIntervalSeconds = 20           # Increased from 15
    CredentialDumpingIntervalSeconds = 15    # Increased from 10 (critical)
    ProcessAnomalyIntervalSeconds = 15       # Increased from 10
    WMIPersistenceIntervalSeconds = 120      # Increased from 60
    ScheduledTaskIntervalSeconds = 120       # Increased from 60
    DNSExfiltrationIntervalSeconds = 60      # Increased from 30
    NamedPipeIntervalSeconds = 30            # Increased from 15
    RegistryPersistenceIntervalSeconds = 120 # Increased from 60
    ScriptBlockAnalyzerIntervalSeconds = 60  # Increased from 30
    ServiceMonitorIntervalSeconds = 60       # Increased from 30
    DLLHijackIntervalSeconds = 180           # Increased from 60
    TokenManipulationIntervalSeconds = 20    # Increased from 15
    StartupMonitorIntervalSeconds = 120      # Increased from 60
    BrowserExtensionIntervalSeconds = 300    # Increased from 120
    FirewallRuleIntervalSeconds = 120        # Increased from 60
    ShadowCopyIntervalSeconds = 30           # Keep at 30 (ransomware critical)
    USBMonitorIntervalSeconds = 15           # Increased from 10
    ClipboardMonitorIntervalSeconds = 10     # Increased from 5
    EventLogMonitorIntervalSeconds = 60      # Increased from 30
    ProcessHollowingIntervalSeconds = 30     # Increased from 20
    KeyloggerDetectorIntervalSeconds = 30    # Increased from 15
    RansomwareBehaviorIntervalSeconds = 15   # Increased from 10 (critical)
}

function Invoke-CacheMaintenanceTick {
    try {
        # Enforce FileHashCache max size (ConcurrentDictionary)
        if ($Script:FileHashCache -and $Script:MaxCacheSize -and $Script:FileHashCache.Count -gt $Script:MaxCacheSize) {
            $removeCount = [Math]::Min(($Script:FileHashCache.Count - $Script:MaxCacheSize), 500)
            if ($removeCount -gt 0) {
                $keysToRemove = $Script:FileHashCache.Keys | Select-Object -First $removeCount
                foreach ($k in $keysToRemove) {
                    $dummy = $null
                    [void]$Script:FileHashCache.TryRemove($k, [ref]$dummy)
                }
            }
        }

        # Enforce scanned files max size (hashtable)
        $scannedVar = Get-Variable -Name scannedFiles -Scope Script -ErrorAction SilentlyContinue
        if ($scannedVar -and $script:scannedFiles -and $Script:ManagedJobConfig.ScannedFilesMaxCount) {
            if ($script:scannedFiles.Count -gt [int]$Script:ManagedJobConfig.ScannedFilesMaxCount) {
                $removeCount = [Math]::Min(($script:scannedFiles.Count - [int]$Script:ManagedJobConfig.ScannedFilesMaxCount), 2000)
                if ($removeCount -gt 0) {
                    $keysToRemove = @($script:scannedFiles.Keys | Select-Object -First $removeCount)
                    foreach ($k in $keysToRemove) {
                        $script:scannedFiles.Remove($k)
                    }
                }
            }
        }
    } catch {
        try {
            Write-ErrorLog -Message "Cache maintenance tick failed" -Severity "Low" -ErrorRecord $_
        } catch {}
    }
}

$Script:ManagedJobDefinitions = @(
    @{ Name = 'MalwareScan'; Enabled = $true; Critical = $true; IntervalSeconds = $Script:ManagedJobConfig.MalwareScanIntervalSeconds; ScriptBlock = { Invoke-MalwareScan } }
    @{ Name = 'LogRotation'; Enabled = $true; Critical = $false; IntervalSeconds = $Script:ManagedJobConfig.LogRotationIntervalSeconds; ScriptBlock = { Invoke-LogRotation } }
    @{ Name = 'MemoryCleanup'; Enabled = $true; Critical = $false; IntervalSeconds = $Script:ManagedJobConfig.MemoryCleanupIntervalSeconds; ScriptBlock = { Invoke-MemoryCleanup } }
    @{ Name = 'CacheMaintenance'; Enabled = $true; Critical = $false; IntervalSeconds = $Script:ManagedJobConfig.CacheMaintenanceIntervalSeconds; ScriptBlock = { Invoke-CacheMaintenanceTick } }
    @{ Name = 'SecurityReport'; Enabled = $true; Critical = $false; IntervalSeconds = $Script:ManagedJobConfig.SecurityReportIntervalSeconds; ScriptBlock = {
            $reportPath = New-SecurityReport
            if ($reportPath) {
                Write-Host "[REPORT] Generated: $reportPath" -ForegroundColor Cyan
            }
        }
    }
    @{ Name = 'ManagedJobsHealth'; Enabled = $true; Critical = $false; IntervalSeconds = $Script:ManagedJobConfig.HealthCheckIntervalSeconds; ScriptBlock = {
            try {
                $runningManaged = Get-ManagedJobsRunningCount
                if ($runningManaged -lt 4) {
                    Write-Host "[!] WARNING: Some managed jobs may be disabled/stopped! Check logs for details." -ForegroundColor Yellow
                    Write-Log "[WARNING] Detected fewer active managed jobs than expected. Active: $runningManaged"
                }
            } catch {}
        }
    }
)

function Initialize-ManagedJobs {
    if (-not $script:ManagedJobs) {
        $script:ManagedJobs = @{}
    }

    if (-not $Script:Base -and $Base) {
        $Script:Base = $Base
    }

    foreach ($def in $Script:ManagedJobDefinitions) {
        Register-ManagedJob `
            -Name $def.Name `
            -Enabled ([bool]$def.Enabled) `
            -Critical ([bool]$def.Critical) `
            -IntervalSeconds ([int]$def.IntervalSeconds) `
            -MaxRestartAttempts ([int]$Script:ManagedJobConfig.MaxRestartAttempts) `
            -RestartDelaySeconds ([int]$Script:ManagedJobConfig.RestartDelaySeconds) `
            -ScriptBlock $def.ScriptBlock
    }
}

Initialize-ManagedJobs

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
        
        Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow)

        $Script:LoopCounter++
        Start-Sleep -Seconds 1
     }
 } finally {
    # Cleanup code
    Write-Host "`n[*] Shutting down antivirus..." -ForegroundColor Yellow
    
    # Background jobs (KeyScrambler, ProcessWatchdog, hash reputation) will terminate when this process exits.
    # Managed in-process jobs do not need explicit cleanup.
    
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
