# Antivirus.ps1 - GEDR + AgentsAntivirus merged EDR (all agents in one script)
# Author: Gorstak

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveRules = $false,
    [Parameter(Mandatory=$false)]
    [string]$Module = $null
)

$script:GEDRRoot = "C:\ProgramData\GEDR"

# Optimized configuration for GEDR EDR modules
# Provides tick intervals, scan limits, batch settings, CPU throttling
$script:ModuleTickIntervals = @{
    "HashDetection" = 90
    "ResponseEngine" = 180
    "MemoryScanning" = 90
    "BeaconDetection" = 60
    "NetworkTrafficMonitoring" = 45
    "AMSIBypassDetection" = 90
    "ProcessAnomalyDetection" = 90
    "EventLogMonitoring" = 90
    "FileEntropyDetection" = 120
    "Initializer" = 300
    "GFocus" = 2
    "WebcamGuardian" = 5
}

$script:ScanLimits = @{
    "MaxFiles" = 500
    "MaxProcesses" = 500
    "MaxConnections" = 1000
    "MaxEvents" = 500
    "SampleSizeBytes" = 4096
}

function Get-TickInterval {
    param([string]$ModuleName)
    if ($script:ModuleTickIntervals.ContainsKey($ModuleName)) {
        return $script:ModuleTickIntervals[$ModuleName]
    }
    return 90
}

function Get-ScanLimit {
    param([string]$LimitName)
    if ($script:ScanLimits.ContainsKey($LimitName)) {
        return $script:ScanLimits[$LimitName]
    }
    return 500
}

function Get-BatchSettings {
    return @{
        BatchSize = 50
        BatchDelayMs = 10
    }
}

function Get-LoopSleep {
    return 5
}

function Test-CPULoadThreshold {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        if ($cpu -and $cpu.CounterSamples[0].CookedValue -gt 90) { return $true }
    } catch { }
    return $false
}

function Get-CPULoad {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        if ($cpu) { return [int]$cpu.CounterSamples[0].CookedValue }
    } catch { }
    return 0
}


# Cache Manager Module - GEDR agents
# Provides caching to reduce repeated expensive operations

$script:SignatureCache = @{}
$script:HashCache = @{}
$script:ProcessCache = @{}
$script:LastCacheClean = Get-Date

function Get-CachedSignature {
    param([string]$FilePath)
    $now = Get-Date
    $ttl = 60
    if ($script:SignatureCache.ContainsKey($FilePath)) {
        $cached = $script:SignatureCache[$FilePath]
        if (($now - $cached.Timestamp).TotalMinutes -lt $ttl) { return $cached.Value }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        $script:SignatureCache[$FilePath] = @{ Value = $sig; Timestamp = $now }
        return $sig
    } catch { return $null }
}

function Get-CachedFileHash {
    param([string]$FilePath, [string]$Algorithm = "SHA256")
    $now = Get-Date
    $ttl = 120
    $key = "$FilePath|$Algorithm"
    if ($script:HashCache.ContainsKey($key)) {
        $cached = $script:HashCache[$key]
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -and $cached.LastWrite -eq $fileInfo.LastWriteTime -and ($now - $cached.Timestamp).TotalMinutes -lt $ttl) {
            return $cached.Value
        }
    }
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if (-not $fileInfo) { return $null }
        $hash = (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction SilentlyContinue).Hash
        $script:HashCache[$key] = @{ Value = $hash; Timestamp = $now; LastWrite = $fileInfo.LastWriteTime }
        return $hash
    } catch { return $null }
}

function Clear-ExpiredCache {
    $now = Get-Date
    if (($now - $script:LastCacheClean).TotalMinutes -lt 30) { return }
    $script:LastCacheClean = $now
    $script:SignatureCache.Keys | Where-Object { ($now - $script:SignatureCache[$_].Timestamp).TotalMinutes -gt 60 } | ForEach-Object { $script:SignatureCache.Remove($_) }
    $script:HashCache.Keys | Where-Object { ($now - $script:HashCache[$_].Timestamp).TotalMinutes -gt 120 } | ForEach-Object { $script:HashCache.Remove($_) }
}


# Initializer Module - GEDR EDR environment setup



$ModuleName = "Initializer"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:Initialized = $false

function Invoke-Initialization {
    try {
        Write-Output "STATS:$ModuleName`:Starting GEDR environment initialization"
        $root = $script:GEDRRoot
        $directories = @(
            $root,
            "$root\Logs",
            "$root\Data",
            "$root\Quarantine",
            "$root\Reports",
            "$root\HashDatabase"
        )
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Output "STATS:$ModuleName`:Created directory: $dir"
            }
        }
        $logFiles = @(
            "$root\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log",
            "$root\Logs\Threats_$(Get-Date -Format 'yyyy-MM-dd').log",
            "$root\Logs\Responses_$(Get-Date -Format 'yyyy-MM-dd').log"
        )
        foreach ($logFile in $logFiles) {
            if (-not (Test-Path $logFile)) {
                $header = "# GEDR EDR Log - Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n# Format: Timestamp|Module|Action|Details`n"
                Set-Content -Path $logFile -Value $header
                Write-Output "STATS:$ModuleName`:Initialized log: $logFile"
            }
        }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("GEDR")) {
                [System.Diagnostics.EventLog]::CreateEventSource("GEDR", "Application")
                Write-Output "STATS:$ModuleName`:Created Event Log source: GEDR"
            }
        } catch { Write-Output "ERROR:$ModuleName`:Failed to create Event Log source: $_" }
        $configFile = "$root\Data\config.json"
        if (-not (Test-Path $configFile)) {
            $defaultConfig = @{
                Version = "1.0"
                Initialized = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Settings = @{ MaxLogSizeMB = 100; QuarantineRetentionDays = 30 }
            }
            $defaultConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $configFile
            Write-Output "STATS:$ModuleName`:Created configuration file"
        }
        $statusFile = "$root\Data\agent_status.json"
        if (-not (Test-Path $statusFile)) {
            @{ LastCheck = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); ActiveAgents = @(); TotalDetections = 0 } | ConvertTo-Json -Depth 3 | Set-Content -Path $statusFile
        }
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Initializer|Environment|GEDR environment initialized" | Add-Content -Path "$root\Logs\System_$(Get-Date -Format 'yyyy-MM-dd').log"
        Write-Output "DETECTION:$ModuleName`:Environment initialization completed"
        return 1
    } catch {
        Write-Output "ERROR:$ModuleName`:Initialization failed: $_"
        return 0
    }
}

function Start-Module {
    $loopSleep = Get-LoopSleep
    while ($true) {
        try {
            if ($script:Initialized -and (Test-CPULoadThreshold)) {
                Start-Sleep -Seconds ($loopSleep * 2)
                continue
            }
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                if (-not $script:Initialized) {
                    $count = Invoke-Initialization
                    if ($count -gt 0) { $script:Initialized = $true }
                } else {
                    $statusFile = "$script:GEDRRoot\Data\agent_status.json"
                    if (Test-Path $statusFile) {
                        $status = Get-Content $statusFile | ConvertFrom-Json
                        $status.LastCheck = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        $status | ConvertTo-Json -Depth 3 | Set-Content -Path $statusFile
                    }
                }
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch { Write-Output "ERROR:$ModuleName`:$_"; Start-Sleep -Seconds 120 }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }


# region AdvancedThreatDetection
# Advanced Threat Detection
# High-entropy files in Windows\Temp, System32\Tasks


$ModuleName = "AdvancedThreatDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }


$ScanPaths = @("$env:SystemRoot\Temp", "$env:SystemRoot\System32\Tasks")
$Extensions = @("*.exe", "*.dll", "*.ps1", "*.vbs")

function Measure-FileEntropy {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -eq 0) { return 0 }
        $sample = if ($bytes.Length -gt 4096) { $bytes[0..4095] } else { $bytes }
        $freq = @{}
        foreach ($b in $sample) {
            if (-not $freq.ContainsKey($b)) { $freq[$b] = 0 }
            $freq[$b]++
        }
        $entropy = 0
        foreach ($c in $freq.Values) {
            $p = $c / $sample.Count
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return $entropy
    } catch { return 0 }
}

function Invoke-AdvancedThreatScan {
    $detections = @()
    foreach ($basePath in $ScanPaths) {
        if (-not (Test-Path $basePath)) { continue }
        foreach ($ext in $Extensions) {
            try {
                Get-ChildItem -Path $basePath -Filter $ext -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $ent = Measure-FileEntropy -FilePath $_.FullName
                    if ($ent -gt 7.5) {
                        $detections += @{
                            Path = $_.FullName
                            Entropy = [Math]::Round($ent, 2)
                            Type = "High-Entropy File"
                            Risk = "High"
                        }
                    }
                }
            } catch { }
        }
    }
    
    if ($detections.Count -gt 0) {
        $logPath = "C:\ProgramData\GEDR\Logs\advanced_threat_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $detections | ForEach-Object {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Path)|Entropy:$($_.Entropy)" | Add-Content -Path $logPath
            Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2091 -Message "ADVANCED THREAT: $($_.Path)" -ErrorAction SilentlyContinue
        }
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) high-entropy files"
    }
    return $detections.Count
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-AdvancedThreatScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
# endregion

# region AMSIBypassDetection
# AMSI Bypass Detection Module
# Detects attempts to bypass Windows AMSI - Optimized for low resource usage



$ModuleName = "AMSIBypassDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName

function Invoke-AMSIBypassScan {
    $detections = @()
    
    # Check for AMSI bypass techniques in running processes
    try {
        $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
        $processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" } | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2004 `
                    -Message "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.BypassPattern -or $detection.Message)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Message)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) AMSI bypass attempts"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-AMSIBypassScan
                $script:LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region AttackToolsDetection
# Attack Tools Detection
# Detects Mimikatz, Cobalt Strike, Metasploit, etc.


$ModuleName = "AttackToolsDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$AttackTools = @("mimikatz", "pwdump", "procdump", "wce", "gsecdump", "cain", "john", "hashcat", "hydra", "medusa", "nmap", "metasploit", "armitage", "cobalt")

function Invoke-AttackToolsScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            $name = ($proc.Name ?? "").ToLower()
            $cmd = ($proc.CommandLine ?? "").ToLower()
            foreach ($tool in $AttackTools) {
                if ($name -like "*$tool*" -or $cmd -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Tool = $tool
                        Type = "Attack Tool Detected"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2092 -Message "ATTACK TOOL: $($d.Tool) - $($d.ProcessName) (PID: $($d.ProcessId))" -ErrorAction SilentlyContinue
            }
            $logPath = "C:\ProgramData\GEDR\Logs\attack_tools_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Tool)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) attack tools"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    return $detections.Count
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-AttackToolsScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
# endregion

# region BeaconDetection
# Beacon Detection Module
# Detects C2 beaconing and command & control communication - Optimized for low resource usage



$ModuleName = "BeaconDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$ConnectionBaseline = @{}

function Initialize-BeaconBaseline {
    try {
        $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        foreach ($conn in $connections) {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $ConnectionBaseline.ContainsKey($key)) {
                $ConnectionBaseline[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                }
            }
            $ConnectionBaseline[$key].Count++
            $ConnectionBaseline[$key].LastSeen = Get-Date
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2037 `
                    -Message "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) beacon indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Initialize-BeaconBaseline
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-BeaconDetection
                $script:LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region BrowserExtensionMonitoring
# Browser Extension Monitoring Module
# Monitors browser extensions for malicious activity


$ModuleName = "BrowserExtensionMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2020 `
                    -Message "BROWSER EXTENSION: $($detection.Type) - $($detection.ExtensionName -or $detection.BrowserProcess)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionName -or $_.BrowserProcess)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) browser extension anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-BrowserExtensionMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region CleanGuard
# CleanGuard.ps1
# Author: Gorstak

$ErrorActionPreference = "SilentlyContinue"

# Configuration
$Config = @{
    InstallPath = "$env:ProgramData\CleanGuard"
    TaskName = "CleanGuard"
}

# Get current script path
$IsScript = $false
if ($PSCommandPath) {
    $CurrentPath = $PSCommandPath
    $IsScript = ($PSCommandPath -match '\.ps1$')
} else {
    $CurrentPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $IsScript = ($CurrentPath -match '\.ps1$')
}

# Determine installation path based on whether we're a script or exe
if ($IsScript) {
    $InstalledScriptPath = Join-Path $Config.InstallPath "CleanGuard.ps1"
    $InstallExe = $InstalledScriptPath  # For compatibility with rest of script
} else {
    $InstalledScriptPath = Join-Path $Config.InstallPath "CleanGuard.exe"
    $InstallExe = $InstalledScriptPath
}

# Check if already installed
function Test-CleanGuardInstalled {
    $task = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    return ($null -ne $task -and (Test-Path $InstalledScriptPath))
}

# Install CleanGuard service
function Install-CleanGuardService {
    Write-Host "Installing CleanGuard..." -ForegroundColor Cyan
    
    # Create install directory
    if (!(Test-Path $Config.InstallPath)) {
        New-Item -ItemType Directory -Path $Config.InstallPath -Force | Out-Null
    }
    
    # Copy script to ProgramData
    Copy-Item -Path $CurrentPath -Destination $InstalledScriptPath -Force
    Write-Host "Copied script to $InstalledScriptPath" -ForegroundColor Gray
    
    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Removing existing task..." -ForegroundColor Gray
        Unregister-ScheduledTask -TaskName $Config.TaskName -Confirm:$false
    }
    
    # Create task action
    if ($IsScript) {
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScriptPath`""
    } else {
        $action = New-ScheduledTaskAction -Execute $InstalledScriptPath
    }
    
    # Create task trigger (at startup)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    
    # Create task principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    # Register the task
    Register-ScheduledTask -TaskName $Config.TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "CleanGuard - Real-time file protection (Author: Gorstak)" | Out-Null
    
    Write-Host ""
    Write-Host "[SUCCESS] CleanGuard installed successfully!" -ForegroundColor Green
    
    Write-Host "Starting CleanGuard service..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $Config.TaskName
    Start-Sleep -Seconds 2
    
    Write-Host "Service started!" -ForegroundColor Green
    Write-Host ""
    
    exit 0
}

# Auto-install if not already installed
if (!(Test-CleanGuardInstalled)) {
    Write-Host "CleanGuard is not installed. Installing now..." -ForegroundColor Yellow
    Write-Host ""
    Install-CleanGuardService
    # Function exits with exit 0
}

# If we're not running from the installed location, launch the installed version and exit
$normalizedCurrent = [System.IO.Path]::GetFullPath($CurrentPath)
$normalizedInstalled = [System.IO.Path]::GetFullPath($InstalledScriptPath)
if ($normalizedCurrent -ne $normalizedInstalled -and $normalizedCurrent.ToLower() -ne $normalizedInstalled.ToLower()) {
    if (Test-Path $InstalledScriptPath) {
        if ($IsScript) {
            Start-Process -FilePath "PowerShell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScriptPath`"" -ErrorAction SilentlyContinue
        } else {
            Start-Process -FilePath $InstalledScriptPath -ErrorAction SilentlyContinue
        }
        exit
    }
}

$Quarantine = "$env:ProgramData\CleanGuard\Quarantine"
$Backup     = "$env:ProgramData\CleanGuard\Backup"
$LogFile    = "$env:ProgramData\CleanGuard\log.txt"
$LastFile   = "$env:ProgramData\CleanGuard\Quarantine\.last"

@($Quarantine, $Backup, (Split-Path $LogFile -Parent)) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

function Log($msg) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Log "CleanGuard started - monitoring .exe, .dll, .sys and .winmd"

function Get-SHA256($path) {
    (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
}

# Identify CleanGuard's own executable/script
# Use the installed path if available, otherwise current path
if (Test-Path $InstallExe) {
    $SelfPath = $InstallExe
} elseif ($PSCommandPath) {
    $SelfPath = $PSCommandPath
} else {
    $SelfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}
$SelfHash = Get-SHA256 $SelfPath

# Allow-list containing CleanGuard itself
$AllowList = @($SelfHash)

function Test-AllowList($hash) {
    return $AllowList -contains $hash
}

function Test-KnownGood($hash) {
    try {
        $json = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 8
        return ($json.'hashlookup:trust' -gt 50)
    } catch {
        return $false
    }
}

function Test-MalwareBazaar($hash) {
    $body = @{ query = "get_info"; hash = $hash } | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "https://mb-api.abuse.ch/api/v1/" -Body $body -ContentType "application/json" -TimeoutSec 12
        return ($resp.query_status -eq "hash_found")
    } catch {
        return $false
    }
}

function Test-SignedByMicrosoft($path) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path
        if ($sig.Status -eq "Valid") {
            if ($sig.SignerCertificate.Subject -match "O=Microsoft Corporation") { return $true }
            if ($sig.SignerCertificate.Thumbprint -match "109F2DD82E0C9D1E6B2B9A46B2D4B5E4F5B9F5D6|3A2F5E8F4E5D6C8B9A1F2E3D4C5B6A7F8E9D0C1B") { return $true }
        }
    } catch {}
    return $false
}

function Move-ToQuarantine($file) {
    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force

    "$bak|$file" | Out-File $LastFile -Encoding UTF8

    Log "QUARANTINED -> $q"
}

function Undo-LastQuarantine {
    if (!(Test-Path $LastFile)) { return }

    $line = Get-Content $LastFile -ErrorAction SilentlyContinue
    if (-not $line) { return }

    $bak, $orig = $line.Split('|', 2)
    if (Test-Path $orig) {
        Remove-Item $orig -Force
    }
    if (Test-Path $bak) {
        Move-Item $bak $orig -Force
        $name = [IO.Path]::GetFileName($orig)
        Log "UNDO -> restored $name"
    }

    Remove-Item $LastFile -Force
}

# Real-time monitoring
$drives   = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
$watchers = @()

foreach ($drive in $drives) {
    $root = $drive.DeviceID + "\"
    Log "Setting up FileSystemWatcher for drive: $root"

    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $root
        $watcher.IncludeSubdirectories = $true
        $watcher.NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite'
        $watchers += $watcher
    } catch {
        Log "Failed to create watcher for $root : $_"
    }
}

$action = {
    $path = $Event.SourceEventArgs.FullPath
    if ($path -notmatch '\.(exe|dll|sys|winmd)$') { return }

    Start-Sleep -Milliseconds 1200
    if (!(Test-Path $path)) { return }

    $name = [IO.Path]::GetFileName($path)
    $hash = Get-SHA256 $path

    if (Test-AllowList $hash) {
        Log "Allow-listed: $name"
        return
    }

    if (Test-KnownGood $hash) {
        Log "Known-good (CIRCL): $name"
        return
    }

    if (Test-SignedByMicrosoft $path) {
        Log "Trusted Microsoft: $name"
        return
    }

    if (Test-MalwareBazaar $hash) {
        Log "MALWARE DETECTED (MalwareBazaar): $name"
        Move-ToQuarantine $path
        return
    }

    $lower = $path.ToLower()
    if ($lower -notmatch 'c:\\windows\\|c:\\program files\\|c:\\program files \(x86\)\\|c:\\windowsapps\\') {
        Log "SUSPICIOUS unsigned file: $name - auto-quarantining"
        Move-ToQuarantine $path
    }
}

foreach ($watcher in $watchers) {
    Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action | Out-Null
    Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action | Out-Null
    $watcher.EnableRaisingEvents = $true
}

Log "Real-time protection ACTIVE"

# Keep script alive
try {
    while ($true) {
        Start-Sleep -Seconds 3600
    }
}
finally {
    if ($watchers) {
        $watchers | ForEach-Object { $_.Dispose() }
    }
}
# endregion

# region ClipboardMonitoring
# Clipboard Monitoring Module
# Monitors clipboard for sensitive data


$ModuleName = "ClipboardMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 10 }

function Invoke-ClipboardMonitoring {
    $detections = @()
    
    try {
        # Monitor clipboard content
        Add-Type -AssemblyName System.Windows.Forms
        
        if ([System.Windows.Forms.Clipboard]::ContainsText()) {
            $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
            
            if (-not [string]::IsNullOrEmpty($clipboardText)) {
                # Check for sensitive data patterns
                $sensitivePatterns = @(
                    @{Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'; Type = 'Email Address'},
                    @{Pattern = '\b\d{3}-\d{2}-\d{4}\b'; Type = 'SSN'},
                    @{Pattern = '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'; Type = 'Credit Card'},
                    @{Pattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|token|bearer)'; Type = 'Password/Token'},
                    @{Pattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; Type = 'IP Address'},
                    @{Pattern = '(?i)(https?://[^\s]+)'; Type = 'URL'}
                )
                
                foreach ($pattern in $sensitivePatterns) {
                    if ($clipboardText -match $pattern.Pattern) {
                        $matches = [regex]::Matches($clipboardText, $pattern.Pattern)
                        
                        if ($matches.Count -gt 0) {
                            $detections += @{
                                Type = "Sensitive Data in Clipboard"
                                DataType = $pattern.Type
                                MatchCount = $matches.Count
                                Risk = if ($pattern.Type -match 'Password|SSN|Credit Card') { "High" } else { "Medium" }
                            }
                        }
                    }
                }
                
                # Check for large clipboard content (possible exfiltration)
                if ($clipboardText.Length -gt 10000) {
                    $detections += @{
                        Type = "Large Clipboard Content"
                        ContentLength = $clipboardText.Length
                        Risk = "Medium"
                    }
                }
                
                # Check for base64 encoded content
                if ($clipboardText -match '^[A-Za-z0-9+/]+={0,2}$' -and $clipboardText.Length -gt 100) {
                    try {
                        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clipboardText))
                        if ($decoded.Length -gt 0) {
                            $detections += @{
                                Type = "Base64 Encoded Content in Clipboard"
                                EncodedLength = $clipboardText.Length
                                DecodedLength = $decoded.Length
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        }
        
        # Check for processes accessing clipboard
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'clipboard|clip'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Exclude legitimate processes
                        $legitProcesses = @("explorer.exe", "dwm.exe", "mstsc.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Type = "Process Accessing Clipboard"
                                Risk = "Medium"
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2018 `
                    -Message "CLIPBOARD MONITORING: $($detection.Type) - $($detection.DataType -or $detection.ProcessName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\Clipboard_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.DataType -or $_.ProcessName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) clipboard anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ClipboardMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region CodeInjectionDetection
# Code Injection Detection Module
# Detects various code injection techniques


$ModuleName = "CodeInjectionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        # Check for processes with unusual memory regions (injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                
                # Check for RWX memory regions (code injection indicator)
                # We'll use heuristics since we can't directly query memory protection
                
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
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2038 `
                    -Message "CODE INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) code injection indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-CodeInjectionDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region COMMonitoring
# COM Object Monitoring Module
# Monitors COM object instantiation and usage


$ModuleName = "COMMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-COMMonitoring {
    $detections = @()
    
    try {
        # Check for suspicious COM objects
        $suspiciousCOMObjects = @(
            "Shell.Application",
            "WScript.Shell",
            "Scripting.FileSystemObject",
            "Excel.Application",
            "Word.Application",
            "InternetExplorer.Application"
        )
        
        # Check running processes for COM usage
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
        
        foreach ($proc in $processes) {
            try {
                # Check command line for COM object creation
                if ($proc.CommandLine) {
                    foreach ($comObj in $suspiciousCOMObjects) {
                        if ($proc.CommandLine -like "*$comObj*" -or 
                            $proc.CommandLine -like "*New-Object*$comObj*" -or
                            $proc.CommandLine -like "*CreateObject*$comObj*") {
                            
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                COMObject = $comObj
                                Type = "Suspicious COM Object Usage"
                                Risk = "Medium"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check Event Log for COM object registration
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'COM|Component Object Model' }
            
            $registrationEvents = $events | Where-Object {
                $_.Message -match 'registration|registration.*failed|COM.*error'
            }
            
            if ($registrationEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $registrationEvents.Count
                    Type = "Unusual COM Registration Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for COM hijacking
        try {
            $comKeys = @(
                "HKCU:\SOFTWARE\Classes\CLSID",
                "HKLM:\SOFTWARE\Classes\CLSID"
            )
            
            foreach ($comKey in $comKeys) {
                if (Test-Path $comKey) {
                    $clsidKeys = Get-ChildItem -Path $comKey -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    foreach ($clsid in $clsidKeys) {
                        $inprocServer = Join-Path $clsid.PSPath "InprocServer32"
                        
                        if (Test-Path $inprocServer) {
                            $default = (Get-ItemProperty -Path $inprocServer -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                            
                            if ($default -and $default -notlike "$env:SystemRoot\*") {
                                $detections += @{
                                    CLSID = $clsid.Name
                                    InprocServer = $default
                                    Type = "COM Hijacking - Non-System InprocServer"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check for Excel/Word automation (common in malware)
        try {
            $excelProcs = Get-Process -Name "EXCEL" -ErrorAction SilentlyContinue
            $wordProcs = Get-Process -Name "WINWORD" -ErrorAction SilentlyContinue
            
            foreach ($proc in ($excelProcs + $wordProcs)) {
                try {
                    $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").CommandLine
                    
                    if ($commandLine -match '\.vbs|\.js|\.ps1|\.bat|powershell|cmd') {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            CommandLine = $commandLine
                            Type = "Office Application with Script Execution"
                            Risk = "High"
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2019 `
                    -Message "COM MONITORING: $($detection.Type) - $($detection.ProcessName -or $detection.CLSID -or $detection.COMObject)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\COMMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.COMObject -or $_.CLSID)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) COM object anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-COMMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region CredentialDumpDetection
# Credential Dumping Detection Module
# Detects attempts to dump credentials from memory


$ModuleName = "CredentialDumpDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

$CredentialDumpTools = @(
    "mimikatz", "sekurlsa", "lsadump", "wce", "fgdump", 
    "pwdump", "hashdump", "gsecdump", "cachedump",
    "procDump", "dumpert", "nanodump", "mslsa"
)

function Invoke-CredentialDumpScan {
    $detections = @()
    
    try {
        # Check running processes
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath
        
        foreach ($proc in $processes) {
            $procNameLower = $proc.Name.ToLower()
            $cmdLineLower = if ($proc.CommandLine) { $proc.CommandLine.ToLower() } else { "" }
            $pathLower = if ($proc.ExecutablePath) { $proc.ExecutablePath.ToLower() } else { "" }
            
            # Check for credential dumping tools
            foreach ($tool in $CredentialDumpTools) {
                if ($procNameLower -like "*$tool*" -or 
                    $cmdLineLower -like "*$tool*" -or 
                    $pathLower -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Tool = $tool
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for suspicious LSASS access
            if ($proc.Name -match "lsass|sam|security") {
                try {
                    $lsassProc = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
                    if ($lsassProc) {
                        # Check if process has handle to LSASS
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                        if ($handles) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                Type = "LSASS Memory Access"
                                Risk = "High"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check for credential dumping API calls in Event Log
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} -ErrorAction SilentlyContinue -MaxEvents 500
            foreach ($event in $securityEvents) {
                if ($event.Message -match 'lsass|sam|security' -and 
                    $event.Message -match 'Read|Write') {
                    $xml = [xml]$event.ToXml()
                    $objectName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ObjectName'}).'#text'
                    if ($objectName -match 'SAM|SECURITY|SYSTEM') {
                        $detections += @{
                            EventId = $event.Id
                            Type = "Registry Credential Access"
                            ObjectName = $objectName
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2005 `
                    -Message "CREDENTIAL DUMP DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.Tool -or $detection.ObjectName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\CredentialDump_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Tool -or $_.ObjectName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) credential dump attempts"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-CredentialDumpScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region CrudePayloadGuard
# CrudePayloadGuard.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunCrudePayloadGuardAtLogon"
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

# Run the functionMore actions
Register-SystemLogonScript

$job = Start-Job -ScriptBlock {
    $pattern = '(?i)(<script|javascript:|onerror=|onload=|alert\()'

    function Disable-Network-Briefly {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        foreach ($adapter in $adapters) {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host " Network briefly disabled"
    }

    function Add-XSSFirewallRule {
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
                Write-Host " Domain blocked via firewall: $domain"
            }
        } catch {
            Write-Warning "[!] Could not block: $url"
        }
    }

    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $proc = $Event.SourceEventArgs.NewEvent.TargetInstance
        $cmdline = $proc.CommandLine

        if ($cmdline -match $pattern) {
            Write-Host "`n[X] Potential XSS detected in: $cmdline"

            if ($cmdline -match 'https?://[^\s"]+') {
                $url = $matches[0]
                Disable-Network-Briefly
                Add-XSSFirewallRule -url $url
            }
        }
    } | Out-Null

    while ($true) { Start-Sleep -Seconds 5 }
}
# endregion

# region DataExfiltrationDetection
# Data Exfiltration Detection Module
# Comprehensive data exfiltration detection beyond DNS


$ModuleName = "DataExfiltrationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$BaselineTransfer = @{}

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        # Check for large outbound data transfers
        try {
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' }
            
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    
                    if ($procConns.Count -gt 0) {
                        # Check network statistics
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats) {
                            $bytesPerSec = $netStats.CounterSamples[0].CookedValue
                            
                            # Large outbound transfer
                            if ($bytesPerSec -gt 1MB) {
                                $baselineKey = $proc.ProcessName
                                $baseline = if ($BaselineTransfer.ContainsKey($baselineKey)) { $BaselineTransfer[$baselineKey] } else { 0 }
                                
                                if ($bytesPerSec -gt $baseline * 2 -and $bytesPerSec -gt 1MB) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        BytesPerSecond = [Math]::Round($bytesPerSec / 1MB, 2)
                                        ConnectionCount = $procConns.Count
                                        Type = "Large Outbound Data Transfer"
                                        Risk = "High"
                                    }
                                }
                                
                                $BaselineTransfer[$baselineKey] = $bytesPerSec
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for file uploads to cloud storage/suspicious domains
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessName -match 'curl|wget|powershell|certutil|bitsadmin' }
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    
                    if ($procObj.CommandLine) {
                        $uploadPatterns = @(
                            'upload|PUT|POST',
                            'dropbox|google.*drive|onedrive|mega|wetransfer',
                            'pastebin|github|paste.*bin',
                            'http.*upload|ftp.*put',
                            '-OutFile.*http',
                            'Invoke-WebRequest.*-Method.*Put'
                        )
                        
                        foreach ($pattern in $uploadPatterns) {
                            if ($procObj.CommandLine -match $pattern -and 
                                $procObj.CommandLine -notmatch 'download|get|GET') {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    CommandLine = $procObj.CommandLine
                                    Pattern = $pattern
                                    Type = "File Upload to External Service"
                                    Risk = "High"
                                }
                                break
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for clipboard with large data (possible exfiltration)
        try {
            Add-Type -AssemblyName System.Windows.Forms
            
            if ([System.Windows.Forms.Clipboard]::ContainsText()) {
                $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
                
                if ($clipboardText.Length -gt 50000) {
                    # Large clipboard content
                    $detections += @{
                        ClipboardSize = $clipboardText.Length
                        Type = "Large Clipboard Content (Possible Exfiltration)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing many files then connecting externally
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" -or $_.Name -like "*.xls*" }
                    
                    if ($fileHandles.Count -gt 20) {
                        $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                            Where-Object { 
                                $_.State -eq "Established" -and 
                                $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)'
                            }
                        
                        if ($conns.Count -gt 0) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandleCount = $fileHandles.Count
                                ExternalConnections = $conns.Count
                                Type = "File Access Followed by External Connection"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes reading sensitive files then connecting externally
        try {
            $sensitivePaths = @(
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Desktop",
                "$env:APPDATA\..\Local\Credentials"
            )
            
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    foreach ($sensitivePath in $sensitivePaths) {
                        if (Test-Path $sensitivePath) {
                            $files = Get-ChildItem -Path $sensitivePath -File -ErrorAction SilentlyContinue |
                                Where-Object { (Get-Date) - $_.LastAccessTime -lt [TimeSpan]::FromMinutes(5) }
                            
                            if ($files.Count -gt 5) {
                                $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                                    Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notmatch '^(10\.|192\.168\.)' }
                                
                                if ($conns.Count -gt 0) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        SensitiveFilesAccessed = $files.Count
                                        ExternalConnections = $conns.Count
                                        Type = "Sensitive File Access Followed by External Connection"
                                        Risk = "Critical"
                                    }
                                    break
                                }
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2040 `
                    -Message "DATA EXFILTRATION: $($detection.Type) - $($detection.ProcessName -or 'System')"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\DataExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) data exfiltration indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DataExfiltrationDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region DLLHijackingDetection
# DLL Hijacking Detection Module
# Detects DLL hijacking attempts


$ModuleName = "DLLHijackingDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Test-DLLHijacking {
    
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

function Invoke-DLLHijackingScan {
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2009 `
                    -Message "DLL HIJACKING: $($detection.ProcessName -or $detection.Type) - $($detection.DllPath -or $detection.Message)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) DLL hijacking indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DLLHijackingScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region DNSExfiltrationDetection
# DNS Exfiltration Detection Module
# Detects data exfiltration via DNS queries


$ModuleName = "DNSExfiltrationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-DNSExfiltrationDetection {
    $detections = @()
    
    try {
        # Monitor DNS queries
        try {
            $dnsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008} -ErrorAction SilentlyContinue -MaxEvents 500
            
            $suspiciousQueries = @()
            
            foreach ($event in $dnsEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $queryName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryName'}).'#text'
                    $queryType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryType'}).'#text'
                    
                    if ($queryName) {
                        # Check for base64-encoded subdomains (common in DNS exfiltration)
                        $subdomain = $queryName.Split('.')[0]
                        if ($subdomain.Length -gt 20 -and 
                            $subdomain -match '^[A-Za-z0-9+/=]+$' -and
                            $subdomain.Length -gt 50) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Base64-Encoded DNS Query"
                                Risk = "High"
                            }
                        }
                        
                        # Check for hex-encoded subdomains
                        if ($subdomain.Length -gt 20 -and 
                            $subdomain -match '^[A-Fa-f0-9]+$' -and
                            $subdomain.Length -gt 50) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Hex-Encoded DNS Query"
                                Risk = "High"
                            }
                        }
                        
                        # Check for unusually long domain names
                        if ($queryName.Length -gt 253) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Unusually Long DNS Query"
                                Risk = "Medium"
                            }
                        }
                        
                        # Check for queries to suspicious TLDs
                        $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".test", ".local")
                        foreach ($tld in $suspiciousTLDs) {
                            if ($queryName -like "*$tld") {
                                $suspiciousQueries += @{
                                    QueryName = $queryName
                                    QueryType = $queryType
                                    TimeCreated = $event.TimeCreated
                                    Type = "DNS Query to Suspicious TLD"
                                    TLD = $tld
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
            
            $detections += $suspiciousQueries
            
            # Check for excessive DNS queries from single process
            try {
                $processes = Get-Process -ErrorAction SilentlyContinue
                
                foreach ($proc in $processes) {
                    try {
                        $procEvents = $dnsEvents | Where-Object {
                            $_.ProcessId -eq $proc.Id -ErrorAction SilentlyContinue
                        }
                        
                        if ($procEvents.Count -gt 100) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DNSQueryCount = $procEvents.Count
                                Type = "Excessive DNS Queries from Process"
                                Risk = "High"
                            }
                        }
                    } catch {
                        continue
                    }
                }
            } catch { }
        } catch { }
        
        # Monitor DNS traffic volume
        try {
            $dnsConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -eq 53 }
            
            if ($dnsConnections.Count -gt 100) {
                $detections += @{
                    ConnectionCount = $dnsConnections.Count
                    Type = "High DNS Traffic Volume"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for DNS tunneling tools
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -match 'dnscat|iodine|dns2tcp|dnsperf'
                }
            
            foreach ($proc in $processes) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Type = "DNS Tunneling Tool Detected"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2029 `
                    -Message "DNS EXFILTRATION: $($detection.Type) - $($detection.QueryName -or $detection.ProcessName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\DNSExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.QueryName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) DNS exfiltration indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DNSExfiltrationDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region DriverWatcher
function Enforce-AllowedDrivers {
    param (
        [string[]]$AllowedVendors = @(
            "Microsoft",
            "Realtek",
            "Dolby",
            "Intel",
            "Advanced Micro Devices", # AMD full name
            "AMD",
            "NVIDIA",
            "MediaTek"
        )
    )

    Write-Host "Starting driver enforcement monitor..." -ForegroundColor Cyan

    Start-Job -ScriptBlock {

        while ($true) {
            try {
                # Get driver info (include InfName for pnputil)
                $drivers = Get-WmiObject Win32_PnPSignedDriver |
                           Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion, InfName

                foreach ($driver in $drivers) {
                    $vendor = $driver.DriverProviderName

                    if ($vendor -notin $Vendors) {
                        Write-Warning "Unauthorized driver detected: $($driver.DeviceName) | Vendor: $vendor | Version: $($driver.DriverVersion)"

                        # Force delete driver package
                        try {
                            pnputil /delete-driver $driver.InfName /uninstall /force | Out-Null
                            Write-Host "Removed driver $($driver.InfName)" -ForegroundColor Yellow
                        } catch {
                            Write-Warning "Failed to remove driver $($driver.InfName)"
                        }
                    }
                }
            } catch {
                Write-Warning "Error during driver scan: $_"
            }

            # Sleep 60 seconds before next scan (adjust as needed)
            Start-Sleep -Seconds 60
        }
    } -ArgumentList ($AllowedVendors)
}
# endregion

# region EventLogMonitoring
# Optimized Event Log Monitoring Module
# Reduced Event Log query overhead



$ModuleName = "EventLogMonitoring"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:LastEventTime = @{}

function Invoke-EventLogMonitoringOptimized {
    $detections = @()
    $maxEvents = Get-ScanLimit -LimitName "MaxEvents"
    
    try {
        $lastCheck = if ($script:LastEventTime.ContainsKey('Security')) {
            $script:LastEventTime['Security']
        } else {
            (Get-Date).AddMinutes(-$TickInterval / 60)
        }
        
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                StartTime = $lastCheck
            } -ErrorAction SilentlyContinue -MaxEvents $maxEvents
            
            $script:LastEventTime['Security'] = Get-Date
            
            # Check for failed logons
            $failedLogons = $securityEvents | Where-Object { $_.Id -eq 4625 }
            if ($failedLogons.Count -gt 10) {
                $detections += @{
                    EventCount = $failedLogons.Count
                    Type = "Excessive Failed Logon Attempts"
                    Risk = "High"
                }
            }
            
            # Check for privilege escalation
            $privilegeEvents = $securityEvents | Where-Object { $_.Id -in @(4672, 4673, 4674) }
            if ($privilegeEvents.Count -gt 0) {
                $detections += @{
                    EventCount = $privilegeEvents.Count
                    Type = "Privilege Escalation Events"
                    Risk = "High"
                }
            }
            
            # Check for log clearing
            $logClearing = $securityEvents | Where-Object { $_.Id -eq 1102 }
            if ($logClearing.Count -gt 0) {
                $detections += @{
                    EventCount = $logClearing.Count
                    Type = "Event Log Cleared"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\EventLogMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|Count:$($_.EventCount)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) event log anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 20)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-EventLogMonitoringOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 60
        }
    }
}
}
# endregion

# region FileEntropyDetection
# Optimized File Entropy Detection Module
# Reduced file I/O with smart sampling



$ModuleName = "FileEntropyDetection"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$HighEntropyThreshold = 7.2
$script:ScannedFiles = @{}

function Measure-FileEntropyOptimized {
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        
        $sampleSize = Get-ScanLimit -LimitName "SampleSizeBytes"
        $sampleSize = [Math]::Min($sampleSize, $fileInfo.Length)
        
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

function Invoke-FileEntropyDetectionOptimized {
    $detections = @()
    $maxFiles = Get-ScanLimit -LimitName "MaxFiles"
    $batchSettings = Get-BatchSettings
    
    try {
        $cutoff = (Get-Date).AddHours(-2)
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
        
        $scannedCount = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            if ($scannedCount -ge $maxFiles) { break }
            
            try {
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.scr -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First ($maxFiles - $scannedCount)
                
                $batchCount = 0
                foreach ($file in $files) {
                    $scannedCount++
                    
                    if ($script:ScannedFiles.ContainsKey($file.FullName)) {
                        $cached = $script:ScannedFiles[$file.FullName]
                        if ($cached.LastWrite -eq $file.LastWriteTime) {
                            continue
                        }
                    }
                    
                    $batchCount++
                    if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                        Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
                    }
                    
                    $entropyResult = Measure-FileEntropyOptimized -FilePath $file.FullName
                    
                    # Mark as scanned
                    $script:ScannedFiles[$file.FullName] = @{
                        LastWrite = $file.LastWriteTime
                        Entropy = if ($entropyResult) { $entropyResult.Entropy } else { 0 }
                    }
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $HighEntropyThreshold) {
                        $detections += @{
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Entropy = [Math]::Round($entropyResult.Entropy, 2)
                            Type = "High Entropy File"
                            Risk = "Medium"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) high entropy files"
        }
        
        Write-Output "STATS:$ModuleName`:Scanned=$scannedCount"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    $toRemove = $script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
    foreach ($key in $toRemove) {
        $script:ScannedFiles.Remove($key)
    }
    
    Clear-ExpiredCache
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-FileEntropyDetectionOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120
        }
    }
}
}
# endregion

# region FilelessDetection
# Fileless Malware Detection Module
# Detects fileless malware techniques


$ModuleName = "FilelessDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-FilelessDetection {
    $detections = @()
    
    try {
        # Check for PowerShell in memory execution
        $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
        
        foreach ($psProc in $psProcesses) {
            try {
                $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($psProc.Id)").CommandLine
                
                if ($commandLine) {
                    # Check for encoded commands
                    if ($commandLine -match '-encodedcommand|-enc|-e\s+[A-Za-z0-9+/=]{100,}') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell Encoded Command Execution"
                            Risk = "High"
                        }
                    }
                    
                    # Check for IEX/Invoke-Expression usage
                    if ($commandLine -match '(?i)(iex|invoke-expression|invoke-expression)') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell IEX Execution"
                            Risk = "High"
                        }
                    }
                    
                    # Check for download and execute
                    if ($commandLine -match '(?i)(downloadstring|downloadfile|webclient|invoke-webrequest).*(http|https|ftp)') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell Download and Execute"
                            Risk = "Critical"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for WMI event consumers (fileless persistence)
        try {
            $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
            
            foreach ($consumer in $wmiConsumers) {
                if ($consumer.__CLASS -match 'ActiveScript|CommandLine') {
                    $detections += @{
                        ConsumerName = $consumer.Name
                        ConsumerClass = $consumer.__CLASS
                        Type = "WMI Fileless Persistence"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for Registry-based fileless execution
        try {
            $regKeys = @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            )
            
            foreach ($regKey in $regKeys) {
                if (Test-Path $regKey) {
                    $values = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                    if ($values) {
                        $valueProps = $values.PSObject.Properties | Where-Object {
                            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                        }
                        
                        foreach ($prop in $valueProps) {
                            $value = $prop.Value
                            
                            # Check for registry-based script execution
                            if ($value -match 'powershell.*-enc|wscript|javascript|vbscript' -and
                                -not (Test-Path $value)) {
                                $detections += @{
                                    RegistryPath = $regKey
                                    ValueName = $prop.Name
                                    Value = $value
                                    Type = "Registry-Based Fileless Execution"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check for .NET reflection-based execution
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'System\.Reflection|System\.CodeDom'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check for unsigned processes using reflection
                        if ($proc.Path -and (Test-Path $proc.Path)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ReflectionModules = $modules.ModuleName -join ','
                                    Type = "Unsigned Process Using Reflection"
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for memory-only modules
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.FileName -notlike "$env:SystemRoot\*" -and
                        $_.FileName -notlike "$env:ProgramFiles*" -and
                        -not (Test-Path $_.FileName)
                    }
                    
                    if ($modules.Count -gt 5) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            MemoryModules = $modules.Count
                            Type = "Process with Many Memory-Only Modules"
                            Risk = "High"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for fileless execution indicators
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object {
                    $_.Message -match 'encodedcommand|iex|invoke-expression|downloadstring'
                }
            
            foreach ($event in $events) {
                $detections += @{
                    EventId = $event.Id
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    Type = "Event Log Fileless Execution Indicator"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2026 `
                    -Message "FILELESS DETECTION: $($detection.Type) - $($detection.ProcessName -or $detection.ConsumerName -or $detection.ValueName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\FilelessDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.ConsumerName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) fileless malware indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-FilelessDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region FirewallRuleMonitoring
# Firewall Rule Monitoring Module
# Monitors firewall rules for suspicious changes


$ModuleName = "FirewallRuleMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }
$BaselineRules = @{}

function Initialize-FirewallBaseline {
    try {
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            if (-not $BaselineRules.ContainsKey($key)) {
                $BaselineRules[$key] = @{
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

function Invoke-FirewallRuleMonitoring {
    $detections = @()
    
    try {
        # Get current firewall rules
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        
        # Check for new or modified rules
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            
            if (-not $BaselineRules.ContainsKey($key)) {
                # New rule detected
                $detections += @{
                    RuleName = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    Type = "New Firewall Rule"
                    Risk = "Medium"
                }
                
                # Update baseline
                $BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            } else {
                # Check if rule was modified
                $baseline = $BaselineRules[$key]
                if ($rule.Enabled -ne $baseline.Enabled) {
                    $detections += @{
                        RuleName = $rule.Name
                        OldState = $baseline.Enabled
                        NewState = $rule.Enabled
                        Type = "Firewall Rule State Changed"
                        Risk = "High"
                    }
                    
                    $baseline.Enabled = $rule.Enabled
                }
            }
        }
        
        # Check for suspicious firewall rules
        foreach ($rule in $rules) {
            try {
                $ruleFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $ruleAppFilters = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                
                # Check for rules allowing all traffic
                if ($ruleFilters) {
                    if ($ruleFilters.RemoteAddress -eq "*" -and $rule.Action -eq "Allow") {
                        $detections += @{
                            RuleName = $rule.Name
                            RemoteAddress = $ruleFilters.RemoteAddress
                            Type = "Firewall Rule Allows All Traffic"
                            Risk = "High"
                        }
                    }
                }
                
                # Check for rules allowing unsigned applications
                if ($ruleAppFilters -and $ruleAppFilters.Program) {
                    foreach ($program in $ruleAppFilters.Program) {
                        if ($program -and (Test-Path $program)) {
                            $sig = Get-AuthenticodeSignature -FilePath $program -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $rule.Action -eq "Allow") {
                                $detections += @{
                                    RuleName = $rule.Name
                                    Program = $program
                                    Type = "Firewall Rule Allows Unsigned Application"
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                }
                
                # Check for rules with unusual port ranges
                $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                if ($portFilters) {
                    if ($portFilters.LocalPort -eq "*" -or 
                        ($portFilters.LocalPort -is [Array] -and $portFilters.LocalPort.Count -gt 100)) {
                        $detections += @{
                            RuleName = $rule.Name
                            LocalPort = $portFilters.LocalPort
                            Type = "Firewall Rule with Unusual Port Range"
                            Risk = "Medium"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for firewall service status
        try {
            $fwService = Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue
            
            if ($fwService -and $fwService.State -ne "Running") {
                $detections += @{
                    ServiceState = $fwService.State
                    Type = "Windows Firewall Service Not Running"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for firewall profiles
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                if ($profile.Enabled -eq $false) {
                    $detections += @{
                        ProfileName = $profile.Name
                        Type = "Firewall Profile Disabled"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2024 `
                    -Message "FIREWALL RULE MONITORING: $($detection.Type) - $($detection.RuleName -or $detection.ProfileName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\FirewallRule_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RuleName -or $_.ProfileName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) firewall rule anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    Initialize-FirewallBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-FirewallRuleMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region HashDetection
# Optimized Hash-based Malware Detection Module
# Significantly reduced file I/O and CPU usage



$ModuleName = "HashDetection"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:ThreatHashes = @{}
$script:ScannedFiles = @{}
$script:Initialized = $false

function Initialize-HashDatabaseOptimized {
    if ($script:Initialized) {
        return
    }
    
    $threatPath = "C:\ProgramData\GEDR\HashDatabase\threats.txt"
    if (Test-Path $threatPath) {
        Get-Content $threatPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^([A-F0-9]{32,64})$') {
                $script:ThreatHashes[$matches[1].ToUpper()] = $true
            }
        }
    }
    
    $script:Initialized = $true
}

function Invoke-HashScanOptimized {
    $threatsFound = @()
    $batchSettings = Get-BatchSettings
    $maxFiles = Get-ScanLimit -LimitName "MaxFiles"
    
    Initialize-HashDatabaseOptimized
    
    $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
    $scannedCount = 0
    
    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        if ($scannedCount -ge $maxFiles) { break }
        
        try {
            $cutoff = (Get-Date).AddHours(-1)
            $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff } |
                Select-Object -First ($maxFiles - $scannedCount)
            
            $batchCount = 0
            foreach ($file in $files) {
                $scannedCount++
                
                if ($script:ScannedFiles.ContainsKey($file.FullName)) {
                    $cached = $script:ScannedFiles[$file.FullName]
                    if ($cached.LastWrite -eq $file.LastWriteTime) {
                        continue
                    }
                }
                
                $batchCount++
                if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
                }
                
                $hash = Get-CachedFileHash -FilePath $file.FullName -Algorithm "SHA256"
                if (-not $hash) { continue }
                
                # Mark as scanned
                $script:ScannedFiles[$file.FullName] = @{
                    LastWrite = $file.LastWriteTime
                    Hash = $hash
                }
                
                # Check against threat database
                if ($script:ThreatHashes.ContainsKey($hash.ToUpper())) {
                    $threatsFound += @{
                        File = $file.FullName
                        Hash = $hash
                        Threat = "Known Malware Hash"
                    }
                }
            }
        } catch {
            continue
        }
    }
    
    if ($threatsFound.Count -gt 0) {
        $logPath = "C:\ProgramData\GEDR\Logs\HashDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $threatsFound | ForEach-Object {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|THREAT|$($_.File)|$($_.Hash)" | Add-Content -Path $logPath
        }
        Write-Output "DETECTION:$ModuleName`:Found $($threatsFound.Count) hash-based threats"
    }
    
    Write-Output "STATS:$ModuleName`:Scanned=$scannedCount,Threats=$($threatsFound.Count)"
    
    $now = Get-Date
    $oldKeys = $script:ScannedFiles.Keys | Where-Object {
        -not (Test-Path $_)
    }
    foreach ($key in $oldKeys) {
        $script:ScannedFiles.Remove($key)
    }
    
    Clear-ExpiredCache
    return $threatsFound.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-HashScanOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 60
        }
    }
}
}
# endregion

# region HoneypotMonitoring
# Honeypot Monitoring
# Creates decoy files and processes to detect unauthorized access


$ModuleName = "HoneypotMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }
$HoneypotFiles = @()
$HoneypotPaths = @(
    "$env:USERPROFILE\Desktop\passwords.txt",
    "$env:USERPROFILE\Documents\credentials.xlsx",
    "$env:USERPROFILE\Documents\credit_cards.txt",
    "$env:USERPROFILE\Desktop\private_keys.txt",
    "$env:APPDATA\credentials.db",
    "$env:USERPROFILE\Documents\financial_data.xlsx"
)

function Initialize-Honeypots {
    try {
        foreach ($honeypotPath in $HoneypotPaths) {
            $dir = Split-Path -Parent $honeypotPath
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            if (-not (Test-Path $honeypotPath)) {
                # Create honeypot file with fake but realistic content
                $content = switch -Wildcard ([System.IO.Path]::GetFileName($honeypotPath)) {
                    "*password*" { "FAKE_PASSWORD_FILE_DO_NOT_USE`r`nusername: admin`r`npassword: fake_password_123`r`nLastModified: $(Get-Date -Format 'yyyy-MM-dd')" }
                    "*credential*" { "FAKE_CREDENTIAL_FILE_DO_NOT_USE`r`nAccount: fake_account`r`nPassword: fake_pass_123`r`nCreated: $(Get-Date -Format 'yyyy-MM-dd')" }
                    "*credit*" { "FAKE_CREDIT_CARD_FILE_DO_NOT_USE`r`nCard: 4111-1111-1111-1111`r`nCVV: 123`r`nExpiry: 12/25" }
                    "*key*" { "FAKE_PRIVATE_KEY_FILE_DO_NOT_USE`r`n-----BEGIN FAKE RSA PRIVATE KEY-----`r`nFAKE_KEY_DATA`r`n-----END FAKE RSA PRIVATE KEY-----" }
                    "*financial*" { "FAKE_FINANCIAL_DATA_FILE_DO_NOT_USE`r`nAccount: 123456789`r`nBalance: $0.00`r`nTransaction: None" }
                    default { "FAKE_FILE_DO_NOT_USE - Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
                }
                
                Set-Content -Path $honeypotPath -Value $content -ErrorAction SilentlyContinue
                
                # Mark as honeypot with file attribute
                try {
                    $file = Get-Item $honeypotPath -ErrorAction Stop
                    $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
                } catch { }
                
                $script:HoneypotFiles += @{
                    Path = $honeypotPath
                    Created = Get-Date
                    LastAccessed = $null
                    AccessCount = 0
                }
                
                Write-Output "STATS:$ModuleName`:Created honeypot: $honeypotPath"
            }
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to initialize honeypots: $_"
    }
}

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        # Check honeypot file access
        foreach ($honeypot in $script:HoneypotFiles) {
            $honeypotPath = $honeypot.Path
            
            if (Test-Path $honeypotPath) {
                try {
                    $file = Get-Item $honeypotPath -ErrorAction Stop
                    $lastAccess = $file.LastAccessTime
                    
                    # Check if file was accessed recently
                    if ($honeypot.LastAccessed -and $lastAccess -gt $honeypot.LastAccessed) {
                        $honeypot.AccessCount++
                        
                        # Detect unauthorized access
                        if ($honeypot.AccessCount -gt 0) {
                            # Find process that accessed the file
                            $accessingProcesses = @()
                            try {
                                $processes = Get-Process -ErrorAction SilentlyContinue
                                
                                foreach ($proc in $processes) {
                                    try {
                                        $procObj = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                                        
                                        if ($procObj.CommandLine -like "*$([System.IO.Path]::GetFileName($honeypotPath))*") {
                                            $accessingProcesses += $proc.ProcessName
                                        }
                                    } catch { }
                                }
                            } catch { }
                            
                            $detections += @{
                                HoneypotPath = $honeypotPath
                                LastAccess = $lastAccess
                                AccessCount = $honeypot.AccessCount
                                AccessingProcesses = $accessingProcesses -join ','
                                Type = "Honeypot File Accessed"
                                Risk = "Critical"
                            }
                            
                            # Log honeypot trigger
                            Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2041 `
                                -Message "HONEYPOT TRIGGERED: $honeypotPath was accessed - Processes: $($accessingProcesses -join ', ')"
                        }
                        
                        $honeypot.LastAccessed = $lastAccess
                    }
                } catch {
                    # File may have been deleted or moved
                    if (-not $honeypot.LastAccessed -or ((Get-Date) - $honeypot.Created).TotalMinutes -lt 5) {
                        $detections += @{
                            HoneypotPath = $honeypotPath
                            Type = "Honeypot File Deleted/Moved"
                            Risk = "Critical"
                        }
                        
                        Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2041 `
                            -Message "HONEYPOT DELETED: $honeypotPath was deleted or moved"
                        
                        # Recreate honeypot
                        Initialize-Honeypots
                    }
                }
            } else {
                # File doesn't exist - recreate
                Initialize-Honeypots
            }
        }
        
        # Check for processes accessing multiple honeypots (malware scanning)
        if ($detections.Count -gt 2) {
            $detections += @{
                HoneypotCount = $detections.Count
                Type = "Multiple Honeypots Accessed (Systematic Scanning)"
                Risk = "Critical"
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\Honeypot_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.HoneypotPath)|$($_.AccessingProcesses)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) honeypot access events"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    Initialize-Honeypots
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $count = Invoke-HoneypotMonitoring
                $script:LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region IdsDetection
# IDS Detection
# Command-line IDS patterns (meterpreter, certutil -urlcache, etc.)


$ModuleName = "IdsDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

$Patterns = @(
    @{ Pattern = "meterpreter"; Desc = "Metasploit meterpreter" }
    @{ Pattern = "certutil\s+-urlcache"; Desc = "Certutil download" }
    @{ Pattern = "bitsadmin\s+/transfer"; Desc = "Bitsadmin download" }
    @{ Pattern = "powershell\s+-enc"; Desc = "Base64 encoded PS" }
    @{ Pattern = "powershell\s+-w\s+hidden"; Desc = "Hidden window PS" }
    @{ Pattern = "invoke-expression"; Desc = "IEX usage" }
    @{ Pattern = "iex\s*\("; Desc = "IEX usage" }
    @{ Pattern = "downloadstring"; Desc = "DownloadString" }
    @{ Pattern = "downloadfile"; Desc = "DownloadFile" }
    @{ Pattern = "webclient"; Desc = "WebClient" }
    @{ Pattern = "net\.webclient"; Desc = "Net.WebClient" }
    @{ Pattern = "bypass.*-executionpolicy"; Desc = "Execution policy bypass" }
    @{ Pattern = "wmic\s+process\s+call\s+create"; Desc = "WMI process creation" }
    @{ Pattern = "reg\s+add.*HKLM.*Run"; Desc = "Registry Run key" }
    @{ Pattern = "schtasks\s+/create"; Desc = "Scheduled task creation" }
    @{ Pattern = "netsh\s+firewall"; Desc = "Firewall modification" }
    @{ Pattern = "sc\s+create"; Desc = "Service creation" }
    @{ Pattern = "rundll32.*\.dll"; Desc = "Rundll32 DLL" }
    @{ Pattern = "regsvr32\s+.*/s"; Desc = "Regsvr32 silent" }
    @{ Pattern = "mshta\s+http"; Desc = "Mshta remote script" }
)

function Invoke-IdsScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            $cmd = $proc.CommandLine ?? ""
            foreach ($p in $Patterns) {
                if ($cmd -match $p.Pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $p.Pattern
                        Description = $p.Desc
                        CommandLine = $cmd.Substring(0, [Math]::Min(500, $cmd.Length))
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2095 -Message "IDS: $($d.Description) - $($d.ProcessName) PID:$($d.ProcessId)" -ErrorAction SilentlyContinue
            }
            $logPath = "C:\ProgramData\GEDR\Logs\ids_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Description)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) IDS matches"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-IdsScan
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 60 } }
# endregion

# region KeyloggerDetection
# Keylogger Detection Module
# Detects keylogging activity


$ModuleName = "KeyloggerDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-KeyloggerScan {
    $detections = @()
    
    try {
        # Check for known keylogger processes
        $keyloggerNames = @("keylog", "keylogger", "keyspy", "keycapture", "keystroke", "keyhook", "keymon", "kl")
        
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $procNameLower = $proc.ProcessName.ToLower()
            foreach ($keylogName in $keyloggerNames) {
                if ($procNameLower -like "*$keylogName*") {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ProcessPath = $proc.Path
                        Type = "Known Keylogger Process"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        # Check for processes with keyboard hooks
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for SetWindowsHookEx usage (common in keyloggers)
                    $modules = $procObj.Modules | Where-Object { 
                        $_.ModuleName -match "hook|keyboard|input" 
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check if process is signed
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ExecutablePath = $proc.ExecutablePath
                                    HookModules = $modules.ModuleName -join ','
                                    Type = "Unsigned Process with Keyboard Hooks"
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
        
        # Check for processes accessing keyboard input devices
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    
                    if ($handles) {
                        # Check for keyboard device access
                        $keyboardHandles = $handles | Where-Object { 
                            $_.Name -match "keyboard|kbdclass|keybd" 
                        }
                        
                        if ($keyboardHandles.Count -gt 0) {
                            # Exclude legitimate processes
                            $legitProcesses = @("explorer.exe", "winlogon.exe", "csrss.exe")
                            if ($proc.ProcessName -notin $legitProcesses) {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    KeyboardHandles = $keyboardHandles.Count
                                    Type = "Direct Keyboard Device Access"
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
        
        # Check for clipboard monitoring (often used with keyloggers)
        try {
            $clipboardProcs = Get-Process | Where-Object {
                $_.Modules.ModuleName -like "*clipboard*" -or
                $_.Path -like "*clipboard*"
            }
            
            foreach ($proc in $clipboardProcs) {
                if ($proc.ProcessName -notin @("explorer.exe", "dwm.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        Type = "Clipboard Monitoring Process"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check Event Log for suspicious keyboard events
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'keyboard|keystroke|hook' }
            
            if ($events.Count -gt 10) {
                $detections += @{
                    EventCount = $events.Count
                    Type = "Excessive Keyboard Events"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2012 `
                    -Message "KEYLOGGER DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.HookModules -or $detection.Type)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\Keylogger_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Risk)|$($_.HookModules -or $_.KeyboardHandles)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) keylogger indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-KeyloggerScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region KeyScramblerManagement
# Key Scrambler Management
# Anti-keylogger measures (placeholder - matches AV)


$ModuleName = "KeyScramblerManagement"

function Start-Module {
    while ($true) {
        Start-Sleep -Seconds 60
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
# endregion

# region LateralMovementDetection
# Lateral Movement Detection Module
# Detects lateral movement techniques (SMB, RDP, WMI, PsExec, etc.)


$ModuleName = "LateralMovementDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        # Check for SMB shares enumeration/access
        try {
            $smbEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'SMB|share|\\\\.*\\'
                }
            
            if ($smbEvents.Count -gt 10) {
                $detections += @{
                    EventCount = $smbEvents.Count
                    Type = "Excessive SMB Share Access (Lateral Movement)"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for RDP connections
        try {
            $rdpEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'RDP|Terminal Services|logon.*type.*10'
                }
            
            if ($rdpEvents.Count -gt 5) {
                foreach ($event in $rdpEvents) {
                    $xml = [xml]$event.ToXml()
                    $subjectUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                    $targetUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    
                    if ($subjectUserName -ne $targetUserName) {
                        $detections += @{
                            EventId = $event.Id
                            SubjectUser = $subjectUserName
                            TargetUser = $targetUserName
                            TimeCreated = $event.TimeCreated
                            Type = "RDP Lateral Movement"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for PsExec usage
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -eq "psexec.exe" -or 
                    $_.CommandLine -like "*psexec*" -or
                    $_.CommandLine -like "*paexec*"
                }
            
            foreach ($proc in $processes) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Type = "PsExec Lateral Movement Tool"
                    Risk = "High"
                }
            }
        } catch { }
        
        # Check for WMI remote execution
        try {
            $wmiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Trace'} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    ($_.Message -match 'remote|Win32_Process.*Create' -or $_.Message -match '\\\\')
                }
            
            if ($wmiEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $wmiEvents.Count
                    Type = "WMI Remote Execution (Lateral Movement)"
                    Risk = "High"
                }
            }
        } catch { }
        
        # Check for pass-the-hash tools
        try {
            $pthTools = @("mimikatz", "psexec", "wmiexec", "pth-winexe", "crackmapexec")
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                foreach ($tool in $pthTools) {
                    if ($proc.ProcessName -like "*$tool*" -or $proc.Path -like "*$tool*") {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Tool = $tool
                            Type = "Pass-the-Hash Tool Detected"
                            Risk = "Critical"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for suspicious network connections to internal IPs
        try {
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.State -eq "Established" -and
                    $_.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' -and
                    $_.RemotePort -in @(445, 3389, 135, 5985, 5986)  # SMB, RDP, RPC, WinRM
                }
            
            $procGroups = $connections | Group-Object OwningProcess
            
            foreach ($group in $procGroups) {
                $uniqueIPs = ($group.Group | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 5) {
                    try {
                        $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                        if ($proc) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                InternalIPCount = $uniqueIPs
                                ConnectionCount = $group.Count
                                Type = "Multiple Internal Network Connections (Lateral Movement)"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2039 `
                    -Message "LATERAL MOVEMENT: $($detection.Type) - $($detection.ProcessName -or $detection.Tool -or $detection.SubjectUser)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\LateralMovement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Tool -or $_.SubjectUser)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) lateral movement indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-LateralMovementDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region LOLBinDetection
# Living-Off-The-Land Binary Detection
# Detects legitimate tools used maliciously


$ModuleName = "LOLBinDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$LOLBinPatterns = @{
    "cmd.exe" = @("\/c.*certutil|powershell|bitsadmin|regsvr32")
    "powershell.exe" = @("-nop.*-w.*hidden|-EncodedCommand|-ExecutionPolicy.*Bypass")
    "wmic.exe" = @("process.*call.*create")
    "mshta.exe" = @("http|https|\.hta")
    "rundll32.exe" = @("javascript:|\.dll.*\,")
    "regsvr32.exe" = @("\/s.*\/i.*http|\.sct")
    "certutil.exe" = @("-urlcache|-decode|\.exe")
    "bitsadmin.exe" = @("/transfer|/rawreturn")
    "schtasks.exe" = @("/create.*/tn.*http|/create.*/tr.*powershell")
    "msbuild.exe" = @("\.xml.*http|\.csproj.*http")
    "csc.exe" = @("\.cs.*http")
}
$DetectionCount = 0

function Get-RunningProcesses {
    try {
        return Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId
    } catch {
        return @()
    }
}

function Test-LOLBinCommandLine {
    param(
        [string]$ProcessName,
        [string]$CommandLine
    )
    
    if ([string]::IsNullOrEmpty($CommandLine)) { return $null }
    
    $processNameLower = $ProcessName.ToLower()
    $cmdLineLower = $CommandLine.ToLower()
    
    if ($LOLBinPatterns.ContainsKey($processNameLower)) {
        foreach ($pattern in $LOLBinPatterns[$processNameLower]) {
            if ($cmdLineLower -match $pattern) {
                return @{
                    Process = $ProcessName
                    CommandLine = $CommandLine
                    Pattern = $pattern
                    Risk = "High"
                }
            }
        }
    }
    
    # Additional heuristics
    if ($cmdLineLower -match 'powershell.*-encodedcommand' -and 
        $cmdLineLower.Length -gt 500) {
        return @{
            Process = $ProcessName
            CommandLine = $CommandLine
            Pattern = "Long encoded PowerShell command"
            Risk = "High"
        }
    }
    
    if ($cmdLineLower -match '(http|https)://[^\s]+' -and 
        $processNameLower -in @('cmd.exe','rundll32.exe','mshta.exe')) {
        return @{
            Process = $ProcessName
            CommandLine = $CommandLine
            Pattern = "Network download from LOLBin"
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-LOLBinScan {
    $detections = @()
    $processes = Get-RunningProcesses
    
    foreach ($proc in $processes) {
        $result = Test-LOLBinCommandLine -ProcessName $proc.Name -CommandLine $proc.CommandLine
        if ($result) {
            $detections += @{
                ProcessId = $proc.ProcessId
                ProcessName = $proc.Name
                CommandLine = $proc.CommandLine
                Pattern = $result.Pattern
                Risk = $result.Risk
                ParentProcessId = $proc.ParentProcessId
                CreationDate = $proc.CreationDate
            }
        }
    }
    
    if ($detections.Count -gt 0) {
        $script:DetectionCount += $detections.Count
        
        foreach ($detection in $detections) {
            Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2002 `
                -Message "LOLBIN DETECTED: $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.Pattern)"
            
            # Log details
            $logPath = "C:\ProgramData\GEDR\Logs\LOLBinDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($detection.ProcessId)|$($detection.ProcessName)|$($detection.Pattern)|$($detection.CommandLine)" | 
                Add-Content -Path $logPath
        }
        
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) LOLBin instances"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-LOLBinScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Scanned processes, Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region MemoryAcquisitionDetection
# Memory Acquisition Detection
# Detects WinPmem, pmem, FTK Imager, etc.


$ModuleName = "MemoryAcquisitionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$ProcessPatterns = @("winpmem", "pmem", "osxpmem", "aff4imager", "winpmem_mini", "memdump", "rawdump")
$CmdPatterns = @("winpmem", "pmem", "\.\pmem", "/dev/pmem", ".aff4", "-o .raw", "-o .aff4", "image.raw", "memory.raw", "physical memory", "memory acquisition", "physicalmemory")

function Invoke-MemoryAcquisitionScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath
        foreach ($proc in $processes) {
            $name = ($proc.Name ?? "").ToLower()
            $cmd = ($proc.CommandLine ?? "") + " " + ($proc.ExecutablePath ?? "")
            
            foreach ($pat in $ProcessPatterns) {
                if ($name -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $pat
                        Type = "Memory Acquisition Tool"
                        Risk = "Critical"
                    }
                    break
                }
            }
            if ($detections[-1].ProcessId -eq $proc.ProcessId) { continue }
            
            foreach ($pat in $CmdPatterns) {
                if ($cmd -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = "cmd:$pat"
                        Type = "Memory Acquisition (cmd)"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2093 -Message "MEMORY ACQUISITION: $($d.Pattern) - $($d.ProcessName) (PID: $($d.ProcessId))" -ErrorAction SilentlyContinue
            }
            $logPath = "C:\ProgramData\GEDR\Logs\memory_acquisition_detections_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) memory acquisition indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    return $detections.Count
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-MemoryAcquisitionScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
# endregion

# region MemoryScanning
# Optimized Memory Scanning Module
# Reduced CPU/RAM/Disk usage with caching and batching



$ModuleName = "MemoryScanning"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName

$script:ProcessBaseline = @{}
$script:LastBaselineUpdate = Get-Date

function Update-ProcessBaseline {
    $now = Get-Date
    if (($now - $script:LastBaselineUpdate).TotalMinutes -lt 5) {
        return
    }
    
    $script:LastBaselineUpdate = $now
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | 
            Where-Object { $_.WorkingSet64 -gt 10MB } |
            Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $key = "$($proc.ProcessName)|$($proc.Id)"
            if (-not $script:ProcessBaseline.ContainsKey($key)) {
                $script:ProcessBaseline[$key] = @{
                    FirstSeen = $now
                    Scanned = $false
                }
            }
        }
        
        $toRemove = @()
        foreach ($key in $script:ProcessBaseline.Keys) {
            $pid = $key.Split('|')[1]
            try {
                $null = Get-Process -Id $pid -ErrorAction Stop
            } catch {
                $toRemove += $key
            }
        }
        foreach ($key in $toRemove) {
            $script:ProcessBaseline.Remove($key)
        }
    } catch { }
}

function Invoke-MemoryScanningOptimized {
    $detections = @()
    $batchSettings = Get-BatchSettings
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        Update-ProcessBaseline
        
        $processes = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.WorkingSet64 -gt 10MB } |
            Select-Object -First $maxProcs
        
        $batchCount = 0
        foreach ($proc in $processes) {
            try {
                $key = "$($proc.ProcessName)|$($proc.Id)"
                
                if ($script:ProcessBaseline.ContainsKey($key) -and $script:ProcessBaseline[$key].Scanned) {
                    continue
                }
                
                $batchCount++
                if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
                }
                
                $modules = $proc.Modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*"
                }
                
                if ($modules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        SuspiciousModules = $modules.Count
                        Type = "Process with Many Non-System Modules"
                        Risk = "Medium"
                    }
                }
                
                if ($script:ProcessBaseline.ContainsKey($key)) {
                    $script:ProcessBaseline[$key].Scanned = $true
                }
                
            } catch {
                continue
            }
        }
        
        $now = Get-Date
        foreach ($key in $script:ProcessBaseline.Keys) {
            if (($now - $script:ProcessBaseline[$key].FirstSeen).TotalSeconds -gt $TickInterval) {
                $script:ProcessBaseline[$key].Scanned = $false
                $script:ProcessBaseline[$key].FirstSeen = $now
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\MemoryScanning_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.ProcessId)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) memory anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Scanned $($processes.Count) processes"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    Clear-ExpiredCache
    
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-MemoryScanningOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region MitreMapping
# MITRE ATT&CK Mapping
# Maps detections to MITRE ATT&CK and logs stats


$ModuleName = "MitreMapping"

$TechniqueMap = @{
    "HashDetection" = "T1204"
    "LOLBin" = "T1218"
    "ProcessAnomaly" = "T1055"
    "AMSIBypass" = "T1562.006"
    "CredentialDump" = "T1003"
    "MemoryAcquisition" = "T1119"
    "WMIPersistence" = "T1547.003"
    "ScheduledTask" = "T1053.005"
    "RegistryPersistence" = "T1547.001"
    "DLLHijacking" = "T1574.001"
    "TokenManipulation" = "T1134"
    "ProcessHollowing" = "T1055.012"
    "Keylogger" = "T1056.001"
    "Ransomware" = "T1486"
    "NetworkAnomaly" = "T1041"
    "Beacon" = "T1071"
    "DNSExfiltration" = "T1048"
    "Rootkit" = "T1014"
    "Clipboard" = "T1115"
    "ShadowCopy" = "T1490"
    "USB" = "T1052"
    "Webcam" = "T1125"
    "AttackTools" = "T1588"
    "AdvancedThreat" = "T1204"
    "EventLog" = "T1562.006"
    "FirewallRule" = "T1562.004"
    "Fileless" = "T1059"
    "MemoryScanning" = "T1003"
    "CodeInjection" = "T1055"
    "DataExfiltration" = "T1048"
    "FileEntropy" = "T1204"
    "Honeypot" = "T1204"
    "LateralMovement" = "T1021"
    "ProcessCreation" = "T1059"
    "YaraDetection" = "T1204"
    "IdsDetection" = "T1059"
}

function Map-ToMitre {
    $tech = $TechniqueMap[$DetectionSource]
    if ($tech) {
        $entry = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DetectionSource = $DetectionSource
            MITRETechnique = $tech
            Details = $Details
        }
        $logPath = "C:\ProgramData\GEDR\Logs\mitre_mapping_$(Get-Date -Format 'yyyy-MM-dd').log"
        "$($entry.Timestamp)|$($entry.DetectionSource)|$($entry.MITRETechnique)|$($entry.Details)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
        return $tech
    }
    return $null
}

function Start-Module {
    while ($true) {
        Start-Sleep -Seconds 60
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
# endregion

# region MobileDeviceMonitoring
# Mobile Device Monitoring
# Win32_PnPEntity for portable/USB/MTP devices


$ModuleName = "MobileDeviceMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$DeviceClasses = @("USB", "Bluetooth", "Image", "WPD", "PortableDevice", "MTP")
$KnownDevices = @{}

function Invoke-MobileDeviceScan {
    $newDevices = @()
    try {
        $devices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            foreach ($cls in $DeviceClasses) {
                if (($_.PNPClass -eq $cls) -or ($_.Service -like "*$cls*")) {
                    return $true
                }
            }
            return $false
        }
        
        foreach ($d in $devices) {
            $key = $d.DeviceID
            if (-not $script:KnownDevices.ContainsKey($key)) {
                $script:KnownDevices[$key] = $true
                $newDevices += @{
                    DeviceID = $d.DeviceID
                    Name = $d.Name
                    PNPClass = $d.PNPClass
                    Status = $d.Status
                }
            }
        }
        
        if ($newDevices.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\mobile_device_$(Get-Date -Format 'yyyy-MM-dd').log"
            foreach ($nd in $newDevices) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|New device|$($nd.Name)|$($nd.PNPClass)|$($nd.DeviceID)" | Add-Content -Path $logPath
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Information -EventId 2094 -Message "MOBILE DEVICE: $($nd.Name) - $($nd.PNPClass)" -ErrorAction SilentlyContinue
            }
            Write-Output "STATS:$ModuleName`:Logged $($newDevices.Count) new mobile/USB devices"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-MobileDeviceScan
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
# endregion

# region NamedPipeMonitoring
# Named Pipe Monitoring Module
# Monitors named pipes for malicious activity


$ModuleName = "NamedPipeMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-NamedPipeMonitoring {
    $detections = @()
    
    try {
        # Get named pipes using WMI
        $pipes = Get-CimInstance Win32_NamedPipe -ErrorAction SilentlyContinue
        
        # Check for suspicious named pipes
        $suspiciousPatterns = @(
            "paexec",
            "svchost",
            "lsass",
            "spoolsv",
            "psexec",
            "mimikatz",
            "impacket"
        )
        
        foreach ($pipe in $pipes) {
            $pipeNameLower = $pipe.Name.ToLower()
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($pipeNameLower -match $pattern) {
                    $detections += @{
                        PipeName = $pipe.Name
                        Pattern = $pattern
                        Type = "Suspicious Named Pipe Pattern"
                        Risk = "Medium"
                    }
                    break
                }
            }
            
            # Check for pipes with unusual names (random characters)
            if ($pipe.Name -match '^[A-Za-z0-9]{32,}$' -and 
                $pipe.Name -notmatch 'microsoft|windows|system') {
                $detections += @{
                    PipeName = $pipe.Name
                    Type = "Named Pipe with Random-Like Name"
                    Risk = "Low"
                }
            }
        }
        
        # Check for processes creating named pipes
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPipes = $pipes | Where-Object {
                        $_.Instances -gt 0
                    }
                    
                    # Check for processes creating many named pipes
                    $pipeCount = ($procPipes | Measure-Object).Count
                    
                    if ($pipeCount -gt 10 -and 
                        $proc.ProcessName -notin @("svchost.exe", "spoolsv.exe", "services.exe")) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            PipeCount = $pipeCount
                            Type = "Process Creating Many Named Pipes"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for named pipe errors
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { 
                    $_.Message -match 'named.*pipe|pipe.*error|pipe.*failed'
                }
            
            $pipeErrors = $events | Where-Object {
                $_.LevelDisplayName -eq "Error"
            }
            
            if ($pipeErrors.Count -gt 5) {
                $detections += @{
                    EventCount = $pipeErrors.Count
                    Type = "Excessive Named Pipe Errors"
                    Risk = "Low"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Information -EventId 2028 `
                    -Message "NAMED PIPE MONITORING: $($detection.Type) - $($detection.PipeName -or $detection.ProcessName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\NamedPipe_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.PipeName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) named pipe anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Active pipes=$($pipes.Count)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-NamedPipeMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region NetworkAnomalyDetection
# Network Anomaly Detection Module
# Detects unusual network activity


$ModuleName = "NetworkAnomalyDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$BaselineConnections = @{}

function Initialize-NetworkBaseline {
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $connections) {
            $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $BaselineConnections.ContainsKey($key)) {
                $BaselineConnections[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                }
            }
            $BaselineConnections[$key].Count++
        }
    } catch { }
}

function Invoke-NetworkAnomalyScan {
    $detections = @()
    
    try {
        # Get current network connections
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
        # Check for unusual destinations
        $suspiciousIPs = @()
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 8080, 8443)
        
        foreach ($conn in $connections) {
            # Check for suspicious ports
            if ($conn.RemotePort -in $suspiciousPorts) {
                $detections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    Type = "Suspicious Port"
                    Risk = "High"
                }
            }
            
            # Check for connections to known bad IPs
            if ($conn.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                # Private IP - check if it's unusual
                $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
                if (-not $BaselineConnections.ContainsKey($key)) {
                    $detections += @{
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        Type = "New Connection to Private IP"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        # Check for processes with unusual network activity
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procConnections = $connections | Where-Object {
                        $owner = (Get-NetTCPConnection -OwningProcess $proc.ProcessId -ErrorAction SilentlyContinue)
                        $owner.Count -gt 0
                    }
                    
                    if ($procConnections.Count -gt 50) {
                        # High number of connections
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ConnectionCount = $procConnections.Count
                            Type = "High Network Activity"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for DNS queries to suspicious domains
        try {
            $dnsQueries = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008} -ErrorAction SilentlyContinue -MaxEvents 100
            
            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin.com", "githubusercontent.com")
            foreach ($event in $dnsQueries) {
                $message = $event.Message
                foreach ($domain in $suspiciousDomains) {
                    if ($message -like "*$domain*") {
                        $detections += @{
                            EventId = $event.Id
                            Message = $message
                            Type = "Suspicious DNS Query"
                            Domain = $domain
                            Risk = "Medium"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for unusual data transfer
        try {
            $netStats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
            foreach ($adapter in $netStats) {
                if ($adapter.SentBytes -gt 1GB -or $adapter.ReceivedBytes -gt 1GB) {
                    # High data transfer
                    $timeSpan = (Get-Date) - $LastTick
                    if ($timeSpan.TotalSeconds -gt 0) {
                        $bytesPerSec = $adapter.SentBytes / $timeSpan.TotalSeconds
                        if ($bytesPerSec -gt 10MB) {
                            $detections += @{
                                Adapter = $adapter.Name
                                SentBytes = $adapter.SentBytes
                                ReceivedBytes = $adapter.ReceivedBytes
                                Type = "High Data Transfer Rate"
                                Risk = "Medium"
                            }
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2015 `
                    -Message "NETWORK ANOMALY: $($detection.Type) - $($detection.ProcessName -or $detection.RemoteAddress -or $detection.Adapter)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\NetworkAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.RemoteAddress)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) network anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    Initialize-NetworkBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-NetworkAnomalyScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region NetworkTrafficMonitoring
# Optimized Network Traffic Monitoring Module
# Reduced polling and caching of connection state



$ModuleName = "NetworkTrafficMonitoring"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:ConnectionCache = @{}
$script:KnownGoodConnections = @{}

function Invoke-NetworkTrafficMonitoringOptimized {
    $detections = @()
    $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
    $batchSettings = Get-BatchSettings
    
    try {
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" } |
            Select-Object -First $maxConnections
        
        $batchCount = 0
        foreach ($conn in $tcpConnections) {
            $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
            
            if ($script:KnownGoodConnections.ContainsKey($key)) {
                continue
            }
            
            $batchCount++
            if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
            }
            
            # Check for suspicious patterns (simplified checks)
            $isPrivate = $conn.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)'
            
            if (-not $isPrivate) {
                # Connection to public IP on ephemeral port
                if ($conn.RemotePort -gt 49152) {
                    $detections += @{
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        Type = "Connection to Public Ephemeral Port"
                        Risk = "Low"
                    }
                }
            } else {
                $script:KnownGoodConnections[$key] = $true
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\NetworkTraffic_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RemoteAddress):$($_.RemotePort)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) traffic anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Active connections=$($tcpConnections.Count)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-NetworkTrafficMonitoringOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region PasswordManagement
# Password Management Module
# Monitors password policies and storage


$ModuleName = "PasswordManagement"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }

function Invoke-PasswordManagement {
    $detections = @()
    
    try {
        # Check password policy
        try {
            $passwordPolicy = Get-LocalUser | ForEach-Object {
                $_.PasswordNeverExpires
            }
            
            $expiredPasswords = $passwordPolicy | Where-Object { $_ -eq $true }
            
            if ($expiredPasswords.Count -gt 0) {
                $detections += @{
                    ExpiredPasswordCount = $expiredPasswords.Count
                    Type = "Accounts with Non-Expiring Passwords"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for weak passwords (indirectly through failed logon attempts)
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue -MaxEvents 100
            
            $failedLogons = $securityEvents | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(24)
            }
            
            if ($failedLogons.Count -gt 50) {
                $detections += @{
                    FailedLogonCount = $failedLogons.Count
                    Type = "Excessive Failed Logon Attempts - Possible Weak Passwords"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for password storage in plain text
        try {
            $searchPaths = @(
                "$env:USERPROFILE\Desktop",
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Downloads",
                "$env:TEMP"
            )
            
            $passwordFiles = @()
            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    try {
                        $files = Get-ChildItem -Path $path -Filter "*.txt","*.log","*.csv" -File -ErrorAction SilentlyContinue |
                            Select-Object -First 50
                        
                        foreach ($file in $files) {
                            try {
                                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                                if ($content -match '(?i)(password|pwd|passwd)\s*[:=]\s*\S+') {
                                    $passwordFiles += @{
                                        File = $file.FullName
                                        Type = "Plain Text Password Storage"
                                        Risk = "High"
                                    }
                                }
                            } catch { }
                        }
                    } catch { }
                }
            }
            
            $detections += $passwordFiles
        } catch { }
        
        # Check for credential dumping tools
        try {
            $credDumpTools = @("mimikatz", "lsadump", "pwdump", "fgdump", "hashdump")
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                foreach ($tool in $credDumpTools) {
                    if ($proc.ProcessName -like "*$tool*" -or 
                        $proc.Path -like "*$tool*") {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Tool = $tool
                            Type = "Credential Dumping Tool"
                            Risk = "Critical"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for SAM database access
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'SAM|SECURITY|SYSTEM' -and $_.Message -match 'Read|Write' }
            
            if ($securityEvents.Count -gt 0) {
                foreach ($event in $securityEvents) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        Message = $event.Message
                        Type = "SAM Database Access Attempt"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for LSA secrets access
        try {
            $lsaEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { $_.Message -match 'LSA|Local.*Security.*Authority' }
            
            if ($lsaEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $lsaEvents.Count
                    Type = "Excessive LSA Access Attempts"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2030 `
                    -Message "PASSWORD MANAGEMENT: $($detection.Type) - $($detection.ProcessName -or $detection.File -or $detection.Tool)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\PasswordManagement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) password management issues"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-PasswordManagement
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region PrivacyForgeSpoofing
<#
.SYNOPSIS
    PrivacyForge Spoofing - Identity and Fingerprint Spoofing Module
.DESCRIPTION
    Generates and rotates fake identity data to prevent browser fingerprinting
    and tracking. Spoofs software metadata, game telemetry, sensors, system
    metrics, and clipboard to create noise for trackers.
.NOTES
    Author: EDR System
    Requires: PowerShell 5.1+
    Interval: 60 seconds (default)
#>

#Requires -Version 5.1

# ===================== Configuration =====================

$Script:Config = @{
    BaseDir = "C:\ProgramData\GEDR"
    LogDir = "C:\ProgramData\GEDR\Logs"
    TickIntervalSeconds = 60
    RotationIntervalSeconds = 3600  # 1 hour
    DataThreshold = 50  # Rotate after this much simulated data collection
    EnableClipboardSpoofing = $false  # Disabled by default - can overwrite user clipboard
    EnableNetworkSpoofing = $true
    DebugMode = $false
}

# State variables
$Script:PrivacyForgeIdentity = @{}
$Script:PrivacyForgeDataCollected = 0
$Script:PrivacyForgeLastRotation = $null

# ===================== Logging =====================

function Write-AVLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "DETECTION")]
        [string]$Level = "INFO"
    )
    
    if ($Level -eq "DEBUG" -and -not $Script:Config.DebugMode) { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [PrivacyForge] $Message"
    
    # Ensure log directory exists
    if (-not (Test-Path $Script:Config.LogDir)) {
        New-Item -ItemType Directory -Path $Script:Config.LogDir -Force | Out-Null
    }
    
    $logFile = Join-Path $Script:Config.LogDir "PrivacyForge_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Console output with color
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "DETECTION" { "Magenta" }
        "DEBUG" { "Gray" }
        default { "White" }
    }
    Write-Host $logMessage -ForegroundColor $color
}

# ===================== Identity Generation =====================

function Invoke-PrivacyForgeGenerateIdentity {
    <#
    .SYNOPSIS
    Generates a fake identity profile for spoofing purposes
    #>
    
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Jessica", 
                    "Robert", "Amanda", "William", "Ashley", "Richard", "Melissa", "Joseph", "Nicole",
                    "Thomas", "Jennifer", "Charles", "Elizabeth", "Christopher", "Samantha", "Daniel", "Rebecca")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", 
                   "Rodriguez", "Martinez", "Hernandez", "Lopez", "Wilson", "Anderson", "Thomas", "Taylor",
                   "Moore", "Jackson", "Martin", "Lee", "Thompson", "White", "Harris", "Clark")
    $domains = @("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "icloud.com", "aol.com")
    $cities = @("New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", 
                "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
                "Fort Worth", "Columbus", "Charlotte", "Seattle", "Denver", "Boston")
    $countries = @("United States", "Canada", "United Kingdom", "Australia", "Germany", "France", "Spain", "Italy", "Netherlands", "Sweden")
    $languages = @("en-US", "en-GB", "fr-FR", "es-ES", "de-DE", "it-IT", "pt-BR", "nl-NL", "sv-SE")
    $interests = @("tech", "gaming", "news", "sports", "music", "movies", "travel", "food", 
                   "fitness", "books", "photography", "cooking", "art", "science", "finance")
    
    $firstName = Get-Random -InputObject $firstNames
    $lastName = Get-Random -InputObject $lastNames
    $username = "$firstName$lastName" + (Get-Random -Minimum 100 -Maximum 9999)
    $domain = Get-Random -InputObject $domains
    $email = "$username@$domain".ToLower()
    
    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    
    $resolutions = @("1920x1080", "2560x1440", "1366x768", "1536x864", "1440x900", "1280x720", "3840x2160")
    
    return @{
        "name" = "$firstName $lastName"
        "email" = $email
        "username" = $username
        "location" = Get-Random -InputObject $cities
        "country" = Get-Random -InputObject $countries
        "user_agent" = Get-Random -InputObject $userAgents
        "screen_resolution" = Get-Random -InputObject $resolutions
        "interests" = (Get-Random -InputObject $interests -Count 4)
        "device_id" = [System.Guid]::NewGuid().ToString()
        "mac_address" = "{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}" -f `
            (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), `
            (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256), `
            (Get-Random -Minimum 0 -Maximum 256), (Get-Random -Minimum 0 -Maximum 256)
        "language" = Get-Random -InputObject $languages
        "timezone" = (Get-TimeZone).Id
        "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        "canvas_hash" = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        "webgl_vendor" = Get-Random -InputObject @("Google Inc.", "Intel Inc.", "NVIDIA Corporation", "AMD")
        "webgl_renderer" = Get-Random -InputObject @("ANGLE (Intel, Intel(R) UHD Graphics 630)", "ANGLE (NVIDIA, GeForce GTX 1080)", "ANGLE (AMD, Radeon RX 580)")
        "platform" = Get-Random -InputObject @("Win32", "Win64", "MacIntel", "Linux x86_64")
        "cpu_cores" = Get-Random -InputObject @(4, 6, 8, 12, 16)
        "memory_gb" = Get-Random -InputObject @(8, 16, 32, 64)
    }
}

function Invoke-PrivacyForgeRotateIdentity {
    <#
    .SYNOPSIS
    Rotates to a new fake identity
    #>
    
    $Script:PrivacyForgeIdentity = Invoke-PrivacyForgeGenerateIdentity
    $Script:PrivacyForgeDataCollected = 0
    $Script:PrivacyForgeLastRotation = Get-Date
    
    Write-AVLog "Identity rotated - Name: $($Script:PrivacyForgeIdentity.name), Username: $($Script:PrivacyForgeIdentity.username)" "INFO"
}

# ===================== Spoofing Functions =====================

function Invoke-PrivacyForgeSpoofSoftwareMetadata {
    <#
    .SYNOPSIS
    Sends spoofed HTTP headers to confuse trackers
    #>
    
    if (-not $Script:Config.EnableNetworkSpoofing) { return }
    
    try {
        $headers = @{
            "User-Agent" = $Script:PrivacyForgeIdentity.user_agent
            "Cookie" = "session_id=$(Get-Random -Minimum 1000 -Maximum 9999); fake_id=$([System.Guid]::NewGuid().ToString())"
            "X-Device-ID" = $Script:PrivacyForgeIdentity.device_id
            "Accept-Language" = $Script:PrivacyForgeIdentity.language
            "X-Timezone" = $Script:PrivacyForgeIdentity.timezone
            "X-Screen-Resolution" = $Script:PrivacyForgeIdentity.screen_resolution
        }
        
        # Send to a test endpoint (non-blocking, fire and forget)
        $null = Start-Job -ScriptBlock {
            try {
                Invoke-WebRequest -Uri "https://httpbin.org/headers" -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
            } catch {}
        } -ArgumentList $headers
        
        Write-AVLog "Sent spoofed software metadata headers" "DEBUG"
    } catch {
        Write-AVLog "Error spoofing software metadata - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofGameTelemetry {
    <#
    .SYNOPSIS
    Generates fake game telemetry data
    #>
    
    try {
        $fakeTelemetry = @{
            "player_id" = [System.Guid]::NewGuid().ToString()
            "hardware_id" = -join ((1..32) | ForEach-Object { '{0:X}' -f (Get-Random -Maximum 16) })
            "latency" = Get-Random -Minimum 20 -Maximum 200
            "game_version" = "$(Get-Random -Minimum 1 -Maximum 5).$(Get-Random -Minimum 0 -Maximum 9).$(Get-Random -Minimum 0 -Maximum 99)"
            "fps" = Get-Random -Minimum 30 -Maximum 144
            "session_id" = [System.Guid]::NewGuid().ToString()
            "playtime_minutes" = Get-Random -Minimum 10 -Maximum 500
        }
        
        Write-AVLog "Spoofed game telemetry - Player ID: $($fakeTelemetry.player_id)" "DEBUG"
    } catch {
        Write-AVLog "Error spoofing game telemetry - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSensors {
    <#
    .SYNOPSIS
    Generates random sensor data to confuse fingerprinting
    #>
    
    try {
        $sensorData = @{
            "accelerometer" = @{
                "x" = [math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100.0, 2)
                "y" = [math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100.0, 2)
                "z" = [math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100.0, 2)
            }
            "gyroscope" = @{
                "pitch" = [math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100.0, 2)
                "roll" = [math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100.0, 2)
                "yaw" = [math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100.0, 2)
            }
            "magnetometer" = @{
                "x" = [math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100.0, 2)
                "y" = [math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100.0, 2)
                "z" = [math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100.0, 2)
            }
            "light_sensor" = Get-Random -Minimum 0 -Maximum 1000
            "proximity_sensor" = Get-Random -InputObject @(0, 5, 10)
            "ambient_temperature" = [math]::Round((Get-Random -Minimum 1500 -Maximum 3500) / 100.0, 1)
            "battery_temperature" = [math]::Round((Get-Random -Minimum 2000 -Maximum 4000) / 100.0, 1)
        }
        
        Write-AVLog "Spoofed sensor data" "DEBUG"
    } catch {
        Write-AVLog "Error spoofing sensors - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofSystemMetrics {
    <#
    .SYNOPSIS
    Generates fake system performance metrics
    #>
    
    try {
        $fakeMetrics = @{
            "cpu_usage" = [math]::Round((Get-Random -Minimum 500 -Maximum 5000) / 100.0, 1)
            "memory_usage" = [math]::Round((Get-Random -Minimum 3000 -Maximum 8500) / 100.0, 1)
            "battery_level" = Get-Random -Minimum 20 -Maximum 100
            "charging" = (Get-Random -InputObject @($true, $false))
            "disk_usage" = [math]::Round((Get-Random -Minimum 2000 -Maximum 9000) / 100.0, 1)
            "network_latency" = Get-Random -Minimum 5 -Maximum 150
            "uptime_hours" = Get-Random -Minimum 1 -Maximum 720
        }
        
        Write-AVLog "Spoofed system metrics - CPU: $($fakeMetrics.cpu_usage)%, Memory: $($fakeMetrics.memory_usage)%" "DEBUG"
    } catch {
        Write-AVLog "Error spoofing system metrics - $_" "WARN"
    }
}

function Invoke-PrivacyForgeSpoofClipboard {
    <#
    .SYNOPSIS
    Overwrites clipboard with fake data (disabled by default)
    #>
    
    if (-not $Script:Config.EnableClipboardSpoofing) { return }
    
    try {
        $fakeContent = "PrivacyForge: $(Get-Random -Minimum 100000 -Maximum 999999) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Set-Clipboard -Value $fakeContent -ErrorAction SilentlyContinue
        Write-AVLog "Spoofed clipboard content" "DEBUG"
    } catch {
        Write-AVLog "Error spoofing clipboard - $_" "WARN"
    }
}

# ===================== Main Detection Function =====================

function Invoke-PrivacyForgeSpoofing {
    <#
    .SYNOPSIS
    Main spoofing tick function - manages identity rotation and spoofing operations
    #>
    
    # Initialize on first run
    if (-not $Script:PrivacyForgeLastRotation) {
        $Script:PrivacyForgeLastRotation = Get-Date
        Invoke-PrivacyForgeRotateIdentity
    }
    
    try {
        # Check if rotation is needed
        $timeSinceRotation = (Get-Date) - $Script:PrivacyForgeLastRotation
        $shouldRotate = $false
        
        if ($timeSinceRotation.TotalSeconds -ge $Script:Config.RotationIntervalSeconds) {
            $shouldRotate = $true
            Write-AVLog "Time-based rotation triggered" "INFO"
        }
        
        if ($Script:PrivacyForgeDataCollected -ge $Script:Config.DataThreshold) {
            $shouldRotate = $true
            Write-AVLog "Data threshold reached ($Script:PrivacyForgeDataCollected/$($Script:Config.DataThreshold))" "INFO"
        }
        
        if ($shouldRotate -or (-not $Script:PrivacyForgeIdentity.ContainsKey("name"))) {
            Invoke-PrivacyForgeRotateIdentity
        }
        
        # Simulate data collection increment
        $Script:PrivacyForgeDataCollected += Get-Random -Minimum 1 -Maximum 6
        
        # Perform spoofing operations
        Invoke-PrivacyForgeSpoofSoftwareMetadata
        Invoke-PrivacyForgeSpoofGameTelemetry
        Invoke-PrivacyForgeSpoofSensors
        Invoke-PrivacyForgeSpoofSystemMetrics
        Invoke-PrivacyForgeSpoofClipboard
        
        Write-AVLog "Spoofing active - Data collected: $Script:PrivacyForgeDataCollected/$($Script:Config.DataThreshold)" "INFO"
        
    } catch {
        Write-AVLog "Error in main spoofing loop - $_" "ERROR"
    }
}

# ===================== Main Loop =====================

Write-AVLog "========================================" "INFO"
Write-AVLog "PrivacyForge Spoofing Module Starting" "INFO"
Write-AVLog "Tick Interval: $($Script:Config.TickIntervalSeconds)s" "INFO"
Write-AVLog "Rotation Interval: $($Script:Config.RotationIntervalSeconds)s" "INFO"
Write-AVLog "Data Threshold: $($Script:Config.DataThreshold)" "INFO"
Write-AVLog "Clipboard Spoofing: $($Script:Config.EnableClipboardSpoofing)" "INFO"
Write-AVLog "Network Spoofing: $($Script:Config.EnableNetworkSpoofing)" "INFO"
Write-AVLog "========================================" "INFO"

# Initial identity generation
Invoke-PrivacyForgeRotateIdentity

while ($true) {
    try {
        Invoke-PrivacyForgeSpoofing
    } catch {
        Write-AVLog "Unhandled error: $_" "ERROR"
    }
    
    Start-Sleep -Seconds $Script:Config.TickIntervalSeconds
}
# endregion

# region ProcessAnomalyDetection
# Optimized Process Anomaly Detection Module
# Reduced resource usage with baseline caching



$ModuleName = "ProcessAnomalyDetection"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:BaselineProcesses = @{}
$script:KnownGoodProcesses = @{}

function Initialize-BaselineOptimized {
    if ($script:BaselineProcesses.Count -gt 0) {
        return
    }
    
    try {
        $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
        
        $processes = Get-Process -ErrorAction SilentlyContinue | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $key = $proc.ProcessName
            if (-not $script:BaselineProcesses.ContainsKey($key)) {
                $script:BaselineProcesses[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                }
            }
            $script:BaselineProcesses[$key].Count++
        }
    } catch { }
}

function Test-ProcessAnomalyOptimized {
    
    $anomalies = @()
    
    if ($script:KnownGoodProcesses.ContainsKey($Process.ProcessName)) {
        return $anomalies
    }
    
    if ($Process.Path) {
        $systemPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
        foreach ($sysPath in $systemPaths) {
            if ($Process.Path -like "$sysPath\*") {
                try {
                    $sig = Get-CachedSignature -FilePath $Process.Path
                    if ($sig -and $sig.Status -ne "Valid") {
                        $anomalies += "Unsigned executable in system directory"
                    } elseif ($sig -and $sig.Status -eq "Valid") {
                        $script:KnownGoodProcesses[$Process.ProcessName] = $true
                    }
                } catch { }
            }
        }
    }
    
    return $anomalies
}

function Invoke-ProcessAnomalyScanOptimized {
    $detections = @()
    $batchSettings = Get-BatchSettings
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        Initialize-BaselineOptimized
        
        $processes = Get-Process -ErrorAction SilentlyContinue | 
            Where-Object { $_.Path } |
            Select-Object -First $maxProcs
        
        $batchCount = 0
        foreach ($proc in $processes) {
            if ($script:KnownGoodProcesses.ContainsKey($proc.ProcessName)) {
                continue
            }
            
            $batchCount++
            if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
            }
            
            $anomalies = Test-ProcessAnomalyOptimized -Process $proc
            if ($anomalies.Count -gt 0) {
                $detections += @{
                    ProcessId = $proc.Id
                    ProcessName = $proc.ProcessName
                    Path = $proc.Path
                    Anomalies = $anomalies
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "C:\ProgramData\GEDR\Logs\ProcessAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Anomalies -join ';')" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    Clear-ExpiredCache
    return $detections.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ProcessAnomalyScanOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region ProcessCreationDetection
# Process Creation Detection Module
# Detects WMI-based process creation blocking and suspicious process creation patterns


$ModuleName = "ProcessCreationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

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
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2035 `
                    -Message "PROCESS CREATION: $($detection.Type) - $($detection.ProcessName -or $detection.FilterName -or $detection.ParentProcessName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.FilterName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process creation anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ProcessCreationDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region ProcessHollowingDetection
# Process Hollowing Detection Module
# Detects process hollowing attacks


$ModuleName = "ProcessHollowingDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-ProcessHollowingScan {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $procPath = $procObj.Path
                $imgPath = $proc.ExecutablePath
                
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
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2011 `
                    -Message "PROCESS HOLLOWING: $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.Type)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process hollowing indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ProcessHollowingScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region QuarantineManagement
# Quarantine Management Module
# Manages file quarantine operations and tracks quarantined files


$ModuleName = "QuarantineManagement"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }
$QuarantinePath = "C:\ProgramData\GEDR\Quarantine"

function Initialize-Quarantine {
    try {
        if (-not (Test-Path $QuarantinePath)) {
            New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null
        }
        
        # Create quarantine log
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        if (-not (Test-Path $quarantineLog)) {
            "Timestamp|FilePath|QuarantinePath|Reason|FileHash" | Add-Content -Path $quarantineLog
        }
        
        return $true
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to initialize quarantine: $_"
        return $false
    }
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason = "Threat Detected",
        [string]$Source = "Unknown"
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Output "ERROR:$ModuleName`:File not found: $FilePath"
            return $false
        }
        
        $fileName = Split-Path -Leaf $FilePath
        $fileDir = Split-Path -Parent $FilePath
        $fileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $fileExt = [System.IO.Path]::GetExtension($fileName)
        
        # Generate unique quarantine filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $quarantineFileName = "${fileBaseName}_${timestamp}${fileExt}"
        $quarantineFilePath = Join-Path $QuarantinePath $quarantineFileName
        
        # Calculate file hash before moving
        $fileHash = $null
        try {
            $hashObj = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            $fileHash = $hashObj.Hash
        } catch { }
        
        # Move file to quarantine
        Move-Item -Path $FilePath -Destination $quarantineFilePath -Force -ErrorAction Stop
        
        # Log quarantine action
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$FilePath|$quarantineFilePath|$Reason|$fileHash"
        Add-Content -Path $quarantineLog -Value $logEntry
        
        # Write Event Log
        Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2034 `
            -Message "QUARANTINE: File quarantined: $fileName - Reason: $Reason - Source: $Source"
        
        Write-Output "STATS:$ModuleName`:File quarantined: $fileName"
        return $true
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to quarantine $FilePath`: $_"
        return $false
    }
}

function Invoke-QuarantineManagement {
    $stats = @{
        QuarantinedFiles = 0
        QuarantineSize = 0
        OldFiles = 0
    }
    
    try {
        # Initialize quarantine if needed
        if (-not (Test-Path $QuarantinePath)) {
            Initialize-Quarantine
        }
        
        # Check quarantine status
        if (Test-Path $QuarantinePath) {
            $quarantinedFiles = Get-ChildItem -Path $QuarantinePath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "quarantine_log.txt" }
            
            $stats.QuarantinedFiles = $quarantinedFiles.Count
            
            # Calculate total quarantine size
            foreach ($file in $quarantinedFiles) {
                $stats.QuarantineSize += $file.Length
            }
            
            # Check for old quarantined files (older than 90 days)
            $cutoffDate = (Get-Date).AddDays(-90)
            $oldFiles = $quarantinedFiles | Where-Object { $_.LastWriteTime -lt $cutoffDate }
            $stats.OldFiles = $oldFiles.Count
            
            # Optionally remove old files
            if ($stats.OldFiles -gt 0 -and $stats.QuarantineSize -gt 1GB) {
                foreach ($oldFile in $oldFiles) {
                    try {
                        Remove-Item -Path $oldFile.FullName -Force -ErrorAction SilentlyContinue
                        Write-Output "STATS:$ModuleName`:Removed old quarantined file: $($oldFile.Name)"
                    } catch { }
                }
            }
        }
        
        # Check quarantine log integrity
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        if (Test-Path $quarantineLog) {
            $logEntries = Get-Content -Path $quarantineLog -ErrorAction SilentlyContinue
            if ($logEntries.Count -gt 10000) {
                # Archive old log entries
                $archivePath = Join-Path $QuarantinePath "quarantine_log_$(Get-Date -Format 'yyyy-MM-dd').txt"
                Copy-Item -Path $quarantineLog -Destination $archivePath -ErrorAction SilentlyContinue
                "Timestamp|FilePath|QuarantinePath|Reason|FileHash" | Set-Content -Path $quarantineLog
            }
        }
        
        Write-Output "STATS:$ModuleName`:Quarantined=$($stats.QuarantinedFiles), Size=$([Math]::Round($stats.QuarantineSize/1MB, 2))MB, Old=$($stats.OldFiles)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $stats
}

function Start-Module {
    
    Initialize-Quarantine
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $stats = Invoke-QuarantineManagement
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

# Export quarantine function for use by other modules
if ($ModuleConfig) {
    $ModuleConfig.QuarantineFunction = ${function:Invoke-QuarantineFile}
}
}
# endregion

# region RansomwareDetection
# Ransomware Detection Module
# Detects ransomware encryption patterns


$ModuleName = "RansomwareDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 15 }

function Invoke-RansomwareScan {
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
        
        # Check for processes with high file I/O
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
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
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2014 `
                    -Message "RANSOMWARE DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.File -or $detection.EncryptedFiles)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File -or $_.EncryptedFiles)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) ransomware indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-RansomwareScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region RealTimeFileMonitor
# Real-Time File Monitor
# FileSystemWatcher for exe/dll/sys/winmd on fixed and removable drives


$ModuleName = "RealTimeFileMonitor"
$Watchers = @()

function Start-RealtimeMonitor {
    $extensions = @("*.exe", "*.dll", "*.sys", "*.winmd")
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    
    foreach ($drive in $drives) {
        $root = $drive.Root
        if (-not (Test-Path $root)) { continue }
        
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            
            $action = {
                $path = $Event.SourceEventArgs.FullPath
                $ext = [System.IO.Path]::GetExtension($path).ToLower()
                if ($ext -in @(".exe", ".dll", ".sys", ".winmd")) {
                    Start-Sleep -Seconds 1
                    if (Test-Path $path) {
                        try {
                            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            $logPath = "C:\ProgramData\GEDR\Logs\realtime_monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
                            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Created/Changed|$path|$hash" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
                            Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2090 -Message "REAL-TIME: $path" -ErrorAction SilentlyContinue
                        } catch { }
                    }
                }
            }
            
            Register-ObjectEvent $watcher Created -Action $action | Out-Null
            Register-ObjectEvent $watcher Changed -Action $action | Out-Null
            $watcher.EnableRaisingEvents = $true
            $script:Watchers += $watcher
            Write-Output "STATS:$ModuleName`:Watching $root"
        } catch {
            Write-Output "ERROR:$ModuleName`:Failed to watch $root - $_"
        }
    }
    
    Write-Output "STATS:$ModuleName`:Started with $($script:Watchers.Count) watchers"
}
# endregion

# region ReflectiveDLLInjectionDetection
# Reflective DLL Injection Detection Module
# Detects reflective DLL injection and memory-only DLLs


$ModuleName = "ReflectiveDLLInjectionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        # Check for processes with memory-only DLLs (reflective injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                
                # Check for DLLs that don't exist on disk (reflective injection)
                $memoryOnlyDlls = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName)
                }
                
                if ($memoryOnlyDlls.Count -gt 0) {
                    foreach ($dll in $memoryOnlyDlls) {
                        # Exclude known legitimate cases
                        if ($dll.ModuleName -in @("kernel32.dll", "ntdll.dll", "user32.dll")) {
                            continue
                        }
                        
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllName = $dll.ModuleName
                            BaseAddress = $dll.BaseAddress.ToString()
                            DllPath = $dll.FileName
                            Type = "Memory-Only DLL (Reflective Injection)"
                            Risk = "Critical"
                        }
                    }
                }
                
                # Check for unusual DLL base addresses (heap-based injection)
                $unusualAddresses = $modules | Where-Object {
                    $addr = [Int64]$_.BaseAddress
                    # DLLs loaded at unusual addresses (not typical image base)
                    ($addr -lt 0x400000 -or $addr -gt 0x7FFFFFFF0000) -and
                    $_.FileName -like "*.dll"
                }
                
                if ($unusualAddresses.Count -gt 3) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualAddressCount = $unusualAddresses.Count
                        Type = "DLLs at Unusual Memory Addresses"
                        Risk = "High"
                    }
                }
                
                # Check for processes with many unsigned DLLs in memory
                $unsignedInMemory = 0
                foreach ($mod in $modules) {
                    if ($mod.FileName -like "*.dll" -and (Test-Path $mod.FileName)) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $mod.FileName -notlike "$env:SystemRoot\*") {
                                $unsignedInMemory++
                            }
                        } catch { }
                    }
                }
                
                if ($unsignedInMemory -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnsignedDllCount = $unsignedInMemory
                        Type = "Many Unsigned DLLs in Memory"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using reflective loading APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for reflective loading patterns in command line
                    if ($proc.CommandLine -match 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress' -or
                        $proc.CommandLine -match 'reflective|manual.*map|pe.*injection') {
                        
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            CommandLine = $proc.CommandLine
                            Type = "Process Using Reflective Loading APIs"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for hollowed processes (related to reflective injection)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    $procPath = $procObj.Path
                    $imgPath = $proc.ExecutablePath
                    
                    # Check for path mismatch (process hollowing often uses reflective injection)
                    if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ProcessPath = $procPath
                            ImagePath = $imgPath
                            Type = "Process Hollowing with Reflective Injection"
                            Risk = "Critical"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for DLL load failures (may indicate injection attempts)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'DLL.*not.*found|DLL.*load.*failed|reflective'
                }
            
            if ($events.Count -gt 10) {
                $detections += @{
                    EventCount = $events.Count
                    Type = "Excessive DLL Load Failures (Possible Injection Attempts)"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2036 `
                    -Message "REFLECTIVE DLL INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ReflectiveDLL_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName -or $_.BaseAddress)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) reflective DLL injection indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ReflectiveDLLInjectionDetection
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region RegistryPersistenceDetection
# Registry Persistence Detection Module
# Detects malicious registry-based persistence


$ModuleName = "RegistryPersistenceDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

function Test-SuspiciousRegistryValue {
    
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    
    $valueLower = $Value.ToLower()
    
    # Check for suspicious patterns
    $suspiciousPatterns = @(
        'powershell.*-encodedcommand',
        'powershell.*-nop.*-w.*hidden',
        'cmd.*\/c.*powershell',
        'wscript.*http',
        'cscript.*http',
        'rundll32.*javascript',
        'mshta.*http',
        'certutil.*urlcache',
        'bitsadmin.*transfer',
        'regsvr32.*http',
        '\.exe.*http',
        '\.dll.*http'
    )
    
    foreach ($pattern in $suspiciousPatterns) {
        if ($valueLower -match $pattern) {
            return $true
        }
    }
    
    # Check for suspicious file locations
    if ($valueLower -match '\$env:' -and 
        ($valueLower -match 'temp|appdata|local' -or 
         $valueLower -notmatch '^[A-Z]:\\')) {
        return $true
    }
    
    # Check for unsigned executables
    if ($valueLower -like '*.exe' -or $valueLower -like '*.dll') {
        $filePath = $valueLower -replace '"', '' -split ' ' | Select-Object -First 1
        if ($filePath -and (Test-Path $filePath)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    return $true
                }
            } catch { }
        }
    }
    
    return $false
}

function Invoke-RegistryPersistenceScan {
    $detections = @()
    
    try {
        foreach ($regPath in $PersistenceKeys) {
            if (-not (Test-Path $regPath)) { continue }
            
            try {
                $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($values) {
                    $valueProps = $values.PSObject.Properties | Where-Object { 
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                    }
                    
                    foreach ($prop in $valueProps) {
                        $regValue = $prop.Value
                        $regName = $prop.Name
                        
                        if (Test-SuspiciousRegistryValue -Value $regValue) {
                            $detections += @{
                                RegistryPath = $regPath
                                ValueName = $regName
                                Value = $regValue
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch { }
        }
        
        # Check for suspicious service entries
        try {
            $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.PathName -match 'powershell|cmd|wscript|cscript|http' -or
                    $_.StartName -eq 'LocalSystem' -and $_.PathName -notmatch '^[A-Z]:\\Windows'
                }
            
            foreach ($svc in $services) {
                if (Test-SuspiciousRegistryValue -Value $svc.PathName) {
                    $detections += @{
                        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
                        ValueName = "ImagePath"
                        Value = $svc.PathName
                        ServiceName = $svc.Name
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2008 `
                    -Message "REGISTRY PERSISTENCE: $($detection.RegistryPath)\$($detection.ValueName) - $($detection.Value)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.RegistryPath)|$($_.ValueName)|$($_.Value)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) registry persistence mechanisms"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-RegistryPersistenceScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region ResponseEngine
# Response Engine Module
# Centralized response system for all detection modules - Optimized for low resource usage



$ModuleName = "ResponseEngine"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$ResponseQueue = @()
$ResponseActions = @{
    "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "Log")
    "High" = @("Quarantine", "Log", "Alert")
    "Medium" = @("Log", "Alert")
    "Low" = @("Log")
}
$ProcessedThreats = @{}

function Invoke-ResponseAction {
    param(
        [hashtable]$Detection,
        [string]$Severity
    )
    
    $actions = $ResponseActions[$Severity]
    if (-not $actions) {
        $actions = @("Log")
    }
    
    $results = @()
    
    foreach ($action in $actions) {
        try {
            switch ($action) {
                "Quarantine" {
                    if ($Detection.FilePath -or $Detection.DllPath) {
                        $filePath = $Detection.FilePath -or $Detection.DllPath
                        if (Test-Path $filePath) {
                            # Import quarantine function if available
                            $quarantineModule = Get-Module -Name "QuarantineManagement" -ErrorAction SilentlyContinue
                            if (-not $quarantineModule) {
                                # Load quarantine module
                                $quarantinePath = Join-Path $PSScriptRoot "QuarantineManagement.ps1"
                                if (Test-Path $quarantinePath) {
                                    . $quarantinePath
                                }
                            }
                            
                            # Call quarantine function
                            if (Get-Command -Name "Invoke-QuarantineFile" -ErrorAction SilentlyContinue) {
                                Invoke-QuarantineFile -FilePath $filePath -Reason "Threat Detected: $($Detection.Type)" -Source $Detection.ModuleName
                                $results += "Quarantined: $filePath"
                            }
                        }
                    }
                }
                
                "KillProcess" {
                    if ($Detection.ProcessId) {
                        try {
                            $proc = Get-Process -Id $Detection.ProcessId -ErrorAction Stop
                            Stop-Process -Id $Detection.ProcessId -Force -ErrorAction Stop
                            $results += "Killed process: $($proc.ProcessName) (PID: $Detection.ProcessId)"
                        } catch {
                            $results += "Failed to kill process PID: $Detection.ProcessId"
                        }
                    }
                }
                
                "BlockNetwork" {
                    if ($Detection.RemoteAddress -or $Detection.RemotePort) {
                        try {
                            # Block network connection using firewall
                            $remoteIP = $Detection.RemoteAddress
                            $remotePort = $Detection.RemotePort
                            
                            if ($remoteIP) {
                                $ruleName = "Block_Threat_$($remoteIP.Replace('.', '_'))"
                                $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                                
                                if (-not $existingRule) {
                                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue | Out-Null
                                    $results += "Blocked network to: $remoteIP"
                                }
                            }
                        } catch {
                            $results += "Failed to block network: $_"
                        }
                    }
                }
                
                "Alert" {
                    # Send alert (can be extended with email, SIEM, etc.)
                    $alertMsg = "ALERT: $($Detection.Type) - $($Detection.ProcessName -or $Detection.FilePath) - Severity: $Severity"
                    Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2100 `
                        -Message $alertMsg
                    $results += "Alert sent: $alertMsg"
                }
                
                "Log" {
                    # Already logged, but add to response log
                    $logPath = "C:\ProgramData\GEDR\Logs\ResponseEngine_$(Get-Date -Format 'yyyy-MM-dd').log"
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$Severity|$($Detection.Type)|$($Detection.ProcessName -or $Detection.FilePath)|$($Detection.ModuleName)"
                    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
                    $results += "Logged"
                }
            }
        } catch {
            $results += "Error in action $action`: $_"
        }
    }
    
    return $results
}

function Invoke-ResponseEngine {
    $responses = @()
    
    try {
        # Check all module detection logs for new threats
        $logPath = "C:\ProgramData\GEDR\Logs"
        if (Test-Path $logPath) {
            $today = Get-Date -Format 'yyyy-MM-dd'
            $logFiles = Get-ChildItem -Path $logPath -Filter "*_$today.log" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "ResponseEngine_$today.log" -and $_.Name -ne "GEDR_$today.log" }
            
            foreach ($logFile in $logFiles) {
                try {
                    $moduleName = $logFile.BaseName -replace "_$today", ""
                    $logEntries = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue | Select-Object -Last 50
                    
                    foreach ($entry in $logEntries) {
                        # Parse log entry (format: timestamp|type|risk|details)
                        if ($entry -match '\|') {
                            $parts = $entry -split '\|'
                            if ($parts.Length -ge 3) {
                                $timestamp = $parts[0]
                                $detectionType = $parts[1]
                                $risk = $parts[2]
                                $details = $parts[3..($parts.Length-1)] -join '|'
                                
                                # Create detection hash
                                $detectionHash = ($moduleName + $timestamp + $detectionType + $details).GetHashCode()
                                
                                # Skip if already processed
                                if ($ProcessedThreats.ContainsKey($detectionHash)) {
                                    continue
                                }
                                
                                # Determine severity from risk level
                                $severity = switch ($risk) {
                                    "Critical" { "Critical" }
                                    "High" { "High" }
                                    "Medium" { "Medium" }
                                    default { "Low" }
                                }
                                
                                # Create detection object
                                $detection = @{
                                    ModuleName = $moduleName
                                    Timestamp = $timestamp
                                    Type = $detectionType
                                    Risk = $risk
                                    Details = $details
                                    Severity = $severity
                                }
                                
                                # Extract ProcessId, FilePath, etc. from details
                                if ($details -match 'PID:(\d+)') {
                                    $detection.ProcessId = [int]$matches[1]
                                }
                                if ($details -match '(.+\.exe|.+\.dll)') {
                                    $detection.FilePath = $matches[1]
                                }
                                if ($details -match '(\d+\.\d+\.\d+\.\d+)') {
                                    $detection.RemoteAddress = $matches[1]
                                }
                                
                                # Execute response actions
                                $actionResults = Invoke-ResponseAction -Detection $detection -Severity $severity
                                
                                # Mark as processed
                                $ProcessedThreats[$detectionHash] = Get-Date
                                
                                $responses += @{
                                    Detection = $detection
                                    Actions = $actionResults
                                    Timestamp = Get-Date
                                }
                                
                                Write-Output "DETECTION:$ModuleName`:Processed $detectionType from $moduleName - Actions: $($actionResults -join ', ')"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        }
        
        # Cleanup old processed threats (older than 24 hours)
        $oldKeys = $ProcessedThreats.Keys | Where-Object {
            ((Get-Date) - $ProcessedThreats[$_]).TotalHours -gt 24
        }
        foreach ($key in $oldKeys) {
            $ProcessedThreats.Remove($key)
        }
        
        # Also check Event Log for detection events (2001-2100)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=2001..2099} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Source -eq "GEDR" -and
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
                }
            
            foreach ($event in $events) {
                $eventHash = ($event.Id.ToString() + $event.TimeCreated.ToString()).GetHashCode()
                
                if (-not $ProcessedThreats.ContainsKey($eventHash)) {
                    # Parse event message for detection info
                    $message = $event.Message
                    $severity = if ($event.EntryType -eq "Error") { "Critical" } 
                               elseif ($event.EntryType -eq "Warning") { "High" }
                               else { "Medium" }
                    
                    $detection = @{
                        ModuleName = "EventLog"
                        Timestamp = $event.TimeCreated.ToString()
                        Type = $message
                        Severity = $severity
                        EventId = $event.Id
                    }
                    
                    # Extract info from message
                    if ($message -match 'PID:\s*(\d+)') {
                        $detection.ProcessId = [int]$matches[1]
                    }
                    if ($message -match '(?:THREAT|DETECTED|FOUND):\s*(.+?)(?:\s*\||\s*-\s*|$)') {
                        $detection.Details = $matches[1]
                    }
                    
                    # Execute response for critical/high severity
                    if ($severity -in @("Critical", "High")) {
                        $actionResults = Invoke-ResponseAction -Detection $detection -Severity $severity
                        $responses += @{
                            Detection = $detection
                            Actions = $actionResults
                            Timestamp = Get-Date
                        }
                    }
                    
                    $ProcessedThreats[$eventHash] = Get-Date
                }
            }
        } catch { }
        
        if ($responses.Count -gt 0) {
            Write-Output "STATS:$ModuleName`:Processed $($responses.Count) threats"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $responses.Count
}

function Start-Module {
    
    $loopSleep = Get-LoopSleep
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ResponseEngine
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}
}
# endregion

# region RootkitDetection
# Rootkit Detection Module
# Detects rootkit installation and activity


$ModuleName = "RootkitDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-RootkitScan {
    $detections = @()
    
    try {
        # Check for hidden processes (rootkit indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        $cimProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
            Select-Object ProcessId, Name
        
        $processIds = $processes | ForEach-Object { $_.Id } | Sort-Object -Unique
        $cimProcessIds = $cimProcesses | ForEach-Object { $_.ProcessId } | Sort-Object -Unique
        
        $hiddenProcesses = Compare-Object -ReferenceObject $processIds -DifferenceObject $cimProcessIds
        
        if ($hiddenProcesses) {
            foreach ($hidden in $hiddenProcesses) {
                $detections += @{
                    ProcessId = $hidden.InputObject
                    Type = "Hidden Process Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Check for hidden files/directories
        try {
            $systemDirs = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
            
            foreach ($dir in $systemDirs) {
                if (Test-Path $dir) {
                    $files = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Attributes -match 'Hidden' -or $_.Attributes -match 'System' }
                    
                    $suspiciousFiles = $files | Where-Object {
                        $_.Name -match '^(\.|\.\.|sys|drv)' -or
                        $_.Extension -match '^\.(sys|drv|dll)$'
                    }
                    
                    if ($suspiciousFiles.Count -gt 10) {
                        $detections += @{
                            Directory = $dir
                            SuspiciousFiles = $suspiciousFiles.Count
                            Type = "Suspicious Hidden Files in System Directory"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for kernel drivers
        try {
            $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.State -eq "Running" -and
                    $_.PathName -notlike "$env:SystemRoot\*" -or
                    $_.Description -match 'rootkit|stealth|hook'
                }
            
            foreach ($driver in $drivers) {
                $detections += @{
                    DriverName = $driver.Name
                    PathName = $driver.PathName
                    Description = $driver.Description
                    Type = "Suspicious Kernel Driver"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for SSDT hooks (indirectly through Event Log)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -ErrorAction SilentlyContinue -MaxEvents 50
            
            $hookIndicators = $events | Where-Object {
                $_.Message -match 'hook|SSDT|kernel|driver.*unexpected'
            }
            
            if ($hookIndicators.Count -gt 0) {
                $detections += @{
                    EventCount = $hookIndicators.Count
                    Type = "SSDT Hook Indicators"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for processes with unusual privileges
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for SeDebugPrivilege (common in rootkits)
                    if ($procObj.PrivilegedProcessorTime.TotalSeconds -gt 0 -and 
                        $proc.Name -notin @("csrss.exe", "winlogon.exe", "services.exe")) {
                        # Indirect check - process with unusual privileges
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $proc.ExecutablePath -like "$env:SystemRoot\*") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ExecutablePath = $proc.ExecutablePath
                                    Type = "Unsigned Process with System Privileges"
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
        
        # Check for unusual boot entries
        try {
            $bootEntries = Get-CimInstance Win32_BootConfiguration -ErrorAction SilentlyContinue
            
            foreach ($boot in $bootEntries) {
                if ($boot.Description -match 'rootkit|stealth|hook' -or
                    $boot.Description -notlike '*Windows*') {
                    $detections += @{
                        BootEntry = $boot.Description
                        Type = "Suspicious Boot Entry"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Error -EventId 2017 `
                    -Message "ROOTKIT DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.DriverName -or $detection.Directory)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\Rootkit_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.DriverName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) rootkit indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-RootkitScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region ScheduledTaskDetection
# Scheduled Task Detection Module
# Detects malicious scheduled tasks


$ModuleName = "ScheduledTaskDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-ScheduledTaskScan {
    $detections = @()
    
    try {
        # Get all scheduled tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        
        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            $taskActions = $task.Actions
            $taskSettings = $task.Settings
            $suspicious = $false
            $reasons = @()
            
            # Check task actions
            foreach ($action in $taskActions) {
                if ($action.Execute) {
                    $executeLower = $action.Execute.ToLower()
                    
                    # Check for suspicious executables
                    if ($executeLower -match 'powershell|cmd|wscript|cscript|rundll32|mshta') {
                        if ($action.Arguments) {
                            $argsLower = $action.Arguments.ToLower()
                            
                            # Check for suspicious arguments
                            if ($argsLower -match '-encodedcommand|-nop|-w.*hidden|-executionpolicy.*bypass' -or
                                $argsLower -match 'http|https|ftp' -or
                                $argsLower -match 'javascript:|\.hta|\.vbs') {
                                $suspicious = $true
                                $reasons += "Suspicious command line arguments"
                            }
                        }
                        
                        # Check for tasks running as SYSTEM
                        if ($task.Principal.RunLevel -eq "Highest" -or 
                            $task.Principal.UserId -eq "SYSTEM") {
                            $suspicious = $true
                            $reasons += "Runs as SYSTEM/High privilege"
                        }
                    }
                }
            }
            
            # Check for hidden tasks
            if ($taskSettings.Hidden) {
                $suspicious = $true
                $reasons += "Hidden task"
            }
            
            # Check for tasks that run when user is logged off
            if ($taskSettings.RunOnlyIfNetworkAvailable -and 
                $taskSettings.StartWhenAvailable) {
                $suspicious = $true
                $reasons += "Runs when network available (exfiltration risk)"
            }
            
            # Check for tasks in suspicious locations
            foreach ($action in $taskActions) {
                if ($action.WorkingDirectory) {
                    $workDir = $action.WorkingDirectory
                    if ($workDir -match '\$env:|temp|appdata' -and 
                        $workDir -notmatch '^[A-Z]:\\') {
                        $suspicious = $true
                        $reasons += "Suspicious working directory"
                    }
                }
            }
            
            # Check for recently created tasks
            $createdDate = $taskInfo | Select-Object -ExpandProperty 'CreationDate' -ErrorAction SilentlyContinue
            if ($createdDate) {
                $age = (Get-Date) - $createdDate
                if ($age.TotalDays -lt 7) {
                    $suspicious = $true
                    $reasons += "Recently created (within 7 days)"
                }
            }
            
            if ($suspicious) {
                $detections += @{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    Actions = $taskActions
                    Reasons = $reasons
                    State = $task.State
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2007 `
                    -Message "SUSPICIOUS TASK: $($detection.TaskName) - $($detection.Reasons -join ', ')"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ScheduledTask_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                $actionStr = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.TaskName)|$($_.Reasons -join ';')|$actionStr" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) suspicious scheduled tasks"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ScheduledTaskScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region ServiceMonitoring
# Service Monitoring Module
# Monitors Windows services for suspicious activity


$ModuleName = "ServiceMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }
$BaselineServices = @{}

function Initialize-ServiceBaseline {
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($svc in $services) {
            $key = "$($svc.Name)|$($svc.PathName)"
            if (-not $BaselineServices.ContainsKey($key)) {
                $BaselineServices[$key] = @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    StartName = $svc.StartName
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Invoke-ServiceMonitoring {
    $detections = @()
    
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($svc in $services) {
            $key = "$($svc.Name)|$($svc.PathName)"
            
            # Check for new services
            if (-not $BaselineServices.ContainsKey($key)) {
                $detections += @{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    Type = "New Service Detected"
                    Risk = "High"
                }
                
                # Update baseline
                $BaselineServices[$key] = @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    StartName = $svc.StartName
                    FirstSeen = Get-Date
                }
            } else {
                # Check for service state changes
                $baseline = $BaselineServices[$key]
                if ($svc.State -ne $baseline.State) {
                    $detections += @{
                        ServiceName = $svc.Name
                        OldState = $baseline.State
                        NewState = $svc.State
                        Type = "Service State Changed"
                        Risk = "Medium"
                    }
                    $baseline.State = $svc.State
                }
            }
            
            # Check for suspicious service properties
            if ($svc.PathName -and (Test-Path $svc.PathName)) {
                # Check for unsigned service executables
                $sig = Get-AuthenticodeSignature -FilePath $svc.PathName -ErrorAction SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Unsigned Service Executable"
                        Risk = "High"
                    }
                }
                
                # Check for services not in system directories
                if ($svc.PathName -notlike "$env:SystemRoot\*" -and 
                    $svc.PathName -notlike "$env:ProgramFiles*") {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Service Executable Outside System/Program Directories"
                        Risk = "Medium"
                    }
                }
                
                # Check for services with suspicious command line arguments
                if ($svc.PathName -match 'powershell|cmd|wscript|cscript|http') {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Service with Suspicious Command Line"
                        Risk = "High"
                    }
                }
            }
            
            # Check for services running as SYSTEM with suspicious paths
            if ($svc.StartName -eq "LocalSystem" -or $svc.StartName -eq "NT AUTHORITY\SYSTEM") {
                if ($svc.PathName -notlike "$env:SystemRoot\*") {
                    $detections += @{
                        ServiceName = $svc.Name
                        StartName = $svc.StartName
                        PathName = $svc.PathName
                        Type = "SYSTEM Service Outside System Directory"
                        Risk = "Critical"
                    }
                }
            }
            
            # Check for services with unusual display names
            if ($svc.DisplayName -match 'update|installer|system|security|windows' -and
                $svc.Name -notmatch '^[A-Z][a-z]') {
                # Suspicious display name pattern
                $detections += @{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    Type = "Service with Suspicious Display Name"
                    Risk = "Medium"
                }
            }
        }
        
        # Check for stopped critical services
        $criticalServices = @("WinDefend", "SecurityHealthService", "MpsSvc", "BITS")
        foreach ($criticalSvc in $criticalServices) {
            $svc = $services | Where-Object { $_.Name -eq $criticalSvc } | Select-Object -First 1
            if ($svc -and $svc.State -ne "Running") {
                $detections += @{
                    ServiceName = $svc.Name
                    State = $svc.State
                    Type = "Critical Service Stopped"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2025 `
                    -Message "SERVICE MONITORING: $($detection.Type) - $($detection.ServiceName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ServiceMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ServiceName)|$($_.PathName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) service anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    Initialize-ServiceBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ServiceMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region ShadowCopyMonitoring
# Shadow Copy Monitoring Module
# Monitors shadow copy deletion (ransomware indicator)


$ModuleName = "ShadowCopyMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-ShadowCopyMonitoring {
    $detections = @()
    
    try {
        # Check for shadow copies
        $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        
        # Check shadow copy count
        if ($shadowCopies.Count -eq 0) {
            $detections += @{
                Type = "No Shadow Copies Found"
                ShadowCopyCount = 0
                Risk = "Medium"
            }
        }
        
        # Monitor shadow copy deletion
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { 
                    $_.Message -match 'shadow|vss|volume.*snapshot' -or
                    $_.Id -in @(8221, 8222, 8223, 8224)
                }
            
            $deletionEvents = $events | Where-Object {
                $_.Message -match 'delete|deleted|remove|removed'
            }
            
            if ($deletionEvents.Count -gt 0) {
                foreach ($event in $deletionEvents) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        Message = $event.Message
                        Type = "Shadow Copy Deletion Detected"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for VSSAdmin usage
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { $_.Name -eq "vssadmin.exe" -or $_.CommandLine -like "*vssadmin*" }
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine -match 'delete.*shadows|resize.*shadowstorage') {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Type = "VSSAdmin Shadow Copy Manipulation"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        # Check for Volume Shadow Copy Service status
        try {
            $vssService = Get-CimInstance Win32_Service -Filter "Name='VSS'" -ErrorAction SilentlyContinue
            
            if ($vssService) {
                if ($vssService.State -ne "Running") {
                    $detections += @{
                        ServiceState = $vssService.State
                        Type = "Volume Shadow Copy Service Not Running"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check shadow storage configuration
        try {
            $shadowStorage = Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue
            
            foreach ($storage in $shadowStorage) {
                # Check if shadow storage is disabled or too small
                $allocated = $storage.AllocatedSpace
                $maxSize = $storage.MaxSpace
                
                if ($maxSize -eq 0 -or $allocated -eq 0) {
                    $detections += @{
                        Volume = $storage.Volume
                        AllocatedSpace = $allocated
                        MaxSpace = $maxSize
                        Type = "Shadow Storage Disabled or Empty"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2021 `
                    -Message "SHADOW COPY MONITORING: $($detection.Type) - $($detection.ProcessName -or $detection.Volume -or $detection.Message)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\ShadowCopy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Volume)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) shadow copy anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Shadow copies=$($shadowCopies.Count)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ShadowCopyMonitoring
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region TokenManipulationDetection
# Token Manipulation Detection Module
# Detects token theft and impersonation


$ModuleName = "TokenManipulationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-TokenManipulationScan {
    $detections = @()
    
    try {
        # Check for processes with unusual token privileges
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, ParentProcessId
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                
                # Check for SeDebugPrivilege (enables token access)
                try {
                    $token = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue
                    # Indirect check - processes accessing LSASS often have this
                    if ($proc.Name -eq "lsass") {
                        # Check for processes accessing LSASS
                        $accessingProcs = Get-CimInstance Win32_Process | 
                            Where-Object { $_.ParentProcessId -eq $proc.ProcessId -and 
                                          $_.Name -notin @("svchost.exe", "dwm.exe") }
                        
                        foreach ($accProc in $accessingProcs) {
                            $detections += @{
                                ProcessId = $accProc.ProcessId
                                ProcessName = $accProc.Name
                                Type = "LSASS Access - Possible Token Theft"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
                
                # Check for processes running as SYSTEM but not in Windows directory
                if ($procObj.StartInfo.UserName -eq "SYSTEM" -or 
                    $proc.Name -eq "SYSTEM") {
                    if ($proc.ExecutablePath -and 
                        $proc.ExecutablePath -notlike "$env:SystemRoot\*") {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ExecutablePath = $proc.ExecutablePath
                            Type = "SYSTEM token on non-Windows executable"
                            Risk = "High"
                        }
                    }
                }
                
            } catch {
                continue
            }
        }
        
        # Check Security Event Log for token operations
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $subjectUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                $targetUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                
                # Check for unusual token impersonation
                if ($subjectUserName -ne $targetUserName -and 
                    $targetUserName -eq "SYSTEM") {
                    $detections += @{
                        EventId = $event.Id
                        SubjectUser = $subjectUserName
                        TargetUser = $targetUserName
                        Type = "Token Impersonation - SYSTEM"
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for common token manipulation tools
        $tokenTools = @("incognito", "mimikatz", "invoke-tokenmanipulation", "getsystem")
        $runningProcs = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $runningProcs) {
            foreach ($tool in $tokenTools) {
                if ($proc.ProcessName -like "*$tool*" -or 
                    $proc.Path -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ProcessPath = $proc.Path
                        Type = "Token Manipulation Tool"
                        Tool = $tool
                        Risk = "Critical"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2010 `
                    -Message "TOKEN MANIPULATION: $($detection.ProcessName -or $detection.Type) - $($detection.Tool -or $detection.TargetUser)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\TokenManipulation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Risk)|$($_.Tool -or $_.TargetUser)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) token manipulation attempts"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-TokenManipulationScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region USBMonitoring
# USB Device Monitoring Module
# Monitors USB device connections and activity


$ModuleName = "USBMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        # Get USB devices
        $usbDevices = Get-CimInstance Win32_USBControllerDevice -ErrorAction SilentlyContinue
        
        foreach ($usbDevice in $usbDevices) {
            try {
                $device = Get-CimInstance -InputObject $usbDevice.Dependent -ErrorAction SilentlyContinue
                
                if ($device) {
                    # Check for suspicious USB device types
                    $suspiciousDevices = @{
                        "HID" = "Human Interface Device"
                        "USBSTOR" = "USB Mass Storage"
                    }
                    
                    $deviceType = $device.DeviceID
                    
                    # Check for HID devices (keyloggers, etc.)
                    if ($deviceType -match "HID") {
                        $detections += @{
                            DeviceId = $device.DeviceID
                            DeviceName = $device.Name
                            DeviceType = "HID Device"
                            Type = "USB HID Device Connected"
                            Risk = "Medium"
                        }
                    }
                    
                    # Check for USB storage devices
                    if ($deviceType -match "USBSTOR") {
                        $detections += @{
                            DeviceId = $device.DeviceID
                            DeviceName = $device.Name
                            DeviceType = "USB Storage"
                            Type = "USB Storage Device Connected"
                            Risk = "Low"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check Event Log for USB device events
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001,20002,20003} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object { $_.Message -match 'USB|removable|storage' }
            
            $recentEvents = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
            }
            
            if ($recentEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $recentEvents.Count
                    Type = "Excessive USB Device Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for USB device autorun
        try {
            $autorunKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            )
            
            foreach ($key in $autorunKeys) {
                if (Test-Path $key) {
                    $noDriveAutorun = Get-ItemProperty -Path $key -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
                    
                    if ($noDriveAutorun -and $noDriveAutorun.NoDriveTypeAutoRun -eq 0) {
                        $detections += @{
                            RegistryKey = $key
                            Type = "USB Autorun Enabled"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing USB devices
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'usb|hid|storage'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Exclude legitimate processes
                        $legitProcesses = @("explorer.exe", "svchost.exe", "services.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                USBModules = $modules.ModuleName -join ','
                                Type = "Process Accessing USB Devices"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for USB device driver modifications
        try {
            $usbDrivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.PathName -match 'usb|hid' -and
                    $_.PathName -notlike "$env:SystemRoot\*"
                }
            
            foreach ($driver in $usbDrivers) {
                $detections += @{
                    DriverName = $driver.Name
                    DriverPath = $driver.PathName
                    Type = "Non-Standard USB Driver"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Information -EventId 2022 `
                    -Message "USB MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.ProcessName -or $detection.DriverName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) USB device anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:USB devices=$($usbDevices.Count)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-USBMonitoring
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region WebcamGuardian
# Webcam Guardian Module
# Monitors webcam access and protects privacy


$ModuleName = "WebcamGuardian"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-WebcamGuardian {
    $detections = @()
    
    try {
        # Check for webcam devices
        try {
            $webcamDevices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Name -match 'camera|webcam|video|imaging|usb.*video' -or
                    $_.PNPDeviceID -match 'VID_.*PID_.*.*CAMERA'
                }
            
            if ($webcamDevices.Count -gt 0) {
                Write-Output "STATS:$ModuleName`:Webcam devices=$($webcamDevices.Count)"
            }
        } catch { }
        
        # Check for processes accessing webcam
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    # Check for webcam-related modules
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'ksuser|avicap32|msvfw32|amstream|qcap|vidcap'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check if process is authorized
                        $authorizedProcesses = @("explorer.exe", "dwm.exe", "chrome.exe", "firefox.exe", "msedge.exe", "teams.exe", "zoom.exe", "skype.exe")
                        
                        if ($proc.ProcessName -notin $authorizedProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                ProcessPath = $proc.Path
                                WebcamModules = $modules.ModuleName -join ','
                                Type = "Unauthorized Webcam Access"
                                Risk = "High"
                            }
                        }
                    }
                    
                    # Check for video capture libraries
                    $videoModules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'video|capture|stream|directshow|media'
                    }
                    
                    if ($videoModules.Count -gt 3 -and 
                        $proc.ProcessName -notin $authorizedProcesses) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            VideoModules = $videoModules.ModuleName -join ','
                            Type = "Process with Many Video Capture Modules"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for webcam-related registry keys
        try {
            $webcamRegKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
            )
            
            foreach ($regKey in $webcamRegKeys) {
                if (Test-Path $regKey) {
                    $values = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                    
                    if ($values) {
                        # Check for applications with webcam access
                        $appAccess = $values.PSObject.Properties | Where-Object {
                            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -and
                            $_.Value -ne "Deny"
                        }
                        
                        foreach ($app in $appAccess) {
                            # Check if app is suspicious
                            if ($app.Name -notmatch 'microsoft|windows|explorer|chrome|firefox|edge|teams|zoom|skype') {
                                $detections += @{
                                    RegistryKey = $regKey
                                    AppName = $app.Name
                                    Access = $app.Value
                                    Type = "Suspicious App with Webcam Access"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for webcam access
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { 
                    $_.Message -match 'camera|webcam|video.*capture|imaging.*device'
                }
            
            $webcamEvents = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
            }
            
            if ($webcamEvents.Count -gt 10) {
                $detections += @{
                    EventCount = $webcamEvents.Count
                    Type = "Excessive Webcam Access Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for webcam blocking/monitoring tools
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -match 'camtasia|obs|webcam|camera|guardian|privacy'
                }
            
            foreach ($proc in $processes) {
                # These are usually legitimate, but log them
                Write-Output "STATS:$ModuleName`:Webcam-related process=$($proc.Name)"
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2031 `
                    -Message "WEBCAM GUARDIAN: $($detection.Type) - $($detection.ProcessName -or $detection.AppName)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\WebcamGuardian_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.AppName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) webcam access anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-WebcamGuardian
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region WMIPersistenceDetection
# WMI Persistence Detection Module
# Detects WMI-based persistence mechanisms


$ModuleName = "WMIPersistenceDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-WMIPersistenceScan {
    $detections = @()
    
    try {
        # Check WMI Event Consumers
        $eventConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        
        foreach ($consumer in $eventConsumers) {
            # Check for suspicious consumer types
            if ($consumer.__CLASS -match 'ActiveScript|CommandLine') {
                $suspicious = $false
                $details = @{}
                
                # Check CommandLineEventConsumer
                if ($consumer.__CLASS -eq '__EventConsumer') {
                    $cmdLine = $consumer.CommandLineTemplate
                    if ($cmdLine) {
                        $details.CommandLine = $cmdLine
                        # Check for suspicious commands
                        if ($cmdLine -match 'powershell|cmd|certutil|bitsadmin|wmic' -or
                            $cmdLine -match 'http|https|ftp' -or
                            $cmdLine -match '-encodedcommand|-nop|-w.*hidden') {
                            $suspicious = $true
                        }
                    }
                }
                
                # Check ActiveScriptEventConsumer
                if ($consumer.__CLASS -match 'ActiveScript') {
                    $script = $consumer.ScriptText
                    if ($script -and ($script.Length -gt 1000 -or 
                        $script -match 'wscript|eval|exec|shell')) {
                        $suspicious = $true
                        $details.ScriptLength = $script.Length
                    }
                }
                
                if ($suspicious) {
                    $detections += @{
                        ConsumerName = $consumer.Name
                        ConsumerClass = $consumer.__CLASS
                        Details = $details
                        Risk = "High"
                    }
                }
            }
        }
        
        # Check WMI Event Filters
        $eventFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        
        foreach ($filter in $eventFilters) {
            $query = $filter.Query
            if ($query) {
                # Check for suspicious event filters
                if ($query -match 'SELECT.*FROM.*__InstanceModificationEvent' -or
                    $query -match 'SELECT.*FROM.*Win32_ProcessStartTrace') {
                    $filterName = $filter.Name
                    
                    # Check if filter is bound to suspicious consumer
                    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                        Where-Object { $_.Filter -like "*$filterName*" }
                    
                    if ($bindings) {
                        $detections += @{
                            FilterName = $filterName
                            Query = $query
                            Type = "Event Filter Binding"
                            Risk = "Medium"
                        }
                    }
                }
            }
        }
        
        # Check for suspicious WMI namespaces
        try {
            $namespaces = Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[a-f0-9]{32}$' }
            
            foreach ($ns in $namespaces) {
                $detections += @{
                    Namespace = $ns.Name
                    Type = "Suspicious WMI Namespace"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2006 `
                    -Message "WMI PERSISTENCE DETECTED: $($detection.ConsumerName -or $detection.FilterName -or $detection.Namespace) - $($detection.Type)"
            }
            
            $logPath = "C:\ProgramData\GEDR\Logs\WMIPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ConsumerName -or $_.FilterName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) WMI persistence mechanisms"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-WMIPersistenceScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}
}
# endregion

# region YaraDetection
# YARA Detection
# Runs yara.exe against suspicious files (if present)


$ModuleName = "YaraDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 120 }
$YaraPaths = @("$env:ProgramFiles\Yara\yara64.exe", "$env:ProgramFiles (x86)\Yara\yara.exe", "yara.exe", "yara64.exe")
$RulesPaths = @("C:\ProgramData\GEDR\Yara", "C:\ProgramData\GEDR\Rules", "$PSScriptRoot\YaraRules")
$ScanPaths = @("$env:Temp", "$env:TEMP", "$env:SystemRoot\Temp")

function Get-YaraExe {
    foreach ($p in $YaraPaths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-RulesPath {
    foreach ($p in $RulesPaths) {
        if (Test-Path $p) {
            $rules = Get-ChildItem -Path $p -Filter *.yar -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($rules) { return $rules.Directory.FullName }
        }
    }
    return $null
}

function Invoke-YaraScan {
    $yara = Get-YaraExe
    if (-not $yara) {
        return 0
    }
    
    $rulesDir = Get-RulesPath
    if (-not $rulesDir) {
        return 0
    }
    
    $detections = @()
    foreach ($base in $ScanPaths) {
        if (-not (Test-Path $base)) { continue }
        try {
            $files = Get-ChildItem -Path $base -Include *.exe, *.dll, *.ps1 -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($f in $files) {
                try {
                    $out = & $yara -r "$rulesDir\*.yar" $f.FullName 2>&1
                    if ($out -and $out -match '\S') {
                        $detections += @{
                            File = $f.FullName
                            Match = ($out | Select-Object -First 5) -join "; "
                        }
                    }
                } catch { }
            }
        } catch { }
    }
    
    if ($detections.Count -gt 0) {
        foreach ($d in $detections) {
            Write-EventLog -LogName Application -Source "GEDR" -EntryType Warning -EventId 2096 -Message "YARA: $($d.File) - $($d.Match)" -ErrorAction SilentlyContinue
        }
        $logPath = "C:\ProgramData\GEDR\Logs\yara_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.File)|$($_.Match)" | Add-Content -Path $logPath }
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) YARA matches"
    }
    return $detections.Count
}

function Start-Module {
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-YaraScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 120 } }
# endregion

# region GFocus
# GFocus.ps1 - Network traffic monitor + firewall rule cleanup
# Single script: monitor mode (default) or -RemoveRules to clear NTM_Block_* / BlockedConnection_*
# Monitors IPs; blocks or allows or removes block as the user surfs. Address bar is inferred from
# browser 80/443 connections (no extension): first 80/443 = navigation, within 30s = dependencies.
# Browsers only: games and other apps are never monitored or blocked. Block rules are
# browser-specific (program= + remoteip). DNS IPs (8.8.8.8, 1.1.1.1, etc.) are never blocked.
# Requires Administrator privileges

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string[]]$AllowedDomains = @(),
    [Parameter(Mandatory=$false)]
    [switch]$AutoStart = $false,
    [Parameter(Mandatory=$false)]
    [switch]$RemoveRules = $false
)

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# --- Remove-rules mode: clear NTM_Block_* and BlockedConnection_*, then exit ---
function Remove-BlockedRules {
    Write-ColorOutput "Removing all blocked connection rules..." "Yellow"
    $totalRemoved = 0

    $blockedRules = Get-NetFirewallRule -DisplayName "BlockedConnection_*" -ErrorAction SilentlyContinue
    if ($blockedRules) {
        $count = ($blockedRules | Measure-Object).Count
        Write-ColorOutput "Found $count BlockedConnection_* rule(s)." "Cyan"
        foreach ($Rule in $blockedRules) {
            Remove-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue
            Write-ColorOutput "  Removed: $($Rule.DisplayName)" "Green"
            $totalRemoved++
        }
    } else {
        Write-ColorOutput "No BlockedConnection_* rules found." "Gray"
    }

    $out = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
    $ruleMatches = [regex]::Matches($out, 'Rule Name:\s*(NTM_Block_[^\s\r\n]+)')
    $ntmList = @($ruleMatches | ForEach-Object { $_.Groups[1].Value.Trim() } | Sort-Object -Unique)
    if ($ntmList.Count -gt 0) {
        Write-ColorOutput "Found $($ntmList.Count) NTM_Block_* rule(s)." "Cyan"
        foreach ($name in $ntmList) {
            $del = netsh advfirewall firewall delete rule name="$name" 2>&1 | Out-String
            if ($del -notmatch 'No rules match') {
                Write-ColorOutput "  Removed: $name" "Green"
                $totalRemoved++
            }
        }
    } else {
        Write-ColorOutput "No NTM_Block_* rules found." "Gray"
    }

    if ($totalRemoved -gt 0) {
        Write-ColorOutput "`nDone. Removed $totalRemoved rule(s) in total." "Green"
    } else {
        Write-ColorOutput "`nNo blocked connection rules to remove." "Gray"
    }
}

if ($RemoveRules) {
    Remove-BlockedRules
    exit 0
}

# --- Monitor mode (NTM) ---
$script:AllowedDomains = @()
$script:AllowedIPs = @()
$script:BlockedConnections = @{}
$script:MonitoringActive = $true
$script:CurrentBrowserConnections = @{}
$script:GFocusSeen = @{}

# Browsers only: monitoring and blocking apply solely to these processes.
$BrowserProcesses = @(
    'chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave', 'vivaldi', 'waterfox', 'palemoon',
    'seamonkey', 'librewolf', 'tor', 'dragon', 'iridium', 'chromium', 'maxthon', 'slimjet', 'citrio',
    'blisk', 'sidekick', 'epic', 'ghostery', 'falkon', 'kinza', 'orbitum', 'coowon', 'coc_coc_browser',
    'browser', 'qqbrowser', 'ucbrowser', '360chrome', '360se', 'sleipnir', 'k-meleon', 'basilisk',
    'floorp', 'pulse', 'naver', 'whale', 'coccoc', 'yandex', 'avastbrowser', 'asb', 'avgbrowser',
    'ccleanerbrowser', 'dcbrowser', 'edge', 'edgedev', 'edgebeta', 'edgecanary', 'operagx', 'operaneon',
    'bravesoftware', 'browsex', 'browsec', 'comet', 'elements', 'flashpeak', 'surf'
)

# Gaming (and all non-browser apps) are never monitored or blocked " explicitly unhindered.
$GamingProcesses = @(
    'steam', 'steamwebhelper', 'epicgameslauncher', 'origin', 'battle.net', 'eadesktop', 'ea app',
    'ubisoft game launcher', 'gog galaxy', 'rungame', 'gamebar', 'gameservices', 'overwolf'
)

# Never block these IPs (common DNS). Blocking them would break resolution for everyone.
$NeverBlockIPs = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1')

function Remove-BlockRulesForIP {
    param([string]$RemoteAddress)
    $safeName = $RemoteAddress -replace '\.', '_' -replace ':', '_'
    $prefix = "NTM_Block_${safeName}_"
    $out = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
    $ruleMatches = [regex]::Matches($out, 'Rule Name:\s*(NTM_Block_[^\s\r\n]+)')
    foreach ($m in $ruleMatches) {
        $name = $m.Groups[1].Value.Trim()
        if ($name -like "${prefix}*") {
            $del = netsh advfirewall firewall delete rule name="$name" 2>&1 | Out-String
            if ($del -notmatch 'No rules match') {
                Write-ColorOutput "REMOVED BLOCK (user surfed): $RemoteAddress -> $name" "Green"
            }
        }
    }
    $toRemove = @($script:BlockedConnections.Keys | Where-Object { $_ -like "${RemoteAddress}|*" })
    foreach ($k in $toRemove) { $script:BlockedConnections.Remove($k) }
}

function Add-AllowedDomain {
    param([string]$Domain)
    $Domain = $Domain -replace '^https?://', '' -replace '/$', ''
    $Domain = ($Domain -split '/')[0]
    if ($Domain -match '^[\d\.]+$' -or $Domain -match '^[\da-f:]+$') {
        if ($script:AllowedIPs -notcontains $Domain) {
            $script:AllowedIPs += $Domain
            Write-ColorOutput "Added allowed IP: $Domain" "Green"
            Remove-BlockRulesForIP -RemoteAddress $Domain
        }
        return
    }
    if ($script:AllowedDomains -notcontains $Domain) {
        $script:AllowedDomains += $Domain
        Write-ColorOutput "Added allowed domain: $Domain" "Green"
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($IP in $IPs) {
                if ($script:AllowedIPs -notcontains $IP) {
                    $script:AllowedIPs += $IP
                    Write-ColorOutput "  Resolved IP: $IP" "Gray"
                    Remove-BlockRulesForIP -RemoteAddress $IP
                }
            }
        } catch {
            Write-ColorOutput "  Warning: Could not resolve domain to IP" "Yellow"
        }
    }
}

function Test-BrowserConnection {
    param([string]$RemoteAddress)
    if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') { return $true }
    if ($script:AllowedIPs -contains $RemoteAddress) { return $true }
    return $false
}

function Watch-BrowserActivity {
    param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)
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
                Write-ColorOutput "DEPENDENCY: Allowing $RemoteAddress (linked to browser navigation)" "Gray"
                Remove-BlockRulesForIP -RemoteAddress $RemoteAddress
            }
            return $true
        }
        elseif ($RemotePort -eq 443 -or $RemotePort -eq 80) {
            if ($script:AllowedIPs -notcontains $RemoteAddress) {
                $script:AllowedIPs += $RemoteAddress
                Write-ColorOutput "BROWSER NAVIGATION: Allowing $RemoteAddress and its dependencies" "Cyan"
                Remove-BlockRulesForIP -RemoteAddress $RemoteAddress
            }
            $script:CurrentBrowserConnections[$RemoteAddress] = $Now
            return $true
        }
        else {
            if ($script:AllowedIPs -notcontains $RemoteAddress) {
                $script:AllowedIPs += $RemoteAddress
                Write-ColorOutput "BROWSER: Allowing $RemoteAddress" "DarkCyan"
                Remove-BlockRulesForIP -RemoteAddress $RemoteAddress
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
                Write-ColorOutput "DEPENDENCY: Allowing $RemoteAddress (linked to browser navigation)" "Gray"
                Remove-BlockRulesForIP -RemoteAddress $RemoteAddress
            }
            return $true
        }
    }
    return $false
}

function New-BlockRule {
    param([string]$RemoteAddress, [int]$RemotePort, [string]$ProcessName, [string]$ProgramPath)
    if ($RemoteAddress -in $NeverBlockIPs) { return }
    $safeName = $RemoteAddress -replace '\.', '_' -replace ':', '_'
    $procSafe = ($ProcessName -replace '\.exe$','').Trim().ToLower()
    $ruleName = "NTM_Block_${safeName}_${procSafe}"
    $key = "${RemoteAddress}|${ProcessName}"
    if (-not $ProgramPath -or -not (Test-Path $ProgramPath)) {
        Write-ColorOutput "Skip block (no program path): $RemoteAddress ($ProcessName)" "Yellow"
        return
    }
    $progArg = "program=`"$ProgramPath`""
    $out = netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip="$RemoteAddress" $progArg 2>&1 | Out-String
    if ($out -match 'already exists') {
        $script:BlockedConnections[$key] = @{ Port = $RemotePort; Process = $ProcessName }
        return
    }
    if ($out -match 'Error|Failed|Unable') {
        Write-ColorOutput "Failed to block $RemoteAddress for $ProcessName : $($out.Trim())" "Red"
        return
    }
    $script:BlockedConnections[$key] = @{ Port = $RemotePort; Process = $ProcessName }
    Write-ColorOutput "BLOCKED (browser only): $RemoteAddress`:$RemotePort ($ProcessName)" "Red"
}

function Start-ConnectionMonitoring {
    Write-ColorOutput "" "Cyan"
    Write-ColorOutput "=== GFocus / Network Traffic Monitor ===" "Cyan"
    Write-ColorOutput "Browsers only: monitoring and blocking apply to browsers only." "Cyan"
    Write-ColorOutput "Gaming and all other apps are unhindered (never monitored or blocked)." "Green"
    Write-ColorOutput "Address bar inferred from browser 80/443 nav + 30s dependencies (no extension)." "Cyan"
    Write-ColorOutput "Block/allow/remove block as user surfs. Press Ctrl+C to stop." "Yellow"
    Write-ColorOutput "To clear block rules later: GFocus.ps1 -RemoveRules" "Gray"
    Write-ColorOutput "" "Cyan"
    $SeenConnections = @{}
    while ($script:MonitoringActive) {
        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
        foreach ($Conn in $Connections) {
            $Key = "$($Conn.RemoteAddress):$($Conn.RemotePort):$($Conn.OwningProcess)"
            if ($SeenConnections.ContainsKey($Key)) { continue }
            $SeenConnections[$Key] = $true
            try {
                $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction Stop
                $ProcessName = $Process.ProcessName
                $ProcessPath = $Process.Path
            } catch { $Process = $null; $ProcessName = "Unknown"; $ProcessPath = $null }
            $procName = ($ProcessName -replace '\.exe$','').Trim().ToLower()
            if ($procName -notin $BrowserProcesses) {
                continue
            }
            $IsBrowserOrDependency = Watch-BrowserActivity -RemoteAddress $Conn.RemoteAddress -ProcessName $ProcessName -RemotePort $Conn.RemotePort
            if ($IsBrowserOrDependency) { continue }
            if (-not (Test-BrowserConnection -RemoteAddress $Conn.RemoteAddress)) {
                $blockKey = "$($Conn.RemoteAddress)|$ProcessName"
                if (-not $script:BlockedConnections.ContainsKey($blockKey)) {
                    New-BlockRule -RemoteAddress $Conn.RemoteAddress -RemotePort $Conn.RemotePort -ProcessName $ProcessName -ProgramPath $ProcessPath
                }
            } else {
                Write-ColorOutput "ALLOWED: $($Conn.RemoteAddress):$($Conn.RemotePort) (Process: $ProcessName)" "Green"
            }
        }
        $Now = Get-Date
        $ToRemove = @()
        foreach ($IP in $script:CurrentBrowserConnections.Keys) {
            if (($Now - $script:CurrentBrowserConnections[$IP]).TotalSeconds -gt 60) { $ToRemove += $IP }
        }
        foreach ($IP in $ToRemove) { $script:CurrentBrowserConnections.Remove($IP) }
        Start-Sleep -Seconds 2
    }
}

function Stop-Monitoring {
    Write-ColorOutput "" "Cyan"
    Write-ColorOutput "=== Stopping GFocus ===" "Cyan"
    Write-ColorOutput "Blocked connections:" "Yellow"
    if ($script:BlockedConnections.Count -eq 0) {
        Write-ColorOutput "  None." "Green"
    } else {
        foreach ($k in $script:BlockedConnections.Keys) {
            $Info = $script:BlockedConnections[$k]
            $ip = ($k -split '\|', 2)[0]
            Write-ColorOutput "  - ${ip}:$($Info.Port) - $($Info.Process) (browser-only rule)" "Red"
        }
    }
    Write-ColorOutput "`nTo remove block rules: GFocus.ps1 -RemoveRules" "Gray"
}

Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Stop-Monitoring }

try {
    Write-ColorOutput "============================================================" "Cyan"
    Write-ColorOutput "     GFocus - Network Traffic Monitor                      " "Cyan"
    Write-ColorOutput "============================================================" "Cyan"
    Write-ColorOutput ""
    foreach ($Domain in $AllowedDomains) { Add-AllowedDomain -Domain $Domain }
    Start-ConnectionMonitoring
} catch {
    Write-ColorOutput "Error: $($_.Exception.Message)" "Red"
} finally {
    Stop-Monitoring
}


function Invoke-GFocusTick {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
    foreach ($Conn in $Connections) {
        $Key = "$($Conn.RemoteAddress):$($Conn.RemotePort):$($Conn.OwningProcess)"
        if ($script:GFocusSeen.ContainsKey($Key)) { continue }
        $script:GFocusSeen[$Key] = $true
        try {
            $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction Stop
            $ProcessName = $Process.ProcessName
            $ProcessPath = $Process.Path
        } catch { $ProcessName = "Unknown"; $ProcessPath = $null }
        $procName = ($ProcessName -replace '\.exe$','').Trim().ToLower()
        if ($procName -notin $BrowserProcesses) { continue }
        $IsBrowserOrDependency = Watch-BrowserActivity -RemoteAddress $Conn.RemoteAddress -ProcessName $ProcessName -RemotePort $Conn.RemotePort
        if ($IsBrowserOrDependency) { continue }
        if (-not (Test-BrowserConnection -RemoteAddress $Conn.RemoteAddress)) {
            $blockKey = "$($Conn.RemoteAddress)|$ProcessName"
            if (-not $script:BlockedConnections.ContainsKey($blockKey)) {
                New-BlockRule -RemoteAddress $Conn.RemoteAddress -RemotePort $Conn.RemotePort -ProcessName $ProcessName -ProgramPath $ProcessPath
            }
        }
    }
    $Now = Get-Date
    $ToRemove = @($script:CurrentBrowserConnections.Keys | Where-Object { ($Now - $script:CurrentBrowserConnections[$_]).TotalSeconds -gt 60 })
    foreach ($IP in $ToRemove) { $script:CurrentBrowserConnections.Remove($IP) }
}
# endregion


# --- Scheduler: run all modules by interval ---
$script:ModuleLastRun = @{}
$schedule = @(
    @{ Name = 'Initializer'; Interval = 300; Invoke = 'Invoke-Initialization' }
    @{ Name = 'HashDetection'; Interval = 90; Invoke = 'Invoke-HashScanOptimized' }
    @{ Name = 'AMSIBypassDetection'; Interval = 90; Invoke = 'Invoke-AMSIBypassScan' }
    @{ Name = 'GFocus'; Interval = 2; Invoke = 'Invoke-GFocusTick' }
    @{ Name = 'ResponseEngine'; Interval = 180; Invoke = 'Invoke-ResponseEngine' }
    @{ Name = 'BeaconDetection'; Interval = 60; Invoke = 'Invoke-BeaconDetection' }
    @{ Name = 'NetworkTrafficMonitoring'; Interval = 45; Invoke = 'Invoke-NetworkTrafficMonitoringOptimized' }
    @{ Name = 'ProcessAnomalyDetection'; Interval = 90; Invoke = 'Invoke-ProcessAnomalyScanOptimized' }
    @{ Name = 'EventLogMonitoring'; Interval = 90; Invoke = 'Invoke-EventLogMonitoringOptimized' }
    @{ Name = 'FileEntropyDetection'; Interval = 120; Invoke = 'Invoke-FileEntropyDetectionOptimized' }
    @{ Name = 'YaraDetection'; Interval = 120; Invoke = 'Invoke-YaraScan' }
    @{ Name = 'WMIPersistenceDetection'; Interval = 60; Invoke = 'Invoke-WMIPersistenceScan' }
    @{ Name = 'ScheduledTaskDetection'; Interval = 60; Invoke = 'Invoke-ScheduledTaskScan' }
    @{ Name = 'RegistryPersistenceDetection'; Interval = 60; Invoke = 'Invoke-RegistryPersistenceScan' }
    @{ Name = 'DLLHijackingDetection'; Interval = 60; Invoke = 'Invoke-DLLHijackingScan' }
    @{ Name = 'TokenManipulationDetection'; Interval = 30; Invoke = 'Invoke-TokenManipulationScan' }
    @{ Name = 'ProcessHollowingDetection'; Interval = 20; Invoke = 'Invoke-ProcessHollowingScan' }
    @{ Name = 'KeyloggerDetection'; Interval = 30; Invoke = 'Invoke-KeyloggerScan' }
    @{ Name = 'ReflectiveDLLInjectionDetection'; Interval = 30; Invoke = 'Invoke-ReflectiveDLLInjectionDetection' }
    @{ Name = 'RansomwareDetection'; Interval = 15; Invoke = 'Invoke-RansomwareScan' }
    @{ Name = 'NetworkAnomalyDetection'; Interval = 30; Invoke = 'Invoke-NetworkAnomalyScan' }
    @{ Name = 'DNSExfiltrationDetection'; Interval = 60; Invoke = 'Invoke-DNSExfiltrationDetection' }
    @{ Name = 'RootkitDetection'; Interval = 60; Invoke = 'Invoke-RootkitScan' }
    @{ Name = 'ClipboardMonitoring'; Interval = 10; Invoke = 'Invoke-ClipboardMonitoring' }
    @{ Name = 'COMMonitoring'; Interval = 60; Invoke = 'Invoke-COMMonitoring' }
    @{ Name = 'BrowserExtensionMonitoring'; Interval = 60; Invoke = 'Invoke-BrowserExtensionMonitoring' }
    @{ Name = 'ShadowCopyMonitoring'; Interval = 30; Invoke = 'Invoke-ShadowCopyMonitoring' }
    @{ Name = 'USBMonitoring'; Interval = 30; Invoke = 'Invoke-USBMonitoring' }
    @{ Name = 'WebcamGuardian'; Interval = 20; Invoke = 'Invoke-WebcamGuardian' }
    @{ Name = 'AttackToolsDetection'; Interval = 60; Invoke = 'Invoke-AttackToolsScan' }
    @{ Name = 'AdvancedThreatDetection'; Interval = 60; Invoke = 'Invoke-AdvancedThreatScan' }
    @{ Name = 'FirewallRuleMonitoring'; Interval = 60; Invoke = 'Invoke-FirewallRuleMonitoring' }
    @{ Name = 'ServiceMonitoring'; Interval = 60; Invoke = 'Invoke-ServiceMonitoring' }
    @{ Name = 'FilelessDetection'; Interval = 20; Invoke = 'Invoke-FilelessDetection' }
    @{ Name = 'MemoryScanning'; Interval = 90; Invoke = 'Invoke-MemoryScanningOptimized' }
    @{ Name = 'NamedPipeMonitoring'; Interval = 60; Invoke = 'Invoke-NamedPipeMonitoring' }
    @{ Name = 'CodeInjectionDetection'; Interval = 30; Invoke = 'Invoke-CodeInjectionDetection' }
    @{ Name = 'DataExfiltrationDetection'; Interval = 60; Invoke = 'Invoke-DataExfiltrationDetection' }
    @{ Name = 'HoneypotMonitoring'; Interval = 300; Invoke = 'Invoke-HoneypotMonitoring' }
    @{ Name = 'LateralMovementDetection'; Interval = 30; Invoke = 'Invoke-LateralMovementDetection' }
    @{ Name = 'ProcessCreationDetection'; Interval = 60; Invoke = 'Invoke-ProcessCreationDetection' }
    @{ Name = 'QuarantineManagement'; Interval = 300; Invoke = 'Invoke-QuarantineManagement' }
    @{ Name = 'PrivacyForgeSpoofing'; Interval = 300; Invoke = 'Invoke-PrivacyForgeSpoofing' }
    @{ Name = 'PasswordManagement'; Interval = 300; Invoke = 'Invoke-PasswordManagement' }
    @{ Name = 'IdsDetection'; Interval = 60; Invoke = 'Invoke-IdsScan' }
    @{ Name = 'CredentialDumpDetection'; Interval = 20; Invoke = 'Invoke-CredentialDumpScan' }
    @{ Name = 'LOLBinDetection'; Interval = 30; Invoke = 'Invoke-LOLBinScan' }
    @{ Name = 'MemoryAcquisitionDetection'; Interval = 90; Invoke = 'Invoke-MemoryAcquisitionScan' }
    @{ Name = 'MobileDeviceMonitoring'; Interval = 90; Invoke = 'Invoke-MobileDeviceScan' }
)

if ($RemoveRules) {
    Remove-BlockedRules
    exit 0
}

# Run Initializer once
Invoke-Initialization | Out-Null

# Optional: start RealTimeFileMonitor watchers (event-based)
if (Get-Command Start-RealtimeMonitor -ErrorAction SilentlyContinue) {
    Start-RealtimeMonitor | Out-Null
}

$loopSleep = 5
while ($true) {
    $now = Get-Date
    foreach ($m in $schedule) {
        if (-not $script:ModuleLastRun.ContainsKey($m.Name)) { $script:ModuleLastRun[$m.Name] = [datetime]::MinValue }
        if (($now - $script:ModuleLastRun[$m.Name]).TotalSeconds -ge $m.Interval) {
            $script:ModuleName = $m.Name
            try {
                & $m.Invoke | Out-Null
            } catch {
                Write-Output "ERROR:$($m.Name):$_"
            }
            $script:ModuleLastRun[$m.Name] = $now
        }
    }
    Start-Sleep -Seconds $loopSleep
}


