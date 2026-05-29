# GRules.ps1
# Windows security script focusing on security rules with enhanced ASR rule application
# Author: Gorstak, optimized by Grok
# Description: Downloads, parses, and applies YARA, Sigma, and Snort rules, including all applicable ASR rules

param (
    [switch]$Monitor,
    [switch]$Backup,
    [switch]$ResetPassword,
    [switch]$Start,
    [string]$SnortOinkcode = "6cc50dfad45e71e9d8af44485f59af2144ad9a3c",
    [switch]$DebugMode,
    [switch]$NoMonitor,
    [string]$ConfigPath = "$env:USERPROFILE\GRules_config.json"
)

$ErrorActionPreference = "Stop"  # Ensure errors are visible
$ProgressPreference = "Continue"  # Show progress in console
$Global:ExitCode = 0
$Global:LogDir = "$env:TEMP\security_rules\logs"
$Global:LogFile = "$Global:LogDir\GRules_$(Get-Date -Format 'yyyyMMdd').log"

# Enable TLS 1.2 for secure connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Configuration
$Global:Config = @{
    Sources = @{
        YaraForge = "https://api.github.com/repos/YARAHQ/yara-forge/releases"
        YaraRules = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        SigmaHQ = "https://github.com/SigmaHQ/sigma/archive/master.zip"
        EmergingThreats = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz"
        SnortCommunity = "https://www.snort.org/downloads/community/community-rules.tar.gz"
    }
    ExcludedSystemFiles = @(
        "svchost.exe", "lsass.exe", "cmd.exe", "explorer.exe", "winlogon.exe",
        "csrss.exe", "services.exe", "msiexec.exe", "conhost.exe", "dllhost.exe",
        "WmiPrvSE.exe", "MsMpEng.exe", "TrustedInstaller.exe", "spoolsv.exe", 
        "LogonUI.exe", "iexplore.exe", "msedge.exe", "firefox.exe", "chrome.exe",
        "regedit.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "SystemSettings.exe", "WerFault.exe", "wuauclt.exe", "control.exe",
        "mstsc.exe", "netsh.exe", "tasklist.exe", "TeamViewer_Desktop.exe",
        "TeamViewer_Service.exe", "vmnat.exe", "vmtoolsd.exe", "program.exe",
        "reg.exe", "wmic.exe", "bitsadmin.exe", "certutil.exe", "schtasks.exe",
        "curl.exe", "mshta.exe", "rundll32.exe", "csc.exe", "msbuild.exe",
        "userinit.exe", "OfficeClickToRun.exe"
    )
    Telemetry = @{
        Enabled = $true
        MaxEvents = 1000
        Path = "$env:TEMP\security_rules\telemetry.json"
    }
    RetrySettings = @{
        MaxRetries = 3
        RetryDelaySeconds = 5
    }
    FirewallBatchSize = 100
}

# ASR Rule Mappings (Broadened for better matching)
$AsrRuleMappings = @{
    "block_office_child_process" = @{
        RuleId = "56a863a9-875e-4185-98a7-b882c64b5ce5"
        SigmaPatterns = @(
            "winword\.exe", "excel\.exe", "powerpnt\.exe", "outlook\.exe",
            "CommandLine:.*\.exe"
        )
    }
    "block_script_execution" = @{
        RuleId = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
        SigmaPatterns = @(
            "powershell\.exe", "wscript\.exe", "cscript\.exe",
            "CommandLine:.*\.ps1", "CommandLine:.*\.vbs", "CommandLine:.*\.js"
        )
    }
    "block_executable_email" = @{
        RuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
        SigmaPatterns = @(
            "outlook\.exe", "CommandLine:.*\.exe"
        )
    }
    "block_office_macros" = @{
        RuleId = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
        SigmaPatterns = @(
            "EventID:.*400", "macro"
        )
    }
    "block_usb_execution" = @{
        RuleId = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
        SigmaPatterns = @(
            "RemovableMedia", "autorun\.exe"
        )
    }
}

# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $color = switch ($EntryType) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    # Always write to console
    Write-Host "[$EntryType] $Message" -ForegroundColor $color
    
    # Write to log file
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    try {
        if (-not (Test-Path $Global:LogDir)) {
            New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null
        }
        $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "[Error] Failed to write to log file $Global:LogFile: $_" -ForegroundColor Red
    }
    
    # Write to Event Log
    try {
        Write-EventLog -LogName "Application" -Source "GRules" -EventId 1000 -EntryType $EntryType -Message $Message -ErrorAction Stop
    } catch {
        Write-Host "[Error] Failed to write to Event Log: $_" -ForegroundColor Red
    }
}

# Initialize Event Log
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("GRules")) {
        New-EventLog -LogName "Application" -Source "GRules"
        Write-Log "Created Event Log source: GRules"
    }
}

# Verify and Enable Process Creation Auditing
function Ensure-ProcessAuditing {
    try {
        # Check if running as administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log "Script not running with administrator privileges. Cannot enable process creation auditing." -EntryType "Error"
            $Global:ExitCode = 1
            return $false
        }

        # Check current audit status
        Write-Log "Checking process creation auditing status..."
        $auditStatus = auditpol /get /subcategory:"Process Creation" /r | ConvertFrom-Csv
        if ($auditStatus.'Success Auditing' -ne "Enable" -or $auditStatus.'Failure Auditing' -ne "Enable") {
            Write-Log "Process creation auditing is disabled (Success: $($auditStatus.'Success Auditing'), Failure: $($auditStatus.'Failure Auditing')). Enabling now..." -EntryType "Warning"
            
            # Execute auditpol command and capture output
            $auditPolOutput = & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
            $auditPolExitCode = $LASTEXITCODE
            
            if ($auditPolExitCode -ne 0) {
                Write-Log "Failed to enable process creation auditing. auditpol exit code: $auditPolExitCode. Output: $auditPolOutput" -EntryType "Error"
                $Global:ExitCode = 1
                return $false
            }

            # Verify again
            Start-Sleep -Milliseconds 500  # Brief delay to ensure policy update
            $auditStatus = auditpol /get /subcategory:"Process Creation" /r | ConvertFrom-Csv
            if ($auditStatus.'Success Auditing' -ne "Enable" -or $auditStatus.'Failure Auditing' -ne "Enable") {
                Write-Log "Failed to enable process creation auditing after execution. Current status - Success: $($auditStatus.'Success Auditing'), Failure: $($auditStatus.'Failure Auditing')" -EntryType "Error"
                $Global:ExitCode = 1
                return $false
            }
            
            Write-Log "Process creation auditing enabled successfully (Success: $($auditStatus.'Success Auditing'), Failure: $($auditStatus.'Failure Auditing'))"
            return $true
        } else {
            Write-Log "Process creation auditing is already enabled (Success: $($auditStatus.'Success Auditing'), Failure: $($auditStatus.'Failure Auditing'))"
            return $true
        }
    } catch {
        Write-Log "Error checking or enabling process creation auditing: $_" -EntryType "Error"
        $Global:ExitCode = 1
        return $false
    }
}

# Resolve Domain to IPs
function Resolve-DomainToIPs {
    param (
        [string]$Domain
    )
    $ips = @()
    if ([string]::IsNullOrWhiteSpace($Domain) -or $Domain -notmatch "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
        Write-Log "Invalid or empty domain provided to Resolve-DomainToIPs: '$Domain'" -EntryType "Warning"
        return $ips
    }
    try {
        $dnsResults = Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop
        $ips = $dnsResults | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
        Write-Log "Resolved domain $Domain to IPs: $($ips -join ', ')"
    } catch {
        Write-Log "Error resolving domain ${Domain}: $_" -EntryType "Warning"
    }
    return $ips
}

# Parse Rules (YARA, Sigma, Snort)
function Parse-Rules {
    param (
        [hashtable]$Rules
    )
    $indicators = @{ Hashes = @(); Files = @(); IPs = @(); Domains = @(); AsrRules = @() }
    
    # YARA Rules
    foreach ($file in $Rules.Yara) {
        try {
            $content = Get-Content $file -Raw
            # Parse hashes (relaxed pattern)
            $hashMatches = [regex]::Matches($content, 'hash\s*=\s*["'']?([0-9a-fA-F]{32,64})["'']?')
            foreach ($match in $hashMatches) {
                $hash = $match.Groups[1].Value
                $indicators.Hashes += @{ Type = "Hash"; Value = $hash; Source = "YARA"; RuleFile = $file }
                Write-Log "Parsed YARA hash: $hash from $file" -EntryType "Information"
            }
            # Parse filenames (stricter pattern)
            $fileMatches = [regex]::Matches($content, 'file\s*=\s*["'']?([a-zA-Z0-9][a-zA-Z0-9_\-\.]*\.(?:exe|dll|bat|ps1|cmd|vbs|js))["'']?')
            foreach ($match in $fileMatches) {
                $fileName = $match.Groups[1].Value
                if ($fileName -notin $Global:Config.ExcludedSystemFiles -and $fileName -notmatch '^(exe|dll|bat|ps1|cmd|Scr|DLL|Exe|EXE)$') {
                    $indicators.Files += @{ Type = "File"; Value = $fileName; Source = "YARA"; RuleFile = $file }
                    Write-Log "Parsed YARA file: $fileName from $file" -EntryType "Information"
                } else {
                    Write-Log "Invalid or excluded filename skipped: $fileName in $file" -EntryType "Warning"
                }
            }
            # Parse IPs
            $ipMatches = [regex]::Matches($content, '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
            foreach ($match in $ipMatches) {
                $indicators.IPs += @{ Type = "IP"; Value = $match.Value; Source = "YARA"; RuleFile = $file }
            }
            # Parse domains
            $domainMatches = [regex]::Matches($content, '\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
            foreach ($match in $domainMatches) {
                $domain = $match.Value
                if ($domain -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
                    $indicators.Domains += @{ Type = "Domain"; Value = $domain; Source = "YARA"; RuleFile = $file }
                    Write-Log "Parsed YARA domain: $domain from $file" -EntryType "Information"
                } else {
                    Write-Log "Invalid domain skipped: $domain in $file" -EntryType "Warning"
                }
            }
        } catch {
            Write-Log "Error parsing YARA rule ${file}: $_" -EntryType "Warning"
        }
    }
    
    # Sigma Rules
    if (Get-Module -ListAvailable -Name PowerShell-YAML) {
        foreach ($file in $Rules.Sigma) {
            try {
                $yaml = ConvertFrom-Yaml (Get-Content $file -Raw)
                $condition = $yaml.condition
                foreach ($ruleName in $AsrRuleMappings.Keys) {
                    $patterns = $AsrRuleMappings[$ruleName].SigmaPatterns
                    foreach ($pattern in $patterns) {
                        if ($condition -match $pattern) {
                            $indicators.AsrRules += @{ Type = "ASR"; RuleId = $AsrRuleMappings[$ruleName].RuleId; Source = "Sigma"; RuleFile = $file }
                            Write-Log "Matched Sigma rule for ASR $ruleName in $file" -EntryType "Information"
                            break
                        }
                    }
                }
                # Parse filenames from Sigma
                $fileMatches = [regex]::Matches($condition, '\bImage:.*\\([a-zA-Z0-9][a-zA-Z0-9_\-\.]*\.(?:exe|dll|bat|ps1|cmd|vbs|js))\b')
                foreach ($match in $fileMatches) {
                    $fileName = $match.Groups[1].Value
                    if ($fileName -notin $Global:Config.ExcludedSystemFiles -and $fileName -notmatch '^(exe|dll|bat|ps1|cmd|Scr|DLL|Exe|EXE)$') {
                        $indicators.Files += @{ Type = "File"; Value = $fileName; Source = "Sigma"; RuleFile = $file }
                        Write-Log "Parsed Sigma file: $fileName from $file" -EntryType "Information"
                    } else {
                        Write-Log "Invalid or excluded filename skipped: $fileName in $file" -EntryType "Warning"
                    }
                }
            } catch {
                Write-Log "Error parsing Sigma rule ${file}: $_" -EntryType "Warning"
            }
        }
    } else {
        Write-Log "PowerShell-YAML module not installed, skipping Sigma rule parsing" -EntryType "Warning"
    }
    
    # Snort Rules
    foreach ($file in $Rules.Snort) {
        try {
            $content = Get-Content $file -Raw
            $ipMatches = [regex]::Matches($content, '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
            foreach ($match in $ipMatches) {
                $indicators.IPs += @{ Type = "IP"; Value = $match.Value; Source = "Snort"; RuleFile = $file }
            }
            $domainMatches = [regex]::Matches($content, '\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
            foreach ($match in $domainMatches) {
                $domain = $match.Value
                if ($domain -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
                    $indicators.Domains += @{ Type = "Domain"; Value = $domain; Source = "Snort"; RuleFile = $file }
                    Write-Log "Parsed Snort domain: $domain from $file" -EntryType "Information"
                } else {
                    Write-Log "Invalid domain skipped: $domain in $file" -EntryType "Warning"
                }
            }
        } catch {
            Write-Log "Error parsing Snort rule ${file}: $_" -EntryType "Warning"
        }
    }
    
    # Merge and deduplicate indicators
    $indicators.Hashes = $indicators.Hashes | Group-Object -Property Value | ForEach-Object { $_.Group[0] }
    $indicators.Files = $indicators.Files | Group-Object -Property Value | ForEach-Object { $_.Group[0] }
    $indicators.IPs = $indicators.IPs | Group-Object -Property Value | ForEach-Object { 
        $group = $_.Group
        $source = ($group.Source -join '')
        $ruleFile = ($group.RuleFile -join '')
        Write-Log "Merged indicator: Type=IP, Value=$($group[0].Value), Source=$source, RuleFile=$ruleFile"
        @{ Type = "IP"; Value = $group[0].Value; Source = $source; RuleFile = $ruleFile }
    }
    $indicators.Domains = $indicators.Domains | Group-Object -Property Value | ForEach-Object { $_.Group[0] }
    $indicators.AsrRules = $indicators.AsrRules | Group-Object -Property RuleId | ForEach-Object { $_.Group[0] }
    
    Write-Log "Parsed $($indicators.Hashes.Count + $indicators.Files.Count + $indicators.IPs.Count + $indicators.Domains.Count + $indicators.AsrRules.Count) unique indicators from rules (Hashes: $($indicators.Hashes.Count), Files: $($indicators.Files.Count), IPs: $($indicators.IPs.Count), Domains: $($indicators.Domains.Count), ASR: $($indicators.AsrRules.Count))."
    return $indicators
}

# Apply Security Rules
function Apply-SecurityRules {
    param (
        [hashtable]$Indicators
    )
    
    # Apply ASR Rules
    foreach ($asr in $Indicators.AsrRules) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $asr.RuleId -AttackSurfaceReductionRules_Actions Enabled
            Write-Log "Applied ASR rule: $($asr.RuleId)"
        } catch {
            Write-Log "Error applying ASR rule $($asr.RuleId): $_" -EntryType "Warning"
        }
    }
    
    # Apply filename exclusions
    foreach ($file in $Indicators.Files) {
        try {
            Add-MpPreference -ExclusionPath $file.Value
            Write-Log "Added filename exclusion for monitoring: $($file.Value) from $($file.Source)"
        } catch {
            Write-Log "Error adding exclusion for $($file.Value): $_" -EntryType "Warning"
        }
    }
    
    # Remove existing firewall rules
    Get-NetFirewallRule -DisplayName "Block C2 IPs Batch*" | Remove-NetFirewallRule
    Write-Log "Removed $(@(Get-NetFirewallRule -DisplayName "Block C2 IPs Batch*").Count) existing firewall rules"
    
    # Apply IP-based firewall rules
    $ipBatch = @()
    $batchCount = 0
    $batchSize = $Global:Config.FirewallBatchSize
    foreach ($ip in $Indicators.IPs) {
        $ipBatch += $ip.Value
        if ($ipBatch.Count -ge $batchSize -or $ip -eq $Indicators.IPs[-1]) {
            $batchCount++
            $ruleName = "Block_C2_IPs_$batchCount"
            try {
                New-NetFirewallRule -DisplayName "Block C2 IPs Batch $batchCount" -Name $ruleName -Direction Outbound -Action Block -RemoteAddress $ipBatch -Enabled True
                Write-Log "Created firewall rule $ruleName for $($ipBatch.Count) IPs"
                Get-NetFirewallRule -Name $ruleName | Format-List | Out-String | ForEach-Object { Write-Log $_ }
            } catch {
                Write-Log "Error creating firewall rule ${ruleName}: $_" -EntryType "Warning"
            }
            $ipBatch = @()
        }
    }
    
    # Apply domain-based firewall rules
    Write-Log "Applying $($Indicators.Domains.Count) domain-based firewall rules..."
    $domainIps = @()
    foreach ($domain in $Indicators.Domains) {
        $ips = Resolve-DomainToIPs -Domain $domain.Value
        if ($ips) {
            $domainIps += $ips
        } else {
            Write-Log "No IPs resolved for domain $($domain.Value), skipping firewall rule" -EntryType "Warning"
        }
    }
    
    $ipBatch = @()
    $batchCount = 0
    foreach ($ip in $domainIps) {
        $ipBatch += $ip
        if ($ipBatch.Count -ge $batchSize -or $ip -eq $domainIps[-1]) {
            $batchCount++
            $ruleName = "Block_C2_Domain_IPs_$batchCount"
            try {
                New-NetFirewallRule -DisplayName "Block C2 Domain IPs Batch $batchCount" -Name $ruleName -Direction Outbound -Action Block -RemoteAddress $ipBatch -Enabled True
                Write-Log "Created firewall rule $ruleName for $($ipBatch.Count) IPs from domains: $($Indicators.Domains.Value -join ', ')"
            } catch {
                Write-Log "Error creating firewall rule ${ruleName}: $_" -EntryType "Warning"
            }
            $ipBatch = @()
        }
    }
    Write-Log "Applying firewall rules for $($domainIps.Count) resolved domain IPs in $batchCount batches..."
    
    Write-Log "Applied $($Indicators.AsrRules.Count) ASR rules, $($Indicators.Hashes.Count) hash-based threats, $($Indicators.Files.Count) filename exclusions, $($Indicators.IPs.Count) IP-based firewall rules, and $($Indicators.Domains.Count) domain-based firewall rules (from $($Indicators.Domains.Count) domains)"
}

# Monitor Processes
function Monitor-Processes {
    if ($NoMonitor) { return }
    Write-Log "Starting process monitoring..."
    try {
        $events = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents $Global:Config.Telemetry.MaxEvents
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $processName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" } | Select-Object -ExpandProperty "#text"
            $processId = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessId" } | Select-Object -ExpandProperty "#text"
            $parentProcessName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessName" } | Select-Object -ExpandProperty "#text"
            Write-Log "Logged process: $processName (PID: $processId, Parent: $parentProcessName)"
        }
        if (-not $events) {
            Write-Log "No process creation events found in Security Event Log. Ensure process creation auditing is enabled (Local Security Policy > Audit Process Creation)." -EntryType "Warning"
            Write-Log "Run 'auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable' to enable auditing." -EntryType "Warning"
        }
    } catch {
        Write-Log "Error querying process creation events: $_" -EntryType "Warning"
    }
}

# Download and verify YARA, Sigma, and Snort rules
function Get-SecurityRules {
    param ($Config)
    
    $tempDir = "$env:TEMP\security_rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $successfulSources = @()
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }

    try {
        Add-MpPreference -ExclusionPath $tempDir
        Write-Log "Added Defender exclusion for $tempDir"

        # YARA Forge rules
        Write-Log "Processing YARA Forge rules..."
        $yaraForgeDir = "$tempDir\yara_forge"
        $yaraForgeZip = "$tempDir\yara_forge.zip"
        if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
        $yaraForgeUri = Get-YaraForgeUrl
        $yaraRuleCount = 0
        
        if (-not $yaraForgeUri) {
            Write-Log "YARA Forge URL unavailable, trying fallback..." -EntryType "Warning"
        }
        elseif (Test-Url -Uri $yaraForgeUri) {
            if (Test-RuleSourceUpdated -Uri $yaraForgeUri -LocalFile $yaraForgeZip) {
                if (Invoke-WebRequestWithRetry -Uri $yaraForgeUri -OutFile $yaraForgeZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $yaraForgeZip -ScanType CustomScan
                    Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
                    $rules.Yara += Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar" | Select-Object -ExpandProperty FullName
                    $yaraRuleCount = ($rules.Yara | ForEach-Object { Get-YaraRuleCount -FilePath $_ } | Measure-Object -Sum).Sum
                    Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                    $successfulSources += "YARA Forge"
                }
            } else {
                Write-Log "YARA Forge rules are up to date"
                $rules.Yara += Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar" | Select-Object -ExpandProperty FullName
                $yaraRuleCount = ($rules.Yara | ForEach-Object { Get-YaraRuleCount -FilePath $_ } | Measure-Object -Sum).Sum
                Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                $successfulSources += "YARA Forge"
            }
        }

        # SigmaHQ rules
        Write-Log "Processing SigmaHQ rules..."
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        if (Test-Url -Uri $Config.Sources.SigmaHQ) {
            if (Test-RuleSourceUpdated -Uri $Config.Sources.SigmaHQ -LocalFile $sigmaZip) {
                if (Invoke-WebRequestWithRetry -Uri $Config.Sources.SigmaHQ -OutFile $sigmaZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $sigmaZip -ScanType CustomScan
                    Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
                    $rules.Sigma += Get-ChildItem -Path "$sigmaDir\sigma-master\rules" -Recurse -Include "*.yml" | Select-Object -ExpandProperty FullName
                    Write-Log "Downloaded and extracted SigmaHQ rules"
                    Write-Log "Found $($rules.Sigma.Count) Sigma rules in $sigmaDir\sigma-master\rules"
                    $successfulSources += "SigmaHQ"
                }
            } else {
                Write-Log "SigmaHQ rules are up to date"
                $rules.Sigma += Get-ChildItem -Path "$sigmaDir\sigma-master\rules" -Recurse -Include "*.yml" | Select-Object -ExpandProperty FullName
                Write-Log "Found $($rules.Sigma.Count) Sigma rules in $sigmaDir\sigma-master\rules"
                $successfulSources += "SigmaHQ"
            }
        }

        # Snort Community rules
        Write-Log "Processing Snort Community rules..."
        $snortDir = "$tempDir\snort"
        $snortZip = "$tempDir\snort_community.tar.gz"
        if (-not (Test-Path $snortDir)) { New-Item -ItemType Directory -Path $snortDir -Force | Out-Null }
        $snortUri = if ($SnortOinkcode) { "$($Config.Sources.SnortCommunity)?oinkcode=$SnortOinkcode" } else { $Config.Sources.SnortCommunity }
        if (Test-Url -Uri $snortUri) {
            if (Test-RuleSourceUpdated -Uri $snortUri -LocalFile $snortZip) {
                if (Invoke-WebRequestWithRetry -Uri $snortUri -OutFile $snortZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $snortZip -ScanType CustomScan
                    Expand-Archive -Path $snortZip -DestinationPath $snortDir -Force
                    $rules.Snort += Get-ChildItem -Path $snortDir -Recurse -Include "*.rules" | Select-Object -ExpandProperty FullName
                    Write-Log "Downloaded and extracted Snort Community rules"
                    $successfulSources += "Snort Community"
                }
            } else {
                Write-Log "Snort Community rules are up to date"
                $rules.Snort += Get-ChildItem -Path $snortDir -Recurse -Include "*.rules" | Select-Object -ExpandProperty FullName
                $successfulSources += "Snort Community"
            }
        } else {
            Write-Log "Snort Community URL is invalid or no Oinkcode provided, trying fallback..." -EntryType "Warning"
            # Fallback to Emerging Threats
            Write-Log "Processing Emerging Threats rules as fallback..."
            $etZip = "$tempDir\emerging_threats.tar.gz"
            if (Test-Url -Uri $Config.Sources.EmergingThreats) {
                if (Test-RuleSourceUpdated -Uri $Config.Sources.EmergingThreats -LocalFile $etZip) {
                    if (Invoke-WebRequestWithRetry -Uri $Config.Sources.EmergingThreats -OutFile $etZip -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $etZip -ScanType CustomScan
                        Expand-Archive -Path $etZip -DestinationPath $snortDir -Force
                        $rules.Snort += Get-ChildItem -Path $snortDir -Recurse -Include "*.rules" | Select-Object -ExpandProperty FullName
                        Write-Log "Downloaded and extracted Emerging Threats rules"
                        $successfulSources += "Emerging Threats"
                    }
                } else {
                    Write-Log "Emerging Threats rules are up to date"
                    $rules.Snort += Get-ChildItem -Path $snortDir -Recurse -Include "*.rules" | Select-Object -ExpandProperty FullName
                    $successfulSources += "Emerging Threats"
                }
            }
        }

        Write-Log "Successfully processed rules from: $($successfulSources -join ', ')"
        return $rules
    } catch {
        Write-Log "Error in Get-SecurityRules: $_" -EntryType "Error"
        $Global:ExitCode = 1
        return $rules
    } finally {
        Remove-MpPreference -ExclusionPath $tempDir
        Write-Log "Removed Defender exclusion for $tempDir"
    }
}

# Validate URL accessibility with retry
function Test-Url {
    param (
        [string]$Uri,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 2
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        }
        catch {
            $attempt++
            Write-Log "URL validation failed for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $false
            }
            
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $false
}

# Check if rule source has been updated
function Test-RuleSourceUpdated {
    param (
        [string]$Uri,
        [string]$LocalFile,
        [int]$MaxRetries = 3
    )
    
    $attempt = 0
    $delay = 2
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Checking update for ${Uri}..."
            $webRequest = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 15
            $lastModified = $webRequest.Headers['Last-Modified']
            
            if ($lastModified) {
                $lastModifiedDate = [DateTime]::Parse($lastModified)
                if (Test-Path $LocalFile) {
                    $fileLastModified = (Get-Item $LocalFile).LastWriteTime
                    return $lastModifiedDate -gt $fileLastModified
                }
                return $true
            }
            return $true
        }
        catch {
            $attempt++
            Write-Log "Error checking update for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $true
            }
            
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $true
}

# Get latest YARA Forge release URL
function Get-YaraForgeUrl {
    try {
        $releases = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases" -UseBasicParsing
        $latest = ($releases.Content | ConvertFrom-Json)[0]
        $asset = $latest.assets | Where-Object { $_.name -match "yara-forge-.*-full\.zip|rules-full\.zip" } | Select-Object -First 1
        if ($asset) {
            Write-Log "Found YARA Forge release: $($asset.name)"
            return $asset.browser_download_url
        }
        Write-Log "No valid YARA Forge full zip found" -EntryType "Warning"
        return $null
    }
    catch {
        Write-Log "Error fetching YARA Forge release: $_" -EntryType "Warning"
        return $null
    }
}

# Count individual YARA rules in a file
function Get-YaraRuleCount {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return 0 }
        $content = Get-Content $FilePath -Raw
        $ruleMatches = [regex]::Matches($content, 'rule\s+\w+\s*\{')
        return $ruleMatches.Count
    }
    catch {
        Write-Log "Error counting rules in ${FilePath}: $_" -EntryType "Warning"
        return 0
    }
}

# Improved web request with retry and exponential backoff
function Invoke-WebRequestWithRetry {
    param (
        [string]$Uri, 
        [string]$OutFile, 
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 5,
        [switch]$UseExponentialBackoff
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Downloading ${Uri} (Attempt $(${attempt}+1))..."
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec 30 -UseBasicParsing
            return $true
        }
        catch {
            $attempt++
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
            Write-Log "Download attempt $attempt for ${Uri} failed: $_ (Status: $statusCode)" -EntryType "Warning"
            
            if ($attempt -eq $MaxRetries) { 
                return $false 
            }
            
            Start-Sleep -Seconds $delay
            if ($UseExponentialBackoff) {
                $delay *= 2
            }
        }
    }
    return $false
}

# Main Execution
try {
    Write-Log "Starting GRules execution..."
    Initialize-EventLog

    # Ensure process auditing is enabled
    if (-not (Ensure-ProcessAuditing)) {
        Write-Log "Process creation auditing could not be enabled. Continuing with other tasks (process monitoring will be skipped)." -EntryType "Warning"
        $Global:ExitCode = 1  # Indicate partial failure
    }

    # Get rules
    $rules = Get-SecurityRules -Config $Global:Config
    if (-not $rules.Yara -and -not $rules.Sigma -and -not $rules.Snort) {
        Write-Log "No rules retrieved. Exiting." -EntryType "Error"
        $Global:ExitCode = 1
        exit $Global:ExitCode
    }

    # Parse rules
    $indicators = Parse-Rules -Rules $rules
    if (-not $indicators.Hashes -and -not $indicators.Files -and -not $indicators.IPs -and -not $indicators.Domains -and -not $indicators.AsrRules) {
        Write-Log "No indicators parsed from rules. Exiting." -EntryType "Error"
        $Global:ExitCode = 1
        exit $Global:ExitCode
    }

    # Apply rules
    Apply-SecurityRules -Indicators $indicators

    # Monitor processes
    Monitor-Processes

    Write-Log "GRules execution completed successfully"
} catch {
    Write-Log "Script execution failed: $_" -EntryType "Error"
    $Global:ExitCode = 1
} finally {
    Write-Log "Script execution finished with exit code $Global:ExitCode"
    exit $Global:ExitCode
}