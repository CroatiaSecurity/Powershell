
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

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Global:ExitCode = 0
$Global:LogDir = "$env:TEMP\security_rules\logs"
$Global:LogFile = "$Global:LogDir\GRules_$(Get-Date -Format 'yyyyMMdd').log"

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
        "WmiPrvSE.exe", "MsMpEng.exe", "TrustedInstaller.exe", "spoolsv.exe", "LogonUI.exe"
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

# ASR Rule Mappings
$AsrRuleMappings = @{
    "block_office_child_process" = @{
        RuleId = "56a863a9-875e-4185-98a7-b882c64b5ce5"
        SigmaPatterns = @("detection.selection.Image: *\\winword.exe", "detection.selection.ParentImage: *\\excel.exe", "detection.selection.ParentImage: *\\powerpnt.exe")
    }
    "block_script_execution" = @{
        RuleId = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
        SigmaPatterns = @("detection.selection.Image: *\\powershell.exe", "detection.selection.Image: *\\wscript.exe", "detection.selection.Image: *\\cscript.exe")
    }
    "block_executable_email" = @{
        RuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
        SigmaPatterns = @("detection.selection.Image: *\\outlook.exe", "detection.selection.ParentImage: *\\outlook.exe")
    }
    "block_office_macros" = @{
        RuleId = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
        SigmaPatterns = @("detection.selection.EventID: 400", "detection.selection.EventType: Macro")
    }
    "block_usb_execution" = @{
        RuleId = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
        SigmaPatterns = @("detection.selection.DeviceName: *RemovableMedia*")
    }
}

# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $maxEventLogLength = 32766
    if (-not (Test-Path $Global:LogDir)) {
        New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null
    }
    
    $truncatedMessage = if ($Message.Length -gt $maxEventLogLength) {
        $Message.Substring(0, $maxEventLogLength - 100) + "... [Truncated, see log file]"
    } else {
        $Message
    }
    
    $color = switch ($EntryType) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$EntryType] $truncatedMessage" -ForegroundColor $color
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    
    try {
        Write-EventLog -LogName "Application" -Source "GRules" -EventId 1000 -EntryType $EntryType -Message $truncatedMessage -ErrorAction Stop
    } catch {
        $errorMsg = "Failed to write to Event Log: $_"
        $errorMsg | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    }
}

# Initialize Event Log
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("GRules")) {
        New-EventLog -LogName "Application" -Source "GRules"
        Write-Log "Created Event Log source: GRules"
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
                    Write-Log "Downloaded and extracted YARA Forge rules"
                    $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    foreach ($file in $rules.Yara) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                    $successfulSources += "YARA Forge"
                } else {
                    Write-Log "Failed to download YARA Forge rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "YARA Forge rules are up to date"
                $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                foreach ($file in $rules.Yara) {
                    $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                }
                Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                $successfulSources += "YARA Forge"
            }
        } else {
            Write-Log "YARA Forge URL is invalid, trying fallback..." -EntryType "Warning"
        }

        # Yara-Rules fallback
        if (-not ($successfulSources -contains "YARA Forge") -or $yaraRuleCount -lt 10) {
            Write-Log "Processing Yara-Rules as fallback due to low YARA Forge rule count ($yaraRuleCount)..."
            $yaraRulesDir = "$tempDir\yara_rules"
            $yaraRulesZip = "$tempDir\yara_rules.zip"
            if (-not (Test-Path $yaraRulesDir)) { New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null }
            $yaraRulesUri = $Config.Sources.YaraRules
            
            if (Test-Url -Uri $yaraRulesUri) {
                if (Test-RuleSourceUpdated -Uri $yaraRulesUri -LocalFile $yaraRulesZip) {
                    if (Invoke-WebRequestWithRetry -Uri $yaraRulesUri -OutFile $yaraRulesZip -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $yaraRulesZip -ScanType CustomScan
                        Expand-Archive -Path $yaraRulesZip -DestinationPath $yaraRulesDir -Force
                        Write-Log "Downloaded and extracted Yara-Rules"
                        $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                        $rules.Yara += $yaraRulesFiles
                        $yaraRuleCount = 0
                        foreach ($file in $yaraRulesFiles) {
                            $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                        }
                        Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                        $successfulSources += "Yara-Rules"
                    } else {
                        Write-Log "Failed to download Yara-Rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Yara-Rules are up to date"
                    $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    $rules.Yara += $yaraRulesFiles
                    $yaraRuleCount = 0
                    foreach ($file in $yaraRulesFiles) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                    $successfulSources += "Yara-Rules"
                }
            } else {
                Write-Log "Yara-Rules URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        # SigmaHQ rules
        Write-Log "Processing SigmaHQ rules..."
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        $sigmaUri = $Config.Sources.SigmaHQ
        
        if (Test-Url -Uri $sigmaUri) {
            if (Test-RuleSourceUpdated -Uri $sigmaUri -LocalFile $sigmaZip) {
                if (Invoke-WebRequestWithRetry -Uri $sigmaUri -OutFile $sigmaZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $sigmaZip -ScanType CustomScan
                    Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
                    Write-Log "Downloaded and extracted SigmaHQ rules"
                    $successfulSources += "SigmaHQ"
                } else {
                    Write-Log "Failed to download SigmaHQ rules after retries, skipping..." -EntryType "Warning"
                }
            } else {
                Write-Log "SigmaHQ rules are up to date"
                $successfulSources += "SigmaHQ"
            }
        } else {
            Write-Log "SigmaHQ URL is invalid, skipping..." -EntryType "Warning"
        }
        
        $sigmaRulesPath = "$sigmaDir\sigma-master\rules"
        if (Test-Path $sigmaRulesPath) {
            $rules.Sigma = Get-ChildItem -Path $sigmaRulesPath -Recurse -Include "*.yml" -Exclude "*deprecated*" -ErrorAction SilentlyContinue
            Write-Log "Found $($rules.Sigma.Count) Sigma rules in $sigmaRulesPath"
        } else {
            Write-Log "Sigma rules directory $sigmaRulesPath does not exist" -EntryType "Warning"
        }

        # Snort Community rules
        Write-Log "Processing Snort Community rules..."
        $snortRules = "$tempDir\snort_community.rules"
        $snortUri = if ($SnortOinkcode) {
            "$($Config.Sources.SnortCommunity)?oinkcode=$SnortOinkcode"
        } else {
            Write-Log "No Snort Oinkcode provided. Snort Community rules require an Oinkcode from https://www.snort.org/users/sign_up" -EntryType "Warning"
            $null
        }
        
        if ($snortUri -and (Test-Url -Uri $snortUri)) {
            if (Test-RuleSourceUpdated -Uri $snortUri -LocalFile $snortRules) {
                if (Invoke-WebRequestWithRetry -Uri $snortUri -OutFile $snortRules -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $snortRules -ScanType CustomScan
                    try {
                        Write-Log "Checking Snort Community hash..."
                        $snortPage = Invoke-WebRequest -Uri "https://www.snort.org/downloads" -UseBasicParsing -TimeoutSec 15
                        if ($snortPage.Content -match 'community-rules\.tar\.gz\.md5.*([a-f0-9]{32})') {
                            $expectedHash = $matches[1]
                            $fileHash = (Get-FileHash -Path $snortRules -Algorithm MD5).Hash
                            if ($fileHash -ne $expectedHash) {
                                Write-Log "Snort Community rules hash mismatch!" -EntryType "Error"
                                throw "Snort Community rules hash verification failed"
                            }
                            Write-Log "Snort Community rules hash verified"
                        } else {
                            Write-Log "Snort Community hash not found, proceeding without verification" -EntryType "Warning"
                        }
                    }
                    catch {
                        Write-Log "Error checking Snort Community hash: $_" -EntryType "Warning"
                    }
                    Write-Log "Downloaded Snort Community rules"
                    $successfulSources += "Snort Community"
                    $rules.Snort += $snortRules
                } else {
                    Write-Log "Failed to download Snort Community rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "Snort Community rules are up to date"
                $successfulSources += "Snort Community"
                $rules.Snort += $snortRules
            }
        } else {
            Write-Log "Snort Community URL is invalid or no Oinkcode provided, trying fallback..." -EntryType "Warning"
        }

        # Emerging Threats fallback
        if (-not ($successfulSources -contains "Snort Community")) {
            Write-Log "Processing Emerging Threats rules as fallback..."
            $emergingRules = "$tempDir\snort_emerging.rules"
            $emergingUri = $Config.Sources.EmergingThreats
            $emergingTar = "$tempDir\emerging_rules.tar.gz"
            
            if (Test-Url -Uri $emergingUri) {
                if (Test-RuleSourceUpdated -Uri $emergingUri -LocalFile $emergingTar) {
                    if (Invoke-WebRequestWithRetry -Uri $emergingUri -OutFile $emergingTar -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $emergingTar -ScanType CustomScan
                        try {
                            $hashUri = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz.md5"
                            $hashResponse = Invoke-WebRequest -Uri $hashUri -UseBasicParsing -TimeoutSec 15
                            if ($hashResponse.Content -match '([a-f0-9]{32})') {
                                $expectedHash = $matches[1]
                                $fileHash = (Get-FileHash -Path $emergingTar -Algorithm MD5).Hash
                                if ($fileHash -ne $expectedHash) {
                                    Write-Log "Emerging Threats rules hash mismatch!" -EntryType "Error"
                                    throw "Emerging Threats rules hash verification failed"
                                }
                                Write-Log "Emerging Threats rules hash verified"
                            } else {
                                Write-Log "Emerging Threats hash not found, proceeding without verification" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error checking Emerging Threats hash: $_" -EntryType "Warning"
                        }
                        
                        try {
                            tar -xzf $emergingTar -C $tempDir
                            if (Test-Path "$tempDir\rules") {
                                Move-Item -Path "$tempDir\rules\*.rules" -Destination $emergingRules -Force
                                Write-Log "Downloaded and extracted Emerging Threats rules"
                                $successfulSources += "Emerging Threats"
                                $rules.Snort += $emergingRules
                            } else {
                                Write-Log "Emerging Threats extraction failed: rules directory not found" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error extracting Emerging Threats rules: $_" -EntryType "Warning"
                        }
                    } else {
                        Write-Log "Failed to download Emerging Threats rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Emerging Threats rules are up to date"
                    $successfulSources += "Emerging Threats"
                    $rules.Snort += $emergingRules
                }
            } else {
                Write-Log "Emerging Threats URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        if ($successfulSources.Count -eq 0) {
            Write-Log "No rule sources were successfully processed!" -EntryType "Error"
            throw "No valid rule sources available"
        }
        
        Write-Log "Successfully processed rules from: $($successfulSources -join ', ')"
        return $rules
    }
    catch {
        Write-Log "Error in Get-SecurityRules: $_" -EntryType "Error"
        return $rules
    }
    finally {
        Write-Log "Completed Get-SecurityRules execution"
    }
}

# Parse rules for actionable indicators and ASR rules
function Parse-Rules {
    param (
        $Rules,
        $Config
    )

    $indicators = @()
    $asrRulesToApply = @()
    $batchSize = 1000
    $systemFiles = $Config.ExcludedSystemFiles
    $debugSamples = @()
    $isDebug = $DebugMode -or (-not (Test-Path "$env:TEMP\security_rules\debug_done.txt"))

    if ($isDebug -and -not $DebugMode) {
        Write-Log "Debug mode enabled for first run to capture unmatched rule samples"
    }

    # YARA rule parsing
    Write-Log "Parsing YARA rules..."
    $yaraCount = $Rules.Yara.Count
    $processed = 0
    $yaraBatches = [math]::Ceiling($yaraCount / $batchSize)
    
    for ($i = 0; $i -lt $yaraBatches; $i++) {
        $batch = $Rules.Yara | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) { 
                    Write-Log "YARA rule file $($rule.FullName) not found" -EntryType "Warning"
                    continue 
                }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                
                # Hash extraction
                $hashPatterns = @(
                    '(?i)meta:.*?(md5|hash)\s*=\s*"`"([a-f0-9]{32})`""',
                    '(?i)meta:.*?(sha1|hash1)\s*=\s*"`"([a-f0-9]{40})`""',
                    '(?i)meta:.*?(sha256|hash256)\s*=\s*"`"([a-f0-9]{64})`""',
                    '(?i)\$[a-z0-9_]*\s*=\s*"`"([a-f0-9]{32,64})`"\s*\/\*\s*(md5|sha1|sha256)\s*\*\/'
                )
                
                foreach ($pattern in $hashPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $hash = $match.Groups[2].Value
                        $indicators += @{ Type = "Hash"; Value = $hash; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA hash: $hash in $($rule.FullName)"
                    }
                }
                
                # Filename extraction
                $filenamePatterns = @(
                    '(?i)meta:.*?(filename|file_name|original_filename)\s*=\s*"`"([^`"]+\.(exe|dll|bat|ps1|scr|cmd))`""',
                    '(?i)\$[a-z0-9_]*\s*=\s*"`"([^`"]*\.(exe|dll|bat|ps1|scr|cmd))`""',
                    '(?i)fullword\s+ascii\s+"`"([^`"]*\.(exe|dll|bat|ps1|scr|cmd))`""'
                )
                
                foreach ($pattern in $filenamePatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $fileName = $match.Groups[2].Value -replace '\\\\', '\'
                        $baseFileName = [System.IO.Path]::GetFileName($fileName)
                        if ($baseFileName -and $baseFileName -notin $systemFiles -and $baseFileName -match '^[a-zA-Z0-9_\-\.]+\.(exe|dll|bat|ps1|scr|cmd)$') {
                            $indicators += @{ Type = "FileName"; Value = $baseFileName; Source = "YARA"; RuleFile = $rule.Name }
                            Write-Log "Found YARA filename: $baseFileName in $($rule.FullName)"
                        } else {
                            Write-Log "Invalid or excluded filename skipped: $baseFileName in $($rule.FullName)" -EntryType "Warning"
                        }
                    }
                }
                
                # Domain and URL extraction
                $domainPatterns = @(
                    '(?i)meta:.*?(domain|url|c2|command_and_control)\s*=\s*"`"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`""',
                    '(?i)\$[a-z0-9_]*\s*=\s*"`"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`""',
                    '(?i)fullword\s+ascii\s+"`"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`""',
                    '(?i)content\s*:.*?"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"'
                )
                
                foreach ($pattern in $domainPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $domain = $match.Groups[2].Value
                        $indicators += @{ Type = "Domain"; Value = $domain; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA domain: $domain in $($rule.FullName)"
                    }
                }
                
                if ($isDebug -and -not ($indicators | Where-Object { $_.Source -eq "YARA" -and $_.RuleFile -eq $rule.Name })) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "YARA rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 25 -eq 0 -or $processed -eq $yaraCount) {
                    Write-Log "Processed $processed/$yaraCount YARA rules"
                }
            }
            catch {
                Write-Log "Error parsing YARA rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "YARA"}).Count -eq 0) {
        Write-Log "No indicators extracted from YARA rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\yara_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched YARA rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Sigma rule parsing
    Write-Log "Parsing Sigma rules..."
    $sigmaCount = $Rules.Sigma.Count
    $processed = 0
    $sigmaBatches = [math]::Ceiling($sigmaCount / $batchSize)
    $yamlModule = Get-Module -ListAvailable -Name PowerShell-YAML
    
    if (-not $yamlModule) {
        Write-Log "PowerShell-YAML module not found, falling back to regex parsing for Sigma rules" -EntryType "Warning"
    }
    
    for ($i = 0; $i -lt $sigmaBatches; $i++) {
        $batch = $Rules.Sigma | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) {
                    Write-Log "Sigma rule file $($rule.FullName) not found" -EntryType "Warning"
                    continue
                }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                $fileNames = @()
                
                if ($yamlModule) {
                    try {
                        $yaml = ConvertFrom-Yaml -Yaml $content -ErrorAction Stop
                        Write-Log "Successfully parsed YAML for $($rule.FullName)"
                        
                        if ($yaml.detection) {
                            foreach ($selectionKey in $yaml.detection.Keys) {
                                $selection = $yaml.detection[$selectionKey]
                                if ($selection -is [hashtable] -or $selection -is [System.Collections.Specialized.OrderedDictionary]) {
                                    # Extract filenames
                                    foreach ($key in @('Image', 'TargetFilename', 'CommandLine', 'ParentImage', 'OriginalFileName', 'ProcessName', 'FileName')) {
                                        $value = $selection[$key]
                                        if ($value -is [string] -and $value -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                            $fileName = [System.IO.Path]::GetFileName($value)
                                            if ($fileName -and $fileName -notin $systemFiles -and $fileName -match '^[a-zA-Z0-9_\-\.]+\.(exe|dll|bat|ps1|scr|cmd)$') {
                                                $fileNames += $fileName
                                            } else {
                                                Write-Log "Invalid or excluded filename skipped: $fileName in $($rule.FullName)" -EntryType "Warning"
                                            }
                                        }
                                        elseif ($value -is [array]) {
                                            foreach ($item in $value) {
                                                if ($item -is [string] -and $item -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                                    $fileName = [System.IO.Path]::GetFileName($item)
                                                    if ($fileName -and $fileName -notin $systemFiles -and $fileName -match '^[a-zA-Z0-9_\-\.]+\.(exe|dll|bat|ps1|scr|cmd)$') {
                                                        $fileNames += $fileName
                                                    } else {
                                                        Write-Log "Invalid or excluded filename skipped: $fileName in $($rule.FullName)" -EntryType "Warning"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    # Check for ASR-compatible conditions
                                    foreach ($asrRule in $AsrRuleMappings.GetEnumerator()) {
                                        foreach ($pattern in $asrRule.Value.SigmaPatterns) {
                                            if ($content -match $pattern) {
                                                $asrRulesToApply += @{
                                                    RuleId = $asrRule.Value.RuleId
                                                    Source = "Sigma"
                                                    RuleFile = $rule.Name
                                                }
                                                Write-Log "Found ASR-compatible Sigma rule: $($asrRule.Key) in $($rule.FullName)"
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-Log "No detection section found in Sigma rule $($rule.FullName)" -EntryType "Warning"
                        }
                    }
                    catch {
                        Write-Log "Error parsing YAML for $($rule.FullName): $_" -EntryType "Warning"
                    }
                } 
                else {
                    $filenamePatterns = @(
                        '(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*[''"]?[^|]*\\([^\s\\|]+\.(exe|dll|bat|ps1|scr|cmd))[''"]?',
                        '(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*[''"]?([^\s\\|/]+\.(exe|dll|bat|ps1|scr|cmd))[''"]?'
                    )
                    
                    foreach ($pattern in $filenamePatterns) {
                        $matches = [regex]::Matches($content, $pattern)
                        foreach ($match in $matches) {
                            $fileName = $match.Groups[2].Value
                            if ($fileName -and $fileName -notin $systemFiles -and $fileName -match '^[a-zA-Z0-9_\-\.]+\.(exe|dll|bat|ps1|scr|cmd)$') {
                                $fileNames += $fileName
                            } else {
                                Write-Log "Invalid or excluded filename skipped: $fileName in $($rule.FullName)" -EntryType "Warning"
                            }
                        }
                    }
                    # Check for ASR-compatible conditions without YAML module
                    foreach ($asrRule in $AsrRuleMappings.GetEnumerator()) {
                        foreach ($pattern in $asrRule.Value.SigmaPatterns) {
                            if ($content -match $pattern) {
                                $asrRulesToApply += @{
                                    RuleId = $asrRule.Value.RuleId
                                    Source = "Sigma"
                                    RuleFile = $rule.Name
                                }
                                Write-Log "Found ASR-compatible Sigma rule: $($asrRule.Key) in $($rule.FullName)"
                            }
                        }
                    }
                }
                
                $fileNames = $fileNames | Select-Object -Unique
                foreach ($fileName in $fileNames) {
                    $indicators += @{ Type = "FileName"; Value = $fileName; Source = "Sigma"; RuleFile = $rule.Name }
                    Write-Log "Found Sigma filename: $fileName in $($rule.FullName)"
                }
                
                if ($isDebug -and -not $fileNames -and -not ($asrRulesToApply | Where-Object { $_.RuleFile -eq $rule.Name })) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "Sigma rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 1000 -eq 0 -or $processed -eq $sigmaCount) {
                    Write-Log "Processed $processed/$sigmaCount Sigma rules"
                }
            }
            catch {
                Write-Log "Error parsing Sigma rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "Sigma"}).Count -eq 0 -and $asrRulesToApply.Count -eq 0) {
        Write-Log "No indicators or ASR rules extracted from Sigma rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\sigma_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched Sigma rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Snort rule parsing
    Write-Log "Parsing Snort rules..."
    $totalIPs = 0
    $totalDomains = 0
    $ipList = @()
    $domainList = @()
    
    foreach ($snortFile in $Rules.Snort) {
        if (Test-Path $snortFile) {
            try {
                $lines = Get-Content $snortFile -ErrorAction Stop
                $lineCount = $lines.Count
                $processed = 0
                
                for ($i = 0; $i -lt $lineCount; $i++) {
                    $line = $lines[$i]
                    
                    if ($line -match '(?:^|\s)(?:alert|log|pass|drop|reject|sdrop)\s+\w+\s+(?:\$\w+\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?') {
                        $srcIp = $matches[1]
                        $dstIp = $matches[2]
                        
                        foreach ($ip in @($srcIp, $dstIp)) {
                            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile"
                            }
                        }
                    }
                    
                    if ($line -match '\[((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*))\]') {
                        $ipString = $matches[1]
                        $ips = $ipString -split ',' | ForEach-Object { $_.Trim() }
                        foreach ($ip in $ips) {
                            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile (Emerging Threats format)"
                            }
                        }
                    }
                    
                    if ($line -match '(?i)content\s*:.*?"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"') {
                        $domain = $matches[1]
                        $domainList += @{ Type = "Domain"; Value = $domain; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                        $totalDomains++
                        Write-Log "Found Snort domain: $domain in $snortFile"
                    }
                    
                    $processed++
                    if ($processed % 250 -eq 0) {
                        Write-Log "Processed $processed/$lineCount lines in ${snortFile}"
                    }
                }
                
                Write-Log "Completed parsing $processed/$lineCount lines in ${snortFile}"
            }
            catch {
                Write-Log "Error parsing Snort file ${snortFile}: $_" -EntryType "Warning"
            }
        } else {
            Write-Log "Snort file ${snortFile} does not exist" -EntryType "Warning"
        }
    }
    
    $indicators += $ipList
    $indicators += $domainList
    
    $uniqueIPs = ($ipList | Select-Object -ExpandProperty Value | Sort-Object -Unique | Measure-Object).Count
    $uniqueDomains = ($domainList | Select-Object -ExpandProperty Value | Sort-Object -Unique | Measure-Object).Count
    
    Write-Log "Extracted $totalIPs total IPs ($uniqueIPs unique), $totalDomains domains ($uniqueDomains unique) from Snort rules"
    
    if ($indicators.Where({$_.Source -eq "Snort"}).Count -eq 0) {
        Write-Log "No indicators extracted from Snort rules" -EntryType "Warning"
        if ($isDebug) {
            $debugSamplesFile = "$env:TEMP\security_rules\snort_debug_samples.txt"
            $sampleLines = $lines | Select-Object -First 10
            $sampleLines | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved Snort rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Deduplicate indicators with source preservation
    Write-Log "Deduplicating $($indicators.Count) indicators..."
    $uniqueIndicators = @()
    $seenIndicators = @{}
    
    foreach ($indicator in $indicators) {
        $key = "$($indicator.Type):$($indicator.Value)"
        if (-not $seenIndicators.ContainsKey($key)) {
            $seenIndicators[$key] = @{
                Type = $indicator.Type
                Value = $indicator.Value
                Source = $indicator.Source
                RuleFile = $indicator.RuleFile
            }
            $uniqueIndicators += $seenIndicators[$key]
            Write-Log "Added indicator: Type=$($indicator.Type), Value=$($indicator.Value), Source=$($indicator.Source), RuleFile=$($indicator.RuleFile)"
        } else {
            $existing = $seenIndicators[$key]
            $existing.Source = ($existing.Source -split ',' | Select-Object -Unique) + $indicator.Source | Where-Object { $_ } | Select-Object -Unique | Join-String -Separator ','
            $existing.RuleFile = ($existing.RuleFile -split ',' | Select-Object -Unique) + $indicator.RuleFile | Where-Object { $_ } | Select-Object -Unique | Join-String -Separator ','
            Write-Log "Merged indicator: Type=$($indicator.Type), Value=$($indicator.Value), Source=$($existing.Source), RuleFile=$($existing.RuleFile)"
        }
    }

    # Deduplicate ASR rules
    $uniqueAsrRules = $asrRulesToApply | Group-Object -Property RuleId | ForEach-Object { $_.Group[0] }
    
    Write-Log "Parsed $($uniqueIndicators.Count) unique indicators from rules (Hashes: $($uniqueIndicators.Where({$_.Type -eq 'Hash'}).Count), Files: $($uniqueIndicators.Where({$_.Type -eq 'FileName'}).Count), IPs: $($uniqueIndicators.Where({$_.Type -eq 'IP'}).Count), Domains: $($uniqueIndicators.Where({$_.Type -eq 'Domain'}).Count))."
    Write-Log "Identified $($uniqueAsrRules.Count) unique ASR rules from Sigma rules"

    if ($isDebug -and -not $DebugMode) {
        New-Item -Path "$env:TEMP\security_rules\debug_done.txt" -ItemType File -Force | Out-Null
    }
    
    return @{
        Indicators = $uniqueIndicators
        AsrRules = $uniqueAsrRules
    }
}

# Apply rules to Windows Defender ASR, Firewall, and Custom Threats
function Apply-SecurityRules {
    param (
        $IndicatorsAndRules,
        $Config
    )

    $Indicators = $IndicatorsAndRules.Indicators
    $AsrRules = $IndicatorsAndRules.AsrRules

    Write-Log "Applying security rules..."
    
    try {
        $existingFirewallRules = Get-NetFirewallRule -Name "Block_C2_*" -ErrorAction SilentlyContinue
        if ($existingFirewallRules) {
            $existingFirewallRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Log "Removed $($existingFirewallRules.Count) existing firewall rules"
        }
        
        $existingThreats = Get-MpThreatDetection | Where-Object { $_.ThreatName -like "GRules_*" }
        foreach ($threat in $existingThreats) {
            try {
                Remove-MpThreat -ThreatID $threat.ThreatID -ErrorAction SilentlyContinue
                Write-Log "Removed existing custom threat: $($threat.ThreatName)"
            }
            catch {
                Write-Log "Error removing custom threat $($threat.ThreatName): $_" -EntryType "Warning"
            }
        }
    }
    catch {
        Write-Log "Error cleaning up existing rules: $_" -EntryType "Warning"
    }
    
    # Apply ASR rules
    $processedAsr = 0
    foreach ($asrRule in $AsrRules) {
        try {
            $ruleId = $asrRule.RuleId
            $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
            $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
            
            $asrIndex = $null
            if ($asrRules) {
                $asrIndex = $asrRules.IndexOf($ruleId)
            }
            
            if ($asrIndex -ge 0) {
                if ($asrActions[$asrIndex] -ne 1) {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
                    Write-Log "Enabled existing ASR rule $ruleId from $($asrRule.Source)"
                }
            }
            else {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
                Write-Log "Added and enabled ASR rule $ruleId from $($asrRule.Source)"
            }
            $processedAsr++
        }
        catch {
            Write-Log "Error applying ASR rule ${ruleId}: $_" -EntryType "Warning"
        }
    }
    
    # Apply hash-based threats
    $hashIndicators = $Indicators | Where-Object { $_.Type -eq "Hash" }
    $hashCount = $hashIndicators.Count
    $processedHash = 0
    
    foreach ($indicator in $hashIndicators) {
        try {
            $hash = $indicator.Value
            $threatName = "GRSonyGrok: GRules_Hash_$hash"
            $description = "Malicious file hash detected from $($indicator.Source) rules"
            
            $tempFile = "$env:TEMP\GRules_threat_$hash.txt"
            $hash | Out-File -FilePath $tempFile -Encoding ASCII
            
            Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
            Add-MpPreference -SubmissionFile $tempFile
            Write-Log "Added custom threat for hash: $hash from $($indicator.Source)"
            $processedHash++
            
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Error applying custom threat for hash $($indicator.Value): $_" -EntryType "Warning"
        }
    }
    
    # Apply filename-based threats
    $fileIndicators = $Indicators | Where-Object { $_.Type -eq "FileName" }
    $fileCount = $fileIndicators.Count
    $processedFile = 0
    
    foreach ($indicator in $fileIndicators) {
        try {
            $fileName = $indicator.Value
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $fileName
            Write-Log "Added filename exclusion for monitoring: $fileName from $($indicator.Source)"
            $processedFile++
        }
        catch {
            Write-Log "Error applying filename exclusion for ${fileName}: $_" -EntryType "Warning"
        }
    }
    
    # Apply IP-based firewall rules
    $ipIndicators = $Indicators | Where-Object { $_.Type -eq "IP" }
    $ipCount = $ipIndicators.Count
    $processedIp = 0
    $batchSize = $Config.FirewallBatchSize
    $ipBatches = [math]::Ceiling($ipCount / $batchSize)
    
    Write-Log "Applying $ipCount IP-based firewall rules in $ipBatches batches..."
    for ($i = 0; $i -lt $ipBatches; $i++) {
        $batch = $ipIndicators | Select-Object -Skip ($i * $batchSize) -First $batchSize
        $ipList = $batch.Value -join ','
        if ($ipList) {
            try {
                New-NetFirewallRule -Name "Block_C2_IPs_$($i+1)" -DisplayName "Block C2 IPs Batch $($i+1)" -Enabled True -Direction Outbound -Action Block -RemoteAddress $ipList -ErrorAction Stop
                Write-Log "Created firewall rule Block_C2_IPs_$($i+1) for $($batch.Count) IPs"
                $processedIp += $batch.Count
            }
            catch {
                Write-Log "Error creating firewall rule for IP batch $($i+1): $_" -EntryType "Warning"
            }
        }
    }
    
    # Apply domain-based firewall rules
    $domainIndicators = $Indicators | Where-Object { $_.Type -eq "Domain" }
    $domainCount = $domainIndicators.Count
    $processedDomain = 0
    
    Write-Log "Applying $domainCount domain-based firewall rules..."
    foreach ($indicator in $domainIndicators) {
        try {
            $domain = $indicator.Value
            New-NetFirewallRule -Name "Block_C2_Domain_$($processedDomain+1)" -DisplayName "Block C2 Domain $domain" -Enabled True -Direction Outbound -Action Block -RemoteAddress $domain -ErrorAction Stop
            Write-Log "Created firewall rule for domain: $domain from $($indicator.Source)"
            $processedDomain++
        }
        catch {
            Write-Log "Error creating firewall rule for domain ${domain}: $_" -EntryType "Warning"
        }
    }
    
    Write-Log "Applied $processedAsr ASR rules, $processedHash hash-based threats, $processedFile filename exclusions, $processedIp IP-based firewall rules, and $processedDomain domain-based firewall rules"
}

# Monitor system processes
function Monitor-Processes {
    param (
        $Config
    )
    
    Write-Log "Starting process monitoring..."
    $telemetryPath = $Config.Telemetry.Path
    $maxEvents = $Config.Telemetry.MaxEvents
    $eventCount = 0
    
    if (-not (Test-Path $telemetryPath)) {
        New-Item -ItemType Directory -Path (Split-Path $telemetryPath -Parent) -Force | Out-Null
    }
    
    try {
        $systemFiles = $Config.ExcludedSystemFiles
        $filter = '*[System[(EventID=1)]] and *[EventData[Data[@Name="Image"] and not (Data[@Name="Image"]="' + ($systemFiles -join '") and not (Data[@Name="Image"]="') + '")]]'
        
        Write-Log "Querying process creation events with filter: $filter"
        
        # Test if Event Log is accessible
        $testEvents = Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" -MaxEvents 1 -ErrorAction SilentlyContinue
        if (-not $testEvents) {
            Write-Log "No events found in Security Event Log. Ensure process creation auditing is enabled (Local Security Policy > Audit Process Creation)." -EntryType "Warning"
            return
        }
        
        $events = Get-WinEvent -FilterXPath $filter -MaxEvents $maxEvents -ErrorAction SilentlyContinue
        if ($events) {
            foreach ($event in $events) {
                $eventData = $event.Properties
                $processName = $eventData[5].Value
                $processId = $eventData[4].Value
                $parentProcessName = $eventData[21].Value
                $commandLine = $eventData[8].Value
                
                $telemetry = @{
                    Timestamp = $event.TimeCreated
                    ProcessName = $processName
                    ProcessId = $processId
                    ParentProcessName = $parentProcessName
                    CommandLine = $commandLine
                }
                
                $telemetry | ConvertTo-Json -Depth 3 | Out-File -FilePath $telemetryPath -Append -Encoding UTF8
                $eventCount++
                
                Write-Log "Logged process: $processName (PID: $processId, Parent: $parentProcessName)"
            }
            Write-Log "Logged $eventCount process events to $telemetryPath"
        } else {
            Write-Log "No process events found matching the criteria. Check Event Log for process creation events (EventID 1) or adjust excluded system files." -EntryType "Information"
            # Log recent process creation events for debugging
            $recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" -FilterXPath '*[System[(EventID=1)]]' -MaxEvents 5 -ErrorAction SilentlyContinue
            if ($recentEvents) {
                Write-Log "Recent process creation events (top 5):"
                foreach ($event in $recentEvents) {
                    $eventData = $event.Properties
                    $processName = $eventData[5].Value
                    Write-Log "Process: $processName, Time: $($event.TimeCreated)"
                }
            } else {
                Write-Log "No process creation events found in Event Log. Ensure auditing is enabled." -EntryType "Warning"
            }
        }
    }
    catch {
        Write-Log "Error in process monitoring: $_" -EntryType "Error"
    }
}

# Main execution
function Main {
    try {
        Initialize-EventLog
        Write-Log "Starting GRules execution..."

        $rules = Get-SecurityRules -Config $Global:Config
        if (-not $rules.Yara -and -not $rules.Sigma -and -not $rules.Snort) {
            Write-Log "No rules retrieved, exiting..." -EntryType "Error"
            $Global:ExitCode = 1
            return
        }

        $indicatorsAndRules = Parse-Rules -Rules $rules -Config $Global:Config
        Apply-SecurityRules -IndicatorsAndRules $indicatorsAndRules -Config $Global:Config

        if ($Monitor -or (-not $NoMonitor)) {
            Monitor-Processes -Config $Global:Config
        }

        Write-Log "GRules execution completed successfully"
    }
    catch {
        Write-Log "Fatal error in GRules: $_" -EntryType "Error"
        $Global:ExitCode = 1
    }
    finally {
        Write-Log "Script execution finished with exit code $Global:ExitCode"
        exit $Global:ExitCode
    }
}

# Execute main function
Main
