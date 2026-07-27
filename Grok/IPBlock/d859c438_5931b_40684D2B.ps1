# IPBlock.ps1
# Author: Gorstak

param (
    [switch]$DryRun
)

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-Elevation {
    if (-not (Test-IsAdmin)) {
        Write-Host "Requesting elevation..." -ForegroundColor Cyan
        $newProcess = New-Object System.Diagnostics.ProcessStartInfo "powershell"
        $newProcess.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -DryRun:$DryRun"
        $newProcess.Verb = "runas"
        $newProcess.WindowStyle = "Normal"
        [System.Diagnostics.Process]::Start($newProcess) | Out-Null
        exit
    }
}

Ensure-Elevation

$documentsFolder = [Environment]::GetFolderPath("MyDocuments")
$blockListDir    = Join-Path $documentsFolder "PeerBlockLists"
$logFile         = Join-Path $documentsFolder "block_log.txt"

New-Item -ItemType Directory -Force -Path $blockListDir | Out-Null

# Reliable public malware-focused lists
$blockListURLs = @(
    "https://www.spamhaus.org/drop/drop.txt",
    "https://reputation.alienvault.com/reputation.data",
    "https://www.spamhaus.org/drop/drop.lasso",                # Spamhaus DROP (malware, botnets)
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",  # Emerging Threats (malware)
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",           # Feodo Tracker (malware C&C)
    "http://cinsscore.com/list/ci-badguys.txt",                          # CINS Army (malware IPs)
    "https://iplists.firehol.org/files/firehol_level3.netset"            # FireHOL Level 3 (malware, botnets)
)

# Whitelist: Only specific local IPs/subnets you trust (e.g., your router, internal servers)
# Remove or narrow these if you don't need them
$whitelist = @()  # Example: your home network only

function Is-PublicIP {
    param([string]$ipString)
    try {
        $ip = [System.Net.IPAddress]::Parse(($ipString -split '[;/#]')[0].Trim())
        return -not $ip.IsIPv6LinkLocal -and -not $ip.IsIPv6SiteLocal -and
               -not ($ip.GetAddressBytes()[0] -eq 10) -and
               -not ($ip.GetAddressBytes()[0..1] -join '.' -eq '192.168') -and
               -not ($ip.GetAddressBytes()[0..1] -join '.' -eq '172.16' -and $ip.GetAddressBytes()[1] -ge 16 -and $ip.GetAddressBytes()[1] -le 31) -and
               -not ($ip.GetAddressBytes()[0] -eq 127) -and
               -not ($ip.GetAddressBytes()[0..1] -join '.' -eq '169.254')
    } catch { return $false }
}

function Download-BlockList {
    param ([string]$url, [int]$maxRetries = 3)
    $fileName = [guid]::NewGuid().ToString() + ".txt"
    $outputFile = Join-Path $blockListDir $fileName
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputFile -ErrorAction Stop -TimeoutSec 30
            Write-Log "Downloaded: $url"
            return $outputFile
        } catch {
            Write-Log "Attempt $i failed for $url : $_" "WARN"
            Start-Sleep -Seconds 5
        }
    }
    Write-Log "Failed to download $url after $maxRetries attempts" "ERROR"
    return $null
}

function Parse-BlockList {
    param([string]$filePath)
    $ips = @()
    Get-Content -Path $filePath | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#") -or $line.StartsWith(";")) { return }
        $ipPart = ($line -split '[;\s#]+')[0].Trim()
        if ($ipPart -match '^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$') {
            if (Is-PublicIP $ipPart) { $ips += $ipPart }
            else { Write-Log "Skipped private/non-public IP: $ipPart" "INFO" }
        }
    }
    return $ips
}

$allIPs = @()
foreach ($url in $blockListURLs) {
    $file = Download-BlockList -url $url
    if ($file) { $allIPs += Parse-BlockList -filePath $file }
}

$uniqueIPs = $allIPs | Sort-Object -Unique

$blockIPs = $uniqueIPs | Where-Object {
    -not ($whitelist -contains $_ -or $whitelist | Where-Object { $_ -like "*/*" -and [System.Net.IPNetwork]::Parse($_).Contains([System.Net.IPAddress]::Parse($_)) })
}

Write-Log "Found $($uniqueIPs.Count) unique public IPs/ranges, $($blockIPs.Count) to block after whitelist"

if ($DryRun) {
    Write-Log "DRY RUN MODE - No rules created"
    $blockIPs | ForEach-Object { Write-Log "WOULD BLOCK: $_" }
} else {
    if ($blockIPs.Count -eq 0) {
        Write-Log "No IPs to block"
    } else {
        $chunkSize = 800
        $ruleIndex = 1
        for ($i = 0; $i -lt $blockIPs.Count; $i += $chunkSize) {
            $chunk = $blockIPs[$i..([math]::Min($i + $chunkSize - 1, $blockIPs.Count - 1))]
            $ipList = $chunk -join ","

            $inName  = "Block Malware IPs - Inbound (Part $ruleIndex)"
            $outName = "Block Malware IPs - Outbound (Part $ruleIndex)"

            New-NetFirewallRule -DisplayName $inName  -Direction Inbound  -Action Block -RemoteAddress $ipList -Profile Any -Enabled True -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $outName -Direction Outbound -Action Block -RemoteAddress $ipList -Profile Any -Enabled True -ErrorAction SilentlyContinue

            Write-Log "Created rules (Part $ruleIndex) blocking $($chunk.Count) IPs"
            $ruleIndex++
        }
    }
}

Write-Log "Script completed. Log saved to $logFile"
Write-Host "Log file: $logFile" -ForegroundColor Yellow