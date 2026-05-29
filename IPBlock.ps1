# Function to check if running with elevated privileges (as Administrator)
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Function to relaunch the script as an Administrator, if not already elevated
function Ensure-Elevation {
    if (-not (Test-IsAdmin)) {
        Write-Log "Restarting script as Administrator."
        $newProcess = New-Object System.Diagnostics.ProcessStartInfo "powershell"
        $newProcess.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -DryRun:$DryRun"
        $newProcess.Verb = "runas"
        $newProcess.WindowStyle = "Hidden"
        [System.Diagnostics.Process]::Start($newProcess)
        exit
    }
}

# Function to log messages with timestamps and severity
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host $logEntry -ForegroundColor $(switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "Green" } })
}

# Function to validate IP addresses or ranges
function Test-ValidIP {
    param (
        [string]$ip
    )
    try {
        if ($ip -match "^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$") {  # Single IP or CIDR
            return $true
        }
        elseif ($ip -match "^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$") {  # IP range
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

# Command-line parameters
param (
    [switch]$DryRun
)

# Ensure script runs as Administrator
Ensure-Elevation

# Get the current user's Documents folder and set paths
$documentsFolder = [Environment]::GetFolderPath("MyDocuments")
$blockListDir = Join-Path $documentsFolder "PeerBlockLists"
$logFile = Join-Path $documentsFolder "block_log.txt"

# Define the URLs of malware-focused blocklists
$blockListURLs = @(
    "https://www.spamhaus.org/drop/drop.lasso",                # Spamhaus DROP (malware, botnets)
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",  # Emerging Threats (malware)
    "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",   # Zeus Tracker (malware C&C)
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",           # Feodo Tracker (malware C&C)
    "http://cinsscore.com/list/ci-badguys.txt",                          # CINS Army (malware IPs)
    "https://www.talosintelligence.com/documents/ip-blacklist",          # Talos Intelligence (malware)
    "https://iplists.firehol.org/files/firehol_level3.netset"            # FireHOL Level 3 (malware, botnets)
)

# Whitelist for exceptions (customize as needed)
$whitelist = @("192.168.1.1", "10.0.0.0/24")

# Create the directory to store downloaded blocklists
New-Item -ItemType Directory -Force -Path $blockListDir | Out-Null

# Function to download blocklists with retries
function Download-BlockList {
    param (
        [string]$url,
        [int]$maxRetries = 3
    )

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()) + ".txt"
    $outputFile = Join-Path $blockListDir $fileName
    $attempt = 0

    while ($attempt -lt $maxRetries) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputFile -ErrorAction Stop
            Write-Log "Downloaded blocklist: $url"
            return $outputFile
        } catch {
            $attempt++
            Write-Log "Attempt $attempt failed for $url: $_" -Level "WARN"
            if ($attempt -eq $maxRetries) {
                Write-Log "Max retries reached for $url" -Level "ERROR"
                return $null
            }
            Start-Sleep -Seconds 5
        }
    }
}

# Function to parse and filter IPs from blocklists
function Parse-BlockList {
    param (
        [string]$filePath
    )

    $outputList = @()
    $content = Get-Content -Path $filePath -ErrorAction SilentlyContinue
    foreach ($line in $content) {
        $line = $line.Trim()
        if ($line -eq "" -or $line.StartsWith("#") -or $line.StartsWith(";")) {
            continue
        }
        if (Test-ValidIP $line) {
            $outputList += $line
        }
    }
    return $outputList
}

# Function to add IP addresses or ranges to Windows Firewall
function Add-IPBlock {
    param (
        [string]$ipRange
    )

    $inboundRuleName = "Block Malware IP (Inbound) - $ipRange"
    $outboundRuleName = "Block Malware IP (Outbound) - $ipRange"

    if (-not $DryRun) {
        # Block inbound traffic
        New-NetFirewallRule -DisplayName $inboundRuleName -Direction Inbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose -ErrorAction SilentlyContinue
        # Block outbound traffic
        New-NetFirewallRule -DisplayName $outboundRuleName -Direction Outbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose -ErrorAction SilentlyContinue
    }
    Write-Log "Blocked IP/Range: $ipRange (DryRun: $DryRun)"
}

# Download and process each blocklist
$allBlockListIPs = @()
foreach ($url in $blockListURLs) {
    $downloadedFile = Download-BlockList -url $url
    if ($downloadedFile) {
        $parsedIPs = Parse-BlockList -filePath $downloadedFile
        $allBlockListIPs += $parsedIPs
    }
}

# Deduplicate IPs and block them
$uniqueIPs = $allBlockListIPs | Sort-Object -Unique

foreach ($ip in $uniqueIPs) {
    try {
        if (-not (Test-ValidIP $ip)) {
            Write-Log "Invalid IP/Range skipped: $ip" -Level "WARN"
            continue
        }
        if ($whitelist -contains $ip -or ($whitelist | Where-Object { $ip -like $_ })) {
            Write-Log "Whitelisted IP/Range skipped: $ip" -Level "INFO"
            continue
        }
        Add-IPBlock -ipRange $ip
    } catch {
        Write-Log "Failed to block IP/Range: $ip - $_" -Level "ERROR"
    }
}

Write-Log "IP blocking process complete (DryRun: $DryRun)" -Level "INFO"
Write-Host "Block list logged to $logFile" -ForegroundColor Yellow