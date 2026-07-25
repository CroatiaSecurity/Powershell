# IPBlock.ps1
# Author: Gorstak (gorstak.eu)
# Description: Downloads malware-focused IP blocklists (Spamhaus DROP, Emerging Threats,
#              Feodo Tracker, CINS, Talos, FireHOL), validates and deduplicates IPs, then
#              creates Windows Firewall rules to block inbound/outbound traffic.
#              One-time run at startup with self-unregistering persistence.
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall
)

$Script:TaskName = "IPBlockSetup"
$Script:InstallDir = "$env:ProgramData\IPBlock"
$Script:ScriptName = "IPBlock.ps1"

# -- Persistence (one-time run at startup) ----------------------
function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "IP blocklist updater (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        $schOut = & schtasks.exe /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONSTART /RL HIGHEST /F 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } else {
            Write-Host "[ERROR] schtasks failed: $schOut" -ForegroundColor Red
        }
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        if ($task) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue }
    } catch {}
    & schtasks.exe /Delete /TN "$($Script:TaskName)" /F 2>$null | Out-Null
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] IPBlock uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

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
        $newProcess.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
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
            Write-Log "Attempt $attempt failed for ${url}: $_" -Level "WARN"
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

    # Block inbound traffic
    New-NetFirewallRule -DisplayName $inboundRuleName -Direction Inbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose -ErrorAction SilentlyContinue
    # Block outbound traffic
    New-NetFirewallRule -DisplayName $outboundRuleName -Direction Outbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose -ErrorAction SilentlyContinue

    Write-Log "Blocked IP/Range: $ipRange"
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

Write-Log "IP blocking process complete" -Level "INFO"
Write-Host "Block list logged to $logFile" -ForegroundColor Yellow

# Self-unregister the scheduled task after successful completion
$task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
