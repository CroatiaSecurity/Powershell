#Requires -RunAsAdministrator
# Pihole.ps1 - System-wide ad blocker for Windows using DNS policy and persistent routes

# Configuration
$FilterLists = @(
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://filters.adtidy.org/windows/filters/2.txt"  # AdGuard Base filter
)
$DnsPolicyKey = "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\BlockAdDomains"
$RouteKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
$BlockedDomains = [System.Collections.Generic.List[string]]::new()
$BlockedIPs = [System.Collections.Generic.List[string]]::new()
$UpdateIntervalHours = 24
$LogFile = "$env:TEMP\AdBlocker.log"
$DebugMode = $true  # Enable for verbose logging

# Check if running as Administrator
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Logging function
function Write-Log {
    param ($Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "$Timestamp - $Message"
}

# Ensure DNS Client service is running
function Initialize-DnsService {
    Write-Log "Ensuring DNS Client service is running..."
    try {
        $service = Get-Service -Name Dnscache -ErrorAction Stop
        if ($service.Status -ne "Running") {
            Start-Service -Name Dnscache -ErrorAction Stop
            Set-Service -Name Dnscache -StartupType Automatic -ErrorAction Stop
        }
        Write-Log "DNS Client service is running."
    } catch {
        Write-Log "Error starting DNS Client service: $_"
    }
}

# Download and parse filter lists
function Update-FilterLists {
    Write-Log "Downloading filter lists..."
    $script:BlockedDomains.Clear()
    $domainCount = 0
    foreach ($url in $FilterLists) {
        Write-Log "Attempting to download: $url"
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $lines = $response.Content -split "`n"
            $lineCount = $lines.Count
            Write-Log "Processing $lineCount lines from $url..."
            $index = 0
            foreach ($line in $lines) {
                $index++
                if ($DebugMode -and ($index % 5000 -eq 0)) {
                    Write-Log "Processed $index of $lineCount lines from $url"
                }
                if ($line -match "^\|\|([^\^]+)\^") {
                    $domain = $Matches[1].Trim()
                    if ($domain -and $domain -notmatch "^\s*#" -and $domain -notmatch "^\s*!") {
                        $script:BlockedDomains.Add($domain)
                        $domainCount++
                    }
                }
            }
            Write-Log "Processed filter list: $url ($domainCount domains so far)"
        } catch {
            Write-Log "Failed to download or process ${url}: $_"
        }
    }
    $script:BlockedDomains = [System.Linq.Enumerable]::ToList([string[]]($script:BlockedDomains | Sort-Object -Unique))
    Write-Log "Loaded $($script:BlockedDomains.Count) unique domains to block."
}

# Resolve IPs for domains (simplified, focusing on known ad servers)
function Resolve-AdServerIPs {
    Write-Log "Resolving IPs for known ad servers..."
    $script:BlockedIPs.Clear()
    $sampleDomains = $script:BlockedDomains | Select-Object -First 50
    $index = 0
    foreach ($domain in $sampleDomains) {
        $index++
        if ($DebugMode) {
            Write-Log "Resolving IP for domain $index/$($sampleDomains.Count): $domain"
        }
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($domain) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            foreach ($ip in $ips) {
                $ipStr = $ip.ToString()
                $subnet = $ipStr -replace "\.\d+$", ".0"  # Assume /24 subnet
                $script:BlockedIPs.Add($subnet)
            }
        } catch {
            Write-Log "Failed to resolve IP for ${domain}: $_"
        }
    }
    $script:BlockedIPs = [System.Linq.Enumerable]::ToList([string[]]($script:BlockedIPs | Sort-Object -Unique))
    Write-Log "Identified $($script:BlockedIPs.Count) unique IP subnets to block."
}

# Configure DNS policy in registry
function Set-DnsPolicy {
    Write-Log "Configuring DNS policy in registry..."
    try {
        # Create or clear DNS policy key
        if (-not (Test-Path $DnsPolicyKey)) {
            New-Item -Path $DnsPolicyKey -Force | Out-Null
        }
        New-Item -Path "$DnsPolicyKey\PolicyEntry" -Force | Out-Null

        # Set policy metadata
        Set-ItemProperty -Path $DnsPolicyKey -Name "Name" -Value "BlockAdDomains" -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "Key" -Value "PolicyEntry" -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "PolicyType" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "Version" -Value 2 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "EntryType" -Value 1 -Type DWord -ErrorAction Stop

        # Add sorted domains to policy
        $policyPath = "$DnsPolicyKey\PolicyEntry"
        $index = 0
        foreach ($domain in $script:BlockedDomains) {
            $index++
            if ($DebugMode -and ($index % 1000 -eq 0)) {
                Write-Log "Configured $index of $($script:BlockedDomains.Count) domains in DNS policy"
            }
            Set-ItemProperty -Path $policyPath -Name $domain -Value "127.0.0.1" -Force -ErrorAction Stop
        }
        Write-Log "Configured DNS policy with $($script:BlockedDomains.Count) domains."
    } catch {
        Write-Log "Error configuring DNS policy: $_"
    }
}

# Configure persistent routes
function Set-PersistentRoutes {
    Write-Log "Configuring persistent routes..."
    try {
        # Clear existing routes
        Get-Item -Path $RouteKey -ErrorAction SilentlyContinue | Get-ItemProperty | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -match "\d+\.\d+\.\d+\.\d+" } | ForEach-Object {
                Remove-ItemProperty -Path $RouteKey -Name $_.Name -ErrorAction SilentlyContinue
            }
        }

        # Add new routes
        foreach ($ip in $script:BlockedIPs) {
            $routeName = "$ip,255.255.255.0,0.0.0.0,1"
            Set-ItemProperty -Path $RouteKey -Name $routeName -Value "" -Force -ErrorAction Stop
            & route add $ip MASK 255.255.255.0 0.0.0.0 -p 2>&1 | Out-Null
        }
        Write-Log "Configured $($script:BlockedIPs.Count) persistent routes."
    } catch {
        Write-Log "Error configuring persistent routes: $_"
    }
}

# Schedule task for periodic updates
function Register-UpdateTask {
    Write-Log "Registering scheduled task for filter updates..."
    try {
        $taskName = "AdBlockerUpdate"
        $taskPath = "\AdBlocker\"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\AdBlocker.ps1`" -UpdateOnly"
        $trigger = New-ScheduledTaskTrigger -Daily -At "12:00AM"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-Log "Scheduled task registered."
    } catch {
        Write-Log "Error registering scheduled task: $_"
    }
}

# Main execution
function Main {
    param ([switch]$UpdateOnly)
    if (-not (Test-Admin)) {
        Write-Log "This script must be run as Administrator. Exiting."
        exit 1
    }
    Initialize-DnsService
    Update-FilterLists
    Resolve-AdServerIPs
    Set-DnsPolicy
    Set-PersistentRoutes
    if ($UpdateOnly) {
        Write-Log "Update-only mode completed. Exiting."
    } else {
        Register-UpdateTask
        Write-Log "AdBlocker initialized and configured. Exiting."
    }
}

# Check for update-only mode
if ($args -contains "-UpdateOnly") {
    Main -UpdateOnly
} else {
    Main
}