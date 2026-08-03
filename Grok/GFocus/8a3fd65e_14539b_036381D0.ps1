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

# Gaming (and all non-browser apps) are never monitored or blocked - explicitly unhindered.
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

function Invoke-GFocusTick {
    if ($null -eq $script:GFocusSeenConnections) { $script:GFocusSeenConnections = @{} }
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
    foreach ($Conn in $Connections) {
        $Key = "$($Conn.RemoteAddress):$($Conn.RemotePort):$($Conn.OwningProcess)"
        if ($script:GFocusSeenConnections.ContainsKey($Key)) { continue }
        $script:GFocusSeenConnections[$Key] = $true
        try {
            $Process = Get-Process -Id $Conn.OwningProcess -ErrorAction Stop
            $ProcessName = $Process.ProcessName
            $ProcessPath = $Process.Path
        } catch { $Process = $null; $ProcessName = "Unknown"; $ProcessPath = $null }
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
    return $script:BlockedConnections.Count
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
    $script:GFocusSeenConnections = @{}
    while ($script:MonitoringActive) {
        Invoke-GFocusTick | Out-Null
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
