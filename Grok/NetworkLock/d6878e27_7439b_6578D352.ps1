
# NetworkLock.ps1 - Simple Network Lockdown for Active Window and Whitelisted Apps
# Runs continuously as SYSTEM, allowing network access only for the foreground process (browser/MMO) and whitelisted apps (OBS, Discord, Spotify, Steam, Epic, Blizzard, etc.).
# Blocks all other outbound connections using Windows Firewall.
# ENHANCED: Explicitly whitelists Steam, Epic, Blizzard, EA, Ubisoft launchers for background operation.
# Logs to C:\NetworkLock.log. No process killing or file quarantine.
# To deploy: Save as .ps1, use Task Scheduler to run as SYSTEM (highest privs, hidden).

# Set log path
$LogPath = "C:\NetworkLock.log"
if (!(Test-Path $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host $Message -ForegroundColor Yellow
}

# Config
$ScanInterval = 30  # Seconds between scans

# Whitelist: Browsers, MMOs, common apps, updaters, and game launchers
$Whitelist = @(
    "chrome", "brave", "firefox", "msedge",           # Browsers
    "obs64", "Discord", "Spotify",                   # Streaming, chat, music
    "WoW", "ffxiv_dx11", "destiny2",                 # MMOs (add your .exe names without .exe)
    "steam", "SteamService", "SteamWebHelper",       # Steam
    "EpicGamesLauncher", "EpicWebHelper",            # Epic Games
    "Battle.net", "BlizzardUpdateAgent",             # Blizzard Battle.net
    "Origin", "EADesktop",                           # EA App
    "UbisoftConnect", "UplayService",                # Ubisoft Connect
    "GOG Galaxy",                                    # GOG Galaxy
    "GoogleUpdate", "MozillaMaintenance", "updater"   # Update services
)

# Directories to scan for additional .exe files (e.g., MMOs, launchers)
$AppDirs = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Games"  # Add your MMO/launcher paths
)

# Dynamic whitelist: Add .exe from AppDirs
function Get-DynamicWhitelist {
    $DynamicWhitelist = @()
    foreach ($Dir in $AppDirs) {
        if (Test-Path $Dir) {
            $Files = Get-ChildItem -Path $Dir -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue
            foreach ($File in $Files) {
                $ProcName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
                if ($ProcName -and $DynamicWhitelist -notcontains $ProcName) {
                    $DynamicWhitelist += $ProcName
                }
            }
        }
    }
    return $DynamicWhitelist
}

# Win32 API for foreground window
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    }
"@

function Get-ForegroundProcess {
    $procId = 0
    $hWnd = [Win32]::GetForegroundWindow()
    [Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId) | Out-Null
    if ($procId -ne 0) {
        try {
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            return $proc
        } catch {
            return $null
        }
    }
    return $null
}

# Combine whitelists
$Whitelist += Get-DynamicWhitelist
Write-Log "=== Network Lockdown Started ==="
Write-Log "DEBUG: Whitelist contains $($Whitelist.Count) items: $($Whitelist -join ', ')"

# Main loop: Monitor and lock down network
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # Get active process
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        Write-Log "DEBUG: Active process: $($ActiveProcess.Name) (ID: $($ActiveProcess.Id), Path: $($ActiveProcess.Path))"
    } else {
        Write-Log "DEBUG: No active process detected."
    }

    # Clear existing lockdown rules
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "NetworkLock_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
            Write-Log "DEBUG: Cleared old rule: $RuleName"
        }
    }

    # Set firewall rules
    if ($ActiveProcess -and $ActiveProcess.Path) {
        Write-Log "INFO: Locking down network for $($ActiveProcess.Name)..."
        # Allow active process
        $RuleName = "NetworkLock_Allow_$($ActiveProcess.Name)_$($ActiveProcess.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleName" dir=out program="$($ActiveProcess.Path)" action=allow enable=yes | Out-Null
            Write-Log "DEBUG: Added allow rule for $($ActiveProcess.Name): $RuleName"
        } catch {
            Write-Log "DEBUG: Failed to add allow rule for $($ActiveProcess.Name): $($_.Exception.Message)"
        }
    }

    # Allow whitelisted processes (e.g., Steam, Epic, Discord)
    $RunningProcs = Get-Process | Where-Object { $Whitelist -contains $_.Name -and $_.Path }
    foreach ($Proc in $RunningProcs) {
        if ($Proc.Id -ne $ActiveProcess.Id) {
            $RuleName = "NetworkLock_Allow_$($Proc.Name)_$($Proc.Id)"
            try {
                netsh advfirewall firewall add rule name="$RuleName" dir=out program="$($Proc.Path)" action=allow enable=yes | Out-Null
                Write-Log "DEBUG: Added allow rule for whitelisted $($Proc.Name): $RuleName"
            } catch {
                Write-Log "DEBUG: Failed to add allow rule for $($Proc.Name): $($_.Exception.Message)"
            }
        }
    }

    # Block all other outbound connections
    $BlockRuleName = "NetworkLock_Block_All"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleName" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleName" dir=out action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all rule: $BlockRuleName"
        }
    } catch {
        Write-Log "DEBUG: Failed to add block-all rule: $($_.Exception.Message)"
    }

    # Log network connections
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Checking $($NetConns.Count) outbound connections:"
        foreach ($Conn in $NetConns) {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $ProcName = $Proc.Name
            if ($ProcName -and ($Whitelist -contains $ProcName -or $Conn.OwningProcess -eq $ActiveProcess.Id)) {
                Write-Log "  - ALLOWED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            } else {
                Write-Log "  - BLOCKED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            }
        }
    } else {
        Write-Log "No outbound network activity."
    }

    Write-Log "=== Scan Cycle Complete. Sleeping $ScanInterval seconds. ==="
    Start-Sleep -Seconds $ScanInterval
}
