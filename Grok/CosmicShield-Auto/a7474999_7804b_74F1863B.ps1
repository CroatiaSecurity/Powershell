
# CosmicShield-Auto.ps1 - Aggressive Automatic Background Protection for Windows 10/11
# Runs continuously, monitoring system-wide (all users) as SYSTEM.
# Auto-terminates suspicious processes, blocks net connections, quarantines files.
# FIXED: Quarantine path, user parsing; tuned for action (wider file window, lower threshold).
# WARNING: High-risk—auto-actions can disrupt system. Test in VM. Logs to C:\CosmicShield.log.
# To deploy: Save as .ps1, use Task Scheduler to run as SYSTEM (highest privs, hidden).

# Set paths
$LogPath = "C:\CosmicShield.log"
$QuarantineDir = "C:\CosmicQuarantine"
if (!(Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host $Message -ForegroundColor Yellow
}

# Config: Tune for aggression
$CPUThreshold = 20  # CPU % for suspicious processes
$MaxAutoQuarantine = 1  # Auto-quarantine if > this many recent files
$ScanInterval = 30  # Seconds between scans
$FileChangeWindowHours = 24  # Look back for file changes

# Whitelist for processes (system + safe apps; add user-specific if needed)
$Whitelist = @("explorer", "svchost", "lsass", "winlogon", "csrss", "System", "Idle", "powershell", "cmd", "taskhostw", "dwm", "wininit", "brave", "chrome", "msedge", "firefox")

Write-Log "=== Cosmic Shield Auto-Mode Started - System-Wide Protection (Tuned) ==="

# Main loop: Infinite background monitoring
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # 1. Auto-Scan and Terminate Suspicious Processes (system-wide)
    Write-Log "DEBUG: Scanning processes with CPU > $CPUThreshold..."
    $SuspiciousProcs = Get-Process | Where-Object { 
        $_.ProcessName -notin $Whitelist -and 
        $_.CPU -gt $CPUThreshold
    } | Select-Object Name, Id, CPU, Path

    if ($SuspiciousProcs.Count -gt 0) {
        Write-Log "ALERT: Auto-terminating $($SuspiciousProcs.Count) suspicious processes:"
        $SuspiciousProcs | ForEach-Object { 
            Write-Log "  - TERMINATING: $($_.Name) (ID: $($_.Id), CPU: $($_.CPU), Path: $($_.Path))"
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                Write-Log "    SUCCESS: $($_.Name) terminated."
            } catch {
                Write-Log "    FAILED: $($_.Name) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "No suspicious processes found."
    }

    # 2. Auto-Scan and Block Network Connections (system-wide outbound)
    Write-Log "DEBUG: Scanning network connections..."
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object RemoteAddress

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Auto-blocking $($NetConns.Count) suspicious outbound connections:"
        $NetConns | ForEach-Object { 
            $RuleName = "CosmicAutoBlock_$($_.RemoteAddress.Replace('.','_'))_$($_.RemotePort)"
            Write-Log "  - BLOCKING: To $($_.RemoteAddress):$($_.RemotePort) (Proc: $($_.OwningProcess))"
            try {
                $Existing = netsh advfirewall firewall show rule name="$RuleName" 2>$null
                if (!$Existing) {
                    netsh advfirewall firewall add rule name="$RuleName" dir=out action=block remoteip=$($_.RemoteAddress) remoteport=$($_.RemotePort) -ErrorAction Stop
                    Write-Log "    SUCCESS: Rule '$RuleName' added."
                } else {
                    Write-Log "    SKIPPED: Rule '$RuleName' already exists."
                }
            } catch {
                Write-Log "    FAILED: $($_.RemoteAddress) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "No suspicious network activity."
    }

    # 3. Auto-Scan and Quarantine Recent File Changes (system-wide, user dirs included)
    Write-Log "DEBUG: Scanning files modified in last $FileChangeWindowHours hours..."
    $KeyDirs = @("C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")  # Covers all users
    $RecentFiles = @()
    foreach ($Dir in $KeyDirs) {
        if (Test-Path $Dir) {
            $Changes = Get-ChildItem -Path $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-$FileChangeWindowHours) }
            $RecentFiles += $Changes | Select-Object FullName, LastWriteTime, Length
        }
    }

    $RecentCount = $RecentFiles.Count
    if ($RecentCount -gt 0) {
        Write-Log "INFO: Detected $RecentCount recent file changes:"
        if ($RecentCount -gt $MaxAutoQuarantine) {
            Write-Log "  - AUTO-QUARANTINING top suspicious files (threshold exceeded)."
            $ToQuarantine = $RecentFiles | Sort-Object Length -Descending | Select-Object -First $MaxAutoQuarantine
            $ToQuarantine | ForEach-Object { 
                $FileName = Split-Path $_.FullName -Leaf
                $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $QuarantinePath = Join-Path $QuarantineDir "${FileName}_Auto_${Timestamp}"
                Write-Log "    QUARANTINING: $($_.FullName) -> $QuarantinePath"
                try {
                    # Copy first, then remove to avoid locked file issues
                    Copy-Item $_.FullName $QuarantinePath -Force -ErrorAction Stop
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Write-Log "      SUCCESS: Copied and removed."
                } catch {
                    Write-Log "      FAILED: $($_.Exception.Message)"
                }
            }
            # Log the rest without action
            $RecentFiles | Where-Object { $_.FullName -notin ($ToQuarantine.FullName) } | ForEach-Object { 
                Write-Log "    MONITORED: $($_.FullName) (no action)"
            }
        } else {
            $RecentFiles | ForEach-Object { Write-Log "  - MONITORED: $($_.FullName) modified $($_.LastWriteTime) (Size: $($_.Length) bytes)" }
        }
    } else {
        Write-Log "No recent file changes."
    }

    # 4. User-specific eye: Check logged-in users' temp dirs
    Write-Log "DEBUG: Scanning logged-in users..."
    $LoggedInUsers = Get-WmiObject Win32_LoggedOnUser | ForEach-Object { 
        if ($_.Antecedent -match 'Name=\"([^\"]+)\"') { $matches[1] } 
    } | Where-Object { $_ -and $_ -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' } | Sort-Object -Unique

    if ($LoggedInUsers) {
        Write-Log "EYE ON USERS: Monitoring $($LoggedInUsers.Count) logged-in users: $($LoggedInUsers -join ', ')"
        foreach ($User in $LoggedInUsers) {
            $UserTemp = "C:\Users\$User\AppData\Local\Temp"
            if (Test-Path $UserTemp) {
                $UserChanges = Get-ChildItem -Path $UserTemp -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-5) }  # Fresh drops
                if ($UserChanges.Count -gt 0) {
                    Write-Log "  - USER ALERT ($User): $($UserChanges.Count) new files in Temp. Logging only."
                    $UserChanges | ForEach-Object { Write-Log "    - $($_.FullName)" }
                }
            } else {
                Write-Log "  - USER NOTE ($User): Temp dir not found (profile may be unloaded)."
            }
        }
    } else {
        Write-Log "EYE ON USERS: No eligible logged-in users detected."
    }

    Write-Log "=== Scan Cycle Complete. Sleeping $ScanInterval seconds. ==="
    Start-Sleep -Seconds $ScanInterval
}
