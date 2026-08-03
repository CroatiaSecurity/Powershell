# CosmicClean.ps1 - Aggressive One-Time Cleanup & Scan
# Terminates suspicious processes, blocks connections, quarantines files - and exits.

# === CONFIG ===
$LogPath = "C:\CosmicClean.log"
$QuarantineDir = "C:\Quarantine"
$CPUThreshold = 20
$MaxAutoQuarantine = 3
$SelfPath = $MyInvocation.MyCommand.Path

# === Setup ===
if (!(Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host $Message -ForegroundColor Yellow
}

function Sanitize-Filename {
    param([string]$FileName)
    return ($FileName -replace '[\\/:*?"<>|]', '_')
}

Write-Log "=== Cosmic Clean Aggressive Cleanup Started ==="

# === 1. Kill Suspicious Processes ===
$Whitelist = @("explorer", "svchost", "lsass", "winlogon", "csrss", "System", "Idle", "powershell", "cmd", "taskhostw", "dwm", "wininit")

$ScriptBin = "C:\Windows\Setup\Scripts\Bin"

$SuspiciousProcs = Get-Process | Where-Object {
    $_.ProcessName -notin $Whitelist -and
    $_.CPU -gt $CPUThreshold -and
    $_.Path -ne $SelfPath -and
    ($_.Path -notlike "$ScriptBin\*")
} | Select-Object Name, Id, CPU, Path

if ($SuspiciousProcs.Count -gt 0) {
    Write-Log "ALERT: Terminating $($SuspiciousProcs.Count) suspicious processes:"
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
    Write-Log "No suspicious processes."
}

# === 2. Block Suspicious Network Connections ===
$NetConns = Get-NetTCPConnection | Where-Object {
    $_.State -eq "Established" -and
    $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object RemoteAddress

if ($NetConns.Count -gt 0) {
    Write-Log "INFO: Blocking $($NetConns.Count) suspicious outbound connections:"
    foreach ($conn in $NetConns) {
        $RuleName = "CosmicAutoBlock_$($conn.RemoteAddress.Replace('.','_'))_$($conn.RemotePort)"
        Write-Log "  - BLOCKING: $($conn.RemoteAddress):$($conn.RemotePort) (Proc: $($conn.OwningProcess))"
        try {
            $existing = netsh advfirewall firewall show rule name="$RuleName" 2>$null
            if (!$existing) {
                netsh advfirewall firewall add rule name="$RuleName" dir=out action=block remoteip=$($conn.RemoteAddress) remoteport=$($conn.RemotePort) >$null
                Write-Log "    SUCCESS: Rule '$RuleName' added."
            } else {
                Write-Log "    SKIPPED: Rule '$RuleName' already exists."
            }
        } catch {
            Write-Log "    FAILED: $($_.Exception.Message)"
        }
    }
} else {
    Write-Log "No suspicious network activity."
}

# === 3. Quarantine Recent Files ===
$KeyDirs = @("C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")
$RecentFiles = @()

foreach ($Dir in $KeyDirs) {
    if (Test-Path $Dir) {
        $Changes = Get-ChildItem -Path $Dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) -and $_.FullName -ne $SelfPath }

        $RecentFiles += $Changes | Select-Object FullName, LastWriteTime, Length
    }
}

$RecentCount = $RecentFiles.Count
if ($RecentCount -gt 0) {
    Write-Log "INFO: Detected $RecentCount recent file changes:"
    if ($RecentCount -gt $MaxAutoQuarantine) {
        Write-Log "  - AUTO-QUARANTINING top suspicious files (threshold exceeded)."
        $ToQuarantine = $RecentFiles | Sort-Object Length -Descending | Select-Object -First $MaxAutoQuarantine
        foreach ($file in $ToQuarantine) {
            $SafeName = Sanitize-Filename (Split-Path $file.FullName -Leaf)
            $QuarantinePath = Join-Path $QuarantineDir "$SafeName-Auto-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Write-Log "    QUARANTINING: $($file.FullName) -> $QuarantinePath"
            try {
                Move-Item $file.FullName $QuarantinePath -Force -ErrorAction Stop
                Write-Log "      SUCCESS."
            } catch {
                Write-Log "      FAILED: $($_.Exception.Message)"
            }
        }

        # Log rest
        $RecentFiles | Where-Object { $_.FullName -notin $ToQuarantine.FullName } | ForEach-Object {
            Write-Log "    MONITORED: $($_.FullName) (no action)"
        }
    } else {
        $RecentFiles | ForEach-Object {
            Write-Log "  - MONITORED: $($_.FullName) modified $($_.LastWriteTime) (Size: $($_.Length) bytes)"
        }
    }
} else {
    Write-Log "No recent file changes."
}

# === 4. User Temp Monitoring ===
$Sessions = Get-CimInstance Win32_LoggedOnUser | ForEach-Object {
    $raw = $_.Antecedent -replace '"', ''
    if ($raw -match 'Win32_Account.Domain="[^"]+",Name="([^"]+)"') {
        return $matches[1]
    }
}
$UniqueUsers = $Sessions | Where-Object { $_ -and $_ -ne "SYSTEM" } | Sort-Object -Unique

if ($UniqueUsers.Count -gt 0) {
    Write-Log "EYE ON USERS: Monitoring $($UniqueUsers.Count) users: $($UniqueUsers -join ', ')"
    foreach ($User in $UniqueUsers) {
        $UserTemp = "C:\Users\$User\AppData\Local\Temp"
        if (Test-Path $UserTemp) {
            $UserChanges = Get-ChildItem -Path $UserTemp -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-5) }

            if ($UserChanges.Count -gt 0) {
                Write-Log "  - USER ALERT ($User): $($UserChanges.Count) new files in Temp. Logging only."
            }
        }
    }
}

Write-Log "=== Cosmic Shield Cleanup Complete. Exiting ==="
