
# CosmicShield-Auto.ps1 - DLL-Aware Automatic Background Protection for Windows 10/11
# Runs continuously, monitoring system-wide (all users) as SYSTEM.
# Auto-terminates suspicious processes, blocks net connections, quarantines files and DLLs.
# ENHANCED: Detects high-CPU DLLs with network activity, whitelists .ps1/.bat/.exe in C:\Users/Program Files/Games.
# WARNING: High-risk-auto-actions can disrupt system (esp. DLL moves). Test in VM. Logs to C:\CosmicShield.log.
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

# Static whitelist for system processes and common DLLs
$StaticWhitelist = @("explorer", "svchost", "lsass", "winlogon", "csrss", "System", "Idle", "powershell", "cmd", "taskhostw", "dwm", "wininit", "brave", "chrome", "msedge", "firefox")
$DLLWhitelist = @("kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "ntdll.dll", "d3d11.dll", "dxgi.dll", "msvcrt.dll")  # Common system/game DLLs

# Game directories to whitelist (add your MMO paths here)
$GameDirs = @("C:\Program Files", "C:\Program Files (x86)", "C:\Games")  # Adjust for your MMO installs

# Dynamic whitelist: Add .ps1, .bat from C:\Users; .ps1/.bat/.exe from Program Files and GameDirs
function Get-DynamicWhitelist {
    $DynamicWhitelist = @()
    $DirsToScan = @("C:\Users") + $GameDirs
    foreach ($Dir in $DirsToScan) {
        if (Test-Path $Dir) {
            $Extensions = if ($Dir -like "*Users*") { @(".ps1", ".bat") } else { @(".ps1", ".bat", ".exe") }
            $Files = Get-ChildItem -Path $Dir -Recurse -File -Include $Extensions -ErrorAction SilentlyContinue
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

# Combine whitelists
$Whitelist = $StaticWhitelist
Write-Log "=== Cosmic Shield Auto-Mode Started - System-Wide Protection (DLL-Aware) ==="
Write-Log "DEBUG: Generating dynamic whitelist..."
$DynamicWhitelist = Get-DynamicWhitelist
$Whitelist += $DynamicWhitelist
Write-Log "DEBUG: Process whitelist contains $($Whitelist.Count) items: $($Whitelist -join ', ')"
Write-Log "DEBUG: DLL whitelist contains $($DLLWhitelist.Count) items: $($DLLWhitelist -join ', ')"

# Main loop: Infinite background monitoring
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # 1. Auto-Scan and Terminate Suspicious Processes (system-wide) + DLL Check
    Write-Log "DEBUG: Scanning processes with CPU > $CPUThreshold..."
    $SuspiciousProcs = Get-Process | Where-Object { 
        $_.ProcessName -notin $Whitelist -and 
        $_.CPU -gt $CPUThreshold
    } | Select-Object Name, Id, CPU, Path

    if ($SuspiciousProcs.Count -gt 0) {
        Write-Log "ALERT: Auto-terminating $($SuspiciousProcs.Count) suspicious processes and checking DLLs:"
        foreach ($Proc in $SuspiciousProcs) {
            Write-Log "  - TERMINATING: $($Proc.Name) (ID: $($Proc.Id), CPU: $($Proc.CPU), Path: $($Proc.Path))"
            try {
                # Check loaded DLLs
                $Modules = Get-Process -Id $Proc.Id -Module -ErrorAction SilentlyContinue | Where-Object { 
                    $_.FileName -and 
                    $_.FileName -notlike "C:\Windows\System32\*" -and 
                    $_.FileName -notlike "C:\Windows\SysWOW64\*" -and 
                    -not ($GameDirs | Where-Object { $_.FileName -like "$_*" }) -and 
                    [System.IO.Path]::GetFileName($_.FileName) -notin $DLLWhitelist
                }
                if ($Modules) {
                    Write-Log "    SUSPICIOUS DLLs in $($Proc.Name):"
                    foreach ($Module in $Modules) {
                        $DLLName = [System.IO.Path]::GetFileName($Module.FileName)
                        Write-Log "      - $DLLName ($($Module.FileName))"
                        # Quarantine DLL if not in protected paths
                        $QuarantinePath = Join-Path $QuarantineDir "${DLLName}_Auto_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                        Write-Log "        QUARANTINING DLL: $($Module.FileName) -> $QuarantinePath"
                        try {
                            Copy-Item $Module.FileName $QuarantinePath -Force -ErrorAction Stop
                            Write-Log "          SUCCESS: DLL copied (removal skipped to avoid crash)."
                        } catch {
                            Write-Log "          FAILED: $($_.Exception.Message)"
                        }
                    }
                }
                Stop-Process -Id $Proc.Id -Force -ErrorAction Stop
                Write-Log "    SUCCESS: $($Proc.Name) terminated."
            } catch {
                Write-Log "    FAILED: $($Proc.Name) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "No suspicious processes found."
    }

    # 2. Auto-Scan and Block Network Connections (system-wide, DLL-aware)
    Write-Log "DEBUG: Scanning network connections..."
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object RemoteAddress

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Checking $($NetConns.Count) outbound connections for DLL activity:"
        foreach ($Conn in $NetConns) {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $ProcName = $Proc.Name
            if ($ProcName -and $Whitelist -contains $ProcName) {
                Write-Log "  - SKIPPED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by whitelisted $ProcName (Proc: $($Conn.OwningProcess))"
            } else {
                Write-Log "  - SUSPICIOUS: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) (Proc: $($Conn.OwningProcess))"
                # Check DLLs for this process
                $Modules = Get-Process -Id $Conn.OwningProcess -Module -ErrorAction SilentlyContinue | Where-Object { 
                    $_.FileName -and 
                    $_.FileName -notlike "C:\Windows\System32\*" -and 
                    $_.FileName -notlike "C:\Windows\SysWOW64\*" -and 
                    -not ($GameDirs | Where-Object { $_.FileName -like "$_*" }) -and 
                    [System.IO.Path]::GetFileName($_.FileName) -notin $DLLWhitelist
                }
                if ($Modules) {
                    Write-Log "    SUSPICIOUS DLLs in $ProcName:"
                    foreach ($Module in $Modules) {
                        $DLLName = [System.IO.Path]::GetFileName($Module.FileName)
                        Write-Log "      - $DLLName ($($Module.FileName))"
                        $QuarantinePath = Join-Path $QuarantineDir "${DLLName}_Auto_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                        Write-Log "        QUARANTINING DLL: $($Module.FileName) -> $QuarantinePath"
                        try {
                            Copy-Item $Module.FileName $QuarantinePath -Force -ErrorAction Stop
                            Write-Log "          SUCCESS: DLL copied (removal skipped to avoid crash)."
                        } catch {
                            Write-Log "          FAILED: $($_.Exception.Message)"
                        }
                    }
                }
                $RuleName = "CosmicAutoBlock_$($Conn.RemoteAddress.Replace('.','_'))_$($Conn.RemotePort)"
                Write-Log "  - BLOCKING: To $($Conn.RemoteAddress):$($Conn.RemotePort)"
                try {
                    $Existing = netsh advfirewall firewall show rule name="$RuleName" 2>$null
                    if (!$Existing) {
                        netsh advfirewall firewall add rule name="$RuleName" dir=out action=block remoteip=$($Conn.RemoteAddress) remoteport=$($Conn.RemotePort) -ErrorAction Stop
                        Write-Log "    SUCCESS: Rule '$RuleName' added."
                    } else {
                        Write-Log "    SKIPPED: Rule '$RuleName' already exists."
                    }
                } catch {
                    Write-Log "    FAILED: $($Conn.RemoteAddress) - $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Log "No suspicious network activity."
    }

    # 3. Auto-Scan and Quarantine Recent File Changes (system-wide, user dirs included)
    Write-Log "DEBUG: Scanning files modified in last $FileChangeWindowHours hours..."
    $KeyDirs = @("C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")
    $RecentFiles = @()
    foreach ($Dir in $KeyDirs) {
        if (Test-Path $Dir) {
            $Changes = Get-ChildItem -Path $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { 
                $_.LastWriteTime -gt (Get-Date).AddHours(-$FileChangeWindowHours) -and 
                -not ($GameDirs | Where-Object { $_.FullName -like "$_*" })
            }
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
                if ($GameDirs | Where-Object { $_.FullName -like "$_*" }) {
                    Write-Log "    SKIPPED: $($_.FullName) in protected game directory"
                } else {
                    Write-Log "    QUARANTINING: $($_.FullName) -> $QuarantinePath"
                    try {
                        Copy-Item $_.FullName $QuarantinePath -Force -ErrorAction Stop
                        Remove-Item $_.FullName -Force -ErrorAction Stop
                        Write-Log "      SUCCESS: Copied and removed."
                    } catch {
                        Write-Log "      FAILED: $($_.Exception.Message)"
                    }
                }
            }
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
                $UserChanges = Get-ChildItem -Path $UserTemp -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-5) }
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
