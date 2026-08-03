
# CosmicLockdown.ps1 - Network Lockdown for Active Browser or MMO
# Runs continuously, monitoring system-wide (all users) as SYSTEM.
# Detects if user is surfing (browser) or playing MMO, allows only those connections, blocks all else.
# Whitelists .ps1/.bat in C:\Users, .exe in Program Files/Games, and update servers.
# WARNING: High-risk-blocks most network traffic. Test in VM. Logs to C:\CosmicLockdown.log.
# To deploy: Save as .ps1, use Task Scheduler to run as SYSTEM (highest privs, hidden).

# Set paths
$LogPath = "C:\CosmicLockdown.log"
$QuarantineDir = "C:\CosmicQuarantine"
if (!(Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host $Message -ForegroundColor Yellow
}

# Config
$ScanInterval = 30  # Seconds between scans
$CPUThreshold = 20  # CPU % for activity detection
$FileChangeWindowHours = 24  # Look back for file changes (for DLL checks)

# Static whitelists
$StaticWhitelist = @("explorer", "svchost", "lsass", "winlogon", "csrss", "System", "Idle", "powershell", "cmd", "taskhostw", "dwm", "wininit", "brave", "chrome", "msedge", "firefox", "updater", "GoogleUpdate", "MozillaMaintenance", "SteamService")
$DLLWhitelist = @("kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "ntdll.dll", "d3d11.dll", "dxgi.dll", "msvcrt.dll", "libcef.dll", "firefox.dll", "xul.dll")
$GameProcesses = @("WoW", "ffxiv_dx11", "destiny2")  # Add your MMO .exe names (without .exe)
$UpdateServers = @("update.google.com", "aus5.mozilla.org", "steampowered.com", "*.blizzard.com")  # Add MMO update servers

# Directories to whitelist
$GameDirs = @("C:\Program Files", "C:\Program Files (x86)", "C:\Games")  # Add your MMO paths
$UpdateDirs = @("C:\Program Files (x86)\Google\Update", "C:\Program Files (x86)\Mozilla Maintenance Service", "C:\Program Files (x86)\Steam", "C:\Users\*\AppData\Local\Google\Chrome\User Data", "C:\Users\*\AppData\Local\Mozilla\Updates", "C:\Users\*\AppData\Local\Temp")

# Dynamic whitelist: Add .ps1, .bat from C:\Users; .exe from Program Files, Games, Update dirs
function Get-DynamicWhitelist {
    $DynamicWhitelist = @()
    $DirsToScan = @("C:\Users") + $GameDirs + $UpdateDirs
    foreach ($Dir in $DirsToScan) {
        if (Test-Path $Dir) {
            $Extensions = if ($Dir -like "*Users*") { @(".ps1", ".bat") } else { @(".exe") }
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

# Win32 API to get foreground window process
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
$Whitelist = $StaticWhitelist + $GameProcesses
Write-Log "=== Cosmic Lockdown Started - Network Isolation Mode ==="
Write-Log "DEBUG: Generating dynamic whitelist..."
$DynamicWhitelist = Get-DynamicWhitelist
$Whitelist += $DynamicWhitelist
Write-Log "DEBUG: Process whitelist contains $($Whitelist.Count) items: $($Whitelist -join ', ')"
Write-Log "DEBUG: DLL whitelist contains $($DLLWhitelist.Count) items: $($DLLWhitelist -join ', ')"

# Main loop: Infinite background monitoring
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # Detect active user activity (browser or MMO)
    $ActiveProcess = $null
    $ForegroundProc = Get-ForegroundProcess
    if ($ForegroundProc -and $Whitelist -contains $ForegroundProc.Name) {
        $ActiveProcess = $ForegroundProc
        Write-Log "DEBUG: Active process detected: $($ActiveProcess.Name) (ID: $($ActiveProcess.Id))"
    } else {
        # Fallback: Check high-CPU processes for MMOs
        $HighCPUProcs = Get-Process | Where-Object { 
            $_.CPU -gt $CPUThreshold -and $Whitelist -contains $_.Name 
        } | Sort-Object CPU -Descending | Select-Object -First 1
        if ($HighCPUProcs) {
            $ActiveProcess = $HighCPUProcs
            Write-Log "DEBUG: High-CPU process detected: $($ActiveProcess.Name) (ID: $($ActiveProcess.Id))"
        }
    }

    # Manage firewall rules
    if ($ActiveProcess) {
        Write-Log "INFO: Locking down network for $($ActiveProcess.Name)..."
        # Clear existing CosmicLockdown rules
        $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "CosmicLockdown_"
        if ($ExistingRules) {
            $ExistingRules | ForEach-Object {
                $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
                netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
                Write-Log "DEBUG: Cleared old rule: $RuleName"
            }
        }

        # Allow connections from active process
        $RuleName = "CosmicLockdown_Allow_$($ActiveProcess.Name)"
        try {
            netsh advfirewall firewall add rule name="$RuleName" dir=out program="$($ActiveProcess.Path)" action=allow enable=yes | Out-Null
            Write-Log "DEBUG: Added allow rule for $($ActiveProcess.Name): $RuleName"
        } catch {
            Write-Log "DEBUG: Failed to add allow rule for $($ActiveProcess.Name): $($_.Exception.Message)"
        }

        # Allow update servers
        foreach ($Server in $UpdateServers) {
            $RuleName = "CosmicLockdown_Allow_Update_$($Server.Replace('.','_'))"
            try {
                netsh advfirewall firewall add rule name="$RuleName" dir=out action=allow remoteip="$Server" enable=yes | Out-Null
                Write-Log "DEBUG: Added allow rule for update server: $Server"
            } catch {
                Write-Log "DEBUG: Failed to add allow rule for $Server: $($_.Exception.Message)"
            }
        }

        # Block all other outbound connections
        $BlockRuleName = "CosmicLockdown_Block_All"
        try {
            $Existing = netsh advfirewall firewall show rule name="$BlockRuleName" 2>$null
            if (!$Existing) {
                netsh advfirewall firewall add rule name="$BlockRuleName" dir=out action=block enable=yes | Out-Null
                Write-Log "DEBUG: Added block-all rule: $BlockRuleName"
            }
        } catch {
            Write-Log "DEBUG: Failed to add block-all rule: $($_.Exception.Message)"
        }
    } else {
        Write-Log "DEBUG: No active browser or MMO detected. Clearing lockdown rules..."
        $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "CosmicLockdown_"
        if ($ExistingRules) {
            $ExistingRules | ForEach-Object {
                $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
                netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
                Write-Log "DEBUG: Cleared rule: $RuleName"
            }
        }
    }

    # Check suspicious processes and DLLs
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
                $Modules = Get-Process -Id $Proc.Id -Module -ErrorAction SilentlyContinue | Where-Object { 
                    $_.FileName -and 
                    $_.FileName -notlike "C:\Windows\System32\*" -and 
                    $_.FileName -notlike "C:\Windows\SysWOW64\*" -and 
                    -not ($GameDirs + $UpdateDirs | Where-Object { $_.FileName -like "$_*" }) -and 
                    [System.IO.Path]::GetFileName($_.FileName) -notin $DLLWhitelist
                }
                if ($Modules) {
                    Write-Log "    SUSPICIOUS DLLs in $($Proc.Name):"
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
                Stop-Process -Id $Proc.Id -Force -ErrorAction Stop
                Write-Log "    SUCCESS: $($Proc.Name) terminated."
            } catch {
                Write-Log "    FAILED: $($Proc.Name) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "No suspicious processes found."
    }

    # Check network connections for non-whitelisted activity
    Write-Log "DEBUG: Scanning network connections..."
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object RemoteAddress

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Checking $($NetConns.Count) outbound connections:"
        foreach ($Conn in $NetConns) {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $ProcName = $Proc.Name
            if ($ProcName -and $Whitelist -contains $ProcName -and $Proc.Id -eq $ActiveProcess.Id) {
                Write-Log "  - ALLOWED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by active $ProcName (Proc: $($Conn.OwningProcess))"
            } else {
                Write-Log "  - SUSPICIOUS: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) (Proc: $($Conn.OwningProcess))"
                $Modules = Get-Process -Id $Conn.OwningProcess -Module -ErrorAction SilentlyContinue | Where-Object { 
                    $_.FileName -and 
                    $_.FileName -notlike "C:\Windows\System32\*" -and 
                    $_.FileName -notlike "C:\Windows\SysWOW64\*" -and 
                    -not ($GameDirs + $UpdateDirs | Where-Object { $_.FileName -like "$_*" }) -and 
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
            }
        }
    } else {
        Write-Log "No suspicious network activity."
    }

    # Check recent file changes (for DLLs or suspicious files)
    Write-Log "DEBUG: Scanning files modified in last $FileChangeWindowHours hours..."
    $KeyDirs = @("C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")
    $RecentFiles = @()
    foreach ($Dir in $KeyDirs) {
        if (Test-Path $Dir) {
            $Changes = Get-ChildItem -Path $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { 
                $_.LastWriteTime -gt (Get-Date).AddHours(-$FileChangeWindowHours) -and 
                -not ($GameDirs + $UpdateDirs | Where-Object { $_.FullName -like "$_*" })
            }
            $RecentFiles += $Changes | Select-Object FullName, LastWriteTime, Length
        }
    }

    $RecentCount = $RecentFiles.Count
    if ($RecentCount -gt 0) {
        Write-Log "INFO: Detected $RecentCount recent file changes:"
        $RecentFiles | ForEach-Object { Write-Log "  - MONITORED: $($_.FullName) modified $($_.LastWriteTime) (Size: $($_.Length) bytes)" }
    } else {
        Write-Log "No recent file changes."
    }

    # User-specific eye: Check logged-in users' temp dirs
    Write-Log "DEBUG: Scanning logged-in users..."
    $LoggedInUsers = Get-WmiObject Win32_LoggedOnUser | ForEach-Object { 
        if ($_.Antecedent -match 'Name=\"([^\"]+)\"') { $matches[1] } 
    } | Where-Object { $_ -and $_ -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' } | Sort-Object -Unique

    if ($LoggedInUsers) {
        Write-Log "EYE ON USERS: Monitoring $($LoggedInUsers.Count) logged-in users: $($LoggedInUsers -join ', ')"
        foreach ($User in $LoggedInUsers) {
            $UserTemp = "C:\Users\$User\AppData\Local\Temp"
            if (Test-Path $UserTemp) {
                $UserChanges = Get-ChildItem -Path $UserTemp -File -ErrorAction SilentlyContinue | Where-Object { 
                    $_.CreationTime -gt (Get-Date).AddMinutes(-5) -and 
                    -not ($UpdateDirs | Where-Object { $_.FullName -like "$_*" })
                }
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
