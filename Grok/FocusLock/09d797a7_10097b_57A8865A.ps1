
# FocusLock.ps1 - Real-Time Network Lockdown for Foreground Apps
# Runs continuously as SYSTEM, logging foreground apps to %TEMP%\FocusLock.log.
# Uses FileSystemWatcher to monitor log changes and instantly whitelist new apps and their child processes.
# Blocks ALL inbound/outbound connections for non-whitelisted processes (exe/dll).
# NO default whitelist—apps must gain focus to be whitelisted.
# Logs to %TEMP%\FocusLock.log. No process killing or file quarantine.
# To deploy: Save as .ps1, use Task Scheduler to run as SYSTEM (highest privs, hidden).

# Get current user's temp folder
$CurrentUser = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName
if ($CurrentUser) {
    $UserName = $CurrentUser.Split('\')[-1]
    $TempPath = [System.IO.Path]::GetTempPath()
} else {
    $TempPath = "C:\Windows\Temp"  # Fallback if no user is logged in
}
$LogPath = Join-Path $TempPath "FocusLock.log"
if (!(Test-Path $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host $Message -ForegroundColor Yellow
}

# Config
$ScanInterval = 30  # Seconds between network scans (FileSystemWatcher handles whitelist updates)

# Initialize empty whitelist
$DynamicFocusWhitelist = @()  # Tracks foreground apps and their child processes

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

# Get child processes
function Get-ChildProcesses {
    param($ParentId)
    $ChildProcs = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ParentId }
    $ChildNames = @()
    foreach ($Child in $ChildProcs) {
        $ChildName = $Child.Name -replace "\.exe$", ""
        if ($ChildName -and $ChildNames -notcontains $ChildName) {
            $ChildNames += $ChildName
        }
    }
    return $ChildNames
}

# FileSystemWatcher to monitor log file
function Start-LogWatcher {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = [System.IO.Path]::GetDirectoryName($LogPath)
    $watcher.Filter = [System.IO.Path]::GetFileName($LogPath)
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite
    $watcher.EnableRaisingEvents = $true

    $onChange = Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier LogFileWatcher -Action {
        $global:DynamicFocusWhitelist = $DynamicFocusWhitelist
        $logContent = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
        if ($logContent) {
            $newEntries = $logContent -split "`n" | Where-Object { $_ -match "Foreground App: (\S+)" }
            foreach ($entry in $newEntries) {
                if ($entry -match "Foreground App: (\S+) \(Path: (.+?), Time:") {
                    $procName = $matches[1]
                    $procPath = $matches[2]
                    if ($procName -and $global:DynamicFocusWhitelist -notcontains $procName) {
                        $global:DynamicFocusWhitelist += $procName
                        Write-Log "INFO: FileSystemWatcher detected new app in log: $procName"
                        
                        # Find running process to get child processes
                        $proc = Get-Process | Where-Object { $_.Name -eq $procName -and $_.Path -eq $procPath } | Select-Object -First 1
                        if ($proc) {
                            $childProcesses = Get-ChildProcesses -ParentId $proc.Id
                            foreach ($child in $childProcesses) {
                                if ($child -and $global:DynamicFocusWhitelist -notcontains $child) {
                                    $global:DynamicFocusWhitelist += $child
                                    Write-Log "INFO: Child process added to whitelist: $child (Parent: $procName)"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return $onChange
}

Write-Log "=== Focus Lockdown Started ==="
Write-Log "DEBUG: Starting with empty whitelist. Apps must gain focus to be whitelisted."
Write-Log "DEBUG: Starting FileSystemWatcher for $LogPath"
$WatcherEvent = Start-LogWatcher

# Main loop: Monitor foreground apps and manage network rules
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # Get active process and log it
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        $ProcName = $ActiveProcess.Name
        Write-Log "DEBUG: Active process: $ProcName (ID: $($ActiveProcess.Id), Path: $($ActiveProcess.Path))"
        
        # Log new foreground process (triggers FileSystemWatcher)
        if ($ProcName -and $DynamicFocusWhitelist -notcontains $ProcName) {
            $LogEntry = "Foreground App: $ProcName (Path: $($ActiveProcess.Path), Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
            $LogEntry | Out-File -FilePath $LogPath -Append
            # FileSystemWatcher will handle whitelisting
        }
    } else {
        Write-Log "DEBUG: No active process detected."
    }

    # Clear existing lockdown rules
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "FocusLock_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
            Write-Log "DEBUG: Cleared old rule: $RuleName"
        }
    }

    # Allow whitelisted processes
    $RunningProcs = Get-Process | Where-Object { $DynamicFocusWhitelist -contains $_.Name -and $_.Path }
    foreach ($Proc in $RunningProcs) {
        # Outbound rule
        $RuleNameOut = "FocusLock_Allow_Out_$($Proc.Name)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameOut" dir=out program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log "DEBUG: Added outbound allow rule for $($Proc.Name): $RuleNameOut"
        } catch {
            Write-Log "DEBUG: Failed to add outbound allow rule for $($Proc.Name): $($_.Exception.Message)"
        }
        # Inbound rule
        $RuleNameIn = "FocusLock_Allow_In_$($Proc.Name)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameIn" dir=in program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log "DEBUG: Added inbound allow rule for $($Proc.Name): $RuleNameIn"
        } catch {
            Write-Log "DEBUG: Failed to add inbound allow rule for $($Proc.Name): $($_.Exception.Message)"
        }
    }

    # Block all other inbound/outbound connections
    $BlockRuleNameOut = "FocusLock_Block_All_Out"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameOut" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameOut" dir=out action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all outbound rule: $BlockRuleNameOut"
        }
    } catch {
        Write-Log "DEBUG: Failed to add block-all outbound rule: $($_.Exception.Message)"
    }
    $BlockRuleNameIn = "FocusLock_Block_All_In"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameIn" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameIn" dir=in action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all inbound rule: $BlockRuleNameIn"
        }
    } catch {
        Write-Log "DEBUG: Failed to add block-all inbound rule: $($_.Exception.Message)"
    }

    # Log network connections
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    if ($NetConns.Count -gt 0) {
        Write-Log "INFO: Checking $($NetConns.Count) connections:"
        foreach ($Conn in $NetConns) {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $ProcName = $Proc.Name
            if ($ProcName -and $DynamicFocusWhitelist -contains $ProcName) {
                Write-Log "  - ALLOWED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            } else {
                Write-Log "  - BLOCKED: Connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
            }
        }
    } else {
        Write-Log "No network activity."
    }

    Write-Log "=== Scan Cycle Complete. Sleeping $ScanInterval seconds. ==="
    Start-Sleep -Seconds $ScanInterval
}

# Cleanup on script exit
$OnExit = {
    Unregister-Event -SourceIdentifier LogFileWatcher -ErrorAction SilentlyContinue
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "FocusLock_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
        }
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $OnExit
