
# FocusLock.ps1 - Real-Time Network Lockdown with Connection Termination
# Runs continuously as SYSTEM, logging foreground apps to %TEMP%\FocusLock.log instantly upon focus.
# Instantly whitelists new apps and their child processes for network access.
# Blocks ALL inbound/outbound connections for non-whitelisted processes (exe/dll).
# Terminates active non-whitelisted connections.
# NO default whitelist—apps must gain focus to be whitelisted.
# NO FileSystemWatcher—whitelisting happens directly on focus detection.
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
$ScanIntervalMs = 1000  # Milliseconds between focus checks (1 second)

# Initialize empty whitelist
$DynamicFocusWhitelist = @()  # Tracks foreground apps and their child processes
$LastForegroundProcess = $null  # Track last foreground to avoid redundant updates

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

# Terminate non-whitelisted connections
function Terminate-NonWhitelistedConnections {
    param($Whitelist)
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    foreach ($Conn in $NetConns) {
        $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        $ProcName = $Proc.Name
        if ($ProcName -and $Whitelist -notcontains $ProcName) {
            # Attempt to terminate connection by adding a temporary block rule
            $TempRuleName = "FocusLock_TempBlock_$($Conn.OwningProcess)_$(Get-Random)"
            try {
                netsh advfirewall firewall add rule name="$TempRuleName" dir=out program="$($Proc.Path)" action=block enable=yes | Out-Null
                Write-Log "INFO: Terminated connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
                # Remove temp rule after brief delay to ensure connection reset
                Start-Sleep -Milliseconds 100
                netsh advfirewall firewall delete rule name="$TempRuleName" | Out-Null
            } catch {
                Write-Log "DEBUG: Failed to terminate connection for $ProcName: $($_.Exception.Message)"
            }
        }
    }
}

Write-Log "=== Focus Lockdown Started ==="
Write-Log "DEBUG: Starting with empty whitelist. Apps must gain focus to be whitelisted."

# Main loop: Monitor foreground apps, log, whitelist, terminate, and manage network rules
while ($true) {
    # Get active process
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        $ProcName = $ActiveProcess.Name
        $ProcId = $ActiveProcess.Id
        $ProcPath = $ActiveProcess.Path

        # Check if foreground process changed
        if ($LastForegroundProcess -eq $null -or $LastForegroundProcess.Id -ne $ProcId -or $LastForegroundProcess.Name -ne $ProcName) {
            Write-Log "DEBUG: New active process: $ProcName (ID: $ProcId, Path: $ProcPath)"
            $LastForegroundProcess = $ActiveProcess

            # Log and whitelist new foreground process
            if ($ProcName -and $DynamicFocusWhitelist -notcontains $ProcName) {
                $DynamicFocusWhitelist += $ProcName
                Write-Log "INFO: New foreground app added to whitelist: $ProcName"
                # Log to file
                $LogEntry = "Foreground App: $ProcName (Path: $ProcPath, Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
                $LogEntry | Out-File -FilePath $LogPath -Append

                # Whitelist child processes
                $ChildProcesses = Get-ChildProcesses -ParentId $ProcId
                foreach ($Child in $ChildProcesses) {
                    if ($Child -and $DynamicFocusWhitelist -notcontains $Child) {
                        $DynamicFocusWhitelist += $Child
                        Write-Log "INFO: Child process added to whitelist: $Child (Parent: $ProcName)"
                    }
                }

                # Update firewall rules immediately
                # Clear existing rules
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
            }
        }
    } else {
        Write-Log "DEBUG: No active process detected."
    }

    # Terminate non-whitelisted connections
    Terminate-NonWhitelistedConnections -Whitelist $DynamicFocusWhitelist

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

    Start-Sleep -Milliseconds $ScanIntervalMs
}

# Cleanup on script exit
$OnExit = {
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "FocusLock_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
        }
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $OnExit
