# GFocus.ps1 - Real-Time Network Lockdown with Connection Termination, Process Killing, and Quarantining
# Author: Gorstak
# Runs continuously as SYSTEM, logging foreground apps to %TEMP%\GFocus.log instantly upon focus.
# Whitelists processes gaining window focus, stored in %TEMP%\GFocusWhitelist.txt, reloaded on restart.
# Blocks ALL inbound/outbound connections for non-whitelisted processes (exe/dll).
# Terminates active non-whitelisted connections, kills processes, and quarantines executables to C:\Quarantine.
# NO default whitelist-focus determines whitelist, persists across reboots.
# NO FileSystemWatcher-whitelisting happens directly on focus detection.
# Logs to %TEMP%\GFocus.log. Auto-registers as a SYSTEM, hidden task on startup.
# Encoding: UTF-8

# Get current user's temp folder
$CurrentUser = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName
if ($CurrentUser) {
    $UserName = $CurrentUser.Split('\')[-1]
    $TempPath = [System.IO.Path]::GetTempPath()
} else {
    $TempPath = "C:\Windows\Temp"  # Fallback if no user is logged in
}
$LogPath = Join-Path $TempPath "GFocus.log"
$WhitelistPath = Join-Path $TempPath "GFocusWhitelist.txt"
if (!(Test-Path $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null }

# Quarantine folder
$QuarantinePath = "C:\Quarantine"
if (!(Test-Path $QuarantinePath)) { New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Host $Message -ForegroundColor Yellow
}

# Save the script to a fixed location for Task Scheduler
$scriptPath = "C:\ProgramData\GFocus.ps1"
if (-not (Test-Path $scriptPath)) {
    Set-Content -Path $scriptPath -Value $PSCommandPath -Force
}

# Function to set up Task Scheduler for startup and persistence
function Register-GFocusTask {
    $taskName = "GFocus"
    $scriptPath = "C:\ProgramData\GFocus.ps1"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
        Write-Host "Antivirus scheduled task registered successfully. Will run at startup."
    }
    catch {
        Write-Host "Failed to register scheduled task: $_"
        exit
    }
}

Register-GFocusTask
# Config
$ScanIntervalMs = 1000  # Milliseconds between focus checks (1 second)

# Initialize whitelist from file or empty array
$DynamicFocusWhitelist = @()
if (Test-Path $WhitelistPath) {
    $DynamicFocusWhitelist = Get-Content -Path $WhitelistPath | Where-Object { $_ -and $_ -notmatch '^\s*$' }
    Write-Log "INFO: Loaded whitelist from $WhitelistPath with $($DynamicFocusWhitelist.Count) entries"
} else {
    Write-Log "INFO: No existing whitelist file found, starting empty."
}

# Critical system processes to avoid killing
$CriticalProcesses = @("svchost", "wininit", "csrss", "smss", "lsass", "winlogon", "services", "System", "explorer")

# Win32 API for foreground window
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
'@

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
        $ChildName = $Child.Name -replace '\.exe$', ''
        if ($ChildName -and $ChildNames -notcontains $ChildName) {
            $ChildNames += $ChildName
        }
    }
    return $ChildNames
}

# Terminate non-whitelisted connections, kill processes, and quarantine executables
function Terminate-NonWhitelistedConnections {
    param($Whitelist)
    $NetConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

    foreach ($Conn in $NetConns) {
        $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        $ProcName = $Proc.Name -replace '\.exe$', ''
        if ($ProcName -and $Whitelist -notcontains $ProcName) {
            # Skip critical system processes
            if ($CriticalProcesses -contains $ProcName) {
                Write-Log "INFO: Skipped terminating critical process $ProcName (Proc: $($Conn.OwningProcess))"
                continue
            }

            # Terminate connection
            $TempRuleName = "GFocus_TempBlock_$($Conn.OwningProcess)_$(Get-Random)"
            try {
                netsh advfirewall firewall add rule name="$TempRuleName" dir=out program="$($Proc.Path)" action=block enable=yes | Out-Null
                Write-Log "INFO: Terminated connection to $($Conn.RemoteAddress):$($Conn.RemotePort) by $ProcName (Proc: $($Conn.OwningProcess))"
                Start-Sleep -Milliseconds 100
                netsh advfirewall firewall delete rule name="$TempRuleName" | Out-Null
            } catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log ("DEBUG: Failed to terminate connection for " + $ProcName + " : " + $ErrorMessage)
            }

            # Kill the process
            try {
                Stop-Process -Id $Conn.OwningProcess -Force -ErrorAction Stop
                Write-Log "INFO: Killed non-whitelisted process $ProcName (Proc: $($Conn.OwningProcess))"
            } catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log ("DEBUG: Failed to kill process " + $ProcName + " : " + $ErrorMessage)
            }

            # Quarantine the executable
            if ($Proc.Path -and (Test-Path $Proc.Path)) {
                try {
                    $QuarantineFile = Join-Path $QuarantinePath "$($ProcName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').exe"
                    if (Get-Process -Name $ProcName -ErrorAction SilentlyContinue) {
                        Write-Log "DEBUG: Skipping quarantine for $ProcName - process still running or file in use"
                    } else {
                        Move-Item -Path $Proc.Path -Destination $QuarantineFile -Force -ErrorAction Stop
                        Write-Log "INFO: Quarantined $ProcName to $QuarantineFile"
                    }
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Log ("DEBUG: Failed to quarantine " + $Proc.Path + " : " + $ErrorMessage)
                }
            }
        }
    }
}

Write-Log "=== GFocus Lockdown Started ==="
Write-Log "DEBUG: Starting with whitelist loaded from $WhitelistPath."

# Main loop: Monitor foreground apps, log, whitelist, terminate, and manage network rules
while ($true) {
    # Get active process
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        $ProcName = $ActiveProcess.Name -replace '\.exe$', ''
        $ProcId = $ActiveProcess.Id
        $ProcPath = $ActiveProcess.Path

        # Check if foreground process changed
        if ($LastForegroundProcess -eq $null -or $LastForegroundProcess.Id -ne $ProcId -or $LastForegroundProcess.Name -ne $ProcName) {
            Write-Log "DEBUG: New active process: $ProcName (ID: $ProcId, Path: $ProcPath)"
            $LastForegroundProcess = $ActiveProcess

            # Log and whitelist new foreground process
            if ($ProcName -and $DynamicFocusWhitelist -notcontains $ProcName) {
                $DynamicFocusWhitelist += $ProcName
                $DynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $WhitelistPath -Encoding UTF8
                Write-Log "INFO: New foreground app added to whitelist: $ProcName"
                # Log to file
                $LogEntry = "Foreground App: $ProcName (Path: $ProcPath, Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
                $LogEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8

                # Whitelist child processes
                $ChildProcesses = Get-ChildProcesses -ParentId $ProcId
                foreach ($Child in $ChildProcesses) {
                    if ($Child -and $DynamicFocusWhitelist -notcontains $Child) {
                        $DynamicFocusWhitelist += $Child
                        $DynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $WhitelistPath -Encoding UTF8
                        Write-Log "INFO: Child process added to whitelist: $Child (Parent: $ProcName)"
                    }
                }
            }
        }
    } else {
        Write-Log "DEBUG: No active process detected."
    }

    # Update firewall rules immediately based on current whitelist
    # Clear existing rules
    $ExistingRules = netsh advfirewall firewall show rule name=all | Select-String "GFocus_"
    if ($ExistingRules) {
        $ExistingRules | ForEach-Object {
            $RuleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$RuleName" | Out-Null
            Write-Log "DEBUG: Cleared old rule: $RuleName"
        }
    }

    # Allow whitelisted processes
    $RunningProcs = Get-Process | Where-Object { $DynamicFocusWhitelist -contains ($_.Name -replace '\.exe$', '') -and $_.Path }
    foreach ($Proc in $RunningProcs) {
        $ProcName = $Proc.Name -replace '\.exe$', ''
        # Outbound rule
        $RuleNameOut = "GFocus_Allow_Out_$($ProcName)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameOut" dir=out program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log ("DEBUG: Added outbound allow rule for " + $ProcName + " : " + $RuleNameOut)
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log ("DEBUG: Failed to add outbound allow rule for " + $ProcName + " : " + $ErrorMessage)
        }
        # Inbound rule
        $RuleNameIn = "GFocus_Allow_In_$($ProcName)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleNameIn" dir=in program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log ("DEBUG: Added inbound allow rule for " + $ProcName + " : " + $RuleNameIn)
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log ("DEBUG: Failed to add inbound allow rule for " + $ProcName + " : " + $ErrorMessage)
        }
    }

    # Block all other inbound/outbound connections
    $BlockRuleNameOut = "GFocus_Block_All_Out"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameOut" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameOut" dir=out action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all outbound rule: $BlockRuleNameOut"
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log ("DEBUG: Failed to add block-all outbound rule: " + $ErrorMessage)
    }
    $BlockRuleNameIn = "GFocus_Block_All_In"
    try {
        $Existing = netsh advfirewall firewall show rule name="$BlockRuleNameIn" 2>$null
        if (!$Existing) {
            netsh advfirewall firewall add rule name="$BlockRuleNameIn" dir=in action=block enable=yes | Out-Null
            Write-Log "DEBUG: Added block-all inbound rule: $BlockRuleNameIn"
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log ("DEBUG: Failed to add block-all inbound rule: " + $ErrorMessage)
    }

    # Terminate non-whitelisted connections, kill processes, and quarantine
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
            $ProcName = $Proc.Name -replace '\.exe$', ''
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