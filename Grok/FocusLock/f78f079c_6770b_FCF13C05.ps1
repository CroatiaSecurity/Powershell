
# FocusLock.ps1 - Network Lockdown for Foreground Apps and Their Child Processes
# Runs continuously as SYSTEM, logging foreground apps to %TEMP%\FocusLock.log.
# Auto-whitelists each new foreground app and its child processes for network access.
# Blocks all other outbound connections (exe/dll) using Windows Firewall.
# NO default whitelist-apps must gain window focus to be whitelisted.
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
$ScanInterval = 30  # Seconds between scans

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

Write-Log "=== Focus Lockdown Started ==="
Write-Log "DEBUG: Starting with empty whitelist. Apps must gain focus to be whitelisted."

# Main loop: Monitor, log, and lock down network
while ($true) {
    Write-Log "=== Starting Scan Cycle ==="

    # Get active process
    $ActiveProcess = Get-ForegroundProcess
    if ($ActiveProcess) {
        $ProcName = $ActiveProcess.Name
        Write-Log "DEBUG: Active process: $ProcName (ID: $($ActiveProcess.Id), Path: $($ActiveProcess.Path))"
        
        # Log and whitelist new foreground process
        if ($ProcName -and $DynamicFocusWhitelist -notcontains $ProcName) {
            $DynamicFocusWhitelist += $ProcName
            Write-Log "INFO: New foreground app added to whitelist: $ProcName"
            # Log to file
            $LogEntry = "Foreground App: $ProcName (Path: $($ActiveProcess.Path), Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
            $LogEntry | Out-File -FilePath $LogPath -Append
            
            # Whitelist child processes
            $ChildProcesses = Get-ChildProcesses -ParentId $ActiveProcess.Id
            foreach ($Child in $ChildProcesses) {
                if ($Child -and $DynamicFocusWhitelist -notcontains $Child) {
                    $DynamicFocusWhitelist += $Child
                    Write-Log "INFO: Child process added to whitelist: $Child (Parent: $ProcName)"
                }
            }
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
        $RuleName = "FocusLock_Allow_$($Proc.Name)_$($Proc.Id)"
        try {
            netsh advfirewall firewall add rule name="$RuleName" dir=out program="$($Proc.Path)" action=allow enable=yes | Out-Null
            Write-Log "DEBUG: Added allow rule for $($Proc.Name): $RuleName"
        } catch {
            Write-Log "DEBUG: Failed to add allow rule for $($Proc.Name): $($_.Exception.Message)"
        }
    }

    # Block all other outbound connections
    $BlockRuleName = "FocusLock_Block_All"
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
            if ($ProcName -and $DynamicFocusWhitelist -contains $ProcName) {
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
