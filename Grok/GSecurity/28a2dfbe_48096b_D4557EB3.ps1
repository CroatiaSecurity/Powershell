# GSecurity.ps1
# Author: Gorstak
# Description: A comprehensive Windows security hardening script with full GFocus dynamic whitelisting and all original features preserved.
# Version: 2.6
# Date: October 26, 2025
# Requires: Administrative privileges

# -------------------
# Configuration
# -------------------
$Config = @{
    LogPath             = "$env:ProgramData\GSecurity.log"
    QuarantinePath      = "C:\Quarantine"
    ScriptDir           = "C:\Windows\Setup\Scripts\Bin"
    CheckIntervalSeconds = 10
    ScanIntervalMs      = 1000  # GFocus foreground scan interval
    ProtectedProcesses  = @("System", "smss", "csrss", "wininit", "services", "lsass", "svchost", "dwm", "explorer", "taskhostw", "winlogon", "conhost", "cmd", "powershell")
    TrustedDriverVendors = @("*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*")
    BadProcessNames     = @("mimikatz", "procdump", "mimilib", "pypykatz")
    BlockedPorts        = @(23, 137, 138, 139, 389, 445, 636, 3389, 5900, 5901, 5902, 5938, 5985, 5986, 7070)
    WhitelistPath       = "$env:TEMP\GFocusWhitelist.txt"
    ConsoleLogonSID     = "S-1-2-1"
}

# -------------------
# Logging Function
# -------------------
function Write-Log {
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("Info", "Warning", "Error")][string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $fallbackLogPath = "$env:TEMP\GSecurity_Fallback.log"
    $logPath = if ($Config.LogPath -and (Test-Path -PathType Container (Split-Path $Config.LogPath -Parent))) { $Config.LogPath } else { $fallbackLogPath }
    try {
        Add-Content -Path $logPath -Value $logEntry -ErrorAction Stop
        if ($Host.Name -match "ConsoleHost") {
            switch ($Level) {
                "Error"   { Write-Host $logEntry -ForegroundColor Red }
                "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
                "Info"    { Write-Host $logEntry -ForegroundColor White }
            }
        }
    } catch {
        Write-Host "Error writing to log at ${logPath}: $_" -ForegroundColor Red
    }
}

# -------------------
# Utility Functions
# -------------------
function Ensure-AdminPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Script requires administrative privileges." -Level Error
        exit 1
    }
}

function Register-ScheduledTaskCustom {
    param (
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$TriggerType = "AtStartup",
        [string]$UserId = "SYSTEM",
        [string]$Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden"
    )
    try {
        $targetPath = Join-Path $Config.ScriptDir (Split-Path $ScriptPath -Leaf)
        if (-not (Test-Path $Config.ScriptDir)) {
            New-Item -Path $Config.ScriptDir -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: ${Config.ScriptDir}" -Level Info
        }
        Copy-Item -Path $ScriptPath -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: ${targetPath}" -Level Info
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$Arguments -File `"$targetPath`""
        $trigger = if ($TriggerType -eq "AtLogon") { New-ScheduledTaskTrigger -AtLogOn } else { New-ScheduledTaskTrigger -AtStartup }
        $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        Write-Log "Scheduled task '$TaskName' created to run at $TriggerType under $UserId." -Level Info
    } catch {
        Write-Log "Failed to register task '$TaskName': $_" -Level Error
    }
}

function Quarantine-File {
    param (
        [string]$FilePath,
        [string]$ProcessName
    )
    if ($FilePath -and (Test-Path $FilePath)) {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $dest = Join-Path $Config.QuarantinePath "$timestamp`_$([System.IO.Path]::GetFileName($FilePath))"
            Move-Item -Path $FilePath -Destination $dest -Force -ErrorAction Stop
            Write-Log "Quarantined $ProcessName to ${dest}" -Level Info
        } catch {
            Write-Log "Error quarantining ${FilePath}: $_" -Level Error
        }
    } else {
        Write-Log "No valid path for quarantining $ProcessName" -Level Warning
    }
}

# -------------------
# GFocus: Dynamic Foreground Whitelisting
# -------------------
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

function Get-ChildProcesses {
    param($ParentId)
    $childProcs = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ParentId }
    $childNames = @()
    foreach ($child in $childProcs) {
        $childName = $child.Name -replace '\.exe$', ''
        if ($childName -and $childNames -notcontains $childName) {
            $childNames += $childName
        }
    }
    return $childNames
}

function Terminate-NonWhitelistedConnections {
    param($Whitelist)
    $netConns = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    foreach ($conn in $netConns) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.Name -replace '\.exe$', '' } else { 'unknown' }
        if ($procName -and $Whitelist -notcontains $procName -and $Config.ProtectedProcesses -notcontains $procName) {
            $tempRuleName = "GFocus_TempBlock_$($conn.OwningProcess)_$(Get-Random)"
            try {
                netsh advfirewall firewall add rule name="$tempRuleName" dir=out program="$($proc.Path)" action=block enable=yes | Out-Null
                Write-Log "Blocked connection to $($conn.RemoteAddress):$($conn.RemotePort) by $procName (PID: $($conn.OwningProcess))" -Level Warning
                Start-Sleep -Milliseconds 100
                netsh advfirewall firewall delete rule name="$tempRuleName" | Out-Null
            } catch {
                Write-Log "Failed to block connection for ${procName}: $_" -Level Error
            }
            try {
                Stop-Process -Id $conn.OwningProcess -Force -ErrorAction Stop
                Write-Log "Killed non-whitelisted process $procName (PID: $($conn.OwningProcess))" -Level Warning
            } catch {
                Write-Log "Failed to kill process ${procName}: $_" -Level Error
            }
            if ($proc -and $proc.Path -and (Test-Path $proc.Path)) {
                Quarantine-File -FilePath $proc.Path -ProcessName $procName
            }
        }
    }
}

function Start-GFocus {
    Write-Log "Starting GFocus: Dynamic foreground whitelisting enabled." -Level Info
    $dynamicFocusWhitelist = @()
    if (Test-Path $Config.WhitelistPath) {
        $dynamicFocusWhitelist = Get-Content -Path $Config.WhitelistPath | Where-Object { $_ -and $_ -notmatch '^\s*$' }
        Write-Log "Loaded existing whitelist from ${Config.WhitelistPath} with $($dynamicFocusWhitelist.Count) entries" -Level Info
    } else {
        Write-Log "No existing whitelist found, starting empty." -Level Info
    }
    $lastForegroundProcess = $null
    while ($true) {
        $activeProcess = Get-ForegroundProcess
        if ($activeProcess) {
            $procName = $activeProcess.Name -replace '\.exe$', ''
            $procId = $activeProcess.Id
            if ($lastForegroundProcess -eq $null -or $lastForegroundProcess.Id -ne $procId) {
                Write-Log "New foreground process detected: $procName (PID: $procId)" -Level Info
                $lastForegroundProcess = $activeProcess
                if ($procName -and $dynamicFocusWhitelist -notcontains $procName) {
                    $dynamicFocusWhitelist += $procName
                    $dynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $Config.WhitelistPath -Encoding UTF8
                    Write-Log "Added $procName to dynamic whitelist." -Level Info
                }
                $childProcesses = Get-ChildProcesses -ParentId $procId
                foreach ($child in $childProcesses) {
                    if ($child -and $dynamicFocusWhitelist -notcontains $child) {
                        $dynamicFocusWhitelist += $child
                        $dynamicFocusWhitelist | Sort-Object -Unique | Set-Content -Path $Config.WhitelistPath -Encoding UTF8
                        Write-Log "Added child process $child to whitelist (parent: $procName)" -Level Info
                    }
                }
            }
        }
        netsh advfirewall firewall show rule name=all | Select-String "GFocus_" | ForEach-Object {
            $ruleName = $_.Line -replace ".*Rule Name:\s*([^\s]+).*", '$1'
            netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
        }
        $runningProcs = Get-Process | Where-Object { $dynamicFocusWhitelist -contains ($_.Name -replace '\.exe$', '') -and $_.Path }
        foreach ($proc in $runningProcs) {
            $procName = $proc.Name -replace '\.exe$', ''
            $ruleNameOut = "GFocus_Allow_Out_$procName_$($proc.Id)"
            netsh advfirewall firewall add rule name="$ruleNameOut" dir=out program="$($proc.Path)" action=allow enable=yes | Out-Null
            $ruleNameIn = "GFocus_Allow_In_$procName_$($proc.Id)"
            netsh advfirewall firewall add rule name="$ruleNameIn" dir=in program="$($proc.Path)" action=allow enable=yes | Out-Null
            Write-Log "Added firewall allow rules for $procName" -Level Info
        }
        $blockRuleNameOut = "GFocus_Block_All_Out"
        if (-not (netsh advfirewall firewall show rule name="$blockRuleNameOut" 2>$null)) {
            netsh advfirewall firewall add rule name="$blockRuleNameOut" dir=out action=block enable=yes | Out-Null
        }
        $blockRuleNameIn = "GFocus_Block_All_In"
        if (-not (netsh advfirewall firewall show rule name="$blockRuleNameIn" 2>$null)) {
            netsh advfirewall firewall add rule name="$blockRuleNameIn" dir=in action=block enable=yes | Out-Null
        }
        Terminate-NonWhitelistedConnections -Whitelist $dynamicFocusWhitelist
        Start-Sleep -Milliseconds $Config.ScanIntervalMs
    }
}

# -------------------
# Process Monitoring
# -------------------
function Monitor-Processes {
    while ($true) {
        try {
            foreach ($name in $Config.BadProcessNames) {
                Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Name -notin $Config.ProtectedProcesses) {
                        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                        Write-Log "Terminated malicious process: $name (PID: $($_.Id))" -Level Warning
                        Quarantine-File -FilePath $_.Path -ProcessName $name
                    }
                }
            }
            Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and (Test-Path $_.ExecutablePath) } | ForEach-Object {
                $exePath = $_.ExecutablePath
                $isHidden = (Get-Item $exePath -ErrorAction SilentlyContinue).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue).Status
                if (($isHidden -or $sigStatus -ne "Valid") -and $_.Name -notin $Config.ProtectedProcesses) {
                    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                    Write-Log "Terminated unsigned/hidden process: ${exePath} (PID: $($_.ProcessId))" -Level Warning
                    Quarantine-File -FilePath $exePath -ProcessName $_.Name
                }
            }
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }
            foreach ($pid in $hidden) {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc -and $proc.Name -notin $Config.ProtectedProcesses) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Log "Terminated stealthy process: $($proc.Name) (PID: $($pid.InputObject))" -Level Warning
                    Quarantine-File -FilePath $proc.Path -ProcessName $proc.Name
                }
            }
        } catch {
            Write-Log "Error in process monitoring: $_" -Level Error
        }
        Start-Sleep -Seconds $Config.CheckIntervalSeconds
    }
}

function Monitor-Keyloggers {
    try {
        $suspiciousProcesses = Get-Process | Where-Object {
            ($_.Modules.ModuleName -match "hook|key|log|capture|sniff") -or
            ($_.Path -match "keylogger|hook|log|capture|sniff") -or
            (Get-Process -Id $_.Id -Module -ErrorAction SilentlyContinue | Where-Object { $_.ModuleName -match "keylogger|hook|log|capture|sniff" })
        }
        foreach ($process in $suspiciousProcesses) {
            if ($process.Name -notin $Config.ProtectedProcesses) {
                Write-Log "Potential keylogger detected: $($process.Name) (PID: $($process.Id))" -Level Warning
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                Quarantine-File -FilePath $process.Path -ProcessName $process.Name
            }
        }
    } catch {
        Write-Log "Error in keylogger monitoring: $_" -Level Error
    }
}

function Monitor-WebServers {
    try {
        $ports = @(80, 443, 8080)
        $connections = Get-NetTCPConnection | Where-Object { $ports -contains $_.LocalPort }
        foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($process -and $process.Name -notin $Config.ProtectedProcesses) {
                Write-Log "Web server detected: $($process.Name) (PID: $($process.Id)) on port $($conn.LocalPort)" -Level Warning
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                Quarantine-File -FilePath $process.Path -ProcessName $process.Name
            }
        }
        $webServices = @("w3svc", "apache2", "nginx")
        foreach ($serviceName in $webServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped web server service: $serviceName" -Level Warning
            }
        }
    } catch {
        Write-Log "Error in web server monitoring: $_" -Level Error
    }
}

function Monitor-AudioProcesses {
    try {
        $audioProcesses = Get-Process | Where-Object { $_.Path -and (Get-Content $_.Path -ErrorAction SilentlyContinue | Select-String "wave|audio|sound|record") }
        foreach ($process in $audioProcesses) {
            if ($process.Name -notin $Config.ProtectedProcesses) {
                Write-Log "Potential audio-monitoring process detected: $($process.Name) (PID: $($process.Id))" -Level Warning
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                Quarantine-File -FilePath $process.Path -ProcessName $process.Name
            }
        }
    } catch {
        Write-Log "Error in audio process monitoring: $_" -Level Error
    }
}

function Detect-And-Terminate-Overlays {
    try {
        $processes = Get-Process | Where-Object { $_.MainWindowTitle -and $_.Name -notin $Config.ProtectedProcesses }
        foreach ($proc in $processes) {
            $window = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $proc.Id }
            if ($window -and $window.MainWindowTitle -match "overlay|hook|inject") {
                Write-Log "Potential overlay process detected: $($proc.Name) (PID: $($proc.Id))" -Level Warning
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Quarantine-File -FilePath $proc.Path -ProcessName $proc.Name
            }
        }
    } catch {
        Write-Log "Error in overlay detection: $_" -Level Error
    }
}

# -------------------
# Network Security
# -------------------
function Harden-Network {
    try {
        foreach ($port in $Config.BlockedPorts) {
            $ruleName = "Block Port $port"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -ErrorAction SilentlyContinue
                Write-Log "Added firewall rule to block port $port" -Level Info
            }
        }
        $netshOutput = netsh bridge show adapter 2>$null
        $bridgeFound = $false
        foreach ($line in $netshOutput) {
            if ($line -match "Yes\s+.*\s+([^\s]+)$") {
                $bridgeFound = $true
                $adapterName = $matches[1]
                Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "Disabled network bridge on adapter: $adapterName" -Level Info
            }
        }
        if (-not $bridgeFound) { Write-Log "No network bridges detected." -Level Info }
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymous" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNullSessAccess" -Value 1 -ErrorAction Stop
        Write-Log "Restricted NULL sessions and anonymous logons." -Level Info
        $componentsToDisable = @("ms_server", "ms_msclient", "ms_pacer", "ms_lltdio", "ms_rspndr")
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            foreach ($component in $componentsToDisable) {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        Write-Log "Disabled unwanted network bindings." -Level Info
        $riskyServices = @("telnetsrv", "ftpsvc", "RemoteRegistry")
        foreach ($service in $riskyServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled risky service: $service" -Level Info
            }
        }
    } catch {
        Write-Log "Error hardening network: $_" -Level Error
    }
}

function Monitor-XSS {
    try {
        Get-NetTCPConnection -State Established | ForEach-Object {
            $remoteIP = $_.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                    Enable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                    Write-Log "XSS detected, blocked ${hostEntry.HostName}: $remoteIP and toggled network adapters." -Level Error
                }
            } catch {}
        }
    } catch {
        Write-Log "Error in XSS monitoring: $_" -Level Error
    }
}

# -------------------
# Registry Monitoring
# -------------------
function Monitor-InProcControls {
    try {
        $basePaths = @("HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID", "HKCR:\WOW6432Node\CLSID")
        foreach ($basePath in $basePaths) {
            $allPaths = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }
            foreach ($path in $allPaths) {
                $inProcPath = Join-Path $path.PSPath "InProcServer32"
                $inProcHandlerPath = Join-Path $path.PSPath "InprocHandler32"
                $value = $null
                if (Test-Path $inProcPath) {
                    $value = (Get-ItemProperty -Path $inProcPath -ErrorAction SilentlyContinue)."(default)"
                } elseif (Test-Path $inProcHandlerPath) {
                    $value = (Get-ItemProperty -Path $inProcHandlerPath -ErrorAction SilentlyContinue)."(default)"
                }
                if ($value -and (Test-Path $value)) {
                    Write-Log "Detected InProc control at ${path.PSPath}: $value" -Level Warning
                    Remove-ItemProperty -Path (Split-Path $path.PSPath -Parent) -Name (Split-Path $path.PSPath -Leaf) -Force -ErrorAction Stop
                    Remove-Item -Path $value -Force -ErrorAction Stop
                    Write-Log "Removed InProc control and file: $value" -Level Info
                }
            }
        }
    } catch {
        Write-Log "Error in InProc control monitoring: $_" -Level Error
    }
}

function Monitor-BCDEntries {
    try {
        $backupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
        & bcdedit /export $backupPath | Out-Null
        Write-Log "Created BCD backup at ${backupPath}" -Level Info
        $bcdOutput = & bcdedit /enum all
        $bcdEntries = @()
        $currentEntry = $null
        foreach ($line in $bcdOutput) {
            if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
                if ($currentEntry) { $bcdEntries += $currentEntry }
                $currentEntry = [PSCustomObject]@{ Identifier = $Matches[1]; Properties = @{} }
            } elseif ($line -match "^(\w+)\s+(.+)$") {
                if ($currentEntry) { $currentEntry.Properties[$Matches[1]] = $Matches[2] }
            }
        }
        if ($currentEntry) { $bcdEntries += $currentEntry }
        $criticalIds = @("{bootmgr}", "{current}", "{default}")
        foreach ($entry in $bcdEntries) {
            if ($entry.Identifier -in $criticalIds) { continue }
            $isSuspicious = $false
            $reason = ""
            if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
                $isSuspicious = $true
                $reason += "Non-Windows description: $($entry.Properties.description); "
            }
            if ($entry.Properties.device -match "vhd=") {
                $isSuspicious = $true
                $reason += "Uses VHD device: $($entry.Properties.device); "
            }
            if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
                $isSuspicious = $true
                $reason += "Non-standard boot path: $($entry.Properties.path); "
            }
            if ($isSuspicious) {
                Write-Log "Suspicious BCD entry: $($entry.Identifier), Reason: $reason" -Level Warning
                & bcdedit /delete $entry.Identifier /f | Out-Null
                Write-Log "Deleted suspicious BCD entry: $($entry.Identifier)" -Level Info
            }
        }
    } catch {
        Write-Log "Error in BCD monitoring: $_" -Level Error
    }
}

# -------------------
# Credential Protection
# -------------------
function Protect-Credentials {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -ErrorAction Stop
        Write-Log "Enabled LSASS as Protected Process Light. Reboot required." -Level Info
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Log "Cleared cached credentials." -Level Info
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Type String -ErrorAction Stop
        Write-Log "Disabled credential caching." -Level Info
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for credential validation." -Level Info
    } catch {
        Write-Log "Error in credential protection: $_" -Level Error
    }
}

function Manage-Passwords {
    try {
        $scriptPath = "$env:ProgramData\PasswordTasks.ps1"
        $scriptContent = @"
function Generate-RandomPassword {
    \$upper = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    \$lower = [char[]]('abcdefghijklmnopqrstuvwxyz')
    \$digit = [char[]]('0123456789')
    \$special = [char[]]('!@#$%^&*()_+-=[]{}|;:,.<>?')
    \$chars = \$upper + \$lower + \$digit + \$special
    \$password = ''
    \$password += \$upper | Get-Random -Count 2
    \$password += \$lower | Get-Random -Count 2
    \$password += \$digit | Get-Random -Count 2
    \$password += \$special | Get-Random -Count 2
    for (\$i = 8; \$i -lt 16; \$i++) {
        \$password += \$chars | Get-Random -Count 1
    }
    return (\$password | Sort-Object {Get-Random}) -join ''
}
function Set-NewRandomPassword {
    \$username = \$env:USERNAME
    \$newPassword = Generate-RandomPassword
    \$securePassword = ConvertTo-SecureString -String \$newPassword -AsPlainText -Force
    Set-LocalUser -Name \$username -Password \$securePassword
    Write-EventLog -LogName Application -Source 'GSecurity' -EntryType Information -EventId 1001 -Message "Password changed for user \$username"
}
New-EventLog -LogName Application -Source 'GSecurity' -ErrorAction SilentlyContinue
Set-NewRandomPassword
"@
        Set-Content -Path $scriptPath -Value $scriptContent -Force -ErrorAction Stop
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $trigger.RepetitionInterval = (New-TimeSpan -Minutes 10)
        $trigger.RepetitionDuration = [TimeSpan]::MaxValue
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest)
        Register-ScheduledTask -TaskName "GenerateRandomPassword" -InputObject $task -Force -ErrorAction Stop
        Write-Log "Scheduled random password updates every 10 minutes after logon." -Level Info
    } catch {
        Write-Log "Error setting up password management task: $_" -Level Error
    }
}

# -------------------
# Browser Hardening
# -------------------
function Secure-BrowserSettings {
    try {
        $browsers = @{
            "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
            "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
            "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
        }
        foreach ($browser in $browsers.GetEnumerator()) {
            if (Test-Path $browser.Value) {
                if ($browser.Key -eq "Firefox") {
                    Get-ChildItem -Path $browser.Value -Directory | ForEach-Object {
                        $prefsJsPath = "$($_.FullName)\prefs.js"
                        if (Test-Path $prefsJsPath) {
                            $prefsContent = Get-Content -Path $prefsJsPath
                            if ($prefsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                                Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                                Write-Log "Disabled WebRTC for Firefox profile: $($_.FullName)" -Level Info
                            }
                        }
                    }
                } elseif ($browser.Key -in @("Chrome", "Edge")) {
                    $prefPath = Join-Path $browser.Value "Default\Preferences"
                    if (Test-Path $prefPath) {
                        $json = Get-Content $prefPath -Raw | ConvertFrom-Json
                        if (-not $json.webrtc) {
                            $json | Add-Member -MemberType NoteProperty -Name webrtc -Value @{ enabled = $false } -Force
                            $json | ConvertTo-Json -Depth 10 | Set-Content $prefPath -Force
                            Write-Log "Disabled WebRTC for $($browser.Key)" -Level Info
                        }
                    }
                }
            }
        }
    } catch {
        Write-Log "Error in browser hardening: $_" -Level Error
    }
}

# -------------------
# Rootkit Detection
# -------------------
function Detect-RootkitByNetstat {
    try {
        $netstatOutput = netstat -ano | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }
        if (-not $netstatOutput) {
            Write-Log "No network connections found via netstat -ano. Possible rootkit activity." -Level Error
            Get-Process | Where-Object { $_.Id -ne $PID -and $_.Name -notin $Config.ProtectedProcesses } | ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated process due to potential rootkit: $($_.Name) (PID: $($_.Id))" -Level Warning
                Quarantine-File -FilePath $_.Path -ProcessName $_.Name
            }
        } else {
            Write-Log "Netstat shows normal activity." -Level Info
        }
    } catch {
        Write-Log "Error in rootkit detection: $_" -Level Error
    }
}

function Monitor-Drivers {
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq "SYSTEM" -or $_.DeviceClass -eq "SOFTWARE" }
        foreach ($driver in $drivers) {
            if ($driver.Manufacturer -notin $Config.TrustedDriverVendors) {
                Write-Log "Untrusted driver detected: $($driver.DeviceName) by $($driver.Manufacturer)" -Level Warning
            }
        }
    } catch {
        Write-Log "Error in driver monitoring: $_" -Level Error
    }
}

function Monitor-FileSystem {
    try {
        $criticalPaths = @("$env:SystemRoot\System32", "$env:ProgramFiles")
        foreach ($path in $criticalPaths) {
            Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.LastWriteTime -gt (Get-Date).AddMinutes(-10)
            } | ForEach-Object {
                Write-Log "Suspicious file modification detected: $($_.FullName)" -Level Warning
                Quarantine-File -FilePath $_.FullName -ProcessName "Unknown"
            }
        }
    } catch {
        Write-Log "Error in file system monitoring: $_" -Level Error
    }
}

function Disable-Network-Briefly {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        foreach ($adapter in $adapters) {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Log "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-Log "Failed to toggle network adapters: $_" "Error"
    }
}

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Log "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Log "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

function Start-XSSWatcher {
    while ($true) {
        $conns = Get-NetTCPConnection -State Established
        foreach ($conn in $conns) {
            $remoteIP = $conn.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-Network-Briefly
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -Force -ErrorAction SilentlyContinue
                    Write-Log "XSS detected, blocked $($hostEntry.HostName) and disabled network." "Error"
                }
            } catch {}
        }
        Start-Sleep -Seconds 3
    }
}

function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit") # Safe system processes
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore processes that no longer exist or access-denied
        }
    }
}

# Import required module
Import-Module -Name Microsoft.PowerShell.Management

# Define base registry path for WOW6432Node CLSIDs
$basePath = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
$hkcrBasePath = "HKCR:\WOW6432Node\CLSID"

# Function to detect InProcServer32 and InprocHandler32 custom controls
function Detect-InProcControls {
    $allPaths = @()
    $allPaths += Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }
    $allPaths += Get-ChildItem -Path $hkcrBasePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }

    foreach ($path in $allPaths) {
        $inProcPath = Join-Path $path.PSPath "InProcServer32"
        $inProcHandlerPath = Join-Path $path.PSPath "InprocHandler32"
        $value = $null

        if (Test-Path $inProcPath) {
            $value = (Get-ItemProperty -Path $inProcPath -ErrorAction SilentlyContinue)."(default)"
        } elseif (Test-Path $inProcHandlerPath) {
            $value = (Get-ItemProperty -Path $inProcHandlerPath -ErrorAction SilentlyContinue)."(default)"
        }

        if ($value -and (Test-Path $value)) {
            Write-Host "Detected InProc control at $path.PSPath with value $value"
            return $true, $path.PSPath, $value
        }
    }
    return $false, $null, $null
}

# Function to remove InProc controls
function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            # Remove registry entry
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path"
            # Remove associated file if it exists
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $_"
        }
    }
}

function Detect-RootkitByNetstat {
    # Run netstat -ano and store the output
    $netstatOutput = netstat -ano | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }

    if (-not $netstatOutput) {
        Write-Warning "No network connections found via netstat -ano. Possible rootkit hiding activity."

        # Optionally: Log the suspicious event
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = "$env:TEMP\rootkit_suspected_$timestamp.log"
        "Netstat -ano returned no results. Possible rootkit activity." | Out-File -FilePath $logFile

        # Get all running processes (you could refine this)
        $processes = Get-Process | Where-Object { $_.Id -ne $PID }

        foreach ($proc in $processes) {
            try {
                # Comment this line if you want to observe first
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Output "Stopped process: $($proc.ProcessName) (PID: $($proc.Id))"
            } catch {
                Write-Warning "Could not stop process: $($proc.ProcessName) (PID: $($proc.Id))"
            }
        }
    } else {
        Write-Host "Netstat looks normal. Active connections detected."
    }
}

function Start-StealthKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}



function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

# Function to check and remove network bridges
function Remove-NetworkBridge {
    try {
        # Get all network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -or $_.Status -eq "Disconnected" }
        
        # Check for network bridge
        $bridge = Get-NetAdapter | Where-Object { $_.Name -like "*Network Bridge*" }
        
        if ($bridge) {
            Write-Host "Network Bridge detected. Attempting to remove..."
            # Remove the network bridge
            Remove-NetAdapter -Name $bridge.Name -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Network Bridge removed."
        }
        
        # Ensure no adapters are part of a bridge
        foreach ($adapter in $adapters) {
            $bindings = Get-NetAdapterBinding -Name $adapter.Name -ErrorAction SilentlyContinue
            foreach ($binding in $bindings) {
                if ($binding.DisplayName -like "*Bridge*") {
                    Write-Host "Bridge binding found on adapter: $($adapter.Name). Disabling..."
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $binding.ComponentID -ErrorAction SilentlyContinue
                    Write-Host "Bridge binding disabled on adapter: $($adapter.Name)"
                }
            }
        }
    }
    catch {
        Write-Host "Error occurred: $_"
    }
}

# Whitelist of critical system processes to protect
$protectedProcesses = @(
    "System", "smss", "csrss", "wininit", "services", "lsass", 
    "svchost", "dwm", "explorer", "taskhostw", "winlogon", 
    "conhost", "cmd", "powershell"
)

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*"
)

function Kill-UntrustedLanProcesses {
    $Safe = @("System","svchost","lsass","services","wininit","winlogon","explorer","taskhostw","dwm","spoolsv")
    $Procs = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like '192.168.*' -or $_.RemoteAddress -like '172.16.*' -or $_.RemoteAddress -like '10.*' -or $_.RemoteAddress -like '127.*' } | ForEach-Object { $Procs[$_.OwningProcess] = $true }
    foreach ($PID in $Procs.Keys) {
        $Proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($Safe -notcontains $Proc.ProcessName) { Stop-Process -Id $PID -Force -ErrorAction SilentlyContinue; Write-Host "Killed $($Proc.ProcessName)" }
    }
}

# Detect and terminate screen overlays
function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object { 
        $_.MainWindowTitle -ne "" -and (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Log "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Log "Overlay process terminated: $($process.ProcessName)"
    }
}

# Detect and terminate keyloggers
function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

# Detect and terminate untrusted drivers
function Detect-And-Terminate-SuspiciousDrivers {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {
        ($_.DisplayName -notlike $trustedDriverVendors) -and $_.Started -eq $true
    }
    foreach ($driver in $drivers) {
        Write-Log "Suspicious driver detected: $($driver.DisplayName)"
        Stop-Service -Name $driver.Name -Force
        Write-Log "Suspicious driver stopped: $($driver.DisplayName)"
    }
}

# -------------------
# Main Execution
# -------------------
function Main {
    Ensure-AdminPrivileges
    Write-Log "Starting GSecurity with full GFocus integration and all original features." -Level Info
    if (-not (Test-Path $Config.QuarantinePath)) {
        try {
            New-Item -Path $Config.QuarantinePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log "Created quarantine directory: ${Config.QuarantinePath}" -Level Info
        } catch {
            Write-Log "Error creating quarantine directory: $_" -Level Error
        }
    }
    Register-ScheduledTaskCustom -TaskName "GSecurity" -ScriptPath $PSCommandPath -TriggerType "AtStartup"
    Harden-Network
    Protect-Credentials
    Manage-Passwords
    Secure-BrowserSettings
    Monitor-BCDEntries
    Start-Job -ScriptBlock { Start-GFocus } -ErrorAction SilentlyContinue
    Start-Job -ScriptBlock {
        while ($true) {
            Monitor-Processes
            Monitor-Keyloggers
            Monitor-WebServers
            Monitor-XSS
            Monitor-InProcControls
            Detect-RootkitByNetstat
            Monitor-AudioProcesses
            Detect-And-Terminate-Overlays
            Monitor-Drivers
            Monitor-FileSystem
            Detect-And-Terminate-SuspiciousDrivers
            Detect-And-Terminate-Keyloggers
            Detect-And-Terminate-Overlays
            Kill-UntrustedLanProcesses
            Remove-NetworkBridge
            Start-ProcessKiller
	        Start-StealthKiller
	        Detect-RootkitByNetstat
            Kill-Listeners
	        Start-XSSWatcher
    $detected, $path, $value = Detect-InProcControls
    if ($detected) {
        Remove-InProcControls -path $path -value $value
    } else {
        Write-Host "No InProc controls detected. Checking again in $CheckIntervalSeconds seconds..."
    }
    Start-Sleep -Seconds 10
}
}
}
    Write-Log "GSecurity initialized. GFocus whitelisting foreground apps." -Level Info

# Run the script
Main