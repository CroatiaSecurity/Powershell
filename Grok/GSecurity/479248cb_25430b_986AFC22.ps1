
#Requires -RunAsAdministrator

# GSecurity.ps1 by Gorstak, enhanced with system-wide subliminal audio filtering and silent Equalizer APO install
# Monitors system processes, web servers, VMs, and media apps; filters audio to remove <20Hz and adds 50ms delay
# Usage: Save as GSecurity.ps1, right-click > Run with PowerShell (as admin)

# Create event source at script start
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
        New-EventLog -LogName "Application" -Source "GSecurity"
        Write-Output "Created event source 'GSecurity' in Application log."
    }
} catch {
    Write-Output "Failed to create event source 'GSecurity': $_"
}

# Write-Log function to handle logging to Event Log
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        Write-EventLog -LogName "Application" -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
        Write-Output $Message
    } catch {
        Write-Output "Log Error: $_ - $Message"
    }
}

# Function to configure media settings and audio filtering
function Set-MediaSafeSettings {
    # Disable auto-play in Windows
    try {
        $AutoPlayRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
        Set-ItemProperty -Path $AutoPlayRegPath -Name "DisableAutoplay" -Value 1 -ErrorAction SilentlyContinue
        Write-Log "Disabled Windows AutoPlay for media."
    } catch {
        Write-Log "Error disabling Windows AutoPlay: $_" -EntryType "Warning"
    }

    # Disable auto-play in Chrome
    $ChromePrefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
    if (Test-Path $ChromePrefsPath) {
        try {
            $Prefs = Get-Content $ChromePrefsPath -Raw | ConvertFrom-Json
            if (-not $Prefs.profile) { $Prefs | Add-Member -MemberType NoteProperty -Name profile -Value @{} }
            $Prefs.profile.content_settings = @{ "autoplay" = @{ "settingValue" = 2 } } # 2 = Block
            $Prefs | ConvertTo-Json -Depth 10 | Set-Content $ChromePrefsPath
            Write-Log "Disabled Chrome auto-play."
        } catch {
            Write-Log "Error disabling Chrome auto-play: $_" -EntryType "Warning"
        }
    }

    # Disable auto-play in Firefox
    $FirefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release"
    $FirefoxPrefsPath = Get-ChildItem $FirefoxProfilesPath -Directory | ForEach-Object { Join-Path $_.FullName "prefs.js" }
    if ($FirefoxPrefsPath -and (Test-Path $FirefoxPrefsPath)) {
        try {
            $PrefsContent = Get-Content $FirefoxPrefsPath -Raw
            $PrefsContent += "`nuser_pref(`"media.autoplay.default`", 1);`nuser_pref(`"media.autoplay.enabled`", false);"
            Set-Content $FirefoxPrefsPath -Value $PrefsContent
            Write-Log "Disabled Firefox auto-play."
        } catch {
            Write-Log "Error disabling Firefox auto-play: $_" -EntryType "Warning"
        }
    }

    # Disable auto-play in Edge
    $EdgePrefsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
    if (Test-Path $EdgePrefsPath) {
        try {
            $Prefs = Get-Content $EdgePrefsPath -Raw | ConvertFrom-Json
            if (-not $Prefs.profile) { $Prefs | Add-Member -MemberType NoteProperty -Name profile -Value @{} }
            $Prefs.profile.content_settings = @{ "autoplay" = @{ "settingValue" = 2 } } # 2 = Block
            $Prefs | ConvertTo-Json -Depth 10 | Set-Content $EdgePrefsPath
            Write-Log "Disabled Edge auto-play."
        } catch {
            Write-Log "Error disabling Edge auto-play: $_" -EntryType "Warning"
        }
    }

    # Install and configure Equalizer APO silently
    $EqualizerAPOPath = "$env:ProgramFiles\EqualizerAPO"
    if (-not (Test-Path $EqualizerAPOPath)) {
        try {
            Write-Log "Installing Equalizer APO silently..."
            # Download Equalizer APO
            $InstallerUrl = "https://sourceforge.net/projects/equalizerapo/files/latest/download"
            $InstallerPath = "$env:TEMP\EqualizerAPOSetup.exe"
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -ErrorAction Stop

            # Pre-configure default audio device in registry to skip Configurator
            $DefaultAudioDevice = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render" -ErrorAction SilentlyContinue)."{0.0.0.00000000}.{*}"
            if ($DefaultAudioDevice) {
                $RegPath = "HKLM:\SOFTWARE\EqualizerAPO"
                if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
                New-ItemProperty -Path $RegPath -Name "SelectedDevices" -Value $DefaultAudioDevice -PropertyType String -ErrorAction SilentlyContinue
                Write-Log "Pre-configured default audio device in Equalizer APO registry."
            }

            # Run silent install and suppress Configurator
            Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -ErrorAction Stop
            Start-Sleep -Seconds 2
            Stop-Process -Name "Configurator" -Force -ErrorAction SilentlyContinue
            Stop-Process -Name "DeviceSelector" -Force -ErrorAction SilentlyContinue
            Write-Log "Equalizer APO installed silently, Configurator suppressed."

            # Suppress reboot and restart audio service
            Restart-Service -Name Audiosrv -Force -ErrorAction SilentlyContinue
            Write-Log "Restarted audio service to apply Equalizer APO without reboot."
        } catch {
            Write-Log "Error installing Equalizer APO: $_" -EntryType "Warning"
            Write-Log "Please install Equalizer APO manually from https://sourceforge.net/projects/equalizerapo/ and configure a high-pass filter for <20Hz."
            return
        }
    }

    # Configure Equalizer APO
    try {
        $ConfigPath = "$EqualizerAPOPath\config\config.txt"
        if (-not (Test-Path $ConfigPath)) {
            New-Item -Path (Split-Path $ConfigPath -Parent) -ItemType Directory -Force | Out-Null
        }
        $ConfigContent = @"
# High-pass filter to remove <20Hz (subliminal frequencies)
Filter: ON HP Fc 20 Hz
# Add 50ms delay to prevent microphony
Delay: 50 ms
"@
        Set-Content -Path $ConfigPath -Value $ConfigContent -ErrorAction Stop
        Write-Log "Configured Equalizer APO: High-pass filter (<20Hz) and 50ms delay applied."

        # Restart audio service to apply changes
        Restart-Service -Name Audiosrv -Force -ErrorAction SilentlyContinue
        Write-Log "Restarted audio service to apply Equalizer APO settings."
    } catch {
        Write-Log "Error configuring Equalizer APO: $_" -EntryType "Warning"
        Write-Log "Please manually configure Equalizer APO to filter <20Hz and add 50ms delay."
    }

    # Lower microphone sensitivity to reduce microphony
    try {
        $MicRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture"
        $MicDevices = Get-ChildItem $MicRegPath -ErrorAction SilentlyContinue
        foreach ($Device in $MicDevices) {
            $PropPath = Join-Path $Device.PSPath "Properties"
            Set-ItemProperty -Path $PropPath -Name "{0.0.1.00000000}.{bb6a6f17-2b8c-43e0-8e4f-7f5a69727a9b},3" -Value 10 -ErrorAction SilentlyContinue
        }
        Write-Log "Lowered microphone sensitivity to reduce microphony."
    } catch {
        Write-Log "Error lowering microphone sensitivity: $_" -EntryType "Warning"
    }
}

# Function to monitor processes using audio
function Monitor-MediaProcesses {
    $MediaApps = @(
        "Discord", "chrome", "firefox", "msedge", "vlc", "wmplayer", "mpc-hc", "potplayer", "spotify",
        "opera", "brave", "tor", "winamp", "itunes", "quicktime"
    )
    $Processes = Get-Process | Where-Object { $_.ProcessName -in $MediaApps -or $_.Path -match "\.(exe|com)$" }
    foreach ($Process in $Processes) {
        try {
            $ProcessId = $Process.Id
            $ProcessName = $Process.ProcessName
            $CpuUsage = ($Process.CPU / 1000) # CPU in seconds
            $MemoryUsage = ($Process.WorkingSet / 1MB) # Memory in MB
            $GpuUsage = 0
            try {
                $GpuInfo = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -like "$ProcessName*" }
                if ($GpuInfo) { $GpuUsage = $GpuInfo.PercentProcessorTime }
            } catch {
                Write-Log "Error checking GPU usage for $ProcessName (PID: $ProcessId): $_" -EntryType "Warning"
            }

            # Check if process is using audio device
            $IsUsingAudio = $false
            try {
                $AudioSessions = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_SessionProcess | Where-Object { $_.ProcessId -eq $ProcessId }
                if ($AudioSessions) { $IsUsingAudio = $true }
            } catch {
                Write-Log "Error checking audio usage for $ProcessName (PID: $ProcessId): $_" -EntryType "Warning"
            }

            # Alert if high resource usage or audio active
            if (($GpuUsage -gt 50 -or $CpuUsage -gt 10) -and $IsUsingAudio) {
                $AlertMessage = "High resource usage in $ProcessName (PID: $ProcessId, CPU: $CpuUsage s, GPU: $GpuUsage%, Memory: $MemoryUsage MB) with audio output. Possible stream active. Check for influence (e.g., hand-raising) and verify audio settings."
                Write-Log $AlertMessage -EntryType "Warning"
                [System.Windows.Forms.MessageBox]::Show($AlertMessage, "GSecurity Audio Alert", "OK", "Warning")
            }

            # Alert if process running >30 minutes with audio
            if ($Process.StartTime -and ((Get-Date) - $Process.StartTime).TotalMinutes -gt 30 -and $IsUsingAudio) {
                $LongRunMessage = "$ProcessName (PID: $ProcessId) has been running with audio for over 30 minutes. Take a break to avoid immersion risks."
                Write-Log $LongRunMessage -EntryType "Warning"
                [System.Windows.Forms.MessageBox]::Show($LongRunMessage, "GSecurity Audio Alert", "OK", "Warning")
            }
        } catch {
            Write-Log "Error monitoring $ProcessName (PID: $ProcessId): $_" -EntryType "Warning"
        }
    }
}

# Register script as a scheduled task at logon
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGSecurityAtLogon"
    )

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Log "Error: Could not determine script path." -EntryType "Error"
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script: $_" -EntryType "Error"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Log "Failed to register task: $_" -EntryType "Error"
    }
}

# Detect and terminate suspicious svchost.exe instances
function Detect-SuspiciousSvchost {
    $legitSvchostPaths = @(
        "$env:SystemRoot\System32\svchost.exe",
        "$env:SystemRoot\SysWOW64\svchost.exe"
    )
    $svchostProcesses = Get-Process -Name svchost -ErrorAction SilentlyContinue

    foreach ($process in $svchostProcesses) {
        try {
            $isSuspicious = $false
            $processId = $process.Id
            $path = $process.Path

            if ($path -notin $legitSvchostPaths) {
                $isSuspicious = $true
                Write-Log "Suspicious svchost detected: Invalid path $path (PID: $processId)" -EntryType "Warning"
            }

            if ($path -and (Test-Path $path)) {
                $signature = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Microsoft*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious svchost detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                }
            }

            $connections = Get-NetTCPConnection -State Listen -OwningProcess $processId -ErrorAction SilentlyContinue
            if ($connections) {
                foreach ($conn in $connections) {
                    $port = $conn.LocalPort
                    $commonSvchostPorts = @(135, 445, 49664, 49665, 49666, 49667, 49668, 49669, 49670)
                    if ($port -notin $commonSvchostPorts) {
                        $isSuspicious = $true
                        Write-Log "Suspicious svchost detected: Listening on unusual port $port (PID: $processId)" -EntryType "Warning"
                    }
                }
            }

            if ($isSuspicious) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated suspicious svchost process: $path (PID: $processId)"
            }
        } catch {
            Write-Log "Error analyzing svchost process (PID: $processId): $_" -EntryType "Warning"
        }
    }
}

# Detect and terminate suspicious system processes
function Detect-SuspiciousSystemProcesses {
    $legitPaths = @{
        "System" = $null
        "smss" = "$env:SystemRoot\System32\smss.exe"
        "csrss" = "$env:SystemRoot\System32\csrss.exe"
        "wininit" = "$env:SystemRoot\System32\wininit.exe"
        "lsass" = "$env:SystemRoot\System32\lsass.exe"
        "services" = "$env:SystemRoot\System32\services.exe"
        "winlogon" = "$env:SystemRoot\System32\winlogon.exe"
        "dwm" = "$env:SystemRoot\System32\dwm.exe"
        "conhost" = "$env:SystemRoot\System32\conhost.exe"
        "LogonUI" = "$env:SystemRoot\System32\LogonUI.exe"
        "sihost" = "$env:SystemRoot\System32\sihost.exe"
        "fontdrvhost" = "$env:SystemRoot\System32\fontdrvhost.exe"
        "WmiPrvSE" = "$env:SystemRoot\System32\wbem\WmiPrvSE.exe"
        "spoolsv" = "$env:SystemRoot\System32\spoolsv.exe"
        "msmpeng" = "$env:ProgramFiles\Windows Defender\MsMpEng.exe"
        "ctfmon" = "$env:SystemRoot\System32\ctfmon.exe"
        "taskhostw" = "$env:SystemRoot\System32\taskhostw.exe"
        "explorer" = "$env:SystemRoot\explorer.exe"
        "rundll32" = "$env:SystemRoot\System32\rundll32.exe"
        "dllhost" = "$env:SystemRoot\System32\dllhost.exe"
        "Discord" = "$env:LOCALAPPDATA\Discord\app-*\Discord.exe"
        "chrome" = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
        "firefox" = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
        "msedge" = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    }

    $processes = Get-Process -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        try {
            $isSuspicious = $false
            $processId = $process.Id
            $path = $process.Path
            $processName = $process.ProcessName

            if ($processName -notin $legitPaths.Keys) { continue }

            $expectedPath = $legitPaths[$processName]
            if ($processName -eq "System") {
                if ($path) {
                    $isSuspicious = $true
                    Write-Log "Suspicious System process detected: Has path $path (PID: $processId)" -EntryType "Warning"
                }
            } elseif ($processName -in @("Discord", "chrome", "firefox", "msedge")) {
                if ($path -and -not ($path -like $expectedPath)) {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid path $path (PID: $processId)" -EntryType "Warning"
                }
            } elseif ($path -ne $expectedPath -and $path) {
                $isSuspicious = $true
                Write-Log "Suspicious $processName detected: Invalid path $path (PID: $processId)" -EntryType "Warning"
            }

            if ($path -and (Test-Path $path)) {
                $signature = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid") {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                } elseif ($processName -eq "Discord" -and $signature.SignerCertificate.Subject -notlike "*Hammer & Chisel*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious Discord detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                } elseif ($processName -in @("chrome", "firefox", "msedge") -and $signature.SignerCertificate.Subject -notlike "*$processName*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                } elseif ($processName -notin @("Discord", "chrome", "firefox", "msedge") -and $signature.SignerCertificate.Subject -notlike "*Microsoft*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                }
            }

            $connections = Get-NetTCPConnection -State Listen -OwningProcess $processId -ErrorAction SilentlyContinue
            if ($connections -and $processName -notin @("svchost", "services")) {
                foreach ($conn in $connections) {
                    $port = $conn.LocalPort
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Listening on port $port (PID: $processId)" -EntryType "Warning"
                }
            }

            if ($isSuspicious) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated suspicious $processName process: $path (PID: $processId)"
            }
        } catch {
            Write-Log "Error analyzing $processName process (PID: $processId): $_" -EntryType "Warning"
        }
    }
}

# Terminate potential web servers (including rootkits)
function Detect-And-Terminate-WebServers {
    $webServerProcesses = @(
        "httpd", "apache", "apache2", "nginx", "iisexpress", "w3wp", "tomcat", "jetty",
        "node", "python", "ruby", "php-fpm", "lighttpd", "cherokee", "uwsgi", "gunicorn",
        "http", "web", "server", "daemon"
    )
    $minimalSafeProcesses = @("System", "smss", "csrss")

    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        Write-Log "No TCP listening connections detected. Terminating all non-critical processes." -EntryType "Warning"
        Get-Process | Where-Object { $_.ProcessName -notin $minimalSafeProcesses } | ForEach-Object {
            try {
                Write-Log "Terminating process: $($_.ProcessName) (PID: $($_.Id))"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated process: $($_.ProcessName)"
            } catch {
                Write-Log "Error terminating process $($_.ProcessName) (PID: $($_.Id)): $_" -EntryType "Warning"
            }
        }
        return
    }

    $suspiciousPids = @{}
    foreach ($connection in $connections) {
        try {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                $port = $connection.LocalPort
                $processName = $process.ProcessName
                $processId = $process.Id

                $isSuspicious = $false
                if ($webServerProcesses -contains $processName -or $processName -match ($webServerProcesses -join "|")) {
                    $isSuspicious = $true
                } else {
                    $netStats = Get-NetAdapterStatistics | Where-Object { $_.ReceivedBytes -gt 1MB -or $_.SentBytes -gt 1MB }
                    if ($netStats) {
                        $isSuspicious = $true
                    }
                    $portCount = ($connections | Where-Object { $_.OwningProcess -eq $processId }).Count
                    if ($portCount -gt 1) {
                        $isSuspicious = $true
                    }
                }

                if ($isSuspicious) {
                    $existingPorts = if ($suspiciousPids[$processId] -and $suspiciousPids[$processId].Ports) { $suspiciousPids[$processId].Ports } else { @() }
                    $suspiciousPids[$processId] = @{
                        ProcessName = $processName
                        Ports = @($port) + $existingPorts
                    }
                    Write-Log "Suspicious process detected: $processName (PID: $processId) listening on port $port"
                }
            }
        } catch {
            Write-Log "Error analyzing process on port $($connection.LocalPort): $_" -EntryType "Warning"
        }
    }

    foreach ($processId in $suspiciousPids.Keys) {
        $processInfo = $suspiciousPids[$processId]
        try {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            Write-Log "Terminated suspicious process: $($processInfo.ProcessName) (PID: $processId) on ports $($processInfo.Ports -join ', ')"
        } catch {
            Write-Log "Error terminating process $($processInfo.ProcessName) (PID: $processId): $_" -EntryType "Warning"
        }
    }

    Get-Process | Where-Object { $webServerProcesses -contains $_.ProcessName -or $_.ProcessName -match ($webServerProcesses -join "|") } | ForEach-Object {
        try {
            Write-Log "Web server process detected: $($_.ProcessName) (PID: $($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Log "Terminated web server process: $($_.ProcessName)"
        } catch {
            Write-Log "Error terminating web server process $($_.ProcessName): $_" -EntryType "Warning"
        }
    }
}

# Terminate all virtual machine processes
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

# Main execution
Add-Type -AssemblyName System.Windows.Forms
Write-Log "Starting GSecurity Script with system-wide audio filtering and silent Equalizer APO install."
Set-MediaSafeSettings
Register-SystemLogonScript

# Run monitoring as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Detect-SuspiciousSvchost
        Detect-SuspiciousSystemProcesses
        Detect-And-Terminate-WebServers
        Stop-VirtualMachines
        Monitor-MediaProcesses
        Write-Log "Monitoring cycle completed"
        Start-Sleep -Seconds 60
    }
}
