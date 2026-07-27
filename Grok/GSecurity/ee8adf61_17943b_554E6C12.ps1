
#Requires -RunAsAdministrator

# GSecurity.ps1 by Gorstak, enhanced with Discord protection
# Monitors system processes, web servers, VMs, and Discord to prevent malicious activity and subliminal media exposure
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

# Function to modify Discord settings to disable auto-play and mute audio
function Set-DiscordSafeSettings {
    $DiscordSettingsPath = "$env:APPDATA\Discord\settings.json"
    if (Test-Path $DiscordSettingsPath) {
        try {
            $Settings = Get-Content $DiscordSettingsPath -Raw | ConvertFrom-Json
            # Disable auto-playing videos and animations
            $Settings.disable_animations = $true
            $Settings.disable_autoplay = $true
            # Mute audio by default
            $Settings.audio_volume = 0
            # Save changes
            $Settings | ConvertTo-Json -Depth 10 | Set-Content $DiscordSettingsPath
            Write-Log "Updated Discord settings to disable auto-play and mute audio."
        } catch {
            Write-Log "Error updating Discord settings: $_" -EntryType "Warning"
        }
    } else {
        Write-Log "Discord settings file not found at $DiscordSettingsPath." -EntryType "Warning"
    }
}

# Function to monitor Discord resource usage
function Monitor-Discord {
    $Discord = Get-Process -Name "Discord" -ErrorAction SilentlyContinue
    if ($Discord) {
        $CpuUsage = ($Discord | Measure-Object -Property CPU -Sum).Sum / 1000 # CPU in seconds
        $MemoryUsage = ($Discord | Measure-Object -Property WorkingSet -Sum).Sum / 1MB # Memory in MB
        $GpuUsage = 0
        try {
            $GpuInfo = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -like "Discord*" }
            if ($GpuInfo) {
                $GpuUsage = $GpuInfo.PercentProcessorTime
            }
        } catch {
            Write-Log "Error checking Discord GPU usage: $_" -EntryType "Warning"
        }

        # Flag if streaming likely (high GPU or CPU)
        if ($GpuUsage -gt 50 -or $CpuUsage -gt 10) {
            $AlertMessage = "High Discord resource usage detected (CPU: $CpuUsage s, GPU: $GpuUsage%, Memory: $MemoryUsage MB). Possible stream active. Check for influence (e.g., hand-raising)."
            Write-Log $AlertMessage -EntryType "Warning"
            [System.Windows.Forms.MessageBox]::Show($AlertMessage, "GSecurity Discord Alert", "OK", "Warning")
        }

        # Alert if Discord running >30 minutes
        $StartTime = (Get-Process -Name "Discord" -ErrorAction SilentlyContinue).StartTime
        if ($StartTime -and ((Get-Date) - $StartTime).TotalMinutes -gt 30) {
            $LongRunMessage = "Discord has been running for over 30 minutes. Take a break to avoid immersion risks."
            Write-Log $LongRunMessage -EntryType "Warning"
            [System.Windows.Forms.MessageBox]::Show($LongRunMessage, "GSecurity Discord Alert", "OK", "Warning")
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

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
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

# Detect and terminate suspicious system processes, including Discord
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
            } elseif ($processName -eq "Discord") {
                if ($path -and -not ($path -like $expectedPath)) {
                    $isSuspicious = $true
                    Write-Log "Suspicious Discord detected: Invalid path $path (PID: $processId)" -EntryType "Warning"
                }
            } elseif ($path -ne $expectedPath -and $path) {
                $isSuspicious = $true
                Write-Log "Suspicious $processName detected: Invalid path $path (PID: $processId)" -EntryType "Warning"
            }

            if ($path -and (Test-Path $path)) {
                $signature = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Microsoft*" -and $processName -ne "Discord") {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
                }
                if ($processName -eq "Discord" -and $signature.SignerCertificate.Subject -notlike "*Hammer & Chisel*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious Discord detected: Invalid signature for $path (PID: $processId)" -EntryType "Warning"
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
Write-Log "Starting GSecurity Script."
Set-DiscordSafeSettings
Register-SystemLogonScript

# Run monitoring as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Detect-SuspiciousSvchost
        Detect-SuspiciousSystemProcesses
        Detect-And-Terminate-WebServers
        Stop-VirtualMachines
        Monitor-Discord
        Write-Log "Monitoring cycle completed"
        Start-Sleep -Seconds 60
    }
}
