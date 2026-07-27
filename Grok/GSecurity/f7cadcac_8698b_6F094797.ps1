
# GSecurity.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGSecurityAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Output "Error: Could not determine script path."
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script: $_"
        return
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

function Disable-Network-Briefly {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 3
    foreach ($adapter in $adapters) {
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Log "Network briefly disabled"
}

function Add-XSSFirewallRule {
    param ([string]$url)
    try {
        $uri = [System.Uri]::new($url)
        $domain = $uri.Host
        $ruleName = "Block_XSS_$domain"

        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $domain `
                -Protocol TCP `
                -Profile Any `
                -Description "Blocked due to potential XSS in URL"
            Write-Log "Domain blocked via firewall: $domain"
        }
    } catch {
        Write-Log "Could not block: $url" -EntryType "Warning"
    }
}

function Terminate-Rootkits {
    try {
        # Check for webcam and microphone devices
        $webcamDevices = Get-PnpDevice | Where-Object { $_.Class -eq "Camera" -or $_.FriendlyName -like "*webcam*" -or $_.FriendlyName -like "*camera*" }
        $micDevices = Get-PnpDevice | Where-Object { $_.Class -eq "AudioEndpoint" -or $_.FriendlyName -like "*microphone*" -or $_.FriendlyName -like "*mic*" }
        $hasWebcamOrMic = ($webcamDevices.Count -gt 0) -or ($micDevices.Count -gt 0)
        if ($hasWebcamOrMic) {
            $deviceNames = @($webcamDevices.FriendlyName + $micDevices.FriendlyName) -join ', '
            Write-Log "Webcam or microphone device(s) detected: $deviceNames"
        }

        # Define an exclusion list for browser processes
        $browserProcesses = @(
            "chrome.exe",         # Google Chrome
            "firefox.exe",        # Mozilla Firefox
            "msedge.exe",         # Microsoft Edge
            "opera.exe",          # Opera
            "operagx.exe",        # Opera GX
            "vivaldi.exe",        # Vivaldi
            "brave.exe",          # Brave
            "safari.exe",         # Safari (Windows, rare)
            "tor.exe",            # Tor Browser
            "waterfox.exe",       # Waterfox
            "palemoon.exe",       # Pale Moon
            "maxthon.exe",        # Maxthon
            "ucbrowser.exe",      # UC Browser
            "yandex.exe"          # Yandex Browser
        )

        # Other known webcam/audio-related processes
        $otherExcludedProcesses = @(
            "Zoom.exe",           # Zoom video conferencing
            "ms-teams.exe",       # Microsoft Teams
            "Camera.exe"          # Windows Camera app
        )

        $connections = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
        }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($pid in $lanProcIds) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $exePath = $proc.Path

                # Check if the process is a browser
                $isBrowser = $browserProcesses -contains $proc.ProcessName

                # Check if the process is in the other excluded list
                if ($otherExcludedProcesses -contains $proc.ProcessName) {
                    Write-Log "Skipping excluded webcam/audio process: $($proc.ProcessName) (PID: $pid)"
                    continue
                }

                if ($exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    if ($signature.Status -ne 'Valid') {
                        # If webcam or microphone devices are present and process is a browser, check for webcam/mic activity
                        if ($hasWebcamOrMic -and $isBrowser) {
                            $isWebcamOrMicRelated = $false
                            try {
                                $modules = Get-Process -Id $pid -Module -ErrorAction SilentlyContinue
                                if ($modules.ModuleName -match "webcam|camera|video|audio|mic|microphone") {
                                    $isWebcamOrMicRelated = $true
                                    Write-Log "Skipping browser process with webcam/mic activity: $($proc.ProcessName) (PID: $pid)"
                                    continue
                                }
                            } catch {
                                Write-Log "Unable to check modules for PID $pid: $($_.ToString())" -EntryType "Warning"
                            }
                        }

                        # Terminate if not webcam/mic-related or not a browser
                        Write-Log "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-Log "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-Log "Path unknown for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-Log "Error processing PID $pid: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-Log "Error during rootkit detection: $($_.ToString())" -EntryType "Error"
    }
}

# Register the scheduled task
Register-SystemLogonScript

# Run Terminate-Rootkits inline immediately
Terminate-Rootkits

# Start XSS monitoring job
$job = Start-Job -ScriptBlock {
    $pattern = '(?i)(<script|javascript:|onerror=|onload=|alert\()'

    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $proc = $Event.SourceEventArgs.NewEvent.TargetInstance
        $cmdline = $proc.CommandLine

        if ($cmdline -match $pattern) {
            Write-Host "`nPotential XSS detected in: $cmdline"

            if ($cmdline -match 'https?://[^\s"]+') {
                $url = $matches[0]
                Disable-Network-Briefly
                Add-XSSFirewallRule -url $url
            }
        }
    } | Out-Null

    while ($true) { Start-Sleep -Seconds 5 }
}
