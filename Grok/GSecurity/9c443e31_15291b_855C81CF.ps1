
#Requires -RunAsAdministrator

# GSecurity.ps1 by Gorstak

# Write-Log function to handle logging
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        # Ensure the event source exists
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName "Application" -Source "GSecurity"
        }
        Write-EventLog -LogName "Application" -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
        Write-Output $Message
    } catch {
        Write-Output "Log Error: $_ - $Message"
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunRetaliateAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        # Fallback to determine script path
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
    $trigger = New-ScheduledTaskTrigger -AtLogOn
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
            $pid = $process.Id
            $path = $process.Path

            # Check file path
            if ($path -notin $legitSvchostPaths) {
                $isSuspicious = $true
                Write-Log "Suspicious svchost detected: Invalid path $path (PID: $pid)" -EntryType "Warning"
            }

            # Check digital signature
            if ($path -and (Test-Path $path)) {
                $signature = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Microsoft*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious svchost detected: Invalid signature for $path (PID: $pid)" -EntryType "Warning"
                }
            }

            # Check network activity
            $connections = Get-NetTCPConnection -State Listen -OwningProcess $pid -ErrorAction SilentlyContinue
            if ($connections) {
                foreach ($conn in $connections) {
                    $port = $conn.LocalPort
                    $commonSvchostPorts = @(135, 445, 49664, 49665, 49666, 49667, 49668, 49669, 49670)
                    if ($port -notin $commonSvchostPorts) {
                        $isSuspicious = $true
                        Write-Log "Suspicious svchost detected: Listening on unusual port $port (PID: $pid)" -EntryType "Warning"
                    }
                }
            }

            if ($isSuspicious) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated suspicious svchost process: $path (PID: $pid)"
            }
        } catch {
            Write-Log "Error analyzing svchost process (PID: $pid): $_" -EntryType "Warning"
        }
    }
}

# Detect and terminate suspicious system processes
function Detect-SuspiciousSystemProcesses {
    $legitPaths = @{
        "System" = $null # System process has no path
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
    }

    $processes = Get-Process -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        try {
            $isSuspicious = $false
            $pid = $process.Id
            $path = $process.Path
            $processName = $process.ProcessName

            # Skip if process name isn't in our list
            if ($processName -notin $legitPaths.Keys) { continue }

            # Check file path
            $expectedPath = $legitPaths[$processName]
            if ($processName -eq "System") {
                if ($path) {
                    $isSuspicious = $true
                    Write-Log "Suspicious System process detected: Has path $path (PID: $pid)" -EntryType "Warning"
                }
            } elseif ($path -ne $expectedPath -and $path) {
                $isSuspicious = $true
                Write-Log "Suspicious $processName detected: Invalid path $path (PID: $pid)" -EntryType "Warning"
            }

            # Check digital signature
            if ($path -and (Test-Path $path)) {
                $signature = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Microsoft*") {
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Invalid signature for $path (PID: $pid)" -EntryType "Warning"
                }
            }

            # Check network activity
            $connections = Get-NetTCPConnection -State Listen -OwningProcess $pid -ErrorAction SilentlyContinue
            if ($connections -and $processName -notin @("svchost", "services")) {
                foreach ($conn in $connections) {
                    $port = $conn.LocalPort
                    # Most system processes (except svchost, services) shouldn't listen on ports
                    $isSuspicious = $true
                    Write-Log "Suspicious $processName detected: Listening on port $port (PID: $pid)" -EntryType "Warning"
                }
            }

            if ($isSuspicious) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated suspicious $processName process: $path (PID: $pid)"
            }
        } catch {
            Write-Log "Error analyzing $processName process (PID: $pid): $_" -EntryType "Warning"
        }
    }
}

# Terminate potential web servers (including rootkits) on any TCP port and handle empty listening connections
function Detect-And-Terminate-WebServers {
    # Common web server and suspicious process names
    $webServerProcesses = @(
        "httpd", "apache", "apache2", "nginx", "iisexpress", "w3wp", "tomcat", "jetty",
        "node", "python", "ruby", "php-fpm", "lighttpd", "cherokee", "uwsgi", "gunicorn",
        "http", "web", "server", "daemon" # Generic suspicious names
    )
    # Minimal safe list for empty connections case
    $minimalSafeProcesses = @("System", "smss", "csrss")

    # Check for TCP listening connections (equivalent to netstat -ano | find "LISTENING")
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    # If no listening connections are found, terminate all non-minimal-safe processes
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

    # Process listening connections for suspicious web servers
    $suspiciousPids = @{}
    foreach ($connection in $connections) {
        try {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                $port = $connection.LocalPort
                $processName = $process.ProcessName
                $pid = $process.Id

                # Heuristics for suspicious behavior
                $isSuspicious = $false
                if ($webServerProcesses -contains $processName -or $processName -match ($webServerProcesses -join "|")) {
                    $isSuspicious = $true
                } else {
                    # Check for high network activity
                    $netStats = Get-NetAdapterStatistics | Where-Object { $_.ReceivedBytes -gt 1MB -or $_.SentBytes -gt 1MB }
                    if ($netStats) {
                        $isSuspicious = $true
                    }
                    # Check if process has multiple listening ports
                    $portCount = ($connections | Where-Object { $_.OwningProcess -eq $pid }).Count
                    if ($portCount -gt 1) {
                        $isSuspicious = $true
                    }
                }

                if ($isSuspicious) {
                    # Check if Ports property exists, otherwise use empty array
                    $existingPorts = if ($suspiciousPids[$pid] -and $suspiciousPids[$pid].Ports) { $suspiciousPids[$pid].Ports } else { @() }
                    $suspiciousPids[$pid] = @{
                        ProcessName = $processName
                        Ports = @($port) + $existingPorts
                    }
                    Write-Log "Suspicious process detected: $processName (PID: $pid) listening on port $port"
                }
            }
        } catch {
            Write-Log "Error analyzing process on port $($connection.LocalPort): $_" -EntryType "Warning"
        }
    }

    # Terminate suspicious processes
    foreach ($pid in $suspiciousPids.Keys) {
        $processInfo = $suspiciousPids[$pid]
        try {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            Write-Log "Terminated suspicious process: $($processInfo.ProcessName) (PID: $pid) on ports $($processInfo.Ports -join ', ')"
        } catch {
            Write-Log "Error terminating process $($processInfo.ProcessName) (PID: $pid): $_" -EntryType "Warning"
        }
    }

    # Additional sweep for processes matching web server names
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
    # Comprehensive list of VM-related process names
    $vmProcesses = @(
        "vmware", "vmware-vmx", "vmware-authd", "vmnat", "vmnetdhcp", "vmware-tray", "vmware-unity-helper",
        "VirtualBox", "VBoxSVC", "VBoxHeadless", "VBoxNetDHCP", "VBoxNetNAT",
        "qemu", "qemu-system", "qemu-kvm", "qemu-img",
        "vmms", "vmsrvc", "vmcompute", "hyper-v", "vmmem", "vmwp", # Hyper-V
        "prl_client_app", "prl_cc", "prl_tools", "parallels", # Parallels
        "xen", "xend", "xenstored", "xenconsoled", # Xen
        "kvm", "libvirtd", "virtqemud", "virtlogd", "virtvboxd" # Other virtualization
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

    # Stop related services
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

# Run the function
Register-SystemLogonScript

# Main execution
try {
    Write-Log "Starting GSecurity"
    while ($true) {
        Detect-SuspiciousSvchost
        Detect-SuspiciousSystemProcesses
        Detect-And-Terminate-WebServers
        Stop-VirtualMachines
        Write-Log "Monitoring cycle completed"
        Start-Sleep -Seconds 60
    }
} catch {
    Write-Log "Fatal error: $_" -EntryType "Error"
    exit 1
}
