#Requires -RunAsAdministrator

# GSecurity.ps1 by Gorstak

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

# Register script as a scheduled task at logon
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGSecurityAtLogon"
    )

    # Check PowerShell version and module
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "Error: This script requires PowerShell 5.0 or later." -EntryType "Error"
        return
    }
    if (-not (Get-Module -ListAvailable -Name ScheduledTasks)) {
        Write-Log "Error: ScheduledTasks module not available." -EntryType "Error"
        return
    }

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

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
        if (-not $action) {
            throw "Failed to create scheduled task action."
        }
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $task = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        if ($task) {
            Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
        } else {
            throw "Task registration returned no task object."
        }
    } catch {
        Write-Log "Failed to register task: $_" -EntryType "Error"
    }
}
# Terminate potential web servers (including rootkits)
function Detect-And-Terminate-WebServers {
        $lanPrefix = "192.168."

        $connections = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -like "$lanPrefix*"
        }

        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($procId in $lanProcIds) {
            try {
                $proc = Get-Process -Id $procId -ErrorAction Stop
                Write-Host "Killing process: $($proc.ProcessName) (PID: $procId) connected to LAN"
                Stop-Process -Id $procId -Force
            } catch {
                Write-Warning "Could not kill process with PID $procId - $_"
            }
        }

        Start-Sleep -Seconds 10
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
Register-SystemLogonScript

# Run monitoring as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Detect-And-Terminate-WebServers
        Stop-VirtualMachines
        Start-Sleep -Seconds 10
    }
}