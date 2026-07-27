
# GSecurity.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "GSecurity"
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
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at system startup under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

Register-SystemLogonScript



# GSecurity.ps1
# Author: Gorstak

function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$EntryType] $Message"

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Add-Content -Path "$env:TEMP\GSecurity.log" -Value $logEntry
    }

    if ($Host.Name -match "ConsoleHost") {
        switch ($EntryType) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor White }
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

Start-Job -ScriptBlock {
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
	Start-XSSWatcher
    }
}
