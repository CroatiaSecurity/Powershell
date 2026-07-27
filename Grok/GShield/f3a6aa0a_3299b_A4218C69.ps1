# GShield.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
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

# Run the function
Register-SystemLogonScript

function Remove-SuspiciousFiles {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }

    foreach ($drive in $drives) {
        # Get all files recursively on the drive
        $files = Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue
        
        # Get all processes and check if their ExecutablePath matches any file on the drive
        $processes = Get-WmiObject Win32_Process | Where-Object {
            $processPath = $_.ExecutablePath
            if ($processPath) {
                $files | Where-Object { $_.FullName -eq $processPath }
            }
        }

        foreach ($process in $processes) {
            $processName = $process.Name
            $processPath = $process.ExecutablePath
            $pid = $process.ProcessId

            # Check if process name is suspicious or executable file does not exist
            if ($processName -eq "Unknown" -or $processName -eq "N/A" -or $processName -eq "" -or ($processPath -and -not (Test-Path $processPath))) {
                # Kill the process if PID exists
                if ($pid) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

Start-Job -ScriptBlock {
    while ($true) {
        Remove-SuspiciousFiles
    }
}