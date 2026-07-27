# Troll.ps1 by Gorstak

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunTrollAtLogon"
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

# Function to check and remove network bridges
function Remove-NetworkBridge {
    try {
        # Run netsh bridge show adapter and capture output
        $netshOutput = netsh bridge show adapter
        $bridgeFound = $false
        $bridgedAdapters = @()

        # Parse netsh output to find adapters with IsBridged: Yes
        foreach ($line in $netshOutput) {
            if ($line -match "Yes\s+.*\s+([^\s]+)$") {
                $bridgeFound = $true
                $bridgedAdapters += $matches[1]  # Capture adapter name
            }
        }

        if ($bridgeFound) {
            Write-Host "Network Bridge detected on adapters: $($bridgedAdapters -join ', '). Attempting to remove..."
            # Attempt to uninstall the bridge
            $uninstallResult = netsh bridge uninstall
            if ($uninstallResult -match "success|completed") {
                Write-Host "Network Bridge removed successfully."
            } else {
                Write-Host "Failed to remove Network Bridge. netsh output: $uninstallResult"
            }
        } else {
            Write-Host "No Network Bridge detected."
        }
    }
    catch {
        Write-Host "Error occurred: $_"
    }
}

# Main loop to persistently monitor and prevent bridge creation
Write-Host "Starting network bridge prevention script. Press Ctrl+C to stop."
Start-Job -ScriptBlock {
    while ($true) {
        Remove-NetworkBridge
        Start-Sleep -Seconds 5  # Check every 5 seconds
    }
}