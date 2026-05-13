# ES.ps1 by Gorstak
# PowerShell script to list and terminate non-console sessions every 5 seconds as a background job
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunESAtLogon"
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

# Define log file path
$logFile = "$env:TEMP\SessionTerminator.log"

# Function to log messages
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

# Function to list and terminate non-console sessions
function Terminate-NonConsoleSessions {
    try {
        # Run qwinsta to list sessions
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" } # Exclude active session marker
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-Log "Listing all sessions:"
        $sessions | ForEach-Object { Write-Log $_ }

        # Parse each session
        foreach ($session in $sessionList) {
            # Skip empty lines or headers
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                # Skip console session
                if ($sessionName -notin @("console")) {
                    Write-Log "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-Log "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-Log "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-Log "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-Log "Error processing sessions: $_"
    }
}

# Start the background job
Start-Job -ScriptBlock {
    $logFile = "$env:TEMP\SessionTerminator.log"

    function Write-Log {
        param($Message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - $Message" | Out-File -FilePath $logFile -Append
    }

    function Terminate-NonConsoleSessions {
        try {
            $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" }
            $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

            Write-Log "Listing all sessions:"
            $sessions | ForEach-Object { Write-Log $_ }

            foreach ($session in $sessionList) {
                if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                    $sessionName = $matches[1]
                    $sessionId = $matches[3]
                    $sessionState = $matches[4]

                    if ($sessionName -notin @("console")) {
                        Write-Log "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                        try {
                            rwinsta $sessionId
                            Write-Log "Successfully terminated session ID $sessionId"
                        } catch {
                            Write-Log "Failed to terminate session ID $sessionId : $_"
                        }
                    } else {
                        Write-Log "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                    }
                }
            }
        } catch {
            Write-Log "Error processing sessions: $_"
        }
    }

    while ($true) {
        Terminate-NonConsoleSessions
        Start-Sleep -Seconds 5
    }
}