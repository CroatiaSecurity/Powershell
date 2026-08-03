# ES.ps1
# Author: Gorstak (gorstak.eu)
# Description: Session security monitor that lists and terminates non-console RDP/remote
#              sessions every 5 seconds to prevent unauthorized remote access. Installs
#              as persistent scheduled task running at logon under SYSTEM.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "ESSessionMonitor"
$Script:InstallDir = "$env:ProgramData\ES"
$Script:ScriptName = "ES.ps1"

function Install-Persistence {
    # Create install directory
    if (-not (Test-Path $Script:InstallDir)) {
        New-Item -Path $Script:InstallDir -ItemType Directory -Force | Out-Null
    }

    # Copy script to install location
    $targetPath = Join-Path $Script:InstallDir $Script:ScriptName
    Copy-Item -Path $PSCommandPath -Destination $targetPath -Force

    # Register scheduled task (cmdlet first, schtasks fallback)
    $installed = $false
    $pwshArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Scheduled task '$($Script:TaskName)' registered via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Host "Register-ScheduledTask failed: $_"
    }

    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Scheduled task '$($Script:TaskName)' registered via schtasks.exe fallback."
                $installed = $true
            } else {
                Write-Host "schtasks fallback failed: $result"
            }
        } catch {
            Write-Host "schtasks fallback exception: $_"
        }
    }

    Write-Host "Persistence installed to: $targetPath"
}

function Uninstall-Persistence {
    try { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    & schtasks.exe /Delete /TN "$($Script:TaskName)" /F 2>$null | Out-Null
    if (Test-Path $Script:InstallDir) {
        Remove-Item -Path $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Persistence removed for '$($Script:TaskName)'."
}

if ($Install) { Install-Persistence; return }
if ($Uninstall) { Uninstall-Persistence; return }

# Auto-install if not running from installed location
$installedPath = Join-Path $Script:InstallDir $Script:ScriptName
if ($PSCommandPath -and $PSCommandPath -ne $installedPath) {
    $existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        Install-Persistence
        return
    }
}

# ==============================
# Main Logic - Session Monitoring
# ==============================

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
