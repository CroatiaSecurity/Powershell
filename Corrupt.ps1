# Corrupt.ps1
# Author: Gorstak (gorstak.eu)
# Description: Anti-telemetry script that overwrites telemetry/tracking files from Microsoft,
#              NVIDIA, Google, Adobe, Intel, AMD, Steam, Epic, Discord, and other vendors with
#              random data every hour. Installs as persistent scheduled task and runs as
#              background job.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "CorruptTelemetry"
$Script:InstallDir = "$env:ProgramData\Corrupt"
$Script:ScriptName = "Corrupt.ps1"

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
    Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
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
# Main Logic - Telemetry File Corruption
# ==============================

# Ensure the script isn't running multiple times
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $PSCommandPath -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

$CorruptTelemetry = {
    # Expanded list of target telemetry files
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
        "$env:LocalAppData\Microsoft\Edge\User Data\Default\Preferences",
        "$env:ProgramData\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
        "$env:ProgramFiles\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
        "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Web Data",
        "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.log",
        "$env:ProgramData\Adobe\ARM\log\ARMTelemetry.etl",
        "$env:LocalAppData\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
        "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp.log",
        "$env:ProgramData\Intel\Telemetry\IntelData.etl",
        "$env:ProgramFiles\Intel\Driver Store\Telemetry\IntelGFX.etl",
        "$env:SystemRoot\System32\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat",
        "$env:ProgramData\AMD\CN\AMDDiag.etl",
        "$env:LocalAppData\AMD\CN\logs\RadeonSoftware.log",
        "$env:ProgramFiles\AMD\CNext\CNext\AMDTel.db",
        "$env:ProgramFiles(x86)\Steam\logs\perf.log",
        "$env:LocalAppData\Steam\htmlcache\Cookies",
        "$env:ProgramData\Steam\SteamAnalytics.etl",
        "$env:ProgramData\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
        "$env:LocalAppData\EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log",
        "$env:LocalAppData\Discord\app-*\modules\discord_analytics\*.log",
        "$env:AppData\Discord\Local Storage\leveldb\*.ldb",
        "$env:LocalAppData\Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log",
        "$env:ProgramData\Autodesk\Adlm\Telemetry\AdlmTelemetry.etl",
        "$env:AppData\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
        "$env:LocalAppData\Mozilla\Firefox\Telemetry\Telemetry.etl",
        "$env:LocalAppData\Logitech\LogiOptions\logs\LogiAnalytics.log",
        "$env:ProgramData\Logitech\LogiSync\Telemetry.etl",
        "$env:ProgramData\Razer\Synapse3\Logs\RazerSynapse.log",
        "$env:LocalAppData\Razer\Synapse\Telemetry\RazerTelemetry.etl",
        "$env:ProgramData\Corsair\CUE\logs\iCUETelemetry.log",
        "$env:LocalAppData\Corsair\iCUE\Analytics\*.etl",
        "$env:ProgramData\Kaspersky Lab\AVP*\logs\Telemetry.etl",
        "$env:ProgramData\McAfee\Agent\logs\McTelemetry.log",
        "$env:ProgramData\Norton\Norton\Logs\NortonAnalytics.etl",
        "$env:ProgramFiles\Bitdefender\Bitdefender Security\logs\BDTelemetry.db",
        "$env:LocalAppData\Slack\logs\SlackAnalytics.log",
        "$env:ProgramData\Dropbox\client\logs\DropboxTelemetry.etl",
        "$env:LocalAppData\Zoom\logs\ZoomAnalytics.log"
    )

    Function Overwrite-File {
        param ($FilePath)
        try {
            if (Test-Path $FilePath) {
                $Size = (Get-Item $FilePath).Length
                $Junk = [byte[]]::new($Size)
                (New-Object Random).NextBytes($Junk)
                [System.IO.File]::WriteAllBytes($FilePath, $Junk)
                Write-Host "Overwrote telemetry file: $FilePath"
            } else {
                Write-Host "File not found: $FilePath"
            }
        } catch {
            Write-Host "Error overwriting ${FilePath}: $($_.Exception.Message)"
        }
    }

    while ($true) {
        $StartTime = Get-Date
        
        # Process each file or wildcard path
        foreach ($File in $TargetFiles) {
            if ($File -match '\*') {
                # Handle wildcard paths
                Get-Item -Path $File -ErrorAction SilentlyContinue | ForEach-Object {
                    Overwrite-File -FilePath $_.FullName
                }
            } else {
                Overwrite-File -FilePath $File
            }
        }

        # Calculate elapsed time and sleep until the next hour
        $ElapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
        $SleepSeconds = [math]::Max(3600 - $ElapsedSeconds, 0)
        Write-Host "Completed run at $(Get-Date). Sleeping for ${SleepSeconds} seconds until next hour..."
        Start-Sleep -Seconds $SleepSeconds
    }
}

# Run the script in a background job
Start-Job -ScriptBlock $CorruptTelemetry
