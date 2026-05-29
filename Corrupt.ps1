# Corrupt.ps1 by Gorstak

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunCorruptAtLogon"
    )

    # Define paths
    $scriptSource = $PSCommandPath
    if (-not $scriptSource) {
        Write-Output "Error: Could not determine script path. Ensure the script is run from a file."
        exit 1
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
        Write-Output "Failed to copy script to ${targetPath}: $_"
        exit 1
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
        exit 1
    }
}

# Run the function
Register-SystemLogonScript

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

# Optional: Keep the console open to monitor the job
# Get-Job | Receive-Job -Keep