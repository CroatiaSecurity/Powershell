# Show All Tray Icons - Makes all notification area icons always visible
# Applies immediately and registers a logon task that re-applies every minute
# so newly created tray icons stay promoted.

$ErrorActionPreference = 'Stop'
$taskName = 'ShowAllTrayIcons'

function Set-AllTrayIconsPromoted {
    $base = 'HKCU:\Control Panel\NotifyIconSettings'
    if (-not (Test-Path -LiteralPath $base)) {
        return 0
    }

    $count = 0
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
        New-ItemProperty -LiteralPath $_.PSPath -Name 'IsPromoted' -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        $count++
    }
    return $count
}

function ConvertTo-XmlAttributeValue([string]$Value) {
    return ($Value -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;')
}

# Legacy "Always show all icons" (still respected by many Windows builds)
try {
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
} catch {}

# Apply immediately for current user
$promoted = Set-AllTrayIconsPromoted
Write-Host "Promoted $promoted tray icon(s) for the current session."

# Compact one-liner for the scheduled task action ($_ must stay literal for the task)
$psCommand = 'Get-ChildItem ''HKCU:\Control Panel\NotifyIconSettings'' -EA SilentlyContinue | ForEach-Object { New-ItemProperty -LiteralPath $_.PSPath -Name IsPromoted -PropertyType DWord -Value 1 -Force -EA SilentlyContinue | Out-Null }; New-ItemProperty -Path ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'' -Name EnableAutoTray -PropertyType DWord -Value 0 -Force -EA SilentlyContinue | Out-Null'

$arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -Command "' + $psCommand + '"'
$argumentsXml = ConvertTo-XmlAttributeValue $arguments

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Keep all notification area icons always visible (IsPromoted=1, EnableAutoTray=0).</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT1M</Interval>
        <Duration>P3650D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$argumentsXml</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$registered = $false
$tmpXml = Join-Path $env:TEMP ("{0}.xml" -f $taskName)

try {
    # Prefer schtasks /XML: Register-ScheduledTask often fails with
    # "Class not registered" on debloated or partially broken Task Scheduler stacks.
    [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)

    $create = & schtasks.exe /Create /TN $taskName /XML $tmpXml /F 2>&1
    if ($LASTEXITCODE -eq 0) {
        $registered = $true
        Write-Host "Scheduled task '$taskName' registered (schtasks)."
    } else {
        Write-Warning ("schtasks failed: {0}" -f ($create | Out-String).Trim())
    }
} catch {
    Write-Warning ("schtasks exception: {0}" -f $_.Exception.Message)
} finally {
    Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
}

if (-not $registered) {
    try {
        Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
        $registered = $true
        Write-Host "Scheduled task '$taskName' registered (Register-ScheduledTask)."
    } catch {
        Write-Warning ("Register-ScheduledTask failed: {0}" -f $_.Exception.Message)
    }
}

if (-not $registered) {
    Write-Error "Could not register scheduled task '$taskName'. Icons were still promoted for this session."
    exit 1
}

# Kick once now so the task path is exercised
try {
    & schtasks.exe /Run /TN $taskName 2>&1 | Out-Null
} catch {}

Write-Host "Done. All tray icons should stay visible across logons."
