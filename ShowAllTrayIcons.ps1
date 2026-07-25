# Show All Tray Icons - Makes all notification area icons always visible
# Installs a silent (no console flash) scheduled task that re-applies every
# minute so newly created tray icons stay promoted.

$ErrorActionPreference = 'Stop'
$taskName   = 'ShowAllTrayIcons'
$installDir = Join-Path $env:ProgramData 'ShowAllTrayIcons'
$promotePs1 = Join-Path $installDir 'Promote.ps1'
$runnerVbs  = Join-Path $installDir 'RunSilent.vbs'

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

    try {
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
            -Name 'EnableAutoTray' -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    return $count
}

function ConvertTo-XmlAttributeValue([string]$Value) {
    return ($Value -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;')
}

function Install-SilentLauncher {
    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    # Worker: no Write-Host, no prompts — pure registry work
    $promoteBody = @'
$ErrorActionPreference = "SilentlyContinue"
$base = "HKCU:\Control Panel\NotifyIconSettings"
if (Test-Path -LiteralPath $base) {
    Get-ChildItem -LiteralPath $base | ForEach-Object {
        New-ItemProperty -LiteralPath $_.PSPath -Name "IsPromoted" -PropertyType DWord -Value 1 -Force | Out-Null
    }
}
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force | Out-Null
'@
    Set-Content -LiteralPath $promotePs1 -Value $promoteBody -Encoding UTF8 -Force

    # VBS runs PowerShell with window style 0 (completely hidden — no flash)
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $vbsBody = @"
' Silent launcher for ShowAllTrayIcons — window style 0 = hidden
Option Explicit
Dim sh, cmd
Set sh = CreateObject("WScript.Shell")
cmd = """$psExe"" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$promotePs1"""
sh.Run cmd, 0, False
"@
    Set-Content -LiteralPath $runnerVbs -Value $vbsBody -Encoding ASCII -Force
}

# Apply immediately for current user (installer console is fine to show once)
$promoted = Set-AllTrayIconsPromoted
Write-Host "Promoted $promoted tray icon(s) for the current session."

Install-SilentLauncher
Write-Host "Installed silent launcher to $installDir"

# Task runs wscript //B (batch mode) so no script host UI either
$wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
$arguments = "//B //Nologo `"$runnerVbs`""
$argumentsXml = ConvertTo-XmlAttributeValue $arguments
$commandXml = ConvertTo-XmlAttributeValue $wscript

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Keep all notification area icons always visible (IsPromoted=1, EnableAutoTray=0). Runs silently via wscript (no console flash).</Description>
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
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$commandXml</Command>
      <Arguments>$argumentsXml</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$registered = $false
$tmpXml = Join-Path $env:TEMP ("{0}.xml" -f $taskName)

try {
    & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
    [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)

    $create = & schtasks.exe /Create /TN $taskName /XML $tmpXml /F 2>&1
    if ($LASTEXITCODE -eq 0) {
        $registered = $true
        Write-Host "Scheduled task '$taskName' registered (silent wscript launcher)."
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

# Exercise once (should not flash)
try {
    & schtasks.exe /Run /TN $taskName 2>&1 | Out-Null
} catch {}

# Clean leftover smoke-test task from earlier debugging
& schtasks.exe /Delete /TN 'GameCache_SmokeTest' /F 2>$null | Out-Null

Write-Host "Done. Tray icons stay visible; task runs with no console window."
