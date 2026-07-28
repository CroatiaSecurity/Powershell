# Show All Tray Icons - Windows 10/11
# Forces ALL notification area icons to always be visible, including system icons.
# Removes policies that block tray icon visibility.
#
# Why a repeating task is required:
#   On Windows 11 each new tray app creates HKCU:\Control Panel\NotifyIconSettings\<id>
#   with IsPromoted=0 (hidden in overflow). EnableAutoTray=0 alone does not promote
#   those new keys. A one-shot logon task never sees icons that appear mid-session.
#   This installer registers a silent task that re-promotes every minute after logon.

$ErrorActionPreference = 'SilentlyContinue'

$taskName   = 'ShowAllTrayIcons'
$installDir = Join-Path $env:ProgramData 'ShowAllTrayIcons'
$promotePs1 = Join-Path $installDir 'Promote.ps1'
$runnerVbs  = Join-Path $installDir 'RunSilent.vbs'

function ConvertTo-XmlAttributeValue([string]$Value) {
    return ($Value -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;')
}

function Invoke-TrayIconPromotion {
    # Policies that hide/suppress tray icons
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'TaskbarNoNotification' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoNetConnectDisconnect' -Force -ErrorAction SilentlyContinue

    # Classic "always show all icons" toggle (Win10; still consulted on Win11)
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

    # Per-icon promotion (this is what actually shows new icons on Win11)
    $notifyPath = 'HKCU:\Control Panel\NotifyIconSettings'
    if (Test-Path -LiteralPath $notifyPath) {
        Get-ChildItem -LiteralPath $notifyPath -ErrorAction SilentlyContinue | ForEach-Object {
            New-ItemProperty -LiteralPath $_.PSPath -Name 'IsPromoted' -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # Win11 corner overflow chevron: 0 = all system corner icons visible
    $trayNotify = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify'
    if (Test-Path -LiteralPath $trayNotify) {
        New-ItemProperty -Path $trayNotify -Name 'SystemTrayChevronVisibility' `
            -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Install-SilentLauncher {
    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    # Lightweight worker: only promote — do NOT wipe IconStreams every minute
    # (that causes tray flicker). Cache wipe happens once during install below.
    $promoteBody = @'
$ErrorActionPreference = "SilentlyContinue"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TaskbarNoNotification" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoNetConnectDisconnect" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
$base = "HKCU:\Control Panel\NotifyIconSettings"
if (Test-Path -LiteralPath $base) {
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
        New-ItemProperty -LiteralPath $_.PSPath -Name "IsPromoted" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
$tn = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify"
if (Test-Path -LiteralPath $tn) {
    New-ItemProperty -Path $tn -Name "SystemTrayChevronVisibility" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
}
'@
    Set-Content -LiteralPath $promotePs1 -Value $promoteBody -Encoding UTF8 -Force

    # VBS runs PowerShell with window style 0 (no console flash)
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

# --- Step 1: Apply immediately for the current user ---
Invoke-TrayIconPromotion

# One-time icon stream cache wipe so existing layout rebuilds with all icons visible.
# Not repeated by the worker (would flicker the tray every minute).
$trayNotify = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify'
if (Test-Path -LiteralPath $trayNotify) {
    Remove-ItemProperty -Path $trayNotify -Name 'IconStreams' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $trayNotify -Name 'PastIconsStream' -Force -ErrorAction SilentlyContinue
}

# --- Step 2: Default profile so new users get EnableAutoTray=0 ---
$defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$tempHive = 'HKU\DefaultUser_Temp'
$loaded = $false

if (Test-Path $defaultNtuser) {
    reg load $tempHive $defaultNtuser 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $loaded = $true
        reg add "$tempHive\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 0 /f 2>&1 | Out-Null
    }
}

# --- Step 3: Install silent worker + repeating logon task ---
Install-SilentLauncher

$wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
$arguments = "//B //Nologo `"$runnerVbs`""
$argumentsXml = ConvertTo-XmlAttributeValue $arguments
$commandXml = ConvertTo-XmlAttributeValue $wscript

# Logon trigger + PT1M repetition: promotes icons that appear mid-session.
# InteractiveToken so the task loads the interactive user's HKCU (not a machine context).
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Keep all notification area icons always visible (IsPromoted=1, EnableAutoTray=0). Re-runs every minute after logon so newly created tray icons are promoted. Silent via wscript.</Description>
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
    }
} catch {
    # fall through to Register-ScheduledTask
} finally {
    Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
}

if (-not $registered) {
    try {
        Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
        $registered = $true
    } catch {
        # last resort: one-shot logon only (new icons still won't promote mid-session)
        try {
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $action = New-ScheduledTaskAction -Execute $psExe `
                -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$promotePs1`""
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings -Force | Out-Null
            $registered = $true
        } catch {}
    }
}

# Kick once so promotion is live without waiting for the next interval
if ($registered) {
    & schtasks.exe /Run /TN $taskName 2>$null | Out-Null
}

# --- Step 4: Unload default hive ---
if ($loaded) {
    [gc]::Collect()
    Start-Sleep -Seconds 1
    reg unload $tempHive 2>&1 | Out-Null
}

# Explorer restart intentionally omitted: disruptive (closes folders, drops tray apps).
# IsPromoted writes are picked up by the shell for new/updated icons without a restart.
# Existing hidden icons may need a sign-out or the next Promote cycle after the app re-registers.
