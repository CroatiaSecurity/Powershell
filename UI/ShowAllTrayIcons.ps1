# Show All Tray Icons
# Same idea as autounattend.xml (schneegans ShowAllTrayIcons=true):
#   Windows 10: EnableAutoTray = 0
#   Windows 11: logon task every 1 min sets IsPromoted=1 on NotifyIconSettings\*
#
# Action uses powershell.exe directly (conhost --headless is often blocked by hardening).
#
# Usage:
#   .\ShowAllTrayIcons.ps1
#   .\ShowAllTrayIcons.ps1 -Uninstall

[CmdletBinding()]
param([switch]$Uninstall)

$ErrorActionPreference = 'SilentlyContinue'
$taskName = 'ShowAllTrayIcons'
$isWin10  = [Environment]::OSVersion.Version.Build -lt 20000
$psExe    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# Exact promote one-liner from unattend (IsPromoted on all tray icon keys)
$promoteCmd = "Set-ItemProperty -Path 'Registry::HKCU\Control Panel\NotifyIconSettings\*' -Name 'IsPromoted' -Value 1 -Type 'DWord';"

function Uninstall-ShowAllTrayIcons {
    if ($isWin10) {
        Remove-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
            -Name 'EnableAutoTray' -Force -ErrorAction SilentlyContinue
        Write-Output 'Removed EnableAutoTray.'
        return
    }
    schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
    $legacy = Join-Path $env:ProgramData 'ShowAllTrayIcons'
    if (Test-Path -LiteralPath $legacy) {
        Remove-Item -LiteralPath $legacy -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output "Removed task '$taskName'."
}

function Install-Win10 {
    Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -Type DWord -Value 0 -Force
    Write-Output 'Windows 10: EnableAutoTray=0'
}

function Install-Win11 {
    # Promote immediately
    Invoke-Expression $promoteCmd

    $user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    function Esc([string]$v) {
        ($v -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;')
    }

    $psArgs = "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$promoteCmd`""

    # Logon + PT1M — same schedule as unattend ShowAllTrayIcons.xml
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$(Esc $user)</UserId>
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
      <Command>$(Esc $psExe)</Command>
      <Arguments>$(Esc $psArgs)</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    $tmpXml = Join-Path $env:TEMP 'ShowAllTrayIcons.xml'
    try {
        [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
        schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
        $create = schtasks.exe /Create /TN $taskName /XML $tmpXml /F 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "Task create failed (run elevated if needed): $create"
            return
        }
        schtasks.exe /Run /TN $taskName 2>$null | Out-Null
        Write-Output "Windows 11: task '$taskName' — logon, every 1 min, IsPromoted=1"
    } finally {
        Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
    }

    $legacy = Join-Path $env:ProgramData 'ShowAllTrayIcons'
    if (Test-Path -LiteralPath $legacy) {
        Remove-Item -LiteralPath $legacy -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Uninstall) {
    Uninstall-ShowAllTrayIcons
    return
}

if ($isWin10) { Install-Win10 } else { Install-Win11 }
