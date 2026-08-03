# Show All Tray Icons
# Windows 10: EnableAutoTray = 0
# Windows 11: set IsPromoted=1 on each HKCU NotifyIconSettings key
#
# Fixes vs older version:
#   - Wildcard Set-ItemProperty does not work; enumerate keys instead
#   - Only write IsPromoted when it is not already 1 (avoids shell thrash)
#   - No every-1-minute PowerShell task (that froze the taskbar)
#   - Logon-only scheduled task + promote on install
#
# Usage:
#   .\ShowAllTrayIcons.ps1
#   .\ShowAllTrayIcons.ps1 -Install
#   .\ShowAllTrayIcons.ps1 -Uninstall
#   .\ShowAllTrayIcons.ps1 -Once   # promote now, do not install task

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
$taskName = 'ShowAllTrayIcons'
$isWin10  = [Environment]::OSVersion.Version.Build -lt 22000
$psExe    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$storeDir = Join-Path $env:LOCALAPPDATA 'ShowAllTrayIcons'
$promotePs1 = Join-Path $storeDir 'Promote.ps1'

function Promote-TrayIcons {
    <#
    .SYNOPSIS
      Set IsPromoted=1 only on icons that need it (Win11 NotifyIconSettings).
    #>
    $base = 'HKCU:\Control Panel\NotifyIconSettings'
    if (-not (Test-Path -LiteralPath $base)) {
        return [pscustomobject]@{ Total = 0; Changed = 0 }
    }

    $total = 0
    $changed = 0
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
        $total++
        $path = $_.PSPath
        $current = $null
        try {
            $current = (Get-ItemProperty -LiteralPath $path -Name 'IsPromoted' -ErrorAction Stop).IsPromoted
        } catch {
            $current = $null
        }
        if ($current -ne 1) {
            Set-ItemProperty -LiteralPath $path -Name 'IsPromoted' -Value 1 -Type DWord -Force
            $changed++
        }
    }
    return [pscustomobject]@{ Total = $total; Changed = $changed }
}

function Write-PromoteScript {
    if (-not (Test-Path -LiteralPath $storeDir)) {
        New-Item -ItemType Directory -Path $storeDir -Force | Out-Null
    }
    # Lightweight helper used by the logon task (ASCII only, no profile).
    $body = @'
$ErrorActionPreference = "SilentlyContinue"
$base = "HKCU:\Control Panel\NotifyIconSettings"
if (-not (Test-Path -LiteralPath $base)) { exit 0 }
Get-ChildItem -LiteralPath $base | ForEach-Object {
    $path = $_.PSPath
    $current = $null
    try { $current = (Get-ItemProperty -LiteralPath $path -Name "IsPromoted" -ErrorAction Stop).IsPromoted } catch {}
    if ($current -ne 1) {
        Set-ItemProperty -LiteralPath $path -Name "IsPromoted" -Value 1 -Type DWord -Force
    }
}
'@
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($promotePs1, $body, $utf8)
}

function Uninstall-ShowAllTrayIcons {
    # Win10 registry
    Remove-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -Force -ErrorAction SilentlyContinue

    # Scheduled task (Win11 helper)
    & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

    # Stored promote script + legacy ProgramData path
    if (Test-Path -LiteralPath $storeDir) {
        Remove-Item -LiteralPath $storeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $legacy = Join-Path $env:ProgramData 'ShowAllTrayIcons'
    if (Test-Path -LiteralPath $legacy) {
        Remove-Item -LiteralPath $legacy -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output "Uninstalled ShowAllTrayIcons (registry, task, local scripts)."
}

function Install-Win10 {
    Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -Type DWord -Value 0 -Force
    Write-Output 'Windows 10: EnableAutoTray=0 (show all tray icons).'
    Write-Output 'Sign out/in or restart Explorer if icons do not refresh.'
}

function Install-Win11 {
    Write-PromoteScript

    $result = Promote-TrayIcons
    Write-Output ("Promoted tray icons now: {0} changed of {1} keys." -f $result.Changed, $result.Total)

    $user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    function Esc([string]$v) {
        ($v -replace '&', '&amp;' -replace '"', '&quot;' -replace '<', '&lt;' -replace '>', '&gt;')
    }

    # Logon only -- no PT1M loop (every-minute powershell + mass registry writes froze the taskbar).
    $psArgs = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$promotePs1`""

    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT15S</Delay>
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
    <StartWhenAvailable>false</StartWhenAvailable>
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
      <Command>$(Esc $psExe)</Command>
      <Arguments>$(Esc $psArgs)</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    $tmpXml = Join-Path $env:TEMP 'ShowAllTrayIcons.xml'
    try {
        [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
        & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
        $create = & schtasks.exe /Create /TN $taskName /XML $tmpXml /F 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "Task create failed (usually fine; promote already ran): $create"
            Write-Output "Re-run this script after installing new tray apps, or sign out/in."
            return
        }
        Write-Output "Windows 11: logon task '$taskName' installed (no periodic loop)."
        Write-Output "New tray apps: re-run this script once, or sign out/in."
    } finally {
        Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
    }

    # Clean legacy ProgramData install if present
    $legacy = Join-Path $env:ProgramData 'ShowAllTrayIcons'
    if (Test-Path -LiteralPath $legacy) {
        Remove-Item -LiteralPath $legacy -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Uninstall) {
    Uninstall-ShowAllTrayIcons
    return
}

if ($Once) {
    if ($isWin10) {
        Install-Win10
    } else {
        $result = Promote-TrayIcons
        Write-Output ("Promoted tray icons: {0} changed of {1} keys." -f $result.Changed, $result.Total)
    }
    return
}

if ($isWin10) { Install-Win10 } else { Install-Win11 }
