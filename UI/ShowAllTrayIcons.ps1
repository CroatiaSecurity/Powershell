# Show All Tray Icons
# Windows 10: EnableAutoTray = 0
# Windows 11: logon scheduled task sets IsPromoted=1 on all NotifyIconSettings keys
#
# No switches needed. Run once and it sets up everything.
# Optimized to finish fast (survives reboot race from GSecurity.bat).

$ErrorActionPreference = 'SilentlyContinue'
$taskName = 'ShowAllTrayIcons'
$isWin10  = [Environment]::OSVersion.Version.Build -lt 22000
$psExe    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$storeDir = Join-Path $env:LOCALAPPDATA 'ShowAllTrayIcons'
$promotePs1 = Join-Path $storeDir 'Promote.ps1'

# --- Windows 10: single registry value, done ---
if ($isWin10) {
    Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'EnableAutoTray' -Type DWord -Value 0 -Force
    exit 0
}

# --- Windows 11: write promote script + create logon task ---

# 1. Write the lightweight promote script to LOCALAPPDATA
if (-not (Test-Path -LiteralPath $storeDir)) {
    New-Item -ItemType Directory -Path $storeDir -Force | Out-Null
}

$body = @'
$base = "HKCU:\Control Panel\NotifyIconSettings"
if (-not (Test-Path -LiteralPath $base)) { exit 0 }
Get-ChildItem -LiteralPath $base | ForEach-Object {
    try {
        $val = (Get-ItemProperty -LiteralPath $_.PSPath -Name "IsPromoted" -ErrorAction Stop).IsPromoted
    } catch { $val = $null }
    if ($val -ne 1) {
        Set-ItemProperty -LiteralPath $_.PSPath -Name "IsPromoted" -Value 1 -Type DWord -Force
    }
}
'@
[System.IO.File]::WriteAllText($promotePs1, $body, (New-Object System.Text.UTF8Encoding $false))

# 2. Create logon scheduled task
$user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
function Esc([string]$v) {
    $v -replace '&','&amp;' -replace '"','&quot;' -replace '<','&lt;' -replace '>','&gt;'
}

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
[System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
& schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
& schtasks.exe /Create /TN $taskName /XML $tmpXml /F 2>$null | Out-Null
Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
