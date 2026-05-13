#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-shot install: run once as Administrator, no input. Sets up password rotation
    (random every 10 min after logon, blank again at logoff) and sets current user password to blank.
#>
$ErrorActionPreference = 'Stop'
$TargetDir = 'C:\ProgramData\PasswordRotator'
$OnLogonTaskName = 'PasswordRotator-OnLogon'

# Embedded worker script (runs as SYSTEM from ProgramData; handles Logon / Rotate / Logoff)
$WorkerScript = @'
param([string]$Mode, [string]$Username)
$ErrorActionPreference = 'Stop'
$TargetDir = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\ProgramData\PasswordRotator' }
$UserFile = Join-Path $TargetDir 'currentuser.txt'

function Get-LoggedInUser {
    $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    $user = $cs.UserName
    if (-not $user) { return $null }
    if ($user -match '\\') { return $user.Split('\')[-1] }
    return $user
}
function Set-UserPassword {
    param([string]$U, [string]$P)
    if ([string]::IsNullOrWhiteSpace($U)) { return }
    try {
        Set-LocalUser -Name $U -Password (ConvertTo-SecureString -String $P -AsPlainText -Force) -ErrorAction Stop
    } catch {
        try {
            [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$U,user"
            $adsi.SetPassword($P)
        } catch {
            "$(Get-Date -Format o) Set-UserPassword: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append
        }
    }
}
function Set-UserPasswordBlank {
    param([string]$N)
    if ([string]::IsNullOrWhiteSpace($N)) { return }
    try {
        [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$N,user"
        $adsi.SetPassword('')
    } catch {
        try { & net user $N '' } catch { "$(Get-Date -Format o) Blank: $_" | Out-File (Join-Path $TargetDir 'log.txt') -Append }
    }
}
function New-RandomPwd {
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
    -join ((1..24) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}
function Remove-TasksForUser { param([string]$U)
    $s = $U -replace '[^a-zA-Z0-9]', '_'
    @("PasswordRotator-10Min-$s", "PasswordRotator-OnLogoff-$s") | ForEach-Object { Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue }
}

switch ($Mode) {
    'Logon' {
        $u = Get-LoggedInUser
        if (-not $u) { exit 0 }
        if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
        $u | Set-Content -Path $UserFile -Force
        Remove-TasksForUser -U $u
        $safe = $u -replace '[^a-zA-Z0-9]', '_'
        $worker = Join-Path $TargetDir 'Worker.ps1'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $trigger10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $action10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Rotate"
        Register-ScheduledTask -TaskName "PasswordRotator-10Min-$safe" -Action $action10 -Trigger $trigger10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null
        $triggerOff = New-ScheduledTaskTrigger -AtLogOff -User $u
        $actionOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Logoff -Username $u"
        Register-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$safe" -Action $actionOff -Trigger $triggerOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable) -Force | Out-Null
        Start-Sleep -Seconds 60
        Set-UserPassword -U $u -P (New-RandomPwd)
    }
    'Rotate' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw).Trim()
        if ($u) { Set-UserPassword -U $u -P (New-RandomPwd) }
    }
    'Logoff' {
        if ($Username) {
            Set-UserPasswordBlank -N $Username
            $s = $Username -replace '[^a-zA-Z0-9]', '_'
            Unregister-ScheduledTask -TaskName "PasswordRotator-10Min-$s" -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$s" -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    'StartupBlank' {
        # Run at boot before logon UI; blank password so user can log in even if logoff task didn't run (e.g. fast restart)
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($u) { Set-UserPasswordBlank -N $u }
    }
}
'@

# Install: deploy worker, create logon task, set current user password to blank
function Install {
    if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
    $WorkerScript | Set-Content -Path (Join-Path $TargetDir 'Worker.ps1') -Encoding UTF8 -Force
    $workerPath = Join-Path $TargetDir 'Worker.ps1'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # Get current user running the script
    $currentUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" -Mode Logon"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $OnLogonTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    # Backup: blank password at boot (before logon) so user can always log in even if logoff task was killed during restart
    $currentUser | Set-Content -Path (Join-Path $TargetDir 'currentuser.txt') -Force -ErrorAction SilentlyContinue
    $triggerStartup = New-ScheduledTaskTrigger -AtStartup
    $actionStartup = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" -Mode StartupBlank"
    Register-ScheduledTask -TaskName 'PasswordRotator-AtStartup' -Action $actionStartup -Trigger $triggerStartup -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null
    try {
        if ($currentUser) {
            [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$currentUser,user"
            $adsi.SetPassword('')
        }
    } catch { }
}

# Uninstall
function Uninstall {
    Unregister-ScheduledTask -TaskName $OnLogonTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -like 'PasswordRotator-*' } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $TargetDir) { Remove-Item -Path $TargetDir -Recurse -Force -ErrorAction SilentlyContinue }
}

$Action = $args[0]
if ($Action -eq 'Uninstall') { Uninstall; exit 0 }
Install
Write-Host 'Done. Password rotator installed; current user password set to blank.'
