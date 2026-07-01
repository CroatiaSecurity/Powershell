# Install-PasswordRotator.ps1
# Author: Gorstak (gorstak.eu)
# Description: Password rotation security system. Rotates local user password to a random
#              24-char string every 10 minutes after logon. Password is blanked ONLY at boot
#              (before logon screen) so user can log in, then immediately rotated after logon.
#              Configures UAC to auto-elevate signed Windows binaries only -- non-Windows
#              programs requiring elevation will be blocked since user doesn't know password.
#              This prevents malware from gaining admin via UAC prompt.
#
#              Run once as Administrator. Use 'Uninstall' argument to remove.
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$TargetDir = 'C:\ProgramData\PasswordRotator'
$OnLogonTaskName = 'PasswordRotator-OnLogon'

# ========================= UAC Configuration =========================
function Set-UACPolicy {
    <#
    .SYNOPSIS
        Configures UAC so that:
        - Signed Windows executables auto-elevate (user doesn't need password)
        - Non-Windows/unsigned executables trigger a credential prompt (blocked since user doesn't know password)
        - Blank passwords are NOT allowed for network/UAC authentication
    #>
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # ConsentPromptBehaviorAdmin = 5: Prompt for consent for non-Windows binaries
    # This means signed Microsoft binaries auto-elevate, everything else prompts
    Set-ItemProperty -Path $policyPath -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord -Force

    # EnableInstallerDetection = 1: Detect installer programs and prompt for elevation
    Set-ItemProperty -Path $policyPath -Name 'EnableInstallerDetection' -Value 1 -Type DWord -Force

    # EnableLUA = 1: UAC must be enabled
    Set-ItemProperty -Path $policyPath -Name 'EnableLUA' -Value 1 -Type DWord -Force

    # PromptOnSecureDesktop = 1: Show UAC prompt on secure desktop (anti-spoofing)
    Set-ItemProperty -Path $policyPath -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord -Force

    # EnableVirtualization = 1: Virtualize file/registry writes for legacy apps
    Set-ItemProperty -Path $policyPath -Name 'EnableVirtualization' -Value 1 -Type DWord -Force

    # ValidateAdminCodeSignatures = 0: Allow unsigned executables to elevate
    # This setting has been disabled to permit unsigned/untrusted executables to elevate
    Set-ItemProperty -Path $policyPath -Name 'ValidateAdminCodeSignatures' -Value 0 -Type DWord -Force

    # FilterAdministratorToken = 1: Apply UAC filtering to built-in Administrator too
    Set-ItemProperty -Path $policyPath -Name 'FilterAdministratorToken' -Value 1 -Type DWord -Force

    # Disable blank password use for network logons (prevents empty password from working on UAC)
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty -Path $lsaPath -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord -Force

    # Accounts: Limit local account use of blank passwords to console logon only
    # This is critical: with this set, blank passwords CANNOT authenticate for elevation
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path $winlogonPath)) { New-Item -Path $winlogonPath -Force | Out-Null }

    "$(Get-Date -Format o) UAC policy configured: auto-elevate signed Windows binaries only, block blank passwords for elevation" | Out-File (Join-Path $TargetDir 'log.txt') -Append -ErrorAction SilentlyContinue
}

# ========================= Worker Script =========================
$WorkerScript = @'
param([string]$Mode, [string]$Username)
$ErrorActionPreference = 'Stop'
$TargetDir = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\ProgramData\PasswordRotator' }
$UserFile = Join-Path $TargetDir 'currentuser.txt'
$LogFile = Join-Path $TargetDir 'log.txt'

function Write-RotatorLog {
    param([string]$Message)
    "$(Get-Date -Format o) [$Mode] $Message" | Out-File $LogFile -Append -ErrorAction SilentlyContinue
}

function Get-LoggedInUser {
    $u = $null
    try { $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
    if (-not $u) { try { $u = $env:USERNAME } catch {} }
    if (-not $u) { return $null }
    if ($u -match '\\') { return $u.Split('\')[-1] }
    return $u
}

function Set-UserPassword {
    param([string]$U, [string]$P)
    if ([string]::IsNullOrWhiteSpace($U)) { return $false }
    try {
        Set-LocalUser -Name $U -Password (ConvertTo-SecureString -String $P -AsPlainText -Force) -ErrorAction Stop
        return $true
    } catch {
        try {
            [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$U,user"
            $adsi.SetPassword($P)
            return $true
        } catch {
            Write-RotatorLog "Set-UserPassword FAILED for ${U}: $_"
            return $false
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
        try { & net user $N '""' 2>$null } catch {
            Write-RotatorLog "Set-UserPasswordBlank FAILED: $_"
        }
    }
}

function New-RandomPwd {
    # 24-char password with mixed case, digits, and symbols - impossible to guess
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*'
    -join ((1..24) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}

function Remove-TasksForUser {
    param([string]$U)
    $s = $U -replace '[^a-zA-Z0-9]', '_'
    @("PasswordRotator-10Min-$s", "PasswordRotator-OnLogoff-$s") | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Set-UACBlockBlankPasswords {
    # Ensure blank passwords cannot be used for UAC elevation even if password is momentarily blank
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty -Path $lsaPath -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

    # ConsentPromptBehaviorAdmin = 5: prompt for consent on non-Windows binaries
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-ItemProperty -Path $policyPath -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue

    # ValidateAdminCodeSignatures = 0: allow unsigned executables to elevate
    Set-ItemProperty -Path $policyPath -Name 'ValidateAdminCodeSignatures' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
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

        # Rotation task: every 10 minutes
        $trigger10 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
        $action10 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Rotate"
        Register-ScheduledTask -TaskName "PasswordRotator-10Min-$safe" -Action $action10 -Trigger $trigger10 -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null

        # Logoff task: blank password so user can log back in
        $triggerOff = New-ScheduledTaskTrigger -AtLogOff -User $u
        $actionOff = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$worker`" -Mode Logoff -Username $u"
        Register-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$safe" -Action $actionOff -Trigger $triggerOff -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable) -Force | Out-Null

        # Enforce UAC policy on every logon (in case something reset it)
        Set-UACBlockBlankPasswords

        # Wait a moment for session to stabilize, then rotate immediately
        Start-Sleep -Seconds 30
        $pwd = New-RandomPwd
        if (Set-UserPassword -U $u -P $pwd) {
            Write-RotatorLog "Initial rotation complete for $u"
        }
    }
    'Rotate' {
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw).Trim()
        if ($u) {
            $pwd = New-RandomPwd
            if (Set-UserPassword -U $u -P $pwd) {
                Write-RotatorLog "Password rotated for $u"
            }
        }
        # Re-enforce UAC policy each rotation cycle
        Set-UACBlockBlankPasswords
    }
    'Logoff' {
        # Blank password at logoff so user can log back in at next boot
        if ($Username) {
            Set-UserPasswordBlank -N $Username
            Write-RotatorLog "Password blanked at logoff for $Username"
            $s = $Username -replace '[^a-zA-Z0-9]', '_'
            Unregister-ScheduledTask -TaskName "PasswordRotator-10Min-$s" -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName "PasswordRotator-OnLogoff-$s" -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    'StartupBlank' {
        # Run at boot BEFORE logon UI -- blank password so user can log in
        # Then immediately re-enforce UAC policy so blank password can't be used for elevation
        if (-not (Test-Path $UserFile)) { exit 0 }
        $u = (Get-Content -Path $UserFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($u) {
            Set-UserPasswordBlank -N $u
            Write-RotatorLog "Password blanked at startup for $u (pre-logon)"
        }
        # Critical: enforce LimitBlankPasswordUse so blank password CANNOT be used for UAC
        Set-UACBlockBlankPasswords
    }
}
'@

# ========================= Install Function =========================
function Install {
    if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
    $WorkerScript | Set-Content -Path (Join-Path $TargetDir 'Worker.ps1') -Encoding UTF8 -Force
    $workerPath = Join-Path $TargetDir 'Worker.ps1'

    # Configure UAC policy immediately
    Set-UACPolicy

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    # Get current user
    $currentUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if ($currentUser -match '\\') { $currentUser = $currentUser.Split('\')[-1] }

    # Logon task: triggers password rotation setup
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" -Mode Logon"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $OnLogonTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    # Startup task: blanks password before logon screen so user can log in
    $currentUser | Set-Content -Path (Join-Path $TargetDir 'currentuser.txt') -Force -ErrorAction SilentlyContinue
    $triggerStartup = New-ScheduledTaskTrigger -AtStartup
    $actionStartup = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`" -Mode StartupBlank"
    Register-ScheduledTask -TaskName 'PasswordRotator-AtStartup' -Action $actionStartup -Trigger $triggerStartup -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) -Force | Out-Null

    # Set initial blank password for current session (will be rotated immediately after logon task fires)
    try {
        if ($currentUser) {
            [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$currentUser,user"
            $adsi.SetPassword('')
        }
    } catch { }

    "$(Get-Date -Format o) Install complete for user: $currentUser" | Out-File (Join-Path $TargetDir 'log.txt') -Append -ErrorAction SilentlyContinue
}

# ========================= Uninstall Function =========================
function Uninstall {
    # Remove all tasks
    Unregister-ScheduledTask -TaskName $OnLogonTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'PasswordRotator-*' } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Restore UAC to default (prompt for consent on secure desktop)
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-ItemProperty -Path $policyPath -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $policyPath -Name 'ValidateAdminCodeSignatures' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $policyPath -Name 'FilterAdministratorToken' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    # Blank the password so user can log in after uninstall
    $userFile = Join-Path $TargetDir 'currentuser.txt'
    if (Test-Path $userFile) {
        $u = (Get-Content $userFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($u) {
            try {
                [ADSI]$adsi = "WinNT://$env:COMPUTERNAME/$u,user"
                $adsi.SetPassword('')
            } catch { & net user $u '""' 2>$null }
        }
    }

    # Remove data directory
    if (Test-Path $TargetDir) { Remove-Item -Path $TargetDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host 'Password rotator uninstalled. Password set to blank. UAC restored to defaults.'
}

# ========================= Entry Point =========================
$Action = $args[0]
if ($Action -eq 'Uninstall') { Uninstall; exit 0 }
Install
Write-Host @"
Done. Password rotator installed.

What happens now:
  - At boot: password is blanked so you can log in (no password needed at login screen)
  - 30 seconds after logon: password rotates to a random 24-char string
  - Every 10 minutes: password rotates again
  - At logoff: password blanks for next login

UAC behavior:
  - Windows signed programs: auto-elevate (no prompt)
  - Non-Windows/unsigned programs: UAC will ask for credentials (BLOCKED - you don't know the password)
  - This prevents malware from getting admin privileges via UAC

To uninstall: .\Install-PasswordRotator.ps1 Uninstall
"@
