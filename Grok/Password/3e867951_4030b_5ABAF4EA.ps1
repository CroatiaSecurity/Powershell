# Password.ps1
# Author: Gorstak

# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You need to run this script as an administrator."
    exit
}

# Script path for reusable functions
$scriptPath = "$env:ProgramData\PasswordTasks.ps1"

# ---------------------------
# Create main script file
# ---------------------------
$scriptContent = @"
function Generate-RandomPassword {
    \$upper = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    \$lower = [char[]]('abcdefghijklmnopqrstuvwxyz')
    \$digit = [char[]]('0123456789')
    \$special = [char[]]('!@#$%^&*()_+-=[]{}|;:,.<>?')
    \$chars = \$upper + \$lower + \$digit + \$special
    \$password = ''
    \$password += \$upper | Get-Random -Count 2
    \$password += \$lower | Get-Random -Count 2
    \$password += \$digit | Get-Random -Count 2
    \$password += \$special | Get-Random -Count 2
    for (\$i = 8; \$i -lt 16; \$i++) {
        \$password += \$chars | Get-Random -Count 1
    }
    return (\$password | Sort-Object {Get-Random}) -join ''
}

function Reset-UserPassword {
    \$username = \$env:USERNAME
    \$nullPassword = ConvertTo-SecureString "" -AsPlainText -Force
    Set-LocalUser -Name \$username -Password \$nullPassword
}

function Set-NewRandomPassword {
    \$username = \$env:USERNAME
    \$newPassword = Generate-RandomPassword
    \$securePassword = ConvertTo-SecureString -String \$newPassword -AsPlainText -Force
    Set-LocalUser -Name \$username -Password \$securePassword
}
"@

# Save script file
Set-Content -Path $scriptPath -Value $scriptContent -Force

# ---------------------------
# Immediately randomize current user password invisibly
# ---------------------------
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = "powershell.exe"
$startInfo.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Set-NewRandomPassword"
$startInfo.CreateNoWindow = $true
$startInfo.UseShellExecute = $false
$process = [System.Diagnostics.Process]::Start($startInfo)
$process.WaitForExit()

# ---------------------------
# Schedule task: reset password on shutdown/restart (invisible)
# ---------------------------
$shutdownTrigger = New-ScheduledTaskTrigger -OnEvent -LogName "System" -Source "USER32" -EventId 1074
$shutdownAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Reset-UserPassword"
$shutdownTaskName = "ResetPasswordOnShutdown"

if (Get-ScheduledTask -TaskName $shutdownTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $shutdownTaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $shutdownTaskName -Action $shutdownAction -Trigger $shutdownTrigger -User "SYSTEM" -RunLevel Highest

# ---------------------------
# Schedule task: generate random password every 10 minutes after login (invisible)
# ---------------------------
$randomPasswordTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$randomPasswordTrigger.RepetitionInterval = [TimeSpan]::FromMinutes(10)
$randomPasswordTrigger.RepetitionDuration = [TimeSpan]::FromDays(999)
$randomPasswordAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Command Set-NewRandomPassword"
$randomPasswordTaskName = "GenerateRandomPasswordHourly"

if (Get-ScheduledTask -TaskName $randomPasswordTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $randomPasswordTaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $randomPasswordTaskName -Action $randomPasswordAction -Trigger $randomPasswordTrigger -User $env:USERNAME -RunLevel Highest
