# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You need to run this script as an administrator."
    exit
}

# Set script path (used by scheduled tasks)
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

# Save the script
Set-Content -Path $scriptPath -Value $scriptContent -Force

# ---------------------------
# Schedule task: reset password on shutdown/restart
# ---------------------------
$shutdownTrigger = New-ScheduledTaskTrigger -OnEvent -LogName "System" -Source "USER32" -EventId 1074
$shutdownAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -Command Reset-UserPassword"
$shutdownTaskName = "ResetPasswordOnShutdown"

# Remove existing task if exists
if (Get-ScheduledTask -TaskName $shutdownTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $shutdownTaskName -Confirm:$false
}

# Register the shutdown task
Register-ScheduledTask -TaskName $shutdownTaskName -Action $shutdownAction -Trigger $shutdownTrigger -User "SYSTEM" -RunLevel Highest

# ---------------------------
# Schedule task: generate random password every 10 minutes after login
# ---------------------------
$randomPasswordTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$randomPasswordTrigger.RepetitionInterval = [TimeSpan]::FromMinutes(10)
$randomPasswordTrigger.RepetitionDuration = [TimeSpan]::FromDays(999)
$randomPasswordAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -Command Set-NewRandomPassword"
$randomPasswordTaskName = "GenerateRandomPasswordHourly"

# Remove existing task if exists
if (Get-ScheduledTask -TaskName $randomPasswordTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $randomPasswordTaskName -Confirm:$false
}

# Register the password rotation task
Register-ScheduledTask -TaskName $randomPasswordTaskName -Action $randomPasswordAction -Trigger $randomPasswordTrigger -User $env:USERNAME -RunLevel Highest

Write-Host "Scheduled tasks created successfully."
