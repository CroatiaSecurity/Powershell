param(
    [switch]$Monitor,
    [switch]$Backup,
    [switch]$ResetPassword
)

# === Configuration ===
$taskScriptPath = "C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1"
$logDir = "C:\logs"
$backupDir = "$env:ProgramData\CookieBackup"
$cookieLogPath = "$backupDir\CookieMonitor.log"
$passwordLogPath = "$backupDir\NewPassword.log"
$errorLogPath = "$backupDir\ScriptErrors.log"
$cookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
$backupPath = "$backupDir\Cookies.bak"

# === Logging ===
function Log-Info($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $cookieLogPath -Append
}

function Log-Error($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR - $msg" | Out-File -FilePath $errorLogPath -Append
}

# === Setup Required Folders ===
function Initialize-Environment {
    foreach ($dir in @($logDir, $backupDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

# === Self-Copy and Schedule ===
function Install-Script {
    $targetFolder = Split-Path $taskScriptPath
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path $PSCommandPath -Destination $taskScriptPath -Force
    Log-Info "Script copied to $taskScriptPath"

    # Unregister all tasks to prevent conflicts
    $taskNames = @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies", "ResetPasswordOnShutdown")
    foreach ($taskName in $taskNames) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # SYSTEM logon task
    $logonTaskName = "MonitorCookiesLogon"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $logonTaskName -Action $action -Trigger $trigger -Principal $principal

    # Startup backup task
    $backupTaskName = "BackupCookiesOnStartup"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Backup"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $backupTaskName -Action $action -Trigger $trigger -Principal $principal

    # Monitoring task (every 5 min)
    $monitorTaskName = "MonitorCookies"
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $trigger = $triggers.Create(1) # 1 = TimeTrigger
    $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $trigger.Repetition.Interval = "PT5M" # 5 minutes
    $trigger.Repetition.Duration = "P365D" # 365 days
    $trigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Monitor"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($monitorTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    # Shutdown password reset
    $shutdownTaskName = "ResetPasswordOnShutdown"
    $eventTriggerQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $eventTrigger = $triggers.Create(0)
    $eventTrigger.Subscription = $eventTriggerQuery
    $eventTrigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -ResetPassword"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($shutdownTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    Log-Info "Scheduled tasks installed."
}

# === Cookie Monitor ===
function Monitor-Cookies {
    if (-not (Test-Path $cookiePath)) {
        Log-Info "No Chrome cookies found."
        return
    }

    try {
        $hashFile = "$backupDir\CookieHash.txt"
        $currentHash = (Get-FileHash -Path $cookiePath -Algorithm SHA256).Hash
        $lastHash = if (Test-Path $hashFile) { (Get-Content $hashFile -Raw).Trim() } else { "" }

        if ($lastHash -and $currentHash -ne $lastHash) {
            Log-Info "Cookie hash changed. Triggering countermeasure..."
            Rotate-Password
            Restore-Cookies
        }

        $currentHash | Set-Content -Path $hashFile -Force
    } catch {
        Log-Error "Monitor-Cookies error: $_"
    }
}

# === Backup ===
function Backup-Cookies {
    try {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if (Test-Path $cookiePath) {
            Copy-Item -Path $cookiePath -Destination $backupPath -Force
            Log-Info "Cookies backed up to $backupPath"
        }
    } catch {
        Log-Error "Backup-Cookies error: $_"
    }
}

# === Restore ===
function Restore-Cookies {
    try {
        if (Test-Path $backupPath) {
            Copy-Item -Path $backupPath -Destination $cookiePath -Force
            Log-Info "Cookies restored from backup"
        }
    } catch {
        Log-Error "Restore-Cookies error: $_"
    }
}

# === Password Rotation ===
function Rotate-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account password change."
            return
        }

        $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*')
        $password = -join ($chars | Get-Random -Count 16)
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$((Get-Date).ToString()) - New password: $password" | Out-File -FilePath $passwordLogPath -Append
        Log-Info "Rotated local password."
    } catch {
        Log-Error "Rotate-Password error: $_"
    }
}

# === Blank Password on Shutdown ===
function Reset-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account reset."
            return
        }

        $blank = ConvertTo-SecureString "" -AsPlainText -Force
        Set-LocalUser -Name $user -Password $blank
        Log-Info "Password reset to blank on shutdown."
    } catch {
        Log-Error "Reset-Password error: $_"
    }
}

# === Entry Point ===
Initialize-Environment

if ($Monitor) { Monitor-Cookies; return }
if ($Backup) { Backup-Cookies; return }
if ($ResetPassword) { Reset-Password; return }

# Main install
Install-Script