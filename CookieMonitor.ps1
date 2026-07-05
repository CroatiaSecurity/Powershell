# CookieMonitor.ps1
# Author: Gorstak (gorstak.eu)
# Description: Monitors Chrome cookie database for unauthorized changes (session hijacking).
#              Backs up cookies at startup, detects hash changes, and restores cookies from
#              backup on tampering. Installs persistent scheduled tasks for monitoring
#              (every 5 min) and backup (startup).
#Requires -RunAsAdministrator

param(
    [switch]$Monitor,
    [switch]$Backup
)

# === Configuration ===
$taskScriptPath = "C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1"
$logDir = "C:\logs"
$backupDir = "$env:ProgramData\CookieBackup"
$cookieLogPath = "$backupDir\CookieMonitor.log"
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
    $taskNames = @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies")
    foreach ($taskName in $taskNames) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # SYSTEM logon task (cmdlet first, schtasks fallback)
    $logonTaskName = "MonitorCookiesLogon"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $logonInstalled = $false
    try {
        Register-ScheduledTask -TaskName $logonTaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        $logonInstalled = $true
    } catch {
        Log-Info "Register-ScheduledTask failed for $logonTaskName, trying schtasks..."
    }
    if (-not $logonInstalled) {
        $schtasksCmd = "schtasks /Create /TN `"$logonTaskName`" /TR `"powershell.exe -ExecutionPolicy Bypass -File \`"$taskScriptPath\`"`" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F"
        cmd /c $schtasksCmd 2>&1 | Out-Null
    }

    # Startup backup task (cmdlet first, schtasks fallback)
    $backupTaskName = "BackupCookiesOnStartup"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Backup"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $backupInstalled = $false
    try {
        Register-ScheduledTask -TaskName $backupTaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
        $backupInstalled = $true
    } catch {
        Log-Info "Register-ScheduledTask failed for $backupTaskName, trying schtasks..."
    }
    if (-not $backupInstalled) {
        $schtasksCmd = "schtasks /Create /TN `"$backupTaskName`" /TR `"powershell.exe -ExecutionPolicy Bypass -File \`"$taskScriptPath\`" -Backup`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
        cmd /c $schtasksCmd 2>&1 | Out-Null
    }

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
            Log-Info "Cookie hash changed. Restoring from backup..."
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

# === Entry Point ===
Initialize-Environment

if ($Monitor) { Monitor-Cookies; return }
if ($Backup) { Backup-Cookies; return }

# Main install
Install-Script