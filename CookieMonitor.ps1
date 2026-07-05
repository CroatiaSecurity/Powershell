# CookieMonitor.ps1
# Author: Gorstak (gorstak.eu)
# Description: Monitors Chrome cookie database for unauthorized changes (session hijacking).
#              Backs up cookies at startup, detects hash changes every 5 minutes, and restores
#              cookies from backup on tampering. Persistent via scheduled task at logon.
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall
)

$Script:TaskName = "CookieMonitorProtection"
$Script:InstallDir = "$env:ProgramData\CookieMonitor"
$Script:ScriptName = "CookieMonitor.ps1"

# === Configuration ===
$backupDir = "$env:ProgramData\CookieMonitor"
$cookieLogPath = "$backupDir\CookieMonitor.log"
$errorLogPath = "$backupDir\ScriptErrors.log"
$cookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
$backupPath = "$backupDir\Cookies.bak"
$hashFile = "$backupDir\CookieHash.txt"

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
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
}

# -- Persistence ------------------------------------------------
function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Chrome cookie integrity monitor (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONLOGON /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    # Also clean up old task names from previous versions
    foreach ($oldTask in @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies")) {
        Unregister-ScheduledTask -TaskName $oldTask -Confirm:$false -ErrorAction SilentlyContinue
    }
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] CookieMonitor uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run (schtasks fallback for debloated Windows where WMI is broken)
$taskExists = (schtasks /Query /TN $Script:TaskName 2>$null) -match $Script:TaskName
if (-not $taskExists) { Install-Persistence }

# === Cookie Backup ===
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

# === Cookie Restore ===
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

# === Cookie Monitor ===
function Monitor-Cookies {
    if (-not (Test-Path $cookiePath)) {
        Log-Info "No Chrome cookies found."
        return
    }
    try {
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

# === Main Logic (runs from installed location) ===
$installedDir = $Script:InstallDir
if ($PSCommandPath -and $PSCommandPath.StartsWith($installedDir, [System.StringComparison]::OrdinalIgnoreCase)) {
    Initialize-Environment
    Log-Info "CookieMonitor started."

    # Backup cookies first
    Backup-Cookies

    # Monitor loop - check every 5 minutes
    while ($true) {
        Monitor-Cookies
        Start-Sleep -Seconds 300
    }
} else {
    Write-Host "[OK] CookieMonitor installed. Monitor runs via scheduled task." -ForegroundColor Green
}
