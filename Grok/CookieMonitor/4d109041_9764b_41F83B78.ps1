
#Requires -RunAsAdministrator
# CookieMonitor.ps1
# Monitors and manages browser cookies, with task scheduling and logging
# Author: Gorstak, optimized by Grok
# Description: Handles cookie backup, monitoring, and password rotation tasks

param (
    [switch]$Monitor,
    [switch]$Backup,
    [switch]$ResetPassword,
    [string]$ConfigPath = "$env:USERPROFILE\CookieMonitor_config.json"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Global:LogDir = "$env:TEMP\security_rules\logs"
$Global:LogFile = "$Global:LogDir\CookieMonitor_$(Get-Date -Format 'yyyyMMdd').log"

# Configuration
$Global:Config = @{
    LogDir = "C:\logs"
    BackupDir = "$env:ProgramData\CookieBackup"
    CookieLogPath = "$env:ProgramData\CookieBackup\CookieMonitor.log"
    PasswordLogPath = "$env:ProgramData\CookieBackup\NewPassword.log"
    ErrorLogPath = "$Global:LogDir\ScriptErrors.log"
    CookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
    BackupPath = "$env:ProgramData\CookieBackup\Cookies.bak"
    TaskScriptPath = "C:\Windows\Setup\Scripts\Bin\CookieMonitor.ps1"
}

# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $maxEventLogLength = 32766
    if (-not (Test-Path $Global:LogDir)) {
        New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null
    }
    
    $truncatedMessage = if ($Message.Length -gt $maxEventLogLength) {
        $Message.Substring(0, $maxEventLogLength - 100) + "... [Truncated, see log file]"
    } else {
        $Message
    }
    
    $color = switch ($EntryType) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$EntryType] $truncatedMessage" -ForegroundColor $color
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    
    try {
        Write-EventLog -LogName "Application" -Source "CookieMonitor" -EventId 1001 -EntryType $EntryType -Message $truncatedMessage -ErrorAction Stop
    } catch {
        $errorMsg = "Failed to write to Event Log: $_"
        $errorMsg | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    }
}

# Initialize Event Log
function Initialize-EventLog {
    if (-not [System.Diagnostics.EventLog]::SourceExists("CookieMonitor")) {
        New-EventLog -LogName "Application" -Source "CookieMonitor"
        Write-Log "Created Event Log source: CookieMonitor"
    }
}

# Register Scheduled Task
function Register-ScheduledTask {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TaskName,
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        [string]$Arguments = "",
        [switch]$AtLogon,
        [switch]$AtStartup,
        [string]$EventQuery
    )
    try {
        if ([string]::IsNullOrEmpty($ScriptPath)) {
            throw "ScriptPath cannot be empty."
        }
        $scriptDir = Split-Path $ScriptPath -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
            Write-Log "Created folder: $scriptDir"
        }
        
        # Avoid redundant copying
        if (-not (Test-Path $ScriptPath)) {
            Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force -ErrorAction Stop
            Write-Log "Copied script to: $ScriptPath"
        }
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Arguments"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        if ($AtLogon) {
            $trigger = New-ScheduledTaskTrigger -AtLogon
        } elseif ($AtStartup) {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        } elseif ($EventQuery) {
            $trigger = New-ScheduledTaskTrigger -Subscription $EventQuery
        } else {
            throw "No valid trigger specified."
        }
        
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop
        Write-Log "Registered task: $TaskName"
    } catch {
        Write-Log "Failed to register task ${TaskName}: $_" -EntryType "Error"
        throw
    }
}

# Cookie Monitoring
function Invoke-CookieMonitor {
    try {
        if (-not (Test-Path $Global:Config.LogDir)) {
            New-Item -ItemType Directory -Path $Global:Config.LogDir -Force | Out-Null
        }
        if (-not (Test-Path $Global:Config.BackupDir)) {
            New-Item -ItemType Directory -Path $Global:Config.BackupDir -Force | Out-Null
        }
        
        # Schedule tasks
        Register-ScheduledTask -TaskName "MonitorCookiesLogon" -ScriptPath $Global:Config.TaskScriptPath -AtLogon
        Register-ScheduledTask -TaskName "BackupCookiesOnStartup" -ScriptPath $Global:Config.TaskScriptPath -AtStartup
        Register-ScheduledTask -TaskName "MonitorCookies" -ScriptPath $Global:Config.TaskScriptPath -EventQuery "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624)]]</Select></Query></QueryList>"
        Register-ScheduledTask -TaskName "ResetPasswordOnShutdown" -ScriptPath $Global:Config.TaskScriptPath -EventQuery "<QueryList><Query Id='0' Path='System'><Select Path='System'>*[System[(EventID=1074)]]</Select></Query></QueryList>" -Arguments "-ResetPassword"
        
        if ($Monitor) {
            # Monitor cookies for changes
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = Split-Path $Global:Config.CookiePath -Parent
            $watcher.Filter = Split-Path $Global:Config.CookiePath -Leaf
            $watcher.EnableRaisingEvents = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite
            
            Register-ObjectEvent -InputObject $watcher -EventName Changed -Action {
                Write-Log "Cookie file changed: $Global:Config.CookiePath"
                Copy-Item -Path $Global:Config.CookiePath -Destination $Global:Config.BackupPath -Force
                Write-Log "Backed up cookies to: $Global:Config.BackupPath"
            }
        }
        
        if ($Backup) {
            Copy-Item -Path $Global:Config.CookiePath -Destination $Global:Config.BackupPath -Force
            Write-Log "Backed up cookies to: $Global:Config.BackupPath"
        }
        
        if ($ResetPassword) {
            Invoke-RotatePassword
        }
    } catch {
        Write-Log "Error in cookie monitor setup: $_" -EntryType "Error"
    }
}

# Rotate Password
function Invoke-RotatePassword {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Write-Log "Skipping Microsoft account password change."
            return
        }
        $chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
        $password = -join ($chars | Get-Random -Count 12)
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$(Get-Date) - New password: $password" | Out-File -FilePath $Global:Config.PasswordLogPath -Append
        Write-Log "Rotated password."
    } catch {
        Write-Log "Password rotation error: $_" -EntryType "Error"
    }
}

# Snort Rules Processing (Placeholder)
function Invoke-SnortRules {
    param (
        [string]$SnortOinkcode = "6cc50dfad45e71e9d8af44485f59af2144ad9a3c"
    )
    $tempDir = "$Global:LogDir\rules"
    $snortRules = "$tempDir\snort_community.rules.tar.gz"
    $snortExtractDir = "$tempDir\snort_rules"
    
    try {
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
        if (-not (Test-Path $snortExtractDir)) { New-Item -ItemType Directory -Path $snortExtractDir -Force | Out-Null }
        
        $snortUri = "https://www.snort.org/downloads/community/community-rules.tar.gz?oinkcode=$SnortOinkcode"
        if (-not (Test-Path $snortRules)) {
            Invoke-WebRequest -Uri $snortUri -OutFile $snortRules -ErrorAction Stop
            Write-Log "Downloaded Snort rules to: $snortRules"
        }
        
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            tar -xzf "$snortRules" -C "$snortExtractDir"
            $tarFile = Get-ChildItem -Path $snortExtractDir -Filter "*.tar" -ErrorAction SilentlyContinue
            if ($tarFile) {
                tar -xf $tarFile.FullName -C $snortExtractDir
                Remove-Item $tarFile.FullName -Force -ErrorAction SilentlyContinue
                $rules = Get-ChildItem -Path $snortExtractDir -Recurse -Include "*.rules"
                Write-Log "Extracted $($rules.Count) Snort rules using tar."
            } else {
                Write-Log "No .tar file found after initial extraction." -EntryType "Error"
            }
        } else {
            Write-Log "tar command not available. Snort rules processing skipped." -EntryType "Error"
        }
    } catch {
        Write-Log "Failed to process Snort rules: $_" -EntryType "Error"
    }
}

# Main Execution
function Main {
    Initialize-EventLog
    if ($Monitor -or $Backup -or $ResetPassword) {
        Invoke-CookieMonitor
    } else {
        Invoke-CookieMonitor
        # Invoke-SnortRules # Uncomment if Snort rules processing is needed
    }
}

Main
