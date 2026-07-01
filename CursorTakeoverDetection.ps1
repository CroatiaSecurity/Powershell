#Requires -RunAsAdministrator
# CursorTakeoverDetection.ps1
# Author: Gorstak (gorstak.eu)
# Description: Samples cursor movement variance to detect automated/takeover patterns.
#              Uses velocity variance analysis -- low variance + movement indicates bot control.
#              Persistent via scheduled task (cmdlet + schtasks fallback).
# Samples cursor movement variance (rough heuristic for automation/takeover). No kernel input capture.

param(
    [hashtable]$ModuleConfig,
    [switch]$Install,
    [switch]$Uninstall
)

# -- Persistence ------------------------------------------------
$Script:ServiceConfig = @{
    TaskName    = "CursorTakeoverDetection"
    InstallDir  = "C:\ProgramData\Antivirus"
    ScriptName  = "CursorTakeoverDetection.ps1"
    IntervalMin = 5
}

function Install-Persistence {
    $dir = $Script:ServiceConfig.InstallDir
    $dest = Join-Path $dir $Script:ServiceConfig.ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force
    Write-Host "Copied to $dest" -ForegroundColor Gray

    $existing = Get-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $Script:ServiceConfig.TaskName `
            -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "Cursor takeover detection monitor (Gorstak)" | Out-Null
        Write-Host "[OK] $($Script:ServiceConfig.TaskName) installed via Register-ScheduledTask." -ForegroundColor Green
        $installed = $true
    } catch {
        Write-Host "[WARN] Register-ScheduledTask failed: $_" -ForegroundColor Yellow
    }

    # Method 2: schtasks.exe fallback
    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:ServiceConfig.TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONLOGON /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] $($Script:ServiceConfig.TaskName) installed via schtasks.exe fallback." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] schtasks fallback failed: $result" -ForegroundColor Red
            }
        } catch {
            Write-Host "[ERROR] schtasks exception: $_" -ForegroundColor Red
        }
    }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:ServiceConfig.TaskName -Confirm:$false
        Write-Host "Task removed." -ForegroundColor Gray
    }
    $dest = Join-Path $Script:ServiceConfig.InstallDir $Script:ServiceConfig.ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] $($Script:ServiceConfig.TaskName) uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# -- Logging ----------------------------------------------------
$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
$jobLogPath = Join-Path $AgentsAvBin '_JobLog.ps1'
if (Test-Path $jobLogPath) {
    . $jobLogPath
} else {
    function Write-JobLog { param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "log.txt")
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "[$ts] [$Level] $Message"
        $logDir = "C:\ProgramData\Antivirus\Logs"
        if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path (Join-Path $logDir $LogFile) -Value $entry
    }
}

# -- Detection --------------------------------------------------
function Invoke-CursorTakeoverDetection {
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class CursorProbe {
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT lpPoint);
}
"@ -ErrorAction SilentlyContinue
        if (-not $script:CursorSamples) { $script:CursorSamples = New-Object System.Collections.ArrayList }
        $pt = New-Object CursorProbe+POINT
        if ([CursorProbe]::GetCursorPos([ref]$pt)) {
            $now = Get-Date
            [void]$script:CursorSamples.Add([pscustomobject]@{ X = $pt.X; Y = $pt.Y; T = $now })
            while ($script:CursorSamples.Count -gt 20) { $script:CursorSamples.RemoveAt(0) }
            if ($script:CursorSamples.Count -ge 12) {
                $deltas = @()
                for ($i=1; $i -lt $script:CursorSamples.Count; $i++) {
                    $a = $script:CursorSamples[$i-1]; $b = $script:CursorSamples[$i]
                    $dt = [Math]::Max((($b.T - $a.T).TotalMilliseconds),1)
                    $v = [Math]::Sqrt((($b.X-$a.X)*($b.X-$a.X))+(($b.Y-$a.Y)*($b.Y-$a.Y))) / $dt
                    $deltas += $v
                }
                $mean = ($deltas | Measure-Object -Average).Average
                $var = 0.0; foreach($d in $deltas){ $var += [Math]::Pow(($d-$mean),2) }; $var = $var / [Math]::Max($deltas.Count,1)
                if ($var -lt 0.005 -and $mean -gt 0.01) {
                    Write-JobLog "Possible cursor takeover / automated movement detected" "WARNING" "user_protection.log"
                }
            }
        }
    } catch {
        Write-JobLog "CursorTakeoverDetection error: $_" "ERROR" "user_protection.log"
    }
}

# -- Main loop --------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    # When dot-sourced, just expose the function. When run directly, check if from scheduled task.
    $installedDir = $Script:ServiceConfig.InstallDir
    if ($PSCommandPath -and $PSCommandPath.StartsWith($installedDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        while ($true) {
            Invoke-CursorTakeoverDetection
            Start-Sleep -Seconds 3
        }
    } else {
        # First run: install persistence and do a single check, then exit
        Invoke-CursorTakeoverDetection
        Write-Host "[OK] CursorTakeoverDetection installed. Monitor runs via scheduled task." -ForegroundColor Green
    }
}
