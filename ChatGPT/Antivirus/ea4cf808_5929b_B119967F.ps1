<#
═══════════════════════════════════════════════════════════════════════════════
 ADVANCED POWERSHELL ANTIVIRUS & SECURITY MONITOR
 Job-Based, Self-Healing, Modular Architecture
═══════════════════════════════════════════════════════════════════════════════
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# =========================================================
# CONFIGURATION (EDIT FREELY)
# =========================================================
$Config = @{
    ScriptVersion = "3.0.0"

    BaseDir   = "$env:ProgramData\SecurityMonitor"
    LogDir    = "$env:ProgramData\SecurityMonitor\Logs"
    JobCheck  = 30
    MaxRestarts = 3
    RestartDelay = 5

    CtrlCPressesRequired = 3
    EnableAutoRestart = $true
}

# =========================================================
# JOB DEFINITIONS
# =========================================================
$JobDefinitions = @(
    @{ Name="ProcessMonitor"; Interval=10; Critical=$true  }
    @{ Name="MemoryScanner";  Interval=30; Critical=$true  }
    @{ Name="NetworkMonitor"; Interval=15; Critical=$true  }
    @{ Name="FileSystem";     Interval=20; Critical=$true  }
    @{ Name="Registry";       Interval=25; Critical=$false }
    @{ Name="Services";       Interval=30; Critical=$false }
    @{ Name="Tasks";          Interval=35; Critical=$false }
    @{ Name="WMI";            Interval=40; Critical=$false }
    @{ Name="LOLbins";        Interval=12; Critical=$true  }
    @{ Name="Rootkits";       Interval=60; Critical=$true  }
    @{ Name="Fileless";       Interval=20; Critical=$true  }
    @{ Name="Behavior";       Interval=25; Critical=$false }
    @{ Name="Integrity";      Interval=45; Critical=$false }
    @{ Name="ThreatIntel";    Interval=50; Critical=$false }
)

# =========================================================
# GLOBALS
# =========================================================
$script:Jobs = @{}
$script:CtrlC = 0

# =========================================================
# CORE ENGINE
# =========================================================
function Initialize-Environment {
    foreach ($d in @($Config.BaseDir,$Config.LogDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

function Write-Log {
    param($Msg,$Level="INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date),$Level,$Msg
    Add-Content "$($Config.LogDir)\security.log" $line
}

function Restart-Script {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Invoke-ManagedJob {
    param($Name,$Interval,$Critical,$Block)

    $fails = 0
    while ($true) {
        try {
            & $Block
            Start-Sleep $Interval
        } catch {
            Write-Log "$Name crashed: $($_.Exception.Message)" "ERROR"
            $fails++
            if ($fails -gt $Config.MaxRestarts) {
                Write-Log "$Name exceeded restart limit" "CRITICAL"
                if ($Critical -and $Config.EnableAutoRestart) { Restart-Script }
                break
            }
            Start-Sleep $Config.RestartDelay
        }
    }
}

function Start-AllJobs {
    foreach ($j in $JobDefinitions) {
        $fn = "Job_$($j.Name)"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { continue }

        $sb = {
            Invoke-ManagedJob `
                -Name $using:j.Name `
                -Interval $using:j.Interval `
                -Critical $using:j.Critical `
                -Block (Get-Command $using:fn).ScriptBlock
        }

        $script:Jobs[$j.Name] = Start-Job -Name $j.Name -ScriptBlock $sb
        Write-Log "Started job $($j.Name)"
    }
}

function Monitor-Jobs {
    while ($true) {
        foreach ($j in $JobDefinitions) {
            $job = Get-Job -Name $j.Name -ErrorAction SilentlyContinue
            if (-not $job -or $job.State -ne "Running") {
                Write-Log "Job $($j.Name) stopped" "WARN"
                if ($j.Critical) { Restart-Script }
            }
        }
        Start-Sleep $Config.JobCheck
    }
}

# =========================================================
# JOB STUBS (SAFE TO EXTEND)
# =========================================================
function Job_ProcessMonitor { Get-Process | Out-Null }
function Job_MemoryScanner  { Start-Sleep 1 }
function Job_NetworkMonitor { Get-NetTCPConnection -ErrorAction SilentlyContinue | Out-Null }
function Job_FileSystem     { Start-Sleep 1 }
function Job_Registry       { Start-Sleep 1 }
function Job_Services       { Get-Service | Out-Null }
function Job_Tasks          { Get-ScheduledTask -ErrorAction SilentlyContinue | Out-Null }
function Job_WMI            { Get-WmiObject Win32_Process | Out-Null }
function Job_LOLbins        { Start-Sleep 1 }
function Job_Rootkits       { Start-Sleep 1 }
function Job_Fileless       { Start-Sleep 1 }
function Job_Behavior       { Start-Sleep 1 }
function Job_Integrity      { Start-Sleep 1 }
function Job_ThreatIntel    { Start-Sleep 1 }

# =========================================================
# CTRL+C PROTECTION
# =========================================================
Register-EngineEvent PowerShell.Exiting -Action {
    $script:CtrlC++
    if ($script:CtrlC -lt $Config.CtrlCPressesRequired) {
        Write-Host "Press Ctrl+C $($Config.CtrlCPressesRequired - $script:CtrlC) more times to exit"
        continue
    }
}

# =========================================================
# MAIN
# =========================================================
Initialize-Environment
Write-Log "Security Monitor started"
Start-AllJobs
Monitor-Jobs
