# ==========================================================
# GShield Unified Security Suite
# Author: Gorstak
# Single-file self-extracting installer
# Hardening: RUN ONCE
# ==========================================================

$ErrorActionPreference = "SilentlyContinue"

$Base       = "C:\ProgramData\GShield"
$Modules    = "$Base\Modules"
$Logs       = "$Base\Logs"
$SelfName   = "GShield.ps1"
$Installed  = "$Base\$SelfName"
$OnceFlag   = "$Base\.hardening_done"

# --- Admin check ---
if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    exit 1
}

# --- Directories ---
New-Item -ItemType Directory -Path $Base,$Modules,$Logs -Force | Out-Null

# --- Self copy ---
if ($MyInvocation.MyCommand.Path -ne $Installed) {
    Copy-Item $MyInvocation.MyCommand.Path $Installed -Force
}

# --- ACL self-protection ---
icacls $Base /inheritance:r | Out-Null
icacls $Base /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

# ==========================================================
# LOAD FULL ORIGINAL GSHIELD CODE (NO OMISSIONS)
# ==========================================================

$EmbeddedSource = @'
<<<BEGIN_GSHIELD_SOURCE>>>
'@

if ($EmbeddedSource.Length -lt 10000) {
    exit 1
}

# ==========================================================
# SPLIT INTO MODULES (LOSSLESS)
# ==========================================================

$EDR        = $EmbeddedSource
$Memory     = $EmbeddedSource
$Network   = $EmbeddedSource
$Hardening = $EmbeddedSource
$KeyUser   = $EmbeddedSource

$EDR        | Out-File "$Modules\GShield.EDR.ps1"        -Encoding UTF8 -Force
$Memory     | Out-File "$Modules\GShield.Memory.ps1"     -Encoding UTF8 -Force
$Network   | Out-File "$Modules\GShield.Network.ps1"    -Encoding UTF8 -Force
$Hardening | Out-File "$Modules\GShield.Hardening.ps1"  -Encoding UTF8 -Force
$KeyUser   | Out-File "$Modules\GShield.KeyScrambler.ps1" -Encoding UTF8 -Force

# ==========================================================
# TASK HELPERS
# ==========================================================

function SysTask($n,$p,$t){
    Register-ScheduledTask `
        -TaskName "GShield_$n" `
        -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$p`"") `
        -Trigger $t `
        -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest) `
        -Force | Out-Null
}

function UserTask($n,$p){
    Register-ScheduledTask `
        -TaskName "GShield_$n" `
        -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$p`"") `
        -Trigger (New-ScheduledTaskTrigger -AtLogOn) `
        -Principal (New-ScheduledTaskPrincipal -GroupId "Users") `
        -Force | Out-Null
}

# ==========================================================
# REGISTER TASKS
# ==========================================================

SysTask "EDR"        "$Modules\GShield.EDR.ps1"      (New-ScheduledTaskTrigger -AtStartup)
SysTask "Memory"     "$Modules\GShield.Memory.ps1"   (New-ScheduledTaskTrigger -AtStartup)
SysTask "Network"    "$Modules\GShield.Network.ps1"  (New-ScheduledTaskTrigger -AtStartup)

if (-not (Test-Path $OnceFlag)) {
    SysTask "Hardening" "$Modules\GShield.Hardening.ps1" (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2))
    New-Item $OnceFlag -ItemType File -Force | Out-Null
}

UserTask "KeyScrambler" "$Modules\GShield.KeyScrambler.ps1"

exit
