# =========================
# GShield Unified Installer
# Author: Gorstak
# =========================

$Base = "C:\ProgramData\GShield"
$ModulesDir = "$Base\Modules"
$SelfPath = $MyInvocation.MyCommand.Path
$InstalledSelf = "$Base\GShield.ps1"

# --- Ensure admin ---
if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit
}

# --- Create directories ---
New-Item -ItemType Directory -Path $Base,$ModulesDir -Force | Out-Null

# --- Copy self ---
if ($SelfPath -ne $InstalledSelf) {
    Copy-Item $SelfPath $InstalledSelf -Force
}

# --- Read own source ---
$source = Get-Content $InstalledSelf -Raw

# --- Extract modules ---
$moduleRegex = '(?s)# === MODULE: (.*?) ===(.*?)# === END MODULE ==='
$modules = [regex]::Matches($source, $moduleRegex)

foreach ($m in $modules) {
    $name = $m.Groups[1].Value.Trim()
    $code = $m.Groups[2].Value.Trim()

    $outFile = "$ModulesDir\GShield.$name.ps1"
    $code | Out-File $outFile -Encoding UTF8 -Force

    Write-Host "[+] Extracted module: $name"
}

# --- Register scheduled tasks ---
function Register-GShieldTask {
    param ($Name, $Script, $Trigger)

    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`""

    Register-ScheduledTask `
        -TaskName "GShield_$Name" `
        -Action $action `
        -Trigger $Trigger `
        -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest) `
        -Force | Out-Null
}

# EDR – continuous
Register-GShieldTask `
    -Name "EDR" `
    -Script "$ModulesDir\GShield.EDR.ps1" `
    -Trigger (New-ScheduledTaskTrigger -AtStartup)

# Memory scanner
Register-GShieldTask `
    -Name "Memory" `
    -Script "$ModulesDir\GShield.Memory.ps1" `
    -Trigger (New-ScheduledTaskTrigger -AtStartup)

# Network / behavior
Register-GShieldTask `
    -Name "Network" `
    -Script "$ModulesDir\GShield.Network.ps1" `
    -Trigger (New-ScheduledTaskTrigger -AtStartup)

# Hardening – run once
Register-GShieldTask `
    -Name "Hardening" `
    -Script "$ModulesDir\GShield.Hardening.ps1" `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1))

Write-Host "[✓] GShield installed successfully"
exit
