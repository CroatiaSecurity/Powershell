#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# === AUTO FIX: Microsoft Account Cache ===
cmdkey /delete:MicrosoftAccount:target=SSO_POP_Device 2>$null
cmdkey /delete:WindowsLive:target=virtualapp/didlogical 2>$null

# === AUTO FIX: Windows Hello / Passport ===
$winBioPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"
$passportPath = "HKLM:\SOFTWARE\Microsoft\PassportForWork"

if (Test-Path $winBioPath) {
    Remove-Item -Path $winBioPath -Recurse -Force
}

if (Test-Path $passportPath) {
    Remove-Item -Path $passportPath -Recurse -Force
}

# === AUTO FIX: LogonUI Cache ===
$logonUIPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"

if (Test-Path $logonUIPath) {
    @(
        "LastLoggedOnUser",
        "LastLoggedOnUserSID",
        "LastLoggedOnDisplayName",
        "SelectedUserSID"
    ) | ForEach-Object {
        Remove-ItemProperty -Path $logonUIPath -Name $_ -Force
    }
}

# === AUTO FIX: Restart TokenBroker ===
Restart-Service -Name "TokenBroker" -Force

# === OPTIONAL: Clean leftover cached creds ===
cmdkey /list | Select-String "MicrosoftAccount|WindowsLive" | ForEach-Object {
    $target = ($_ -split "Target: ")[1]
    if ($target) {
        cmdkey /delete:$target 2>$null
    }
}

# === DONE ===
