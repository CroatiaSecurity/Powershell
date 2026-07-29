# ==========================================================
# GShield Unified Installer (SAFE FOR CONCATENATED SOURCE)
# Author: Gorstak
# ==========================================================

$ErrorActionPreference = "Stop"

$Base    = "C:\ProgramData\GShield"
$Payload = "$Base\GShield_Payload.txt"

# ---- Admin check (FIXED SYNTAX) ----
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "Run as Administrator"
    exit 1
}

# ---- Directories ----
New-Item -ItemType Directory -Path $Base -Force | Out-Null

# ==========================================================
# EMBED RAW PAYLOAD SAFELY (BASE64)
# ==========================================================

$PayloadB64 = @'
<<<PUT_BASE64_OF_GSHIELD.TXT_HERE>>>
'@

if ($PayloadB64 -notmatch '^[A-Za-z0-9+/=]') {
    Write-Error "Payload missing"
    exit 1
}

[IO.File]::WriteAllBytes(
    $Payload,
    [Convert]::FromBase64String($PayloadB64)
)

Write-Host "[✓] GShield payload restored to $Payload"
