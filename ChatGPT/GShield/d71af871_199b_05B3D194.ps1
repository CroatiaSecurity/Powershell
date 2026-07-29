Import-Module "$PSScriptRoot\Core\GShield.EDR.ps1"
Import-Module "$PSScriptRoot\Hardening\GShield.Credentials.ps1"

Start-GShieldEDR
Invoke-GShieldHardening -Once
Start-GShieldKeyScrambler -Optional
