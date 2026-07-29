function Protect-GShield {
    $path = $MyInvocation.MyCommand.Path
    icacls $path /inheritance:r /grant:r SYSTEM:F Administrators:F | Out-Null
}
Protect-GShield
