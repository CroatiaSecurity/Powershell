function Protect-ScriptFile {
    $path = $PSCommandPath
    if (-not $path) { return }

    icacls $path /inheritance:r | Out-Null
    icacls $path /grant:r "SYSTEM:F" | Out-Null
    icacls $path /grant:r "Administrators:RX" | Out-Null
}
