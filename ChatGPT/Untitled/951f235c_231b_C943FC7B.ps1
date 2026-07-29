# Skip ctfmon.exe and its dependencies to prevent stability issues
if ($TargetProcess -match 'ctfmon\.exe' -or $TargetProcess -match 'msctf\.dll') {
    Write-Log "Skipping $TargetProcess (excluded system component)."
    return
}
