function Test-SuspiciousParent {
    param($Proc)

    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($Proc.ParentProcessId)" -ErrorAction SilentlyContinue
    if (!$parent) { return $false }

    $pp = $parent.Name.ToLower()
    return $GShield_KnownLOLBins -contains $pp
}
