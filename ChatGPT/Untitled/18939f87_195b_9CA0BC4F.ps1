function Update-ThreatIntel {
    if ((Get-Date) -lt $global:NextIntelUpdate) { return }

    # download -> validate -> atomically replace
    $global:NextIntelUpdate = (Get-Date).AddDays(7)
}
