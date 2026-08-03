if ($threatName -as [int64]) {
    Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
} else {
    Write-Warning "Skipping custom threat '$threatName' - not a numeric Threat ID."
}
