$threatName = "GRules_File_$([System.IO.Path]::GetFileNameWithoutExtension($fileName))"

try {
    if ($threatName -as [int64]) {
        Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
    } else {
        Write-Warning "Custom threat '$threatName' is not a numeric ID. Skipping Add-MpPreference."
    }
} catch {
    Write-Warning "Error applying threat rule for '$threatName': $_"
}
