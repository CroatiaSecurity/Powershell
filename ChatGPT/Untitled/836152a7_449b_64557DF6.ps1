function Move-ToQuarantine($file) {
    Write-Host "Quarantining: $file"

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Write-Host "   -> Backup: $bak"
    Write-Host "   -> Quarantine: $q"

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force

    Log "Quarantined $file"
}
