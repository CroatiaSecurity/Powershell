function Move-ToQuarantine($file) {

    if (Is-Locked $file) {
        Write-Host "   -> File is LOCKED by another process. Skipping."
        Log "Skipped locked file $file"
        return
    }

    Write-Host "Quarantining: $file"

    $name = [System.IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Write-Host "   -> Backup: $bak"
    Write-Host "   -> Quarantine: $q"

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force

    Log "Quarantined $file"
}
