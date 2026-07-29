if (-not (Test-Path $scannedFilePath)) {
    Write-Log "Scanned files database not found!" -EntryType "Error"
    return
}
