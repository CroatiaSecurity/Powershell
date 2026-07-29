foreach ($line in Get-Content $scannedFilePath) {
    if ($line -match "^[a-fA-F0-9]{64},(True|False)$") {
        $parts = $line.Split(",")
        $hash = $parts[0]
        $status = [bool]::Parse($parts[1])
        $scannedHashes[$hash] = $status
    } else {
        Write-Log "Invalid entry in scanned_files.txt: $line" -EntryType "Warning"
    }
}
