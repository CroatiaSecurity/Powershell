if ($scannedHashes.ContainsKey($fileHash)) {
    $alreadyScanned = $scannedHashes[$fileHash]
} else {
    $alreadyScanned = $false
}
