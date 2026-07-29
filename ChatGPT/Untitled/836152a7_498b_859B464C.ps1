function Check-DigitalSignature($file) {
    Write-Host "Checking signature: $file"
    try {
        $sig = Get-AuthenticodeSignature $file
        if ($sig.Status -eq "Valid") {
            if ($sig.SignerCertificate.Subject -match "O=Microsoft Corporation") {
                Write-Host "   -> Microsoft signed: OK"
                return $true
            }
        }
    } catch {
        Write-Host "   -> Error reading signature"
    }
    Write-Host "   -> NOT trusted"
    return $false
}
