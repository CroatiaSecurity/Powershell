if ($behavior -in @("ProcessHollowing","CredentialAccess") -and $Global:ThreatScore -ge 80) {
    Stop-Process -Id $process.Id -Force
}
