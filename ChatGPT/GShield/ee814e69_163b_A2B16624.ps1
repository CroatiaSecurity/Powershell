Register-EngineEvent PowerShell.Exiting -Action {
    Get-Job | Stop-Job -Force
    Write-AntivirusLog "GShield script terminated. All background jobs stopped."
}
