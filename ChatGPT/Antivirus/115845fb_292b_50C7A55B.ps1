# Keep script running with crash protection
Write-Host "Antivirus running. Press [Ctrl] + [C] to stop."
try {
    while ($true) { Start-Sleep -Milliseconds 1 }
} catch {
    Write-Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $LogFile for details."
}
