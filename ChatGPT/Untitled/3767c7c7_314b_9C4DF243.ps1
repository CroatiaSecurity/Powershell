function Start-EDRAgent {
    Protect-ScriptFile
    Install-ProcessCreationBlocker
    Start-MutualWatchdog

    while ($true) {
        try {
            Invoke-ManagedJobsTick   # your existing logic
        } catch {
            Write-AVLog "EDR loop error: $_" "ERROR"
        }
        Start-Sleep 1
    }
}
