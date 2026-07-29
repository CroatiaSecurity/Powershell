Start-NeuroBehaviorMonitor -OnThreat {
    param($e)

    Write-Log "NeuroBehavior threat from $($e.Process) [$($e.Type)]" "WARN"

    Suspend-Process -Id $e.PID
}
