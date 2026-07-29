Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "GShieldProc" -Action {
    $proc = $Event.SourceEventArgs.NewEvent
    $cmd  = $proc.CommandLine

    $score = Get-CommandLineScore $cmd
    if ($score -ge 4 -or (Test-SuspiciousParent $proc)) {
        Write-Log "Blocked suspicious execution: $cmd" "CRITICAL"
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}
