Register-WmiEvent -Class Win32_ProcessStartTrace -Action {
    $proc = $Event.SourceEventArgs.NewEvent
    $cmd = $proc.CommandLine

    Invoke-AnalyzeProcess -PID $proc.ProcessID -Cmd $cmd
}
