try {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
    $Path = $proc.ExecutablePath
} catch { return }
