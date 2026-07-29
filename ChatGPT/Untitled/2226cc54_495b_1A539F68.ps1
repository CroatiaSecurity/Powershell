$badPatterns = @(
    "nmap",
    "gobuster",
    "enum4linux",
    "rpcclient",
    "smbclient",
    "-sC -sV",
    "-p-",
    "--top-ports",
    "whoami /all",
    "wmic service get"
)

Register-WmiEvent -Class Win32_ProcessStartTrace -Action {
    $cmd = $Event.SourceEventArgs.NewEvent.CommandLine
    $pid = $Event.SourceEventArgs.NewEvent.ProcessID

    foreach ($pattern in $badPatterns) {
        if ($cmd -like "*$pattern*") {
            Stop-Process -Id $pid -Force
        }
    }
}
