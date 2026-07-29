$badPatterns = @(
    "nmap",
    "gobuster",
    "enum4linux",
    "rpcclient",
    "smbclient",
    "-sC -sV",
    "-p-",
    "--top-ports"
)

Get-CimInstance Win32_Process | ForEach-Object {
    $cmd = $_.CommandLine
    foreach ($pattern in $badPatterns) {
        if ($cmd -match [regex]::Escape($pattern)) {
            Write-Host "[BLOCKED] $cmd"

            # Kill process
            Stop-Process -Id $_.ProcessId -Force
        }
    }
}
