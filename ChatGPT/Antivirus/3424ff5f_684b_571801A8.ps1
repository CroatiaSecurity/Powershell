$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $ConsumerName
    CommandLineTemplate =
        'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {
            try {
                $p = Get-Process -Id %ProcessID% -ErrorAction SilentlyContinue
                if (-not $p) { exit }

                $cmd = (Get-CimInstance Win32_Process -Filter ''ProcessId=%ProcessID%'' -ErrorAction SilentlyContinue).CommandLine

                if ($cmd -and $cmd -match ''GShield|Antivirus\.ps1'') { exit }

                Stop-Process -Id %ProcessID% -Force
            } catch {}
        }"'
}
