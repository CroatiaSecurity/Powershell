$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $ConsumerName
    CommandLineTemplate =
'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {
    try {
        $p = Get-Process -Id %ProcessID% -ErrorAction SilentlyContinue
        if (-not $p) { exit }

        # Never kill PowerShell hosts
        if ($p.Name -ieq ''powershell.exe'' -or $p.Name -ieq ''pwsh.exe'') { exit }

        $proc = Get-CimInstance Win32_Process -Filter ''ProcessId=%ProcessID%'' -ErrorAction SilentlyContinue
        $cmd  = $proc.CommandLine

        # Allow our own agent
        if ($cmd -and $cmd -match ''Antivirus\.ps1'') { exit }

        Stop-Process -Id $p.Id -Force
    } catch {}
}"'
}
