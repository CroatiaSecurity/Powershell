function Detect-RootkitByNetstat {
    $netstatOutput = netstat -ano 2>$null | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }
    if (-not $netstatOutput) {
        Write-Log "Netstat returned no results. Possible rootkit hiding activity. Collecting evidence, not killing processes." "Warning"
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = "$env:TEMP\rootkit_suspected_$timestamp.txt"
        netstat -ano > $logFile 2>$null
        Get-Process | Select-Object ProcessName, Id, Path, StartTime | Out-File -FilePath "$env:TEMP\process_list_$timestamp.txt"
        # Optionally: raise an event or notify operator (implement notification hook)
        return
    } else {
        Write-Log "Netstat OK. Active connections detected." "Information"
    }
}
