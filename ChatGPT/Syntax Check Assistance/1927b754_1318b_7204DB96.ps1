while ($true) {
    # 1. Get outgoing connections
    $conns = Get-NetTCPConnection -State Established

    # 2. Resolve IPs to domains (if possible) and match on "xss"
    foreach ($conn in $conns) {
        $remoteIP = $conn.RemoteAddress
        try {
            $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
            if ($hostEntry.HostName -match "xss") {
                # 3. Disable network
                Disable-Network-Briefly

                # 4. Add firewall rule
                New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -Force

                # 5. Kill unsigned or hidden processes
                Get-CimInstance Win32_Process | Where-Object {
                    $_.ExecutablePath -and 
                    (-not (Get-AuthenticodeSignature $_.ExecutablePath).Status -eq "Valid" -or
                     (Get-Item $_.ExecutablePath).Attributes -match "Hidden")
                } | ForEach-Object {
                    try { Stop-Process -Id $_.ProcessId -Force } catch {}
                }

                # 6. Log it
                Write-Log "Blocked and killed due to connection to: $($hostEntry.HostName)"
            }
        } catch {}
    }

    Start-Sleep -Seconds 2  # small pause to prevent CPU spike
}
