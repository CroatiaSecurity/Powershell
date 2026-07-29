function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit") # Safe system processes
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore processes that no longer exist or access-denied
        }
    }
}

Start-Job -ScriptBlock {
    while ($true) {
        Kill-Listeners
        Start-Sleep -Seconds 5  # Prevent CPU abuse
    }
}
