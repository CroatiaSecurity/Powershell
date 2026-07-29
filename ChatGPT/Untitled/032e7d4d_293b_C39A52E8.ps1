function Start-MainLoop {
    while ($script:EngineRunning) {
        try {
            Invoke-ProcessAndNetworkScan
            Write-Log "Periodic scan cycle completed"
        }
        catch {
            Write-Log "Scan cycle error: $_"
        }

        Start-Sleep -Seconds 30
    }
}
