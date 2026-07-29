function Start-AntivirusEngine {
    Write-Log "Starting Antivirus Engine"

    Initialize-Environment
    Initialize-ThreatIntel
    Start-RealtimeMonitoring
    Start-BehaviorEngine
    Start-MemoryScanners

    Start-MainLoop
}
