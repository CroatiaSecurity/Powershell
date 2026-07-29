$result = Start-BehaviorMonitor
if ($result.Detected) {
    Register-Detection -Source 'Behavior' -Severity 40 -Context $result
}
