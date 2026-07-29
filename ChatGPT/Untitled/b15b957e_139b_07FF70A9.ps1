if (Test-SandboxEnvironment) {
    $Global:EDRState.Mode = "Degraded"
    Log "Sandbox/VM environment detected – adjusting thresholds"
}
