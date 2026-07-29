function Write-Telemetry {
    param($Object)
    $Object | ConvertTo-Json -Depth 5 | Add-Content "$Base\telemetry.json"
}
