# ------------------------- EDR Core -------------------------
$EDRState = @{
    Agent      = "Antivirus.ps1"
    Author     = "Gorstak"
    Version    = "1.0-EDR"
    Host       = $env:COMPUTERNAME
    Incidents  = @{}
}

$Telemetry = Join-Path $Base "telemetry.json"

function Write-EDREvent {
    param(
        [string]$Type,
        [int]$Score,
        [string]$Source,
        [string]$Message,
        [hashtable]$Context
    )

    $evt = [ordered]@{
        Time     = (Get-Date).ToString("o")
        Host     = $EDRState.Host
        Agent    = $EDRState.Agent
        Type     = $Type
        Score    = $Score
        Source   = $Source
        Message  = $Message
        Context  = $Context
    }

    ($evt | ConvertTo-Json -Depth 6) | Out-File $Telemetry -Append -Encoding UTF8
}
