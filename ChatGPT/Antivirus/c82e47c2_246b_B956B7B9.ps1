function Write-Heartbeat {
    $hb = [PSCustomObject]@{
        Time = (Get-Date).ToString('o')
        Type = 'Heartbeat'
        Agent = 'Antivirus.ps1'
        Version = '1.0.0'
        Host = $env:COMPUTERNAME
    }
    Write-Telemetry $hb
}
