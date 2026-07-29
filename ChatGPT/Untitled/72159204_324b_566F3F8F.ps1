$Global:ThreatScore = 0
function Add-ThreatScore($points) {
    $Global:ThreatScore += $points
    if ($Global:ThreatScore -ge 100) {
        Write-EDREvent -Type "Incident" -Score 100 -Source "Correlation" `
          -Message "Host reached incident threshold" `
          -Context @{ Score = $Global:ThreatScore }
    }
}
