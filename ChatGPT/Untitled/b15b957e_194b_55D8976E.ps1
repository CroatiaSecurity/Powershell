Write-EDREvent `
  -Type "Behavior" `
  -Score 60 `
  -Source $behavior `
  -Message "Suspicious behavior detected" `
  -Context @{
      Process = $process.Name
      PID     = $process.Id
  }
