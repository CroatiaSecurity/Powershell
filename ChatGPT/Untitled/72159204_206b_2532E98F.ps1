Write-EDREvent `
  -Type "MemoryInjection" `
  -Score 95 `
  -Source "MemoryScanner" `
  -Message "In-memory malicious indicators detected" `
  -Context @{
      Process = $_.Name
      PID     = $_.Id
  }
