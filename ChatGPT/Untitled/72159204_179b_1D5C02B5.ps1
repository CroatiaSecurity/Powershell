Write-EDREvent `
  -Type "ExecutionBlocked" `
  -Score 70 `
  -Source $type `
  -Message "Execution blocked in real-time" `
  -Context @{
      File = $file
      PID  = $pid
  }
