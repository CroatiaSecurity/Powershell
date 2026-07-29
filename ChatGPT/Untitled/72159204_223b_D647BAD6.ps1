Write-EDREvent `
  -Type "Malware" `
  -Score 90 `
  -Source "MalwareBazaar" `
  -Message "Known malware hash detected" `
  -Context @{
      File = $file
      Hash = $sha256
  }

Do-Quarantine $file "MalwareBazaar match"
