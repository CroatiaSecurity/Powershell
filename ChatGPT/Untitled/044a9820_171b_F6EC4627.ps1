   $proc = Get-Process | Where-Object { $_.Path -eq $path }
   if ($proc) {
       Stop-Process -Id $proc.Id -Force
       Write-Log "Terminated process using $path"
   }
