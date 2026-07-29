   $quarantineDir = "C:\Quarantine"
   if (-not (Test-Path $quarantineDir)) { New-Item -Path $quarantineDir -ItemType Directory }
   $dest = Join-Path $quarantineDir (Split-Path $path -Leaf)
   Move-Item -Path $path -Destination $dest -Force
   Write-Log "Quarantined suspicious file to $dest"
