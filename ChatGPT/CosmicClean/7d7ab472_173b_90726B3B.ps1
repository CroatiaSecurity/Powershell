  # install (one-time)
  Install-Module -Name ps2exe -Scope CurrentUser

  # pack
  Invoke-PS2EXE -InputFile "C:\path\CosmicClean.ps1" -OutputFile "C:\path\CosmicClean.exe"
