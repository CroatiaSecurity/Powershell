# create base64 from the script (run in PowerShell)
$bytes = [System.Text.Encoding]::Unicode.GetBytes((Get-Content -Raw 'C:\path\CosmicClean.ps1'))
$enc = [Convert]::ToBase64String($bytes)
# then from cmd or a wrapper:
powershell.exe -NoProfile -EncodedCommand <paste-enc-here>
