# Create COM object (ProgID will be SimpleAntivirusWrapper.SimpleAntivirus unless changed)
# If a ProgID isn't defined explicitly, use CreateObject with the class's full name or use Type.GetTypeFromCLSID
$com = New-Object -ComObject SimpleAntivirusWrapper.SimpleAntivirus
$result = $com.RunScan()
Write-Host $result
