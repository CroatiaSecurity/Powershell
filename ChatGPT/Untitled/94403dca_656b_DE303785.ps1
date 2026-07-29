# --- EXE Monitoring (Simple Integration) ---
$allowedPaths = @(
    "C:\Users\",
    "C:\Program Files\",
    "C:\Program Files (x86)\"
)

Write-Log "Starting EXE monitoring..."

while ($true) {
    foreach ($path in $allowedPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_.FullName
                if (-not $scannedFiles.ContainsKey($file)) {
                    $scannedFiles[$file] = $true
                    Write-Log "Detected new EXE: $file"
                }
            }
        }
    }
    Start-Sleep -Seconds 10
}
