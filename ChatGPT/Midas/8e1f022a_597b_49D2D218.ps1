# --- Ensure script copies itself to Bin folder ---
try {
    $scriptDir  = "C:\Windows\Setup\Scripts\Bin"
    $scriptPath = Join-Path $scriptDir "Midas.ps1"
    $currentPath = $MyInvocation.MyCommand.Path

    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
        Write-Log "Created script directory: $scriptDir"
    }

    # Always copy/update itself
    Copy-Item -Path $currentPath -Destination $scriptPath -Force -ErrorAction Stop
    Write-Log "Copied script to: $scriptPath"
}
catch {
    Write-Log "Failed to copy script: $_"
}
