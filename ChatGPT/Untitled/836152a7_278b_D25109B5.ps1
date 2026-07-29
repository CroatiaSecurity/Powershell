function Restore-FromQuarantine($file) {
    Write-Host "Restoring: $file"

    $name = [IO.Path]::GetFileName($file)
    $orig = Join-Path (Split-Path $file -Parent) $name

    Write-Host "   -> Restored to: $orig"

    Move-Item $file $orig -Force

    Log "Restored $file"
}
