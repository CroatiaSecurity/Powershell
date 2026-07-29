try {
    Stop-Process -Id $pid -Force
} catch {
    Write-Warning "Could not stop PID $pid ($((Get-Process -Id $pid -ErrorAction SilentlyContinue).Name)): $_"
}
