$protectedNames = @("System", "Idle", "wininit", "csrss", "lsass", "smss", "services", "svchost")

foreach ($proc in Get-Process) {
    if ($protectedNames -contains $proc.Name) {
        continue
    }

    try {
        Stop-Process -Id $proc.Id -Force
    } catch {
        Write-Warning "Could not stop process $($proc.Name): $_"
    }
}
