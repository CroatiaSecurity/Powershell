$mutex = New-Object System.Threading.Mutex($false, "Global\GodsProtectionLock")
if (-not $mutex.WaitOne(0)) {
    return
}
