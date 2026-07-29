foreach ($monitorPath in $allowedPaths) {
    try {
        # EXE watcher
        $exeWatcher = New-Object System.IO.FileSystemWatcher
        $exeWatcher.Path = $monitorPath
        $exeWatcher.Filter = "*.exe"
        $exeWatcher.IncludeSubdirectories = $true
        $exeWatcher.EnableRaisingEvents = $true
        $exeWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        # DLL watcher
        $dllWatcher = New-Object System.IO.FileSystemWatcher
        $dllWatcher.Path = $monitorPath
        $dllWatcher.Filter = "*.dll"
        $dllWatcher.IncludeSubdirectories = $true
        $dllWatcher.EnableRaisingEvents = $true
        $dllWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
    }
    catch {
        Write-Warning "Failed to create watcher for $monitorPath: $_"
    }
}
