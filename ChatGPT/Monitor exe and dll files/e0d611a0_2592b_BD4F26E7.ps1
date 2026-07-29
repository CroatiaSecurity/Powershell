# Set up FileSystemWatcher for each allowed path (watch .exe AND .dll)
foreach ($monitorPath in $allowedPaths) {
    try {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $monitorPath
        $fileWatcher.Filter = "*.*"  # catch all and filter inside the handler
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true
        $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        $action = {
            param($sender, $e)
            try {
                # Normalize path
                $path = $e.FullPath -replace '/', '\'

                # Only handle .exe and .dll (case-insensitive)
                if ($path -notmatch '\.(?i:(exe|dll))$') { return }

                if ($e.ChangeType -in "Created", "Changed") {
                    Write-Log "Detected file change: $path (ChangeType: $($e.ChangeType))"

                    # Run permission modification commands
                    $takeownOut = & takeown /f "$path" /A 2>&1
                    Write-Log "takeown output: $takeownOut"
                
                    $resetOut = & icacls "$path" /reset 2>&1
                    Write-Log "icacls /reset output: $resetOut"
                
                    $inheritOut = & icacls "$path" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output: $inheritOut"
                
                    $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
                    Write-Log "icacls /grant output: $grantOut"
                
                    # Verify final permissions
                    $finalPerms = & icacls "$path" 2>&1
                    Write-Log "Final perms for $path`: $finalPerms"
                
                    Start-Sleep -Milliseconds 500  # Throttle to prevent event flood
                }
            } catch {
                Write-Log "Watcher error for $path`: $($_.Exception.Message)"
            }
        }

        # Register events for Created and Changed
        Register-ObjectEvent -InputObject $fileWatcher -EventName Created -SourceIdentifier "FileCreated_$monitorPath" -Action $action -ErrorAction Stop
        Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -SourceIdentifier "FileChanged_$monitorPath" -Action $action -ErrorAction Stop
        Write-Log "FileSystemWatcher set up for $monitorPath (monitoring .exe & .dll)"
    } catch {
        Write-Log "Failed to set up watcher for $monitorPath`: $($_.Exception.Message)"
    }
}
