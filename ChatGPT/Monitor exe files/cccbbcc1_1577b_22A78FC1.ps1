# --- EXE Monitoring Section (added) ---
$allowedPaths = @(
    "C:\Users\",
    "C:\Program Files\",
    "C:\Program Files (x86)\"
)

try {
    foreach ($path in $allowedPaths) {
        if (-not (Test-Path $path)) {
            Write-Log "Path not found (skipped EXE monitoring): $path"
            continue
        }

        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $path
        $watcher.Filter = '*.exe'
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true

        Register-ObjectEvent $watcher Created -Action {
            param($sender, $eventArgs)
            Start-Sleep -Milliseconds 300
            if (Test-Path $eventArgs.FullPath) {
                Write-Log "New EXE detected: $($eventArgs.FullPath)"
            }
        }

        Register-ObjectEvent $watcher Changed -Action {
            param($sender, $eventArgs)
            Start-Sleep -Milliseconds 300
            if (Test-Path $eventArgs.FullPath) {
                Write-Log "EXE modified: $($eventArgs.FullPath)"
            }
        }

        Register-ObjectEvent $watcher Renamed -Action {
            param($sender, $eventArgs)
            Write-Log "EXE renamed: $($eventArgs.OldFullPath) -> $($eventArgs.FullPath)"
        }

        Register-ObjectEvent $watcher Deleted -Action {
            param($sender, $eventArgs)
            Write-Log "EXE deleted: $($eventArgs.FullPath)"
        }

        Write-Log "EXE monitoring active for: $path"
    }
} catch {
    Write-Log "Error setting up EXE monitoring: $_"
}
