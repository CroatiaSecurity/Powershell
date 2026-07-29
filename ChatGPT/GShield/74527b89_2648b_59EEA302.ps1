Import-Module ThreadJob

Start-ThreadJob -Name "GShield-Monitor" -ScriptBlock {
    function Kill-Listeners {
        $knownServices = @("svchost", "System", "lsass", "wininit")
        try {
            $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            foreach ($conn in $connections) {
                $pid = $conn.OwningProcess
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc -and ($knownServices -notcontains $proc.ProcessName)) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }

    function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    function Start-XSSWatcher {
        try {
            $events = Get-WinEvent -LogName "Security" -MaxEvents 15 |
                Where-Object { $_.Message -like "*remote interactive*" }
            foreach ($evt in $events) {
                Write-Output "Remote session: $($evt.TimeCreated) - $($evt.Message)"
            }
        } catch {}
    }

    # --- Add FileSystemWatcher for all suitable drives ---
    $driveTypes = @("Fixed", "Removable", "Network")
    $drives = Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $driveTypes -contains $_.Description }

    foreach ($drive in $drives) {
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $drive.Root
            $watcher.Filter = "*.dll"
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true

            Register-ObjectEvent -InputObject $watcher -EventName "Created" -SourceIdentifier "Watch_$($drive.Name)" -Action {
                $path = $Event.SourceEventArgs.FullPath
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $path
                    if ($sig.Status -ne 'Valid') {
                        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                        Write-Output "⚠️ Unsigned DLL deleted: $path"
                    }
                } catch {}
            }
        } catch {
            Write-Output "⚠️ Failed to register watcher for drive $($drive.Root): $_"
        }
    }

    # --- Protection loop ---
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Start-Sleep -Seconds 10
    }
}
