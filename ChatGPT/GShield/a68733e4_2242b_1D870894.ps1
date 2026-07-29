Start-Job -Name "GShield-Monitor" -ScriptBlock {
    # --- Kill-Listeners ---
    function Kill-Listeners {
        $knownServices = @("svchost", "System", "lsass", "wininit")
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            try {
                $pid = $conn.OwningProcess
                $procName = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName
                if ($knownServices -notcontains $procName) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }

    # --- Start-ProcessKiller ---
    function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    # --- Start-XSSWatcher ---
    function Start-XSSWatcher {
        $events = Get-WinEvent -LogName "Security" -MaxEvents 20 |
            Where-Object { $_.Message -like "*remote interactive*" }
        foreach ($evt in $events) {
            Write-Output "Remote session activity: $($evt.TimeCreated) - $($evt.Message)"
        }
    }

    # --- DLL FileSystemWatcher ---
    $dllWatcher = New-Object System.IO.FileSystemWatcher
    $dllWatcher.Path = "C:\"
    $dllWatcher.IncludeSubdirectories = $true
    $dllWatcher.Filter = "*.dll"
    $dllWatcher.EnableRaisingEvents = $true

    Register-EngineEvent -InputObject $dllWatcher -EventName Created -SourceIdentifier "DllCreated" -Action {
        $path = $Event.SourceEventArgs.FullPath
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -ne 'Valid') {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Write-Output "Deleted unsigned DLL: $path"
            }
        } catch {}
    }

    # --- Main loop ---
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Wait-Event -SourceIdentifier "DllCreated" -Timeout 5 | Out-Null
        Start-Sleep -Seconds 10
    }
}
