Import-Module ThreadJob

Start-ThreadJob -Name "GShield-Monitor" -ScriptBlock {
    # --- Kill listening ports not belonging to known processes ---
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

    # --- Kill suspicious processes ---
    function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    # --- Watch for recent XSS/RDP events ---
    function Start-XSSWatcher {
        try {
            $events = Get-WinEvent -LogName "Security" -MaxEvents 15 |
                Where-Object { $_.Message -like "*remote interactive*" }
            foreach ($evt in $events) {
                Write-Output "Remote session: $($evt.TimeCreated) - $($evt.Message)"
            }
        } catch {}
    }

    # --- DLL FileSystemWatcher ---
    $dllWatcher = New-Object System.IO.FileSystemWatcher
    $dllWatcher.Path = "C:\"
    $dllWatcher.Filter = "*.dll"
    $dllWatcher.IncludeSubdirectories = $true
    $dllWatcher.EnableRaisingEvents = $true

    Register-ObjectEvent -InputObject $dllWatcher -EventName "Created" -SourceIdentifier "UnsignedDLL" -Action {
        $path = $Event.SourceEventArgs.FullPath
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -ne 'Valid') {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Write-Output "⚠️ Deleted unsigned DLL: $path"
            }
        } catch {}
    }

    # --- Continuous protection loop ---
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Start-Sleep -Seconds 10
    }
}
