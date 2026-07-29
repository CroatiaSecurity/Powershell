Start-Job -Name "DllMonitor" -ScriptBlock {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "C:\"
    $watcher.IncludeSubdirectories = $true
    $watcher.Filter = "*.dll"
    $watcher.EnableRaisingEvents = $true

    Register-EngineEvent -InputObject $watcher -EventName Created -SourceIdentifier "DllCreated" -Action {
        $path = $Event.SourceEventArgs.FullPath
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -ne 'Valid') {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Write-Output "Deleted unsigned DLL: $path"
            }
        } catch {}
    }

    while ($true) {
        Wait-Event -SourceIdentifier "DllCreated" -Timeout 5 | Out-Null
    }
}
