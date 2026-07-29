$watcher = New-Object IO.FileSystemWatcher
$watcher.Path = "C:\"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher Created -Action {
    Invoke-AnalyzeFile $Event.SourceEventArgs.FullPath
}
