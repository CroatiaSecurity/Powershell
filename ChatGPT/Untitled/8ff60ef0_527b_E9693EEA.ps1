# Watch EXE
$fileWatcherExe = New-Object System.IO.FileSystemWatcher
$fileWatcherExe.Path = $drive
$fileWatcherExe.Filter = "*.exe"
...
Register-ObjectEvent -InputObject $fileWatcherExe -EventName Created -SourceIdentifier "FileCreatedExe_$drive" -Action $action

# Watch DLL
$fileWatcherDll = New-Object System.IO.FileSystemWatcher
$fileWatcherDll.Path = $drive
$fileWatcherDll.Filter = "*.dll"
...
Register-ObjectEvent -InputObject $fileWatcherDll -EventName Created -SourceIdentifier "FileCreatedDll_$drive" -Action $action
