# One for EXE
$fileWatcherExe = New-Object System.IO.FileSystemWatcher
$fileWatcherExe.Path = $drive.DeviceID + "\"
$fileWatcherExe.Filter = "*.exe"
...

# One for DLL
$fileWatcherDll = New-Object System.IO.FileSystemWatcher
$fileWatcherDll.Path = $drive.DeviceID + "\"
$fileWatcherDll.Filter = "*.dll"
...
