$watcher = New-Object System.IO.FileSystemWatcher
$onChanged = Register-ObjectEvent $watcher "Changed" -Action { ... }
$onCreated = Register-ObjectEvent $watcher "Created" -Action { ... }
