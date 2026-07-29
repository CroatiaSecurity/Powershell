   $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match "^[A-Z]:\\$" }
   foreach ($drive in $drives) {
       if ($drive.DisplayRoot -notmatch "C:\\$") {  # Skip C: if you want
           $allowedPaths += $drive.Root
       }
   }
