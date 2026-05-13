while($true){
    $s=New-Object -Com WScript.Shell
    $paths = "$env:USERPROFILE\Desktop", 
             "$env:APPDATA\Microsoft\Windows\Start Menu\Programs", 
             "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"

    gci $paths -Recurse -Include *.lnk -ErrorAction SilentlyContinue | ? {
        $s.CreateShortcut($_.FullName).TargetPath -like "\\*"
    } | rm -Force
    
    sleep 3600
}

