Start-Job -Name "XSSWatcher" -ScriptBlock {
    function Start-XSSWatcher {
        $events = Get-WinEvent -LogName "Security" -MaxEvents 20 |
            Where-Object { $_.Message -like "*remote interactive*" }
        foreach ($evt in $events) {
            Write-Output "Remote session activity: $($evt.Message)"
        }
    }

    while ($true) {
        Start-XSSWatcher
        Start-Sleep -Seconds 20
    }
}
