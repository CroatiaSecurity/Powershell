Start-Job -Name "ProcessKiller" -ScriptBlock {
    function Start-ProcessKiller {
        $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force
        }
    }

    while ($true) {
        Start-ProcessKiller
        Start-Sleep -Seconds 15
    }
}
