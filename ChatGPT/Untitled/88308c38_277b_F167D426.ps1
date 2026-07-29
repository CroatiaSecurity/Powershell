$null = Register-EngineEvent PowerShell.Exiting -Action {
    $script:ctrlCCount++
    if ($script:ctrlCCount -lt $Config.CtrlCPressesRequired) {
        Write-Host "Press Ctrl+C $($Config.CtrlCPressesRequired - $script:ctrlCCount) more times to exit"
        continue
    }
}
