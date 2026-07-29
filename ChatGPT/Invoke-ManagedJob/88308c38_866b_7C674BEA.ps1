function Invoke-ManagedJob {
    param (
        [string]$JobName,
        [int]$Interval,
        [bool]$Critical,
        [scriptblock]$ScriptBlock
    )

    $restartCount = 0

    while ($true) {
        try {
            & $ScriptBlock
            Start-Sleep -Seconds $Interval
        }
        catch {
            Write-Log "[$JobName] ERROR: $($_.Exception.Message)" "ERROR"

            $restartCount++

            if ($restartCount -gt $Config.MaxJobRestartAttempts) {
                Write-Log "[$JobName] exceeded max restarts" "CRITICAL"

                if ($Critical -and $Config.EnableAutoRestart) {
                    Write-Log "Critical job failed, restarting script" "CRITICAL"
                    Restart-Script
                }

                break
            }

            Start-Sleep -Seconds $Config.JobRestartDelay
        }
    }
}
