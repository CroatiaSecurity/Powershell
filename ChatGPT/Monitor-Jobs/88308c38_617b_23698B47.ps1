function Monitor-Jobs {
    while ($true) {
        foreach ($job in $JobDefinitions) {
            if (-not $job.Enabled) { continue }

            $running = Get-Job -Name $job.Name -ErrorAction SilentlyContinue

            if (-not $running -or $running.State -ne 'Running') {
                Write-Log "Job $($job.Name) stopped unexpectedly" "WARN"

                if ($job.Critical) {
                    Write-Log "Restarting critical job $($job.Name)" "CRITICAL"
                    Start-AllJobs
                }
            }
        }

        Start-Sleep -Seconds $Config.JobHealthCheckInterval
    }
}
