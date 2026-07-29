function Start-AllJobs {
    foreach ($job in $JobDefinitions) {
        if (-not $job.Enabled) {
            Write-Log "Job $($job.Name) is disabled" "INFO"
            continue
        }

        if (-not (Get-Command "Job_$($job.Name)" -ErrorAction SilentlyContinue)) {
            Write-Log "Job function Job_$($job.Name) not found" "WARN"
            continue
        }

        $scriptBlock = {
            Invoke-ManagedJob `
                -JobName $using:job.Name `
                -Interval $using:job.Interval `
                -Critical $using:job.Critical `
                -ScriptBlock (Get-Command "Job_$($job.Name)").ScriptBlock
        }

        $script:managedJobs[$job.Name] = Start-Job -Name $job.Name -ScriptBlock $scriptBlock

        Write-Log "Started job $($job.Name)" "INFO"
    }
}
