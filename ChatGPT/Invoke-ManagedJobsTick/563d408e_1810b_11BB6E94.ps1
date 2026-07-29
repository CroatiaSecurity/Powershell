function Invoke-ManagedJobsTick {
    param(
        [Parameter(Mandatory=$true)]
        [DateTime]$NowUtc
    )

    if (-not $script:ManagedJobs) {
        return
    }

    foreach ($job in $script:ManagedJobs.Values) {
        if (-not $job.Enabled) { continue }
        if ($null -ne $job.DisabledUtc) { continue }
        if ($job.NextRunUtc -gt $NowUtc) { continue }

        $job.LastStartUtc = $NowUtc

        try {
            if ($null -ne $job.ArgumentList) {
                Invoke-Command -ScriptBlock $job.ScriptBlock -ArgumentList $job.ArgumentList
            }
            else {
                & $job.ScriptBlock
            }

            $job.LastSuccessUtc = [DateTime]::UtcNow
            $job.RestartAttempts = 0
            $job.LastError = $null
            $job.NextRunUtc = $job.LastSuccessUtc.AddSeconds(
                [Math]::Max(1, $job.IntervalSeconds)
            )
        }
        catch {
            $job.LastError = $_
            $job.RestartAttempts++

            try {
                Write-AVLog "Managed job '$($job.Name)' failed (attempt $($job.RestartAttempts)/$($job.MaxRestartAttempts)) : $($_.Exception.Message)" "WARN"
            }
            catch {}

            if ($job.RestartAttempts -ge $job.MaxRestartAttempts) {
                $job.RestartAttempts = 0
                $job.DisabledUtc = $null
                $job.NextRunUtc = [DateTime]::UtcNow.AddMinutes(5)

                try {
                    Write-AVLog "Managed job '$($job.Name)' exceeded max restart attempts; backing off for 5 minutes" "ERROR"
                }
                catch {}

                continue
            }

            $job.NextRunUtc = [DateTime]::UtcNow.AddSeconds(
                [Math]::Max(1, $job.RestartDelaySeconds)
            )
        }
    }
}
