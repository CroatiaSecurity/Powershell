function Start-ProcessKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}
