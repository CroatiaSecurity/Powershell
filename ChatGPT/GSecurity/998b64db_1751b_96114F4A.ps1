# Load config (example)
$configPath = "C:\Windows\Setup\Scripts\Bin\gsecurity-config.json"
$DefaultConfig = @{
    DryRun = $true
    ProcessWhitelist = @("svchost", "explorer", "lsass", "wininit", "services")
    KillIfUnsignedOnly = $false
}
if (Test-Path $configPath) {
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
} else {
    $cfg = $DefaultConfig
}

function Start-StealthKiller {
    while ($true) {
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sig = Get-AuthenticodeSignature $exePath
                $sigStatus = $sig.Status
                $procName = $_.Name
                if ($procName -in $cfg.ProcessWhitelist) { return }

                # build a reason list
                $reasons = @()
                if ($isHidden) { $reasons += "Hidden file attribute" }
                if ($sigStatus -ne "Valid") { $reasons += "Unsigned or invalid signature: $sigStatus" }

                if ($reasons.Count -gt 0) {
                    $msg = "Potential stealthy process $_.ProcessId ($procName). Reasons: $($reasons -join '; ')"
                    Write-Log $msg "Warning"
                    if (-not $cfg.DryRun) {
                        try {
                            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-Log "Killed process $_.ProcessId ($procName)" "Warning"
                        } catch { Write-Log "Failed to kill $_.ProcessId : $_" "Error" }
                    }
                }
            }
        }
        Start-Sleep -Seconds 5
    }
}
