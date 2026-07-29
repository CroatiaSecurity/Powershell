# Define script version + hash check prior to replacing target
$ScriptVersion = "1.0"
function Get-FileHashString($path) {
    if (-not (Test-Path $path)) { return $null }
    return (Get-FileHash -Path $path -Algorithm SHA256).Hash
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "GSecurity"
    )

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) { Write-Log "Unable to determine script path." "Error"; return }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)
    if (-not (Test-Path $targetFolder)) { New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null }

    # Compare hashes and only copy if different
    $srcHash = Get-FileHashString $scriptSource
    $dstHash = Get-FileHashString $targetPath
    if ($srcHash -and $srcHash -eq $dstHash) {
        Write-Log "Target script already up-to-date." "Information"
    } else {
        try {
            Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
            Write-Log "Copied script to: $targetPath" "Information"
        } catch {
            Write-Log "Failed to copy script: $_" "Error"
            return
        }
    }

    # Only create the scheduled task if it doesn't exist
    try {
        if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop
            Write-Log "Scheduled task '$TaskName' created." "Information"
        } else {
            Write-Log "Scheduled task '$TaskName' already exists." "Information"
        }
    } catch {
        Write-Log "Failed to register task: $_" "Error"
    }
}
