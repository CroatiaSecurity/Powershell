function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if (-not $path) { Write-Log "Remove-InProcControls: missing registry path" "Warning"; return }
    try {
        # Backup the key (export)
        $backupFile = Join-Path $env:TEMP ("reg_backup_" + (Get-Random) + ".reg")
        reg export "`"$path`"" $backupFile /y 2>$null

        # If $value is a file path, ensure canonical absolute path and copy to quarantine
        if ($value -and ([System.IO.Path]::IsPathRooted($value)) -and (Test-Path $value)) {
            $quarantine = "C:\Quarantine\GSecurity"
            New-Item -Path $quarantine -ItemType Directory -Force | Out-Null
            $dest = Join-Path $quarantine ([IO.Path]::GetFileName($value) + "_" + (Get-Date -Format "yyyyMMddHHmmss"))
            Copy-Item -Path $value -Destination $dest -Force -ErrorAction SilentlyContinue
            Write-Log "Backed up $value to $dest" "Information"
        }

        # Remove the registry key safely (remove the CLSID node)
        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed registry key: $path" "Warning"
    } catch {
        Write-Log "Error removing $path : $_" "Error"
    }
}
