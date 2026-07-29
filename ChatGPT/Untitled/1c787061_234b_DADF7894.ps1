foreach ($exclude in $Global:ExcludedProcesses) {
    if ($TargetProcess -match [regex]::Escape($exclude) -or $FilePath -match [regex]::Escape($exclude)) {
        Write-Log "Skipping excluded target: $exclude"
        return
    }
}
