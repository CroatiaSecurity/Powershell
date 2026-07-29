function Invoke-GShieldScan {
    param([Parameter(Mandatory)][string]$Path)

    $real = Resolve-RealPath $Path
    if (!$real) { return }

    if (-not ($GShield_ScanExtensions -contains ([IO.Path]::GetExtension($real).ToLower()))) {
        return
    }

    $hash = Get-LockedFileHash $real
    if (!$hash) { return }

    if (Test-SignatureTrust $real) {
        return
    }

    # Reputation hooks go here (MalwareBazaar, local deny, YARA)

    Write-Log "Suspicious file detected: $real ($hash)" "ALERT"
    Quarantine-File $real
}
