function Invoke-InitialScan {
    Write-Log "Performing initial scan of high-risk folders"

    foreach ($folder in $script:HighRiskFolders) {
        if (Test-Path $folder) {
            Write-Log "Scanning: $folder"
            Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue |
                ForEach-Object { Invoke-ThreatAnalysis -FilePath $_.FullName }
        }
    }
}
