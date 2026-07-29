function Initialize-Environment {
    Write-Log "Initializing environment"

    New-Item -ItemType Directory `
        -Path $Config.BaseDirectory,
              $Config.QuarantineDirectory,
              $Config.BackupDirectory,
              $RulesDirectory `
        -Force -ErrorAction SilentlyContinue | Out-Null

    Load-Database

    if ($Config.EnableThreatIntel) {
        Initialize-Yara
    }
}
