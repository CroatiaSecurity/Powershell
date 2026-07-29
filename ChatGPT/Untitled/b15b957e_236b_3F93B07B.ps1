$RulesPath = Join-Path $Base "rules"
New-Item $RulesPath -ItemType Directory -Force | Out-Null

# Validate YARA rules before activating
& $yaraExe -C $output 2>$null
if ($LASTEXITCODE -eq 0) {
    Log "YARA rule validated: $fileName"
}
