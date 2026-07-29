# dry-run report only
.\Baseline-Guard.ps1

# run and automatically fix deviations (higher risk; create backups first)
.\Baseline-Guard.ps1 -AutoFix
