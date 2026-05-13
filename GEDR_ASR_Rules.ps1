# GEDR ASR Rules PowerShell Script
# Attack Surface Reduction rules for Windows Defender
# Run as Administrator

$AsrRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block Office child process creation"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block script execution in Office apps"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block executable email attachments"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block Office macros from Internet"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block USB execution"
}

Write-Host "Applying GEDR ASR Rules..." -ForegroundColor Green

foreach ($ruleId in $AsrRules.Keys) {
    $description = $AsrRules[$ruleId]
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
        Write-Host "Applied: $description ($ruleId)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to apply: $description - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "ASR Rules application complete." -ForegroundColor Green
