# GFocusRulesRemover.ps1 - GEDR-aligned: remove all NTM_Block_* and BlockedConnection_* firewall rules (same as GEDR Dashboard "Remove GFocus blocks")
# Run on demand: .\GFocusRulesRemover.ps1 -RemoveRules

#Requires -RunAsAdministrator

param([switch]$RemoveRules)

if (-not $RemoveRules) {
    Write-Host "Usage: .\GFocusRulesRemover.ps1 -RemoveRules"
    exit 0
}

$totalRemoved = 0

Get-NetFirewallRule -DisplayName "BlockedConnection_*" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-NetFirewallRule -DisplayName $_.DisplayName -ErrorAction SilentlyContinue
    $script:totalRemoved++
}

$out = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
$ruleMatches = [regex]::Matches($out, 'Rule Name:\s*(NTM_Block_[^\s\r\n]+)')
$ntmList = @($ruleMatches | ForEach-Object { $_.Groups[1].Value.Trim() } | Sort-Object -Unique)
foreach ($name in $ntmList) {
    if ($name) {
        $del = netsh advfirewall firewall delete rule name="$name" 2>&1 | Out-String
        if ($del -notmatch 'No rules match') { $script:totalRemoved++ }
    }
}

Write-Host "Removed $script:totalRemoved rule(s) (NTM_Block_* and BlockedConnection_*)."
