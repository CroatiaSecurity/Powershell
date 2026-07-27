# SimplePatcher.ps1 - No external modules required
$LogPath = "C:\ProgramData\VulnPatcher\log.txt"
$ScriptDir = "C:\ProgramData\VulnPatcher"

function Log { param([string]$msg); $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "$ts - $msg" | Tee-Object -FilePath $LogPath -Append; Write-Host "$ts - $msg" }

Log "=== SimplePatcher START ==="

# Ensure persistence
if (-not (Test-Path $ScriptDir)) { New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null }
Copy-Item $MyInvocation.MyCommand.Path "$ScriptDir\SimplePatcher.ps1" -Force

# Download CISA KEV
$kevUrl = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
$kevPath = "$env:TEMP\kev.csv"
try {
    Invoke-WebRequest -Uri $kevUrl -OutFile $kevPath -UseBasicParsing
    Log "CISA KEV downloaded."
} catch {
    Log "FAILED to download CISA KEV: $_"
    exit 1
}

# Parse and check
$vulns = Import-Csv $kevPath
$installedKBs = Get-HotFix | Select-Object -ExpandProperty HotFixID
$missing = @()

foreach ($v in $vulns) {
    $cve = $v.CVEID
    $kb = $v.'Vendor Advisory or Patch (KB Article)'
    
    if ($kb -match "KB\d{6,7}") {
        $kbNum = ($kb | Select-String "KB\d{6,7}").Matches.Value
        if ($installedKBs -notcontains $kbNum) {
            $missing += [PSCustomObject]@{CVE=$cve; KB=$kbNum}
            Log "MISSING: $cve requires $kbNum"
        } else {
            Log "OK: $cve covered by $kbNum"
        }
    }
}

Log "Found $($missing.Count) missing patches:"
$missing | ForEach-Object { Log "  - $($_.CVE): Download KB$($_.KB -replace 'KB','') from catalog.update.microsoft.com" }

# Create task for manual review
$taskPath = "$ScriptDir\SimplePatcher.ps1"
schtasks /create /tn "VulnPatcher-Simple" /tr "powershell -File `"$taskPath`"" /sc daily /st 03:00 /ru SYSTEM /f
Log "Scheduled daily task created. Review missing patches above."

Remove-Item $kevPath -Force
Log "=== SimplePatcher COMPLETE ==="