$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
# Window-title keyword pairs for possible scareware/ransomware screens. Many false positives.
param([hashtable]$ModuleConfig)
. (Join-Path $AgentsAvBin '_JobLog.ps1')

function Invoke-RansomwareScarewareDetection {
    try {
        $patterns = @("encrypted","bitcoin","decrypt","ransom","pay to unlock","your files have been","restore your files","microsoft support","pay fine")
        $allow = @("explorer","logonui","lockapp","consent","applicationframehost","steam","epicgameslauncher")
        foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
            try {
                if (-not $p.MainWindowTitle) { continue }
                $n = ($p.ProcessName | Out-String).Trim().ToLowerInvariant()
                if ($allow -contains $n) { continue }
                $t = $p.MainWindowTitle.ToLowerInvariant()
                $hits = 0
                foreach ($pat in $patterns) { if ($t -like "*$pat*") { $hits++ } }
                if ($hits -ge 2) {
                    Write-JobLog "Possible ransomware scareware: $($p.ProcessName) (PID: $($p.Id)) | $($p.MainWindowTitle)" "THREAT" "user_protection.log"
                }
            } catch {}
        }
    } catch {
        Write-JobLog "RansomwareScarewareDetection error: $_" "ERROR" "user_protection.log"
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RansomwareScarewareDetection }

