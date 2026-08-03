function Kill-UntrustedLanOrListeningProcesses {
    <#
    .SYNOPSIS
        Terminates any process that has LAN or local listening activity,
        excluding trusted Windows processes.
    .DESCRIPTION
        Scans for processes that are either:
        - Connected to LAN IPs (10.*, 172.16.*, 192.168.*)
        - Listening on local ports
        Then checks whether they are Microsoft-signed and/or in a safe list.
    #>

    [CmdletBinding()]
    param()

    Write-Host "[*] Scanning LAN and listening processes..." -ForegroundColor Cyan

    $SafeProcesses = @(
        "System","svchost.exe","lsass.exe","services.exe","wininit.exe",
        "winlogon.exe","explorer.exe","taskhostw.exe","dwm.exe","spoolsv.exe",
        "smss.exe","RuntimeBroker.exe","SearchIndexer.exe","audiodg.exe","csrss.exe"
    )

    $PrivateRanges = @('10.','172.16.','192.168.')

    $ActiveProcs = @{}

    # 1 LAN connections
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
        $remote = $_.RemoteAddress
        if ($PrivateRanges | Where-Object { $remote -like "$_*" }) {
            $ActiveProcs[$_.OwningProcess] = $true
        }
    }

    # 2 Listening ports
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $ActiveProcs[$_.OwningProcess] = $true
    }

    if (-not $ActiveProcs.Keys) {
        Write-Host "[*] No LAN or listening processes detected." -ForegroundColor Yellow
        return
    }

    foreach ($PID in $ActiveProcs.Keys) {
        try {
            $Proc = Get-Process -Id $PID -ErrorAction Stop
            $Name = $Proc.ProcessName + ".exe"
            $Path = $Proc.Path

            # Check whitelist first
            if ($SafeProcesses -contains $Name) {
                Write-Host "[OK] Safe process: $Name" -ForegroundColor Green
                continue
            }

            # Check digital signature
            $Signed = $false
            try {
                $sig = Get-AuthenticodeSignature -FilePath $Path
                if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -like "*Microsoft*") {
                    $Signed = $true
                }
            } catch {}

            if (-not $Signed) {
                Write-Host "[X] Killing unsigned or unknown process: $Name ($PID)" -ForegroundColor Red
                Stop-Process -Id $PID -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "[OK] Signed by Microsoft: $Name" -ForegroundColor DarkCyan
            }

        } catch {
            Write-Host "[!] Could not analyze PID $PID" -ForegroundColor DarkYellow
        }
    }

    Write-Host "[*] LAN/listening process cleanup complete." -ForegroundColor Cyan
}
