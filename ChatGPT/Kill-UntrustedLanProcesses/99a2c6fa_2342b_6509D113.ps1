function Kill-UntrustedLanProcesses {
    <#
    .SYNOPSIS
        Terminates all processes with LAN activity except safe Windows ones.
    .DESCRIPTION
        Detects processes with active TCP connections to local subnet IPs and kills any
        that are not in the safe Windows whitelist.
    .NOTES
        Requires administrative privileges.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Host "[*] Gathering LAN-active processes..." -ForegroundColor Cyan

    # Define safe processes that commonly appear on LAN connections
    $SafeProcesses = @(
        "System",
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "winlogon.exe",
        "explorer.exe",
        "taskhostw.exe",
        "dwm.exe",
        "spoolsv.exe",
        "smss.exe",
        "RuntimeBroker.exe",
        "SearchIndexer.exe",
        "audiodg.exe",
        "csrss.exe"
    )

    # Get local subnet ranges (simplified for common private LANs)
    $PrivateRanges = @(
        '10.',        # 10.0.0.0/8
        '172.16.',    # 172.16.0.0/12
        '192.168.'    # 192.168.0.0/16
    )

    # Get all active TCP connections with owning processes
    $LanConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        $Remote = $_.RemoteAddress
        $PrivateRanges | ForEach-Object { $Remote -like "$_*" }
    }

    if (-not $LanConnections) {
        Write-Host "[*] No LAN-active processes detected." -ForegroundColor Yellow
        return
    }

    $PIDs = $LanConnections | Select-Object -ExpandProperty OwningProcess -Unique

    foreach ($PID in $PIDs) {
        try {
            $Proc = Get-Process -Id $PID -ErrorAction Stop
            $Name = $Proc.ProcessName + ".exe"

            if ($SafeProcesses -contains $Name) {
                Write-Host "[OK] Safe process detected: $Name ($PID)" -ForegroundColor Green
            } else {
                Write-Host "[X] Terminating suspicious process: $Name ($PID)" -ForegroundColor Red
                Stop-Process -Id $PID -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "[!] Failed to process PID $PID — $_" -ForegroundColor DarkYellow
        }
    }

    Write-Host "[*] LAN process cleanup complete." -ForegroundColor Cyan
}
