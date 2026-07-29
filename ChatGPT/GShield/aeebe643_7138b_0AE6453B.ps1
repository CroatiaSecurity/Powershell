Start-Job -Name "GShieldMonitorLoop" -ScriptBlock {
    while ($true) {
        try {
            # ========== Terminate LAN-based unsigned processes ==========
            function Write-RootkitLog {
                param (
                    [string]$Message,
                    [string]$EntryType = "Information"
                )
                try {
                    if (-not [System.Diagnostics.EventLog]::SourceExists("GShield")) {
                        New-EventLog -LogName Application -Source "GShield"
                    }
                    Write-EventLog -LogName Application -Source "GShield" -EntryType $EntryType -EventId 1000 -Message $Message
                } catch {
                    Write-Output "$EntryType`: $Message"
                }
            }

            function Terminate-Rootkits {
                try {
                    $connections = Get-NetTCPConnection | Where-Object {
                        $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
                    }
                    $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

                    foreach ($pid in $lanProcIds) {
                        try {
                            $proc = Get-Process -Id $pid -ErrorAction Stop
                            $exePath = $proc.Path
                            if ($exePath) {
                                $signature = Get-AuthenticodeSignature -FilePath $exePath
                                if ($signature.Status -ne 'Valid') {
                                    Write-RootkitLog "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                                    Stop-Process -Id $pid -Force
                                }
                            }
                        } catch {}
                    }
                } catch {}
            }

            Terminate-Rootkits

            # ========== Terminate Non-Console Sessions ==========
            function Terminate-NonConsoleSessions {
                try {
                    $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" }
                    $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

                    foreach ($session in $sessionList) {
                        if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                            $sessionName = $matches[1]
                            $sessionId = $matches[3]
                            if ($sessionName -notin @("console")) {
                                rwinsta $sessionId
                            }
                        }
                    }
                } catch {}
            }

            Terminate-NonConsoleSessions

            # ========== InProc Control Detection ==========
            function Detect-InProcControls {
                $paths = @(
                    "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID",
                    "HKCR:\WOW6432Node\CLSID"
                )
                foreach ($basePath in $paths) {
                    $clsids = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match "{[0-9A-Fa-f\-]{36}}" }

                    foreach ($clsid in $clsids) {
                        foreach ($subkey in @("InProcServer32", "InprocHandler32")) {
                            $regPath = Join-Path $clsid.PSPath $subkey
                            if (Test-Path $regPath) {
                                $value = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue)."(default)"
                                if ($value -and (Test-Path $value)) {
                                    Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                                    Remove-Item -Path $value -Force -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                }
            }

            Detect-InProcControls

            # ========== Unsigned DLL Scan ==========
            $quarantine = "C:\Quarantine"
            $localDB = "$quarantine\scanned_files.txt"
            $scannedFiles = @{}

            if (Test-Path $localDB) {
                Get-Content $localDB | ForEach-Object {
                    if ($_ -match "^([0-9a-f]{64}),(true|false)$") {
                        $scannedFiles[$matches[1]] = [bool]$matches[2]
                    }
                }
            }

            function Set-FileOwnershipAndPermissions ($filePath) {
                try {
                    takeown /F $filePath /A | Out-Null
                    icacls $filePath /reset | Out-Null
                    icacls $filePath /grant "Administrators:F" /inheritance:d | Out-Null
                    return $true
                } catch {
                    return $false
                }
            }

            function Stop-ProcessUsingDLL ($filePath) {
                try {
                    $procs = Get-Process | Where-Object {
                        $_.Modules | Where-Object { $_.FileName -eq $filePath }
                    }
                    foreach ($proc in $procs) {
                        Stop-Process -Id $proc.Id -Force
                    }
                } catch {
                    taskkill /F /IM $proc.Name /T | Out-Null
                }
            }

            function Quarantine-File ($filePath) {
                $target = Join-Path $quarantine (Split-Path $filePath -Leaf)
                Move-Item $filePath $target -Force -ErrorAction SilentlyContinue
            }

            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne "C" -or $_.Root -ne "C:\Windows\Assembly\" }

            foreach ($drive in $drives) {
                $dlls = Get-ChildItem "$($drive.Root)" -Recurse -Filter *.dll -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.FullName -notlike "C:\Windows\Assembly\*" }

                foreach ($dll in $dlls) {
                    try {
                        $hash = (Get-FileHash -Path $dll.FullName -Algorithm SHA256).Hash.ToLower()
                        $sig = Get-AuthenticodeSignature -FilePath $dll.FullName

                        if (-not $scannedFiles.ContainsKey($hash)) {
                            $isValid = $sig.Status -eq 'Valid'
                            $scannedFiles[$hash] = $isValid
                            "$hash,$isValid" | Out-File $localDB -Append -Encoding UTF8

                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions $dll.FullName) {
                                    Stop-ProcessUsingDLL $dll.FullName
                                    Quarantine-File $dll.FullName
                                }
                            }
                        }
                    } catch {}
                }
            }

            Start-Sleep -Seconds 15
        } catch {
            Write-Output "Monitor loop error: $_"
        }
    }
}
