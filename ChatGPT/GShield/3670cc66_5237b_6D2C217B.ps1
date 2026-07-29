# Unified background job for rootkit, session termination, and InProc detection
Start-Job -Name "GShieldMonitorLoop" -ScriptBlock {
    while ($true) {
        try {
            # Terminate LAN-based unsigned processes
            . {
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
            }

            # Terminate non-console sessions
            . {
                function Write-Log {
                    param($Message)
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    "$timestamp - $Message" | Out-File -FilePath "$env:TEMP\SessionTerminator.log" -Append
                }

                function Terminate-NonConsoleSessions {
                    try {
                        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" }
                        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

                        foreach ($session in $sessionList) {
                            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                                $sessionName = $matches[1]
                                $sessionId = $matches[3]
                                $sessionState = $matches[4]

                                if ($sessionName -notin @("console")) {
                                    rwinsta $sessionId
                                    Write-Log "Terminated session: ID=$sessionId, Name=$sessionName"
                                }
                            }
                        }
                    } catch {
                        Write-Log "Error in session termination: $_"
                    }
                }

                Terminate-NonConsoleSessions
            }

            # Detect and remove InProc controls
            . {
                function Detect-InProcControls {
                    $paths = @(
                        "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID",
                        "HKCR:\WOW6432Node\CLSID"
                    )

                    foreach ($basePath in $paths) {
                        $clsids = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue |
                            Where-Object { $_.PSChildName -match "{[0-9A-Fa-f\-]{36}}" }

                        foreach ($clsid in $clsids) {
                            $subPaths = @("InProcServer32", "InprocHandler32") | ForEach-Object {
                                Join-Path $clsid.PSPath $_
                            }

                            foreach ($subPath in $subPaths) {
                                if (Test-Path $subPath) {
                                    $value = (Get-ItemProperty -Path $subPath -ErrorAction SilentlyContinue)."(default)"
                                    if ($value -and (Test-Path $value)) {
                                        Remove-Item -Path $subPath -Force -ErrorAction SilentlyContinue
                                        Remove-Item -Path $value -Force -ErrorAction SilentlyContinue
                                    }
                                }
                            }
                        }
                    }
                }

                Detect-InProcControls
            }

            Start-Sleep -Seconds 10
        } catch {
            Write-Output "Error in monitoring loop: $_"
        }
    }
}
