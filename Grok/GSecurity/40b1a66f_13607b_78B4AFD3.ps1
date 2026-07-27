# GSecurity.ps1
# Author: Gorstak

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Host "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Host "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

function Test-IPInRange {
    param (
        [string]$IP,
        [string]$CIDR
    )
    $ipAddress = [System.Net.IPAddress]::Parse($IP)
    $network = $CIDR -split '/'
    $networkAddress = [System.Net.IPAddress]::Parse($network[0])
    $subnetMask = [System.Net.IPAddress]::Parse((Convert-CIDRToSubnetMask -CIDR $network[1]))
    $ipBytes = $ipAddress.GetAddressBytes()
    $networkBytes = $networkAddress.GetAddressBytes()
    $maskBytes = $subnetMask.GetAddressBytes()
    $result = $true
    for ($i = 0; $i -lt $ipBytes.Length; $i++) {
        if (($ipBytes[$i] -band $maskBytes[$i]) -ne $networkBytes[$i]) {
            $result = $false
            break
        }
    }
    return $result
}

function Convert-CIDRToSubnetMask {
    param ([int]$CIDR)
    $binaryMask = ("1" * $CIDR + "0" * (32 - $CIDR)).ToCharArray()
    $mask = [System.Net.IPAddress]::Parse((($binaryMask -join '').Insert(8, ".").Insert(17, ".").Insert(26, ".") -replace '(.{8})', '$1.'))
    return $mask
}

function Kill-Connections {
    $SuspiciousCIDRs = @("208.95.0.0/16", "208.97.0.0/16", "65.9.0.0/16", "194.36.0.0/16",
                         "52.109.0.0/16", "2.16.0.0/16", "2.18.0.0/16", "20.82.0.0/16", 
                         "20.190.0.0/16", "135.236.0.0/16", "23.32.0.0/16", "2.22.89.0/24",
                         "23.35.0.0/16", "40.69.0.0/16", "51.124.0.0/16")
    try {
        Get-NetTCPConnection | Where-Object {
            $SuspiciousCIDRs | ForEach-Object { Test-IPInRange -IP $_.RemoteAddress -CIDR $_ } | Where-Object { $_ }
        } | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -notcontains $proc.ProcessName) {
                $remoteIP = $_.RemoteAddress
                New-NetFirewallRule -DisplayName "BlockRootkit-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                Write-Host "Blocked connection to $remoteIP for $($proc.ProcessName) (PID $($_.OwningProcess))"
            }
        }
    } catch {
        Write-Host "Error in rootkit monitoring: $_" -ForegroundColor Red
    }
}

function Kill-Rootkits {
    $Safe = @("System","svchost","lsass","services","wininit","winlogon","explorer","taskhostw","dwm","spoolsv","notepad")
    $Procs = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like '192.168.*' -or $_.RemoteAddress -like '172.16.*' -or $_.RemoteAddress -like '10.*' -or $_.RemoteAddress -like '127.*' } | ForEach-Object { $Procs[$_.OwningProcess] = $true }
    foreach ($PID in $Procs.Keys) {
        $Proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($Safe -notcontains $Proc.ProcessName) { Stop-Process -Id $PID -Force -ErrorAction SilentlyContinue; Write-Host "Killed $($Proc.ProcessName)" }
    }
}

function Start-ProcessKiller {
        $badNames = @("mimikatz", "", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Host "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Host "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object { 
        $_.MainWindowTitle -ne "" -and (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Host "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Host "Overlay process terminated: $($process.ProcessName)"
    }
}

function Start-StealthKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Host "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Host "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}

function Monitor-XSS {
    try {
        Get-NetTCPConnection -State Established | ForEach-Object {
            $remoteIP = $_.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                    Enable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                    Write-Host "XSS detected, blocked ${hostEntry.HostName}: $remoteIP and toggled network adapters." -Level Error
                }
            } catch {}
        }
    } catch {
        Write-Host "Error in XSS monitoring: $_" -Level Error
    }
}

# Command-line patterns to block
$BlockedCmdPatterns = @(
    "\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}", # GUID
    "\.dll\b", # DLL references
    "QuitInfo", # Matches /QuitInfo or QuitInfo in any part of the string
    "Processid" # Matches /Processid or Processid in any part of the string
)

$BlockedCertSubject = "Martin Tofall"

function Test-CommandLinePattern {
    param (
        [string]$CommandLine
    )
    if ([string]::IsNullOrEmpty($CommandLine)) {
        return $false
    }
    foreach ($pattern in $BlockedCmdPatterns) {
        if ($CommandLine -match $pattern) {
            return $true
        }
    }
    return $false
}

function Test-CertificateSubject {
    param (
        [string]$Path
    )
    try {
        if (-not (Test-Path $Path)) {
            return $false
        }
        $cert = Get-AuthenticodeSignature -FilePath $Path
        if ($cert -and $cert.Status -eq "Valid" -and $cert.SignerCertificate.Subject -like "*$BlockedCertSubject*") {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Start-ProcessMonitoring {
    try {
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        Register-WmiEvent -Query $query -SourceIdentifier "ProcessCreation" -Action {
            try {
                $target = $Event.SourceEventArgs.NewEvent.TargetInstance
                $name = $target.Name
                $commandLine = $target.CommandLine
                $exePath = $target.ExecutablePath
                $pid = [uint32]$target.ProcessId
                $reason = ""

                if (Test-CommandLinePattern -CommandLine $commandLine) {
                    $reason = "command-line pattern in `"$commandLine`""
                } elseif ($exePath -and (Test-CertificateSubject -Path $exePath)) {
                    $reason = "certificate contains `"$BlockedCertSubject`""
                }

                if ($reason) {
                    Write-Host "[BLOCK] $name (PID $pid) - $reason"
                    try {
                        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                        Write-Host "[KILLED] PID $pid"
                    } catch {
                        Write-Host "[KILL FAIL] PID $pid : $_"
                    }
                }
            } catch {
                Write-Host "[ERROR] Process event: $_"
            }
        } | Out-Null
        Write-Host "WMI process monitoring active."
    } catch {
        Write-Host "[ERROR] Starting process monitoring: $_"
    }
}

# Define base registry path for WOW6432Node CLSIDs
$basePath = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
$hkcrBasePath = "HKCR:\WOW6432Node\CLSID"

# Function to detect InProcServer32 and InprocHandler32 custom controls
function Detect-InProcControls {
    $allPaths = @()
    $allPaths += Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }
    $allPaths += Get-ChildItem -Path $hkcrBasePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }

    foreach ($path in $allPaths) {
        $inProcPath = Join-Path $path.PSPath "InProcServer32"
        $inProcHandlerPath = Join-Path $path.PSPath "InprocHandler32"
        $value = $null

        if (Test-Path $inProcPath) {
            $value = (Get-ItemProperty -Path $inProcPath -ErrorAction SilentlyContinue)."(default)"
        } elseif (Test-Path $inProcHandlerPath) {
            $value = (Get-ItemProperty -Path $inProcHandlerPath -ErrorAction SilentlyContinue)."(default)"
        }

        if ($value -and (Test-Path $value)) {
            Write-Host "Detected InProc control at $path.PSPath with value $value"
            return $true, $path.PSPath, $value
        }
    }
    return $false, $null, $null
}

# Function to remove InProc controls
function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            # Remove registry entry
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path"
            # Remove associated file if it exists
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $_"
        }
    }
}

# Start monitoring and keep the script running
while ($true) {
    Kill-Rootkits
    Start-ProcessKiller
    Kill-Connections
    Detect-And-Terminate-Keyloggers
    Detect-And-Terminate-Overlays
    Start-StealthKiller
    Monitor-XSS
    Start-ProcessMonitoring
    Write-Host "Process monitoring active. Press Ctrl+C to stop."
    $detected, $path, $value = Detect-InProcControls
    if ($detected) {
        Remove-InProcControls -path $path -value $value
	}
    Start-Sleep -Seconds 10
}