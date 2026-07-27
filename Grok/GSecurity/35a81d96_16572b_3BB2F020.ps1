# GSecurity.ps1 - SAFE VERSION
# Author: Gorstak

$script:SafeProcesses = @(
    # Critical Windows System Processes
    "System", "smss", "csrss", "wininit", "services", "idle",
    "winlogon", "lsass", "dwm", "sihost", "fontdrvhost",
    "Registry", "MemCompression", "Secure System", "explorer",
    "powershell", "pwsh", "svchost", "RuntimeBroker",
    "SearchHost", "StartMenuExperienceHost", "ShellExperienceHost",
    "TextInputHost", "SecurityHealthSystray", "SecurityHealthService",
    "MsMpEng", "NisSrv", "SgrmBroker", "audiodg",
    
    # Common legitimate applications
    "chrome", "firefox", "msedge", "Code", "notepad",
    "Teams", "Slack", "Discord", "Spotify", "Steam",
    "taskmgr", "mmc", "regedit", "cmd", "conhost",
    "Taskmgr", "SystemSettings", "ApplicationFrameHost",
    "WinStore.App", "Video.UI", "Calculator", "notepad++",
    "mstsc", "SnippingTool", "ScreenSketch", "OneDrive"
)

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            if ($script:SafeProcesses -contains $proc.Name) {
                Write-Host "Skipping safe process: $($proc.Name)" -ForegroundColor Green
                return
            }
            
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Host "Killed process PID $Pid ($($proc.Name))" -ForegroundColor Yellow
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Host "Restarted Explorer after killing parent of suspicious process." -ForegroundColor Yellow
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" -ForegroundColor Yellow
                    }
                }
            }
        }
    } catch {}
}

function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            if ($script:SafeProcesses -contains $process.ProcessName) {
                Write-Host "Skipping safe process: $($process.ProcessName) (matched keylogger pattern but is whitelisted)" -ForegroundColor Green
                continue
            }
            
            Write-Host "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Red
            Kill-Process-And-Parent -Id $process.Id -Force
            Write-Host "Keylogger process terminated: $($process.ProcessName)" -ForegroundColor Yellow
        }
    }
}

function Detect-And-Terminate-Overlays {
    Write-Host "Checking for suspicious overlays..." -ForegroundColor Cyan
    
    $overlayProcesses = Get-Process | Where-Object { 
        $isSafe = $script:SafeProcesses -contains $_.ProcessName
        
        # Skip safe processes immediately
        if ($isSafe) { return $false }
        
        $hasWindow = $_.MainWindowHandle -ne 0
        $isUnnamed = ($_.MainWindowTitle -eq "" -or $_.MainWindowTitle -eq $null)
        
        # Only flag if: has a window AND is unnamed AND is not safe
        $hasWindow -and $isUnnamed
    }
    
    if ($overlayProcesses) {
        foreach ($process in $overlayProcesses) {
            Write-Host "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id), Unnamed Window)" -ForegroundColor Yellow
            Kill-Process-And-Parent -Id $process.Id -Force -ErrorAction SilentlyContinue
            Write-Host "Overlay process terminated: $($process.ProcessName)" -ForegroundColor Red
        }
    }
}

function Start-StealthKiller {
    Write-Host "Running stealth detection..." -ForegroundColor Cyan
    
    # Kill unsigned or hidden-attribute processes
    Get-CimInstance Win32_Process | ForEach-Object {
        $exePath = $_.ExecutablePath
        if ($exePath -and (Test-Path $exePath)) {
            $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
            if ($proc -and -not ($script:SafeProcesses -contains $proc.ProcessName)) {
                $isHidden = (Get-Item $exePath -ErrorAction SilentlyContinue).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                
                if ($isHidden) {
                    Write-Host "Killing hidden-attribute process: $exePath (PID: $($_.ProcessId))" -ForegroundColor Red
                    Kill-Process-And-Parent -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                }
                elseif ($sigStatus -ne 'Valid' -and $exePath -notlike "*\Windows\*") {
                    Write-Host "WARNING: Unsigned process: $exePath" -ForegroundColor Yellow
                }
            }
        }
    }

    # Kill stealthy processes (present in WMI but not in tasklist)
    try {
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
            if ($proc -and -not ($script:SafeProcesses -contains $proc.ProcessName)) {
                Kill-Process-And-Parent -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                Write-Host "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Error in stealthy process detection: $_" -ForegroundColor Red
    }
}

function Start-ProcessKiller {
    $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
    foreach ($name in $badNames) {
        Get-Process -Name "*$name*" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Found malicious process: $($_.ProcessName) (PID $($_.Id))" -ForegroundColor Red
            Kill-Process-And-Parent -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Kill-Connections {
    $SuspiciousCIDRs = @("208.95.0.0/16", "208.97.0.0/16", "65.9.0.0/16", "194.36.0.0/16",  
                         "52.109.0.0/16", "2.16.0.0/16", "2.18.0.0/16", "20.82.0.0/16", 
                         "20.190.0.0/16", "135.236.0.0/16", "23.32.0.0/16", "2.22.89.0/24", 
                         "23.35.0.0/16", "40.69.0.0/16", "51.124.0.0/16")
    
    $SuspiciousIPv6CIDRs = @(
        "2001:4860::/32",
        "2606:4700::/32"
    )
    
    try {
        Get-NetTCPConnection | Where-Object {
            $connection = $_
            $isSuspicious = $false
            
            if ($connection.RemoteAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                # IPv4 check
                foreach ($cidr in $SuspiciousCIDRs) {
                    if (Test-IPInRange -IP $connection.RemoteAddress -CIDR $cidr) {
                        $isSuspicious = $true
                        break
                    }
                }
            }
            elseif ($connection.RemoteAddress -match ':') {
                # IPv6 check
                foreach ($cidr in $SuspiciousIPv6CIDRs) {
                    if (Test-IPv6InRange -IP $connection.RemoteAddress -CIDR $cidr) {
                        $isSuspicious = $true
                        break
                    }
                }
            }
            
            $isSuspicious
        } | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and -not ($script:SafeProcesses -contains $proc.ProcessName)) {
                $remoteIP = $_.RemoteAddress
                New-NetFirewallRule -DisplayName "BlockRootkit-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                Write-Host "Blocked connection to $remoteIP for $($proc.ProcessName) (PID $($_.OwningProcess))" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Error in rootkit monitoring: $_" -ForegroundColor Red
    }
}

function Kill-Rootkits {
    Write-Host "[DEBUG] Scanning for local network connections..." -ForegroundColor Cyan
    
    # Initialize hashtable BEFORE use
    $Procs = @{}
    
    # Get all connections to/from local LAN addresses
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { 
        $_.LocalAddress -like '127.*' -or
        $_.LocalAddress -like '192.168.*' -or
        $_.LocalAddress -like '172.16.*' -or
        $_.LocalAddress -like '172.17.*' -or
        $_.LocalAddress -like '172.18.*' -or
        $_.LocalAddress -like '172.19.*' -or
        $_.LocalAddress -like '172.2*' -or
        $_.LocalAddress -like '172.30.*' -or
        $_.LocalAddress -like '172.31.*' -or
        $_.LocalAddress -like '10.*'
    } | ForEach-Object { 
        $Procs[$_.OwningProcess] = $true 
    }
    
    Write-Host "[DEBUG] Found $($Procs.Count) processes with local connections" -ForegroundColor Cyan
    
    # Kill each process (unless it's in the SafeProcesses whitelist)
    foreach ($ProcessID in $Procs.Keys) {
        $Proc = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue
        if ($Proc) {
            Write-Host "[DEBUG] Checking: $($Proc.ProcessName) (PID $ProcessID)" -ForegroundColor Gray
            
            if ($script:SafeProcesses -contains $Proc.ProcessName) {
                Write-Host "[DEBUG] Skipping safe process: $($Proc.ProcessName)" -ForegroundColor Green
            } else {
                Write-Host "Killing suspicious local connection process: $($Proc.ProcessName) (PID $ProcessID)" -ForegroundColor Red
                Kill-Process-And-Parent -Id $ProcessID -Force -ErrorAction SilentlyContinue
            }
        }
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
                    Write-Host "XSS detected, blocked $($hostEntry.HostName): $remoteIP and toggled network adapters." -ForegroundColor Red
                }
            } catch {}
        }
    } catch {
        Write-Host "Error in XSS monitoring: $_" -ForegroundColor Red
    }
}

function Remove-HiddenProcesses {
    Get-Process | Where-Object { 
        $_.Path -and (Test-Path $_.Path) 
    } | ForEach-Object {
        if (-not ($script:SafeProcesses -contains $_.ProcessName)) {
            $isHidden = (Get-Item $_.Path -ErrorAction SilentlyContinue).Attributes -match "Hidden"
            if ($isHidden) {
                Write-Host "Removing hidden process: $($_.ProcessName) at $($_.Path)" -ForegroundColor Red
                Kill-Process-And-Parent -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path" -ForegroundColor Yellow
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Error removing $path : $_" -ForegroundColor Red
        }
    }
}

function Test-IPInRange {
    param (
        [string]$IP,
        [string]$CIDR
    )
    try {
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
    } catch {
        return $false
    }
}

function Test-IPv6InRange {
    param (
        [string]$IP,
        [string]$CIDR
    )
    try {
        $ipAddress = [System.Net.IPAddress]::Parse($IP)
        $network = $CIDR -split '/'
        $networkAddress = [System.Net.IPAddress]::Parse($network[0])
        $prefixLength = [int]$network[1]
        
        $ipBytes = $ipAddress.GetAddressBytes()
        $networkBytes = $networkAddress.GetAddressBytes()
        
        $fullBytes = [Math]::Floor($prefixLength / 8)
        $remainingBits = $prefixLength % 8
        
        for ($i = 0; $i -lt $fullBytes; $i++) {
            if ($ipBytes[$i] -ne $networkBytes[$i]) {
                return $false
            }
        }
        
        if ($remainingBits -gt 0) {
            $mask = [byte](0xFF -shl (8 - $remainingBits))
            if (($ipBytes[$fullBytes] -band $mask) -ne ($networkBytes[$fullBytes] -band $mask)) {
                return $false
            }
        }
        
        return $true
    } catch {
        return $false
    }
}

function Convert-CIDRToSubnetMask {
    param ([int]$CIDR)
    $binaryMask = ("1" * $CIDR + "0" * (32 - $CIDR)).ToCharArray()
    $mask = [System.Net.IPAddress]::Parse((($binaryMask -join '').Insert(8, ".").Insert(17, ".").Insert(26, ".") -replace '(.{8})', '$1.'))
    return $mask
}

function Detect-InProcControls {
    return $false, "", ""
}

function Stop-MaliciousProcess {
    param($Pid, $Reason)
    # Placeholder
}

# Main loop
Write-Host "GSecurity started. Monitoring for threats..." -ForegroundColor Green
while ($true) {
    Start-ProcessKiller
    Kill-Connections
    Detect-And-Terminate-Keyloggers
    Detect-And-Terminate-Overlays
    Start-StealthKiller
    Monitor-XSS
    Remove-HiddenProcesses
    Kill-Rootkits
    
    $detected, $path, $value = Detect-InProcControls
    if ($detected) {
        Write-Host "InProc control detected at $path with value $value" -ForegroundColor Yellow
        Remove-InProcControls -path $path -value $value
    }

    Get-Process | Where-Object { $_.Path -like "*\Temp\*" -and $_.Path } | ForEach-Object {
        if (-not ($script:SafeProcesses -contains $_.ProcessName)) {
            if ((Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue).Status -ne 'Valid') {
                Write-Host "Killing unsigned process in Temp: $($_.ProcessName) at $($_.Path)" -ForegroundColor Red
                Kill-Process-And-Parent -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Start-Sleep -Seconds 10
}
