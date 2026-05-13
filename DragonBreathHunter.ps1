# DragonBreathHunter.ps1 - Detection and Mitigation Script for RONINGLOADER & Gh0st RAT
# Author: Grok (inspired by public IOCs and threat reports)
# Date: November 17, 2025
# Run as Administrator

# Initialize log
$LogPath = "C:\DragonBreathScan_Log.txt"
function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append
    Write-Host "$Timestamp - $Message"
}

Write-Log "=== Starting Dragon Breath Campaign Scan ==="

# Step 1: Detect Suspicious NSIS Installers (Trojanized EXEs)
Write-Log "Scanning for suspicious NSIS installers in common drop locations..."
$NSISPatterns = @("*.exe", "*.nsi")  # Look for EXEs and NSIS scripts
$DropPaths = @("$env:TEMP", "$env:APPDATA", "C:\ProgramData", "$env:USERPROFILE\Downloads")
$SuspiciousNSIS = @()
foreach ($Path in $DropPaths) {
    if (Test-Path $Path) {
        $Files = Get-ChildItem -Path $Path -Include $NSISPatterns -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 1MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) }  # Recent large files
        foreach ($File in $Files) {
            # Simple heuristic: Check if file name mimics legit software (e.g., chrome, teams) but in odd paths
            if ($File.Name -match "(chrome|teams|vpn|browser|setup)" -and $File.FullName -notmatch "Google|Microsoft") {
                $SuspiciousNSIS += $File.FullName
                Write-Log "Suspicious NSIS-like file: $($File.FullName) (Size: $($File.Length) bytes)"
            }
        }
    }
}
if ($SuspiciousNSIS.Count -gt 0) {
    Write-Log "Found $($SuspiciousNSIS.Count) potential trojanized NSIS files. Quarantining..."
    foreach ($File in $SuspiciousNSIS) {
        Move-Item -Path $File -Destination "$env:TEMP\Quarantine\$($File.Name)" -Force -ErrorAction SilentlyContinue
        Write-Log "Quarantined: $File"
    }
} else {
    Write-Log "No suspicious NSIS installers detected."
}

# Step 2: Scan Running Processes for Known Malicious Binaries (e.g., Snieoatwtregoable.exe, taskload.exe, svchost injections)
Write-Log "Scanning processes for RONINGLOADER/Gh0st indicators..."
$MaliciousProcesses = @("Snieoatwtregoable.exe", "taskload.exe", "letsvpnlatest.exe", "ollama.sys")  # From campaign IOCs
$RunningProcs = Get-Process | Where-Object { $MaliciousProcesses -contains $_.ProcessName -or $_.MainModule.FileName -like "*tp.png*" }  # Heuristic for PNG shellcode
foreach ($Proc in $RunningProcs) {
    Write-Log "Suspicious process detected: $($Proc.ProcessName) (PID: $($Proc.Id))"
    # Attempt safe termination (avoid killing system svchost)
    if ($Proc.ProcessName -notin @("svchost")) {
        Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Terminated PID $($Proc.Id)"
    }
}

# Step 3: Check for Suspicious Modules/DLLs Loaded (Gh0st RAT injection points)
Write-Log "Checking loaded modules for anomalies (e.g., rogue DLLs in svchost.exe or regsvr32.exe)..."
$SuspiciousModules = @()
$KeyProcs = Get-Process -Name "svchost", "regsvr32", "rundll32" -ErrorAction SilentlyContinue
foreach ($Proc in $KeyProcs) {
    $Modules = $Proc.Modules | Where-Object { $_.ModuleName -like "*.dll" -and $_.FileName -notlike "*Windows*" -and $_.FileName -notlike "*System32*" }
    $SuspiciousModules += $Modules | ForEach-Object { $_.FileName }
}
if ($SuspiciousModules.Count -gt 0) {
    Write-Log "Suspicious modules found: $($SuspiciousModules -join ', ')"
    # Unload if possible (advanced; requires handle.exe or similar, skipped for safety)
} else {
    Write-Log "No anomalous modules detected."
}

# Step 4: Scan Registry for Persistence (e.g., Run keys, rogue DLL injections)
Write-Log "Scanning registry for persistence mechanisms..."
$RunKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
$SuspiciousEntries = @()
foreach ($Key in $RunKeys) {
    $Entries = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
    foreach ($Prop in $Entries.PSObject.Properties) {
        if ($Prop.Value -match "(gh0st|roning|tp.png|snieo)" -or $Prop.Value -like "*\Temp\*") {
            $SuspiciousEntries += "$Key\$($Prop.Name) -> $($Prop.Value)"
        }
    }
}
if ($SuspiciousEntries.Count -gt 0) {
    Write-Log "Suspicious registry entries: $($SuspiciousEntries -join '; ')"
    # Remove (prompt first in full version)
    foreach ($Entry in $SuspiciousEntries) {
        # Example removal: Remove-ItemProperty -Path $Key -Name $Prop.Name -Force
        Write-Log "Recommend manual removal of: $Entry"
    }
} else {
    Write-Log "No suspicious registry persistence found."
}

# Step 5: Check Network Connections for C2 (Gh0st RAT beacons; hardcoded from reports - update with fresh IOCs)
Write-Log "Scanning network connections for potential C2..."
$NetConns = Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -in @(4444, 1337) }  # Common Gh0st ports
$SuspiciousConns = $NetConns | Where-Object { $_.RemoteAddress -match "known_c2_ip_pattern" }  # Placeholder; replace with real IOCs e.g., from ThreatFox
foreach ($Conn in $SuspiciousConns) {
    Write-Log "Suspicious connection: $($Conn.LocalAddress):$($Conn.LocalPort) -> $($Conn.RemoteAddress):$($Conn.RemotePort)"
    # Kill owning process
    Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue | Stop-Process -Force
}
if ($SuspiciousConns.Count -eq 0) {
    Write-Log "No suspicious network activity detected."
}

# Step 6: Check Scheduled Tasks (Common for loaders)
Write-Log "Scanning scheduled tasks for anomalies..."
$Tasks = Get-ScheduledTask | Where-Object { $_.TaskName -match "(update|vpn|chrome)" -and $_.State -eq "Ready" }
foreach ($Task in $Tasks) {
    $Action = $Task.Actions.Execute | Where-Object { $_ -like "*powershell*" -or $_ -like "*rundll32*" }
    if ($Action) {
        Write-Log "Suspicious task: $($Task.TaskName) -> $Action"
        # Disable: Disable-ScheduledTask -TaskName $Task.TaskName
    }
}

# Step 7: Mitigation - Enable ASR Rules, Run Defender Scan, Clear Temp
Write-Log "Applying mitigations..."
# Enable Attack Surface Reduction (ASR) for script/blocking (e.g., block NSIS/PowerShell abuse)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "BlockWin32ApiCallsFromOfficeMacro" -Value 1 -PropertyType DWORD -Force
Write-Log "Enabled ASR rules for Office macros and script execution."

# Quick Defender scan on temp dirs
Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
Write-Log "Initiated Windows Defender Quick Scan."

# Clear temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Cleared temporary files."

# Step 8: Event Logs for Anomalies (e.g., process creation from NSIS)
Write-Log "Checking event logs for suspicious activity (last 24h)..."
$Events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match "NSIS|powershell|gh0st" }
if ($Events) {
    Write-Log "Suspicious events found: $($Events.Count)"
    $Events | Select-Object TimeCreated, Id, Message | Format-Table -Wrap | Out-File -FilePath $LogPath -Append
} else {
    Write-Log "No anomalous events in Security log."
}

Write-Log "=== Scan Complete. Review $LogPath for details. Reboot recommended. ==="
Write-Host "Scan complete! Check $LogPath for full log."