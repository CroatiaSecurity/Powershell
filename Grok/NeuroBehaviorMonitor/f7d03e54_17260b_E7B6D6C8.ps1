# NeuroBehaviorMonitor.ps1 - Neuro-behavioral threat detection & response (standalone)
# Active protection: detects and RESPONDS to focus abuse, flash stimulus, topmost abuse,
# cursor jitter, and color distortion. Takes action to neutralize threats.
# Runs continuously - press Ctrl+C to stop.

#Requires -Version 5.1

param(
    [ValidateSet("Full", "Moderate", "AlertOnly")]
    [string]$ResponseLevel = "Full",
    [int]$TickIntervalSeconds = 1,
    [switch]$DebugMode = $false
)

$ModuleName = "NeuroBehaviorMonitor"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = $TickIntervalSeconds
$script:SelfPid = $PID
$script:ResponseLevel = $ResponseLevel
$script:DebugEnabled = $DebugMode

$script:TopmostAllowlist = @(
    "explorer",
    "taskmgr",
    "dwm",
    "systemsettings",
    "applicationframehost",
    "shellexperiencehost",
    "searchapp",
    "startmenuexperiencehost",
    "msedge",
    "chrome",
    "firefox",
    "powershell",
    "windowsterminal",
    "code"
)

# Helper function for deduplication
function Test-ShouldReport {
    param([string]$Key)
    
    if ($null -eq $script:ReportedItems) {
        $script:ReportedItems = @{}
    }
    
    if ($script:ReportedItems.ContainsKey($Key)) {
        return $false
    }
    
    $script:ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

# Helper function for logging
function Write-Detection {
    param(
        [string]$Message,
        [string]$Level = "THREAT",
        [string]$LogFile = "neurobehaviormonitor_detections.log"
    )
    
    # Skip debug messages if debug mode is disabled
    if ($Level -eq "DEBUG" -and -not $script:DebugEnabled) { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$ModuleName] $Message"
    
    # Write to console
    switch ($Level) {
        "THREAT" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor Cyan }
        "DEBUG" { Write-Host $logEntry -ForegroundColor Gray }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        default { Write-Host $logEntry }
    }
    
    # Write to log file
    $logPath = Join-Path $env:LOCALAPPDATA "NeuroBehaviorMonitor\Logs"
    if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
    Add-Content -Path (Join-Path $logPath $LogFile) -Value $logEntry -ErrorAction SilentlyContinue
}

# Helper function for threat response - multiple response types
function Invoke-ThreatResponse {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason,
        [ValidateSet("Kill", "Minimize", "RemoveTopmost", "RestoreFocus", "All")]
        [string]$Action = "All",
        [IntPtr]$WindowHandle = [IntPtr]::Zero
    )
    
    if ($script:ResponseLevel -eq "AlertOnly") {
        Write-Detection "ALERT ONLY: $ProcessName (PID: $ProcessId) - $Reason" -Level "WARNING"
        return
    }
    
    Write-Detection "RESPONSE: $ProcessName (PID: $ProcessId) - $Reason - Action: $Action" -Level "THREAT"
    
    $criticalProcesses = @("System", "smss", "csrss", "wininit", "services", "lsass", "svchost", "dwm", "explorer", "winlogon")
    $isCritical = $criticalProcesses -contains $ProcessName
    
    try {
        switch ($Action) {
            "RemoveTopmost" {
                if ($WindowHandle -ne [IntPtr]::Zero) {
                    [NeuroWin32]::SetWindowPos($WindowHandle, [NeuroWin32]::HWND_NOTOPMOST, 0, 0, 0, 0, 0x0003) | Out-Null
                    Write-Detection "ACTION: Removed topmost flag from $ProcessName" -Level "INFO"
                }
            }
            "Minimize" {
                if ($WindowHandle -ne [IntPtr]::Zero) {
                    [NeuroWin32]::ShowWindow($WindowHandle, 6) | Out-Null
                    Write-Detection "ACTION: Minimized window of $ProcessName" -Level "INFO"
                }
            }
            "RestoreFocus" {
                $shell = New-Object -ComObject WScript.Shell
                $shell.AppActivate("explorer") | Out-Null
                Write-Detection "ACTION: Restored focus to desktop" -Level "INFO"
            }
            "Kill" {
                if ($isCritical) {
                    Write-Detection "BLOCKED: Cannot kill critical process $ProcessName" -Level "WARNING"
                    return
                }
                if ($script:ResponseLevel -eq "Moderate") {
                    Write-Detection "MODERATE MODE: Would kill $ProcessName but limited to non-lethal response" -Level "WARNING"
                    if ($WindowHandle -ne [IntPtr]::Zero) {
                        [NeuroWin32]::ShowWindow($WindowHandle, 6) | Out-Null
                    }
                    return
                }
                Stop-Process -Id $ProcessId -Force -ErrorAction Stop
                Write-Detection "ACTION: Terminated process $ProcessName (PID: $ProcessId)" -Level "INFO"
            }
            "All" {
                if ($WindowHandle -ne [IntPtr]::Zero) {
                    [NeuroWin32]::SetWindowPos($WindowHandle, [NeuroWin32]::HWND_NOTOPMOST, 0, 0, 0, 0, 0x0003) | Out-Null
                    [NeuroWin32]::ShowWindow($WindowHandle, 6) | Out-Null
                }
                if (-not $isCritical -and $script:ResponseLevel -eq "Full") {
                    Start-Sleep -Milliseconds 500
                    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
                    Write-Detection "ACTION: Full response - minimized and terminated $ProcessName" -Level "INFO"
                } else {
                    Write-Detection "ACTION: Minimized and removed topmost from $ProcessName" -Level "INFO"
                }
            }
        }
    }
    catch {
        Write-Detection "Response failed for $ProcessName : $($_.Exception.Message)" -Level "WARNING"
    }
}

function Start-Detection {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NeuroWin32 {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern IntPtr SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TOPMOST = 0x00000008;
    public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
}
"@ -ErrorAction SilentlyContinue

    if (-not ($script:FocusHistory)) { $script:FocusHistory = @{} }
    if (-not ($script:LastBrightness)) { $script:LastBrightness = -1 }
    if (-not ($script:FlashScore)) { $script:FlashScore = 0 }
    if (-not ($script:LastCursorPos)) { $script:LastCursorPos = @{X=0;Y=0} }
    if (-not ($script:CursorFirstSeen)) { $script:CursorFirstSeen = [DateTime]::MinValue }
    if (-not ($script:CursorJitterCount)) { $script:CursorJitterCount = 0 }
    if (-not ($script:LastAvgR)) { $script:LastAvgR = -1 }
    if (-not ($script:DistortScore)) { $script:DistortScore = 0 }

    $topmostAllowlist = @("explorer","taskmgr","dwm","systemsettings","applicationframehost","shellexperiencehost","searchapp","startmenuexperiencehost","msedge","chrome","firefox")

    try {
        $hWnd = [NeuroWin32]::GetForegroundWindow()
        if ($hWnd -eq [IntPtr]::Zero) { return }
        $fpid = 0
        [NeuroWin32]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null
        if ($fpid -eq 0) { return }

        $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { "unknown" }
        if ($procName -eq "powershell" -and $fpid -eq $script:SelfPid) { return }

        # Screen metrics (64x64 sample)
        $bmp = [System.Drawing.Bitmap]::new(64,64)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen(0,0,0,0,$bmp.Size)
        $g.Dispose()
        $sumR=0;$sumG=0;$sumB=0;$sumBright=0;$samples=0
        for ($x=0; $x -lt 64; $x+=4) {
            for ($y=0; $y -lt 64; $y+=4) {
                $c = $bmp.GetPixel($x,$y)
                $sumR+=$c.R; $sumG+=$c.G; $sumB+=$c.B
                $sumBright+=$c.R+$c.G+$c.B
                $samples++
            }
        }
        $bmp.Dispose()
        $n = if ($samples -gt 0) { $samples } else { 1 }
        $avgR=$sumR/$n; $avgG=$sumG/$n; $avgB=$sumB/$n
        $bright = $sumBright

        # Focus steal - RESPOND by minimizing and optionally killing
        if (-not $script:FocusHistory.ContainsKey($fpid)) { $script:FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }
        $fe = $script:FocusHistory[$fpid]
        $fe.Count++; $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        if ($elapsed -gt 10) { $fe.Count=1; $fe.FirstSeen=[DateTime]::UtcNow }
        $script:FocusHistory[$fpid]=$fe
        if ($elapsed -lt 10 -and $fe.Count -gt 8) {
            $key = "NBM_FocusAbuse:$procName_$fpid"
            if (Test-ShouldReport -Key $key) {
                Write-Detection "Focus abuse: $procName (PID: $fpid) stole focus >8 times in 10s"
                Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "FocusAbuse" -Action "All" -WindowHandle $hWnd
            }
            $script:FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow}
        }

        # Flash stimulus - RESPOND by minimizing (potential seizure/harm trigger)
        if ($script:LastBrightness -ge 0) {
            $delta = [Math]::Abs($bright - $script:LastBrightness)
            if ($delta -gt 40000) { $script:FlashScore++ } else { $script:FlashScore = [Math]::Max(0, $script:FlashScore - 1) }
            if ($script:FlashScore -ge 6) {
                $key = "NBM_Flash:$procName_$([DateTime]::UtcNow.ToString('HHmmss'))"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "Flash stimulus: rapid brightness changes while $procName in foreground" -Level "THREAT"
                    Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "FlashStimulus (seizure risk)" -Action "Minimize" -WindowHandle $hWnd
                }
                $script:FlashScore = 0
            }
        }
        $script:LastBrightness = $bright

        # Topmost abuse - RESPOND by removing topmost flag
        $exStyle = [NeuroWin32]::GetWindowLong($hWnd, [NeuroWin32]::GWL_EXSTYLE)
        if (([int]$exStyle -band [NeuroWin32]::WS_EX_TOPMOST) -ne 0 -and $topmostAllowlist -notcontains $procName.ToLower()) {
            $key = "NBM_Topmost:$procName_$fpid"
            if (Test-ShouldReport -Key $key) {
                Write-Detection "Topmost abuse: $procName (PID: $fpid) forced always-on-top"
                Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "TopmostAbuse" -Action "RemoveTopmost" -WindowHandle $hWnd
            }
        }

        # Cursor jitter - RESPOND by minimizing (potential clickjacking/annoyance)
        try {
            $pos = [System.Windows.Forms.Cursor]::Position
            $dx = [Math]::Abs($pos.X - $script:LastCursorPos.X)
            $dy = [Math]::Abs($pos.Y - $script:LastCursorPos.Y)
            $script:LastCursorPos = @{X=$pos.X; Y=$pos.Y}
            if ($script:CursorFirstSeen -eq [DateTime]::MinValue) { $script:CursorFirstSeen = [DateTime]::UtcNow } else {
                $elapsed2 = ([DateTime]::UtcNow - $script:CursorFirstSeen).TotalSeconds
                if ($elapsed2 -gt 10) { $script:CursorJitterCount=0; $script:CursorFirstSeen=[DateTime]::UtcNow }
                if ($dx + $dy -gt 60) { $script:CursorJitterCount++ }
                if ($elapsed2 -lt 10 -and $script:CursorJitterCount -gt 6) {
                    $key = "NBM_Cursor:$procName_$fpid"
                    if (Test-ShouldReport -Key $key) {
                        Write-Detection "Cursor jitter abuse detected while $procName in foreground"
                        Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "CursorJitter" -Action "Minimize" -WindowHandle $hWnd
                    }
                    $script:CursorJitterCount=0; $script:CursorFirstSeen=[DateTime]::UtcNow
                }
            }
        } catch { }

        # Color distortion - RESPOND by minimizing (visual attack)
        if ($script:LastAvgR -ge 0) {
            $invR = 255 - $script:LastAvgR; $invG = 255 - $script:LastAvgG; $invB = 255 - $script:LastAvgB
            $isInv = [Math]::Abs($avgR - $invR) -lt 25 -and [Math]::Abs($avgG - $invG) -lt 25 -and [Math]::Abs($avgB - $invB) -lt 25
            $dR=[Math]::Abs($avgR - $script:LastAvgR); $dG=[Math]::Abs($avgG - $script:LastAvgG); $dB=[Math]::Abs($avgB - $script:LastAvgB)
            if ($isInv) {
                $key = "NBM_Color:$procName_$([DateTime]::UtcNow.ToString('HHmmss'))"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "Color distortion/inversion detected while $procName in foreground"
                    Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "ColorInversion" -Action "Minimize" -WindowHandle $hWnd
                }
            } else {
                $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB))
                if ($maxD -gt 70) { $script:DistortScore++ } else { $script:DistortScore = [Math]::Max(0, $script:DistortScore - 1) }
                if ($script:DistortScore -ge 5) {
                    $key = "NBM_Distort:$procName_$([DateTime]::UtcNow.ToString('HHmmss'))"
                    if (Test-ShouldReport -Key $key) {
                        Write-Detection "Screen color distortion detected while $procName in foreground"
                        Invoke-ThreatResponse -ProcessId $fpid -ProcessName $procName -Reason "ColorDistortion" -Action "Minimize" -WindowHandle $hWnd
                    }
                    $script:DistortScore = 0
                }
            }
        }
        $script:LastAvgR=$avgR; $script:LastAvgG=$avgG; $script:LastAvgB=$avgB
    }
    catch {
        Write-Detection "Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main tick function
function Invoke-NeuroBehaviorMonitor {
    $now = Get-Date
    if ($script:LastRun -ne [DateTime]::MinValue -and ($now - $script:LastRun).TotalSeconds -lt $script:TickInterval) {
        return
    }
    $script:LastRun = $now
    
    try {
        Start-Detection
    }
    catch {
        Write-Detection "Error in $ModuleName : $($_.Exception.Message)" -Level "ERROR"
    }
}

# ===================== Main Loop =====================

function Start-NeuroBehaviorMonitoring {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "     NeuroBehaviorMonitor - Active Threat Response System   " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Response Level: $($script:ResponseLevel)" -ForegroundColor $(switch($script:ResponseLevel){"Full"{"Green"}"Moderate"{"Yellow"}"AlertOnly"{"Gray"}})
    Write-Host "Tick Interval: $($script:TickInterval)s" -ForegroundColor Gray
    Write-Host "Debug Mode: $($script:DebugEnabled)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Threat Detection & Response:" -ForegroundColor Cyan
    Write-Host "  - Focus abuse    -> Minimize + Kill (Full) / Minimize (Moderate)" -ForegroundColor White
    Write-Host "  - Flash stimulus -> Minimize window (seizure protection)" -ForegroundColor White
    Write-Host "  - Topmost abuse  -> Remove topmost flag" -ForegroundColor White
    Write-Host "  - Cursor jitter  -> Minimize window" -ForegroundColor White
    Write-Host "  - Color distort  -> Minimize window" -ForegroundColor White
    Write-Host ""
    Write-Host "Response Levels:" -ForegroundColor Cyan
    Write-Host "  Full     = Minimize + Remove flags + Kill process" -ForegroundColor Green
    Write-Host "  Moderate = Minimize + Remove flags (no kills)" -ForegroundColor Yellow
    Write-Host "  AlertOnly= Log only, no action taken" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press Ctrl+C to stop monitoring." -ForegroundColor Yellow
    Write-Host ""
    
    while ($true) {
        try {
            Invoke-NeuroBehaviorMonitor
        }
        catch {
            Write-Detection "Unhandled error: $($_.Exception.Message)" -Level "ERROR"
        }
        Start-Sleep -Seconds $script:TickInterval
    }
}

# Execute main loop
Start-NeuroBehaviorMonitoring
