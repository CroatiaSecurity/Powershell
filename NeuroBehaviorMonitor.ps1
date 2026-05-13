$AgentsAvBin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Bin'))
# Focus/flash/cursor/screen heuristics (GEDR NeuroBehaviorMonitor). State persisted for standalone ticks.
param([hashtable]$ModuleConfig)
. (Join-Path $AgentsAvBin '_JobLog.ps1')

$script:NBM_StatePath = "$env:ProgramData\Antivirus\State\NeuroBehaviorMonitor_state.clixml"

function Get-NBMState {
    if (-not (Test-Path (Split-Path $script:NBM_StatePath))) {
        New-Item -ItemType Directory -Path (Split-Path $script:NBM_StatePath) -Force | Out-Null
    }
    if (Test-Path $script:NBM_StatePath) {
        try { return Import-Clixml -Path $script:NBM_StatePath } catch {}
    }
    return @{
        LastRun = [DateTime]::MinValue
        TickInterval = 1
        FocusHistory = @{}
        LastBrightness = -1
        FlashScore = 0
        LastCursorPos = @{ X = 0; Y = 0 }
        CursorFirstSeen = [DateTime]::MinValue
        CursorJitterCount = 0
        LastAvgR = -1; LastAvgG = -1; LastAvgB = -1
        DistortScore = 0
        ReportedItems = @{}
    }
}

function Save-NBMState([hashtable]$S) {
    try { Export-Clixml -Path $script:NBM_StatePath -InputObject $S -Force } catch {}
}

function Test-NBMShouldReport {
    param([hashtable]$State, [string]$Key)
    if ($State.ReportedItems.ContainsKey($Key)) { return $false }
    $State.ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

function Invoke-NeuroBehaviorMonitor {
    $st = Get-NBMState
    $now = Get-Date
    if ($st.LastRun -ne [DateTime]::MinValue -and ($now - $st.LastRun).TotalSeconds -lt $st.TickInterval) { Save-NBMState $st; return }
    $st.LastRun = $now

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        if (-not ([System.Management.Automation.PSTypeName]'NeuroWin32AV').Type) {
            Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class NeuroWin32AV { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid); [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex); public const int GWL_EXSTYLE = -20; public const int WS_EX_TOPMOST = 0x00000008; }' -ErrorAction SilentlyContinue
        }
        $hWnd = [NeuroWin32AV]::GetForegroundWindow(); if ($hWnd -eq [IntPtr]::Zero) { Save-NBMState $st; return }
        $fpid = 0u; [NeuroWin32AV]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null; if ($fpid -eq 0) { Save-NBMState $st; return }
        $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue; $procName = if ($proc) { $proc.ProcessName } else { "unknown" }; if ($procName -eq "powershell" -and $fpid -eq $PID) { Save-NBMState $st; return }
        $bmp = [System.Drawing.Bitmap]::new(64,64); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen(0,0,0,0,$bmp.Size); $g.Dispose()
        $sumR=0;$sumG=0;$sumB=0;$sumBright=0;$samples=0; for ($x=0; $x -lt 64; $x+=4) { for ($y=0; $y -lt 64; $y+=4) { $c = $bmp.GetPixel($x,$y); $sumR+=$c.R; $sumG+=$c.G; $sumB+=$c.B; $sumBright+=$c.R+$c.G+$c.B; $samples++ } }; $bmp.Dispose()
        $n = if ($samples -gt 0) { $samples } else { 1 }; $avgR=$sumR/$n; $avgG=$sumG/$n; $avgB=$sumB/$n; $bright = $sumBright
        if (-not $st.FocusHistory.ContainsKey($fpid)) { $st.FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }; $fe = $st.FocusHistory[$fpid]; $fe.Count++; $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        if ($elapsed -gt 10) { $fe.Count=1; $fe.FirstSeen=[DateTime]::UtcNow }; $st.FocusHistory[$fpid]=$fe
        if ($elapsed -lt 10 -and $fe.Count -gt 8) { $key = "NBM_FocusAbuse:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Focus abuse by $procName (PID: $fpid)" "THREAT" }; $st.FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }
        if ($st.LastBrightness -ge 0) { $delta = [Math]::Abs($bright - $st.LastBrightness); if ($delta -gt 40000) { $st.FlashScore++ } else { $st.FlashScore = [Math]::Max(0, $st.FlashScore - 1) }; if ($st.FlashScore -ge 6) { $key = "NBM_Flash:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Flash stimulus detected ($procName)" "THREAT" }; $st.FlashScore = 0 } }; $st.LastBrightness = $bright
        $TopmostAllowlist = @("explorer","taskmgr","dwm","systemsettings","applicationframehost","shellexperiencehost","searchapp","startmenuexperiencehost","msedge","chrome","firefox")
        $exStyle = [NeuroWin32AV]::GetWindowLong($hWnd, [NeuroWin32AV]::GWL_EXSTYLE); if (([int]$exStyle -band [NeuroWin32AV]::WS_EX_TOPMOST) -ne 0 -and $TopmostAllowlist -notcontains $procName.ToLower()) { $key = "NBM_Topmost:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Topmost abuse by $procName (PID: $fpid)" "THREAT" } }
        try { $pos = [System.Windows.Forms.Cursor]::Position; $dx = [Math]::Abs($pos.X - $st.LastCursorPos.X); $dy = [Math]::Abs($pos.Y - $st.LastCursorPos.Y); $st.LastCursorPos = @{X=$pos.X; Y=$pos.Y}; if ($st.CursorFirstSeen -eq [DateTime]::MinValue) { $st.CursorFirstSeen = [DateTime]::UtcNow } else { $elapsed2 = ([DateTime]::UtcNow - $st.CursorFirstSeen).TotalSeconds; if ($elapsed2 -gt 10) { $st.CursorJitterCount=0; $st.CursorFirstSeen=[DateTime]::UtcNow }; if ($dx + $dy -gt 60) { $st.CursorJitterCount++ }; if ($elapsed2 -lt 10 -and $st.CursorJitterCount -gt 6) { $key = "NBM_Cursor:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Cursor jitter abuse ($procName)" "THREAT" }; $st.CursorJitterCount=0; $st.CursorFirstSeen=[DateTime]::UtcNow } } } catch { }
        if ($st.LastAvgR -ge 0) { $invR = 255 - $st.LastAvgR; $invG = 255 - $st.LastAvgG; $invB = 255 - $st.LastAvgB; $isInv = [Math]::Abs($avgR - $invR) -lt 25 -and [Math]::Abs($avgG - $invG) -lt 25 -and [Math]::Abs($avgB - $invB) -lt 25; $dR=[Math]::Abs($avgR - $st.LastAvgR); $dG=[Math]::Abs($avgG - $st.LastAvgG); $dB=[Math]::Abs($avgB - $st.LastAvgB); if ($isInv) { $key = "NBM_Color:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Color distortion/inversion ($procName)" "THREAT" } } else { $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB)); if ($maxD -gt 70) { $st.DistortScore++ } else { $st.DistortScore = [Math]::Max(0, $st.DistortScore - 1) }; if ($st.DistortScore -ge 5) { $key = "NBM_Distort:$procName"; if (Test-NBMShouldReport -State $st -Key $key) { Write-JobLog "NeuroBehaviorMonitor: Screen distortion ($procName)" "THREAT" }; $st.DistortScore = 0 } } }; $st.LastAvgR=$avgR; $st.LastAvgG=$avgG; $st.LastAvgB=$avgB
    } catch { Write-JobLog "NeuroBehaviorMonitor error: $_" "ERROR" }
    Save-NBMState $st
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-NeuroBehaviorMonitor }

