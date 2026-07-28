# NeuroBehaviorMonitor.ps1
# Author: Gorstak (gorstak.eu)
# Description: Detects UI manipulation attacks including focus abuse, screen flash stimuli,
#              topmost window abuse, cursor jitter automation, and color distortion/inversion.
#              Uses heuristic scoring with persistent state. Runs via scheduled task at logon.
#Requires -RunAsAdministrator

param(
    [switch]$Install,
    [switch]$Uninstall
)

$Script:TaskName = "NeuroBehaviorMonitor"
$Script:InstallDir = "$env:ProgramData\NeuroBehaviorMonitor"
$Script:ScriptName = "NeuroBehaviorMonitor.ps1"

# -- Persistence ------------------------------------------------
function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "UI manipulation attack detector (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        $schOut = & schtasks.exe /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONLOGON /RL HIGHEST /F 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } else {
            Write-Host "[ERROR] schtasks failed: $schOut" -ForegroundColor Red
        }
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    try {
        $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        if ($task) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue }
    } catch {}
    & schtasks.exe /Delete /TN "$($Script:TaskName)" /F 2>$null | Out-Null
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] NeuroBehaviorMonitor uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

# -- Main Logic -------------------------------------------------
$script:StatePath = Join-Path $Script:InstallDir "state.clixml"
$script:LogFile = Join-Path $Script:InstallDir "detections.log"

function Write-Detection {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor Red
    $entry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

function Get-State {
    if (Test-Path $script:StatePath) {
        try { return Import-Clixml -Path $script:StatePath } catch {}
    }
    return @{
        LastRun = [DateTime]::MinValue
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

function Save-State([hashtable]$S) {
    try { Export-Clixml -Path $script:StatePath -InputObject $S -Force } catch {}
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
try {
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class NeuroWin32 { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid); [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex); public const int GWL_EXSTYLE = -20; public const int WS_EX_TOPMOST = 0x00000008; }' -ErrorAction SilentlyContinue
} catch {}

$TopmostAllowlist = @("explorer","taskmgr","dwm","systemsettings","applicationframehost","shellexperiencehost","searchapp","startmenuexperiencehost","msedge","chrome","firefox")

while ($true) {
    try {
        $st = Get-State
        $now = Get-Date
        $st.LastRun = $now

        $hWnd = [NeuroWin32]::GetForegroundWindow()
        if ($hWnd -eq [IntPtr]::Zero) { Save-State $st; Start-Sleep -Seconds 1; continue }
        $fpid = 0u
        [NeuroWin32]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null
        if ($fpid -eq 0) { Save-State $st; Start-Sleep -Seconds 1; continue }
        $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { "unknown" }
        if ($procName -eq "powershell" -and $fpid -eq $PID) { Save-State $st; Start-Sleep -Seconds 1; continue }

        # Screen sample
        $bmp = [System.Drawing.Bitmap]::new(64,64)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen(0,0,0,0,$bmp.Size)
        $g.Dispose()
        $sumR=0;$sumG=0;$sumB=0;$sumBright=0;$samples=0
        for ($x=0; $x -lt 64; $x+=4) { for ($y=0; $y -lt 64; $y+=4) { $c = $bmp.GetPixel($x,$y); $sumR+=$c.R; $sumG+=$c.G; $sumB+=$c.B; $sumBright+=$c.R+$c.G+$c.B; $samples++ } }
        $bmp.Dispose()
        $n = if ($samples -gt 0) { $samples } else { 1 }
        $avgR=$sumR/$n; $avgG=$sumG/$n; $avgB=$sumB/$n; $bright = $sumBright

        # Focus abuse detection
        if (-not $st.FocusHistory.ContainsKey($fpid)) { $st.FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow} }
        $fe = $st.FocusHistory[$fpid]; $fe.Count++
        $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        if ($elapsed -gt 10) { $fe.Count=1; $fe.FirstSeen=[DateTime]::UtcNow }
        $st.FocusHistory[$fpid]=$fe
        if ($elapsed -lt 10 -and $fe.Count -gt 8) {
            $key = "FocusAbuse:$procName"
            if (-not $st.ReportedItems.ContainsKey($key)) {
                Write-Detection "Focus abuse by $procName (PID: $fpid)"
                $st.ReportedItems[$key] = [DateTime]::UtcNow
            }
            $st.FocusHistory[$fpid]=@{Count=0;FirstSeen=[DateTime]::UtcNow}
        }

        # Flash stimulus detection
        if ($st.LastBrightness -ge 0) {
            $delta = [Math]::Abs($bright - $st.LastBrightness)
            if ($delta -gt 40000) { $st.FlashScore++ } else { $st.FlashScore = [Math]::Max(0, $st.FlashScore - 1) }
            if ($st.FlashScore -ge 6) {
                $key = "Flash:$procName"
                if (-not $st.ReportedItems.ContainsKey($key)) {
                    Write-Detection "Flash stimulus detected ($procName)"
                    $st.ReportedItems[$key] = [DateTime]::UtcNow
                }
                $st.FlashScore = 0
            }
        }
        $st.LastBrightness = $bright

        # Topmost abuse
        $exStyle = [NeuroWin32]::GetWindowLong($hWnd, [NeuroWin32]::GWL_EXSTYLE)
        if (([int]$exStyle -band [NeuroWin32]::WS_EX_TOPMOST) -ne 0 -and $TopmostAllowlist -notcontains $procName.ToLower()) {
            $key = "Topmost:$procName"
            if (-not $st.ReportedItems.ContainsKey($key)) {
                Write-Detection "Topmost abuse by $procName (PID: $fpid)"
                $st.ReportedItems[$key] = [DateTime]::UtcNow
            }
        }

        # Cursor jitter detection
        try {
            $pos = [System.Windows.Forms.Cursor]::Position
            $dx = [Math]::Abs($pos.X - $st.LastCursorPos.X); $dy = [Math]::Abs($pos.Y - $st.LastCursorPos.Y)
            $st.LastCursorPos = @{X=$pos.X; Y=$pos.Y}
            if ($st.CursorFirstSeen -eq [DateTime]::MinValue) { $st.CursorFirstSeen = [DateTime]::UtcNow }
            else {
                $elapsed2 = ([DateTime]::UtcNow - $st.CursorFirstSeen).TotalSeconds
                if ($elapsed2 -gt 10) { $st.CursorJitterCount=0; $st.CursorFirstSeen=[DateTime]::UtcNow }
                if ($dx + $dy -gt 60) { $st.CursorJitterCount++ }
                if ($elapsed2 -lt 10 -and $st.CursorJitterCount -gt 6) {
                    $key = "Cursor:$procName"
                    if (-not $st.ReportedItems.ContainsKey($key)) {
                        Write-Detection "Cursor jitter abuse ($procName)"
                        $st.ReportedItems[$key] = [DateTime]::UtcNow
                    }
                    $st.CursorJitterCount=0; $st.CursorFirstSeen=[DateTime]::UtcNow
                }
            }
        } catch {}

        # Color distortion/inversion
        if ($st.LastAvgR -ge 0) {
            $invR = 255 - $st.LastAvgR; $invG = 255 - $st.LastAvgG; $invB = 255 - $st.LastAvgB
            $isInv = [Math]::Abs($avgR - $invR) -lt 25 -and [Math]::Abs($avgG - $invG) -lt 25 -and [Math]::Abs($avgB - $invB) -lt 25
            if ($isInv) {
                $key = "Color:$procName"
                if (-not $st.ReportedItems.ContainsKey($key)) {
                    Write-Detection "Color distortion/inversion ($procName)"
                    $st.ReportedItems[$key] = [DateTime]::UtcNow
                }
            } else {
                $dR=[Math]::Abs($avgR - $st.LastAvgR); $dG=[Math]::Abs($avgG - $st.LastAvgG); $dB=[Math]::Abs($avgB - $st.LastAvgB)
                $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB))
                if ($maxD -gt 70) { $st.DistortScore++ } else { $st.DistortScore = [Math]::Max(0, $st.DistortScore - 1) }
                if ($st.DistortScore -ge 5) {
                    $key = "Distort:$procName"
                    if (-not $st.ReportedItems.ContainsKey($key)) {
                        Write-Detection "Screen distortion ($procName)"
                        $st.ReportedItems[$key] = [DateTime]::UtcNow
                    }
                    $st.DistortScore = 0
                }
            }
        }
        $st.LastAvgR=$avgR; $st.LastAvgG=$avgG; $st.LastAvgB=$avgB

        Save-State $st
    } catch {}
    Start-Sleep -Seconds 1
}
