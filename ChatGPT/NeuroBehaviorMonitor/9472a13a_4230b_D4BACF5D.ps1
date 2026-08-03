<#
============================================================
  NeuroBehaviorMonitor EXTENDED
  Cognitive/Stimulus Manipulation Behavioral Sensor
============================================================
#>

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class NBMWin32 {

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern IntPtr GetDC(IntPtr hwnd);

    [DllImport("gdi32.dll")]
    public static extern int BitBlt(IntPtr hdcDest, int xDest, int yDest, int wDest, int hDest,
        IntPtr hdcSource, int xSrc, int ySrc, int rop);

    public const int SRCCOPY = 0x00CC0020;

    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }
}
"@

# region STATE
$script:NBM = @{
    LastWindow = 0
    FocusHistory = @{}
    LastBrightness = $null
    FlashScore = 0
}
# endregion

function Get-ForegroundProcess {
    $hWnd = [NBMWin32]::GetForegroundWindow()
    if ($hWnd -eq 0) { return $null }

    $pid = 0
    [NBMWin32]::GetWindowThreadProcessId($hWnd, [ref]$pid) | Out-Null

    try {
        Get-Process -Id $pid -ErrorAction Stop
    } catch { return $null }
}

function Measure-ScreenBrightness {

    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap 64,64
    $g = [System.Drawing.Graphics]::FromImage($bmp)

    $g.CopyFromScreen(0,0,0,0,$bmp.Size)

    $sum = 0
    for ($x=0;$x -lt 64;$x+=4){
        for ($y=0;$y -lt 64;$y+=4){
            $c = $bmp.GetPixel($x,$y)
            $sum += ($c.R + $c.G + $c.B)
        }
    }

    $g.Dispose()
    $bmp.Dispose()

    return $sum
}

function Test-LuminanceFlash {

    $current = Measure-ScreenBrightness

    if ($script:NBM.LastBrightness -ne $null) {

        $delta = [math]::Abs($current - $script:NBM.LastBrightness)

        if ($delta -gt 40000) {
            $script:NBM.FlashScore++
        }
        else {
            $script:NBM.FlashScore = [math]::Max(0, $script:NBM.FlashScore - 1)
        }

        if ($script:NBM.FlashScore -ge 6) {
            return $true
        }
    }

    $script:NBM.LastBrightness = $current
    return $false
}

function Test-FocusSteal($proc) {

    if (-not $proc) { return $null }

    if (-not $script:NBM.FocusHistory.ContainsKey($proc.Id)) {
        $script:NBM.FocusHistory[$proc.Id] = @{
            Count=0; FirstSeen=(Get-Date)
        }
    }

    $entry = $script:NBM.FocusHistory[$proc.Id]
    $entry.Count++

    $elapsed = ((Get-Date) - $entry.FirstSeen).TotalSeconds
    if ($elapsed -lt 10 -and $entry.Count -gt 8) {
        return $true
    }

    return $false
}

function New-NBMEvent($type,$proc){

    [pscustomobject]@{
        Time = Get-Date
        Type = $type
        Process = $proc.ProcessName
        PID = $proc.Id
        Path = $proc.Path
    }
}

function Start-NeuroBehaviorMonitor {

    param(
        [scriptblock]$OnThreat
    )

    Write-Host "[NBM] Sensor active"

    while ($true) {

        try {

            $proc = Get-ForegroundProcess
            if (-not $proc) { Start-Sleep 200; continue }

            if (Test-FocusSteal $proc) {
                $event = New-NBMEvent "FocusAbuse" $proc
                Write-Output $event
                if ($OnThreat) { & $OnThreat $event }
            }

            if (Test-LuminanceFlash) {
                $event = New-NBMEvent "FlashStimulus" $proc
                Write-Output $event
                if ($OnThreat) { & $OnThreat $event }
            }

        }
        catch {}

        Start-Sleep -Milliseconds 250
    }
}
