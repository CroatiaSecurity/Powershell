<#
════════════════════════════════════════════════════════════
 NeuroBehaviorMonitor.ps1
 Heuristic detection of manipulative UI behavior
 For integration into GShield-style EDR framework
════════════════════════════════════════════════════════════
#>

#region Win32 Imports

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }
}
"@

#endregion

#region Global State

$script:NBM_State = @{
    LastForeground        = $null
    FocusSwitchCount      = 0
    LastFocusSwitchTime   = Get-Date
    FlashEvents           = @()
    AudioSpikes           = @()
}

#endregion

function Write-NBMLog {
    param([string]$Message, [string]$Level = "INFO")

    $line = "[NBM][$Level] $Message"
    Write-Output $line

    # Optional: forward to your main EDR log
    # Write-Log $Message $Level
}

function Test-FocusAbuse {

    $current = [Win32]::GetForegroundWindow()

    if ($script:NBM_State.LastForeground -ne $current) {

        $now = Get-Date
        $delta = ($now - $script:NBM_State.LastFocusSwitchTime).TotalSeconds

        if ($delta -lt 2) {
            $script:NBM_State.FocusSwitchCount++
        }
        else {
            $script:NBM_State.FocusSwitchCount = 0
        }

        if ($script:NBM_State.FocusSwitchCount -ge 5) {
            Write-NBMLog "Excessive rapid focus switching detected." "WARN"
        }

        $script:NBM_State.LastFocusSwitchTime = $now
        $script:NBM_State.LastForeground = $current
    }
}

function Test-FullscreenFlash {

    $hWnd = [Win32]::GetForegroundWindow()
    if (-not $hWnd) { return }

    $rect = New-Object Win32+RECT
    [Win32]::GetWindowRect($hWnd, [ref]$rect) | Out-Null

    $width  = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top

    $screenWidth  = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
    $screenHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height

    $isFullscreen = ($width -ge ($screenWidth - 10)) -and ($height -ge ($screenHeight - 10))

    if ($isFullscreen) {

        $now = Get-Date
        $script:NBM_State.FlashEvents += $now

        # Keep only last 5 seconds
        $script:NBM_State.FlashEvents = $script:NBM_State.FlashEvents |
            Where-Object { ($_ - $now).TotalSeconds -gt -5 }

        if ($script:NBM_State.FlashEvents.Count -ge 15) {
            Write-NBMLog "Possible rapid fullscreen visual cycling (flash pattern)." "WARN"
        }
    }
}

function Test-AudioSpike {

    # Simple heuristic via event logs (System Audio events)
    $events = Get-WinEvent -LogName System -MaxEvents 5 -ErrorAction SilentlyContinue |
              Where-Object { $_.ProviderName -match "Audio" }

    foreach ($e in $events) {
        if ($e.TimeCreated -gt (Get-Date).AddSeconds(-2)) {
            Write-NBMLog "Recent audio subsystem spike detected." "INFO"
        }
    }
}

function Start-NeuroBehaviorMonitor {

    Write-NBMLog "Neuro-Behavior Monitor started."

    while ($true) {
        try {
            Test-FocusAbuse
            Test-FullscreenFlash
            Test-AudioSpike
        }
        catch {
            Write-NBMLog "Error: $($_.Exception.Message)" "ERROR"
        }

        Start-Sleep -Milliseconds 500
    }
}
