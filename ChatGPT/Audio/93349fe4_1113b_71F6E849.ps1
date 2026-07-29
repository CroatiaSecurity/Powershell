# Requires: VB-Audio Virtual Cable installed

$ProcessorExe = "$PSScriptRoot\AudioStressProcessor.exe"

function Set-DefaultAudioDevice {
    param([string]$Name)

    $policy = New-Object -ComObject PolicyConfigClient
    $devices = Get-CimInstance Win32_SoundDevice

    foreach ($dev in $devices) {
        if ($dev.Name -like "*$Name*") {
            $policy.SetDefaultEndpoint($dev.PNPDeviceID, 0)
            $policy.SetDefaultEndpoint($dev.PNPDeviceID, 1)
            $policy.SetDefaultEndpoint($dev.PNPDeviceID, 2)
        }
    }
}

# Mute system
Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public class Audio {
  [DllImport("user32.dll")]
  public static extern int SendMessageW(int hWnd, int hMsg, int wParam, int lParam);
}
"@

[Audio]::SendMessageW(0xffff, 0x319, 0x30292, 0) # mute

# Set virtual cable as default
Set-DefaultAudioDevice "VB-Audio"

# Start processor
Start-Process $ProcessorExe

Write-Host "Audio Stress Guard active. Press Ctrl+C to stop."

try {
    while ($true) { Start-Sleep 1 }
}
finally {
    [Audio]::SendMessageW(0xffff, 0x319, 0x30292, 1) # unmute
}
