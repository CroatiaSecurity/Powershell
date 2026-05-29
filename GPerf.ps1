#Requires -RunAsAdministrator
$Host.UI.RawUI.WindowTitle = "Performance Tweak Utility"

# --- Helper Function for Registry Keys ---
function Set-RegKey {
    param (
        [string]$path,
        [string]$name,
        [string]$value,
        [string]$type = "DWord"
    )
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    if ($type -eq "DWord") {
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force -ErrorAction SilentlyContinue
    }
}

# --- BCD Tweaks (Boot Optimization) ---
bcdedit /set disabledynamictick yes | Out-Null
bcdedit /set quietboot yes | Out-Null

# --- CPU Optimizations ---
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
powercfg -setactive scheme_current | Out-Null
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name "DistributeTimers" -value 1
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -name "Win32PrioritySeparation" -value 26

# --- Memory Management ---
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name "DisablePagingExecutive" -value 1
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name "IoPageLockLimit" -value 0x400000

# --- Network Optimizations ---
netsh.exe interface tcp set supplemental Internet congestionprovider=ctcp | Out-Null
netsh.exe interface tcp set global fastopen=enabled | Out-Null
netsh.exe interface tcp set global rss=enabled | Out-Null
Set-NetTCPSetting -SettingName * -InitialCongestionWindow 10 -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue
Disable-NetAdapterPowerManagement -Name * -ErrorAction SilentlyContinue
Disable-NetAdapterLso -Name * -ErrorAction SilentlyContinue
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Tcp1323Opts" -value 1
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "MaxUserPort" -value 65534
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "TcpTimedWaitDelay" -value 30

# Disable Nagle's Algorithm
$tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$tcpInterfaces = Get-ChildItem -Path $tcpipPath -ErrorAction SilentlyContinue
foreach ($tcpInterface in $tcpInterfaces) {
    Set-RegKey -path $tcpInterface.PSPath -name "TCPNoDelay" -value 1
    Set-RegKey -path $tcpInterface.PSPath -name "TcpAckFrequency" -value 1
}

# AFD Buffer Sizes
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -name "DefaultReceiveWindow" -value 33178
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -name "DefaultSendWindow" -value 33178

# --- Power Plan ---
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# --- Explorer Enhancements ---
Set-RegKey -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "FolderContentsInfoTip" -value 1
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "HideFileExt" -value 0
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "ShowSecondsInSystemClock" -value 1

# --- Visual Settings ---
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "DragFullWindows" -value "1" -type "String"
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "FontSmoothing" -value "2" -type "String"
Set-RegKey -path "HKCU:\Control Panel\Desktop" -name "FontSmoothingType" -value 2

# --- Graphics Optimization ---
Set-RegKey -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -name "SystemResponsiveness" -value 0
Set-RegKey -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -name "VisualFXSetting" -value 3

# --- Service Optimizations ---
$services = @("Spooler", "WSearch")
foreach ($service in $services) {
    if ((Get-Service -Name $service -ErrorAction SilentlyContinue).StartType -ne "Disabled") {
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }
}

# --- Add SvcHostSplitDisable to all services ---
$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$allServices = Get-ChildItem -Path $servicesPath -ErrorAction SilentlyContinue
foreach ($service in $allServices) {
    Set-RegKey -path $service.PSPath -name "SvcHostSplitDisable" -value 1
}

# --- Enable DirectPlay ---
Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -NoRestart -ErrorAction SilentlyContinue

# --- Remove Bloat Features ---
$bloatFeatures = @("TFTP", "TelnetClient", "SimpleTCP")
foreach ($feature in $bloatFeatures) {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue).State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
    }
}

# --- Remove Bloat Capabilities ---
$bloatCaps = @("*InternetExplorer*", "*WindowsMediaPlayer*")
foreach ($cap in $bloatCaps) {
    $capsToRemove = Get-WindowsCapability -Online | Where-Object { $_.Name -like $cap -and $_.State -eq 'Installed' }
    foreach ($capToRemove in $capsToRemove) {
        Remove-WindowsCapability -Online -Name $capToRemove.Name -ErrorAction SilentlyContinue
    }
}

# --- SvcHost Split Threshold ---
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$mem = $os.TotalVisibleMemorySize
$ram = $mem + 1024000
Set-RegKey -path "HKLM:\SYSTEM\CurrentControlSet\Control" -name "SvcHostSplitThresholdInKB" -value $ram

# --- Final Message ---
Write-Output "Performance tweaks applied successfully. Please restart your system to ensure all changes take effect."