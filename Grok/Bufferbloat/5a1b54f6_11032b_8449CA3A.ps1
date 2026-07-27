# Bufferbloat.ps1
# Author: Gorstak

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  AGGRESSIVE BUFFERBLOAT REDUCTION FOR MEDIATEK WIFI 6E" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$regContent = @"
Windows Registry Editor Version 5.00

; ============================================================================
; AGGRESSIVE BUFFERBLOAT REDUCTION FOR MEDIATEK WIFI 6E
; ============================================================================
; This configuration prioritizes LOW LATENCY over maximum throughput
; Apply at your own risk - test after applying
; ============================================================================

; ============================================================================
; TCP/IP AGGRESSIVE LATENCY OPTIMIZATION
; ============================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
; Disable TCP window scaling to prevent large buffers
"Tcp1323Opts"=dword:00000000
; Immediate ACKs - no delayed acknowledgments
"TcpAckFrequency"=dword:00000001
"TCPDelAckTicks"=dword:00000000
; Aggressive duplicate ACK threshold
"TcpMaxDupAcks"=dword:00000002
; Small initial window
"TcpInitialRtt"=dword:00000300
; Limit TCP window sizes
"TcpWindowSize"=dword:00008000
"GlobalMaxTcpWindowSize"=dword:00008000
; Disable TCP offloading features that add latency
"DisableTaskOffload"=dword:00000001
; Use CUBIC congestion control (better for latency)
"TcpCongestionControl"=dword:00000001
; Aggressive retransmission
"TcpMaxDataRetransmissions"=dword:00000003
; Disable receive-side coalescing
"EnableRSC"=dword:00000000
; Disable large send offload
"EnableTCPChimney"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces]
; Apply to all interfaces
"TcpAckFrequency"=dword:00000001
"TCPDelAckTicks"=dword:00000000

; ============================================================================
; AFD (WINSOCK) BUFFER LIMITS
; ============================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters]
; Severely limit socket buffers to prevent bufferbloat
"DefaultReceiveWindow"=dword:00008000
"DefaultSendWindow"=dword:00008000
; Fast buffer allocation
"DynamicSendBufferDisable"=dword:00000000
"FastSendDatagramThreshold"=dword:00000400
; Limit non-blocking send/receive
"NonBlockingSendSpecialBuffering"=dword:00000001
; Small IRPs
"LargeBufferSize"=dword:00001000
"MediumBufferSize"=dword:00000800
"SmallBufferSize"=dword:00000400
; Aggressive completion
"TransmitWorker"=dword:00000020
"BufferMultiplier"=dword:00000400
; Limit backlog
"EnableDynamicBacklog"=dword:00000001
"MinimumDynamicBacklog"=dword:00000014
"MaximumDynamicBacklog"=dword:00000100

; ============================================================================
; QOS PACKET SCHEDULER - PRIORITIZE LATENCY
; ============================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched\Parameters]
; Disable all bandwidth reservation
"NonBestEffortLimit"=dword:00000000
; Priority-based scheduling
"TimerResolution"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched]
"NonBestEffortLimit"=dword:00000000

; ============================================================================
; DISABLE AUTO-TUNING (Prevents buffer bloat)
; ============================================================================

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:ffffffff
"SystemResponsiveness"=dword:00000000

; ============================================================================
; NDIS - NETWORK ADAPTER OPTIMIZATION
; ============================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS\Parameters]
; Disable packet coalescing
"MaxNumRssCpus"=dword:00000004
; Small receive buffers
"RssBaseCpu"=dword:00000000
"NumberOfRssQueues"=dword:00000002

; ============================================================================
; MEDIATEK WIFI 6E SPECIFIC SETTINGS
; ============================================================================
; Note: Replace {ADAPTER-GUID} with your actual adapter GUID
; Find via: Get-NetAdapter | Select Name, InterfaceGuid
; Or apply manually via Device Manager -> Network Adapter -> Advanced

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000]
; Disable interrupt moderation (adds latency)
"*InterruptModeration"="0"
; Minimum receive buffers
"*ReceiveBuffers"="64"
"*TransmitBuffers"="64"
; Disable offloading
"*TCPChecksumOffloadIPv4"="0"
"*TCPChecksumOffloadIPv6"="0"
"*UDPChecksumOffloadIPv4"="0"
"*UDPChecksumOffloadIPv6"="0"
"*IPChecksumOffloadIPv4"="0"
"*LSOv2IPv4"="0"
"*LSOv2IPv6"="0"
"*PMARPOffload"="0"
"*PMNSOffload"="0"
; Disable power saving
"*WakeOnMagicPacket"="0"
"*WakeOnPattern"="0"
"PnPCapabilities"=dword:00000018
; Throughput booster OFF (reduces buffering)
"ThroughputBoosterEnabled"="0"
; Packet coalescing OFF
"PacketCoalescing"="0"
; WMM/QoS settings
"*QOS"="1"
"WMMEnabled"="1"
; Roaming aggressiveness - medium (prevents connection issues)
"RoamingPreference"="2"
; Channel width - prefer narrower for lower latency
"ChannelWidth"="1"
; Disable fat channel intolerant
"FatChannelIntolerant"="0"

; ============================================================================
; MULTIMEDIA CLASS SCHEDULER - LOW LATENCY
; ============================================================================

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:ffffffff
"SystemResponsiveness"=dword:00000000
"LazyModeTimeout"=dword:00002710
"NoLazyMode"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="High"
"SFIO Priority"="High"

; ============================================================================
; DISABLE BACKGROUND NETWORK FEATURES
; ============================================================================

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched]
"MaxOutstandingSends"=dword:00000001

; ============================================================================
; DNS OPTIMIZATION
; ============================================================================

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters]
"MaxCacheTtl"=dword:00000258
"MaxNegativeCacheTtl"=dword:00000000
"NegativeSOACacheTime"=dword:00000000

; ============================================================================
; WINDOWS UPDATE DELIVERY OPTIMIZATION - LIMIT BANDWIDTH
; ============================================================================

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization]
"DODownloadMode"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization]
"SystemSettingsDownloadMode"=dword:00000003
"@

Write-Host "[1/3] Applying registry optimizations..." -ForegroundColor Yellow
$tempRegFile = "$env:TEMP\bufferbloat-fix.reg"
$regContent | Out-File -FilePath $tempRegFile -Encoding ASCII

try {
    Start-Process "reg.exe" -ArgumentList "import `"$tempRegFile`"" -Wait -NoNewWindow
    Write-Host "  Registry settings applied successfully!" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to apply registry settings: $_" -ForegroundColor Red
    pause
    exit
}

# Clean up temp file
Remove-Item $tempRegFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[2/3] Applying netsh network optimizations..." -ForegroundColor Yellow

# Disable TCP auto-tuning
Write-Host "  - Disabling TCP auto-tuning..." -ForegroundColor Gray
netsh int tcp set global autotuninglevel=disabled | Out-Null

# Set congestion provider to CTCP (Compound TCP)
Write-Host "  - Setting congestion control to CTCP..." -ForegroundColor Gray
netsh int tcp set global congestionprovider=ctcp | Out-Null

# Disable ECN (can cause bufferbloat with some routers)
Write-Host "  - Disabling ECN..." -ForegroundColor Gray
netsh int tcp set global ecncapability=disabled | Out-Null

# Disable timestamps (reduces overhead)
Write-Host "  - Disabling TCP timestamps..." -ForegroundColor Gray
netsh int tcp set global timestamps=disabled | Out-Null

# Disable heuristics
Write-Host "  - Disabling TCP heuristics..." -ForegroundColor Gray
netsh interface tcp set heuristics disabled | Out-Null

# Configure RSS
Write-Host "  - Configuring RSS..." -ForegroundColor Gray
netsh int tcp set global rss=enabled | Out-Null

# Set initial RTO to 3000ms
Write-Host "  - Setting initial RTO..." -ForegroundColor Gray
netsh int tcp set global initialRto=3000 | Out-Null

Write-Host "  Network settings configured!" -ForegroundColor Green

Write-Host ""
Write-Host "[3/3] Configuring network adapters..." -ForegroundColor Yellow

# Disable offloads and configure buffers
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
    $adapter = $_
    Write-Host "  - Configuring: $($adapter.Name)" -ForegroundColor Gray
    
    # Disable offloads
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    
    # Set receive/transmit buffers to minimum
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Receive Buffers" -DisplayValue "64" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Transmit Buffers" -DisplayValue "64" -ErrorAction SilentlyContinue
    
    # Disable power management
    $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | Where-Object {$_.InstanceName -match [regex]::Escape($adapter.PnPDeviceID)}
    if ($powerMgmt) {
        $powerMgmt.Enable = $false
        $powerMgmt.Put() | Out-Null
    }
}

Write-Host "  Adapter configuration complete!" -ForegroundColor Green

