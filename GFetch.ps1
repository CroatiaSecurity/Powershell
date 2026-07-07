<#
.SYNOPSIS
    GFetch - A Neofetch/Winfetch style system info script for Windows
    Compatible with Windows 10+ (PowerShell 5.1+)
    Resilient to WMI/CIM failures - uses registry/API fallbacks
#>

# --- Gather System Info (with CIM fallbacks) ---

# OS Info
$OS = $null
try { $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}

if ($OS) {
    $OSName = $OS.Caption -replace 'Microsoft ', ''
    $OSBuild = $OS.BuildNumber
    $OSVersion = $OS.Version
    $LastBootTime = $OS.LastBootUpTime
    $TotalMemKB = $OS.TotalVisibleMemorySize
    $FreeMemKB = $OS.FreePhysicalMemory
} else {
    # Fallback: registry + environment
    $curVer = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -EA SilentlyContinue
    $OSName = if ($curVer.ProductName) { $curVer.ProductName } else { "Windows" }
    $OSBuild = if ($curVer.CurrentBuildNumber) { $curVer.CurrentBuildNumber } else { "" }
    $major = if ($curVer.CurrentMajorVersionNumber) { $curVer.CurrentMajorVersionNumber } else { "10" }
    $minor = if ($curVer.CurrentMinorVersionNumber) { $curVer.CurrentMinorVersionNumber } else { "0" }
    $OSVersion = "$major.$minor.$OSBuild"
    # Boot time from event log or perf counter
    $LastBootTime = $null
    try {
        $tick = [Environment]::TickCount64
        $LastBootTime = (Get-Date).AddMilliseconds(-$tick)
    } catch {
        try {
            $tick = [Environment]::TickCount
            $LastBootTime = (Get-Date).AddMilliseconds(-$tick)
        } catch {}
    }
    # Memory via .NET
    $TotalMemKB = $null
    $FreeMemKB = $null
    try {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class MemInfo {
    [StructLayout(LayoutKind.Sequential)] public struct MEMORYSTATUSEX {
        public uint dwLength; public uint dwMemoryLoad;
        public ulong ullTotalPhys; public ulong ullAvailPhys;
        public ulong ullTotalPageFile; public ulong ullAvailPageFile;
        public ulong ullTotalVirtual; public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }
    [DllImport("kernel32.dll")] public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
}
"@ -ErrorAction SilentlyContinue
        $mem = New-Object MemInfo+MEMORYSTATUSEX
        $mem.dwLength = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($mem)
        [void][MemInfo]::GlobalMemoryStatusEx([ref]$mem)
        $TotalMemKB = [math]::Round($mem.ullTotalPhys / 1KB)
        $FreeMemKB = [math]::Round($mem.ullAvailPhys / 1KB)
    } catch {}
}

# CPU Info
$CPU = $null
try { $CPU = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 } catch {}

if ($CPU) {
    $CPUName = ($CPU.Name -replace '\s+', ' ').Trim()
    $CPUCores = $CPU.NumberOfCores
    $CPUThreads = $CPU.NumberOfLogicalProcessors
    $CPUUsage = $CPU.LoadPercentage
} else {
    # Fallback: registry
    $cpuReg = Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -EA SilentlyContinue
    $CPUName = if ($cpuReg.ProcessorNameString) { ($cpuReg.ProcessorNameString -replace '\s+', ' ').Trim() } else { "Unknown CPU" }
    $CPUCores = $env:NUMBER_OF_PROCESSORS
    $CPUThreads = $env:NUMBER_OF_PROCESSORS
    # Try to get actual core count from registry
    try {
        $coreCount = (Get-ChildItem "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor" -EA SilentlyContinue).Count
        if ($coreCount -gt 0) { $CPUThreads = $coreCount }
    } catch {}
    $CPUUsage = $null
}
if ($null -eq $CPUUsage) { $CPUUsage = "N/A" } else { $CPUUsage = "${CPUUsage}%" }

# GPU Info
$GPU = $null
try {
    $GPU = Get-CimInstance Win32_VideoController -ErrorAction Stop | Where-Object { $_.Name -notmatch 'Microsoft|Basic' } | Select-Object -First 1
    if (-not $GPU) { $GPU = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -First 1 }
} catch {}

if ($GPU) {
    $GPUName = $GPU.Name
} else {
    # Fallback: registry
    $GPUName = "N/A"
    try {
        $vidKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -EA SilentlyContinue
        foreach ($key in $vidKeys) {
            $props = Get-ItemProperty $key.PSPath -EA SilentlyContinue
            if ($props.DriverDesc -and $props.DriverDesc -notmatch 'Microsoft|Basic') {
                $GPUName = $props.DriverDesc
                break
            }
        }
        # If still N/A, take any GPU
        if ($GPUName -eq "N/A") {
            foreach ($key in $vidKeys) {
                $props = Get-ItemProperty $key.PSPath -EA SilentlyContinue
                if ($props.DriverDesc) { $GPUName = $props.DriverDesc; break }
            }
        }
    } catch {}
}

# ComputerSystem
$CS = $null
try { $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}

# BaseBoard
$Baseboard = $null
try { $Baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop } catch {}

if ($Baseboard) {
    $MoboStr = "$($Baseboard.Manufacturer) $($Baseboard.Product)"
} else {
    # Fallback: registry
    $MoboStr = "Unknown"
    try {
        $biosReg = Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -EA SilentlyContinue
        if ($biosReg.BaseBoardManufacturer -and $biosReg.BaseBoardProduct) {
            $MoboStr = "$($biosReg.BaseBoardManufacturer) $($biosReg.BaseBoardProduct)"
        }
    } catch {}
}

# User and Host
$UserName = $env:USERNAME
$HostName = $env:COMPUTERNAME

# Kernel
$Kernel = "NT $OSVersion"

# Uptime
$UptimeStr = "N/A"
if ($LastBootTime) {
    try {
        $Uptime = (Get-Date) - $LastBootTime
        $UptimeStr = ""
        if ($Uptime.Days -gt 0) { $UptimeStr += "$($Uptime.Days)d " }
        if ($Uptime.Hours -gt 0) { $UptimeStr += "$($Uptime.Hours)h " }
        $UptimeStr += "$($Uptime.Minutes)m"
    } catch { $UptimeStr = "N/A" }
}

# Shell
$ShellVersion = "PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"

# Terminal detection
$Terminal = $null
try {
    $parentId = $null
    # Try CIM first
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop
        $parentId = $proc.ParentProcessId
    } catch {
        # Fallback: .NET Process
        try {
            $currentProc = [System.Diagnostics.Process]::GetCurrentProcess()
            # PowerShell 5.1 doesn't have Parent property; use WMI-free method
            Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class ProcInfo {
    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1; public IntPtr PebBaseAddress; public IntPtr Reserved2a;
        public IntPtr Reserved2b; public IntPtr UniqueProcessId; public IntPtr InheritedFromUniqueProcessId;
    }
    [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(
        IntPtr hProcess, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength, out int returnLength);
    public static int GetParentPid(IntPtr handle) {
        var pbi = new PROCESS_BASIC_INFORMATION();
        int retLen; NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out retLen);
        return pbi.InheritedFromUniqueProcessId.ToInt32();
    }
}
"@ -ErrorAction SilentlyContinue
            $parentId = [ProcInfo]::GetParentPid($currentProc.Handle)
        } catch {}
    }
    if ($parentId) {
        $parentProc = $null
        try {
            $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" -ErrorAction Stop
            $termName = [System.IO.Path]::GetFileNameWithoutExtension($parentProc.Name)
        } catch {
            # Fallback: .NET Process
            try {
                $p = [System.Diagnostics.Process]::GetProcessById($parentId)
                $termName = [System.IO.Path]::GetFileNameWithoutExtension($p.ProcessName)
            } catch {}
        }
        if ($termName) {
            $Terminal = switch ($termName) {
                'WindowsTerminal'   { 'Windows Terminal' }
                'cmd'               { 'CMD' }
                'powershell'        { 'Windows PowerShell' }
                'pwsh'              { 'PowerShell Core' }
                'ConEmuC64'         { 'ConEmu' }
                'ConEmuC'           { 'ConEmu' }
                'Code'              { 'VS Code' }
                'Kiro'              { 'Kiro' }
                default             { $termName }
            }
        }
    }
} catch {}
if (-not $Terminal) { $Terminal = "Unknown" }

# Memory
$TotalMem = 0
$UsedMem = 0
$MemPercent = 0
$MemStr = "N/A"
if ($TotalMemKB -and $TotalMemKB -gt 0) {
    $TotalMem = [math]::Round($TotalMemKB / 1MB, 1)
    if ($FreeMemKB) {
        $UsedMem = [math]::Round(($TotalMemKB - $FreeMemKB) / 1MB, 1)
    }
    if ($TotalMem -gt 0) {
        $MemPercent = [math]::Round(($UsedMem / $TotalMem) * 100)
    }
    $MemStr = "${UsedMem} GB / ${TotalMem} GB (${MemPercent}%)"
}

# Disk
$DiskStr = "N/A"
$DiskTotal = 0
$DiskUsed = 0
$DiskPercent = 0
try {
    $Disk = $null
    try { $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop } catch {}
    if ($Disk -and $Disk.Size -gt 0) {
        $DiskTotal = [math]::Round($Disk.Size / 1GB, 1)
        $DiskUsed = [math]::Round(($Disk.Size - $Disk.FreeSpace) / 1GB, 1)
    } else {
        # Fallback: .NET DriveInfo
        $drv = [System.IO.DriveInfo]::new($env:SystemDrive)
        if ($drv.IsReady -and $drv.TotalSize -gt 0) {
            $DiskTotal = [math]::Round($drv.TotalSize / 1GB, 1)
            $DiskUsed = [math]::Round(($drv.TotalSize - $drv.TotalFreeSpace) / 1GB, 1)
        }
    }
    if ($DiskTotal -gt 0) {
        $DiskPercent = [math]::Round(($DiskUsed / $DiskTotal) * 100)
        $DiskStr = "${DiskUsed} GB / ${DiskTotal} GB (${DiskPercent}%)"
    }
} catch {}

# Disk type (SSD or HDD)
$DiskType = "Unknown"
try {
    $physDisk = Get-CimInstance MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($physDisk) {
        $DiskType = switch ($physDisk.MediaType) {
            3 { "HDD" }
            4 { "SSD" }
            5 { "SCM" }
            default { "Unknown" }
        }
    }
} catch {}

# Resolution
$Resolution = "N/A"
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $Resolution = "$($screen.Width)x$($screen.Height)"
} catch {}

# Packages
$Packages = $null
try {
    $reg64 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }).Count
    $reg32 = (Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }).Count
    $Packages = $reg64 + $reg32
} catch { $Packages = "?" }

# Local IP
$LocalIP = "N/A"
try {
    $adapter = $null
    try { $adapter = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -eq $true -and $_.IPAddress } | Select-Object -First 1 } catch {}
    if ($adapter) {
        $LocalIP = ($adapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    } else {
        # Fallback: .NET
        $netIfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($iface in $netIfaces) {
            if ($iface.OperationalStatus -eq 'Up' -and $iface.NetworkInterfaceType -ne 'Loopback') {
                $ipProps = $iface.GetIPProperties()
                $unicast = $ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' }
                if ($unicast) { $LocalIP = $unicast[0].Address.ToString(); break }
            }
        }
    }
} catch {}

# Public IP
$PublicIP = "N/A"
try {
    $PublicIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 3 -ErrorAction SilentlyContinue)
} catch {}

# Network adapter
$NetAdapter = "N/A"
try {
    $na = $null
    try { $na = Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1 } catch {}
    if ($na) {
        $NetAdapter = $na.Name
    } else {
        # Fallback: .NET
        $netIfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        $upIface = $netIfaces | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } | Select-Object -First 1
        if ($upIface) { $NetAdapter = $upIface.Description }
    }
} catch {}

# Battery
$BatteryStr = $null
try {
    $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($bat) {
        $batPercent = $bat.EstimatedChargeRemaining
        $batStatus = switch ($bat.BatteryStatus) {
            1 { "Discharging" }
            2 { "AC Power" }
            3 { "Fully Charged" }
            4 { "Low" }
            5 { "Critical" }
            6 { "Charging" }
            7 { "Charging (High)" }
            8 { "Charging (Low)" }
            9 { "Charging (Critical)" }
            default { "Unknown" }
        }
        $BatteryStr = "${batPercent}% ($batStatus)"
    }
} catch {}

# Boot mode (UEFI vs Legacy)
$BootMode = "Legacy (BIOS)"
try {
    $fwType = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control" -ErrorAction SilentlyContinue).PEFirmwareType
    if ($fwType -eq 2) { $BootMode = "UEFI" }
    elseif ($fwType -eq 1) { $BootMode = "Legacy (BIOS)" }
} catch {
    if (Test-Path "$env:SystemRoot\System32\SecureBoot") { $BootMode = "UEFI" }
}

# Locale
$Locale = (Get-Culture).DisplayName

# Theme (Light or Dark)
$Theme = "N/A"
try {
    $themeReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ErrorAction SilentlyContinue
    if ($null -ne $themeReg.AppsUseLightTheme) {
        $Theme = if ($themeReg.AppsUseLightTheme -eq 0) { "Dark" } else { "Light" }
    }
} catch {}

# Windows activation
$Activation = "Unknown"
try {
    $lic = $null
    try { $lic = Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop | Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 } | Select-Object -First 1 } catch {}
    if ($lic) {
        $Activation = "Activated"
    } else {
        # Fallback: cscript slmgr
        try {
            $slmgr = & cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /dli 2>$null
            if ($slmgr -match 'License Status:\s*Licensed') { $Activation = "Activated" }
            else { $Activation = "Not Activated" }
        } catch { $Activation = "Unknown" }
    }
} catch {}

# Wallpaper path
$Wallpaper = "N/A"
try {
    $wpReg = Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue
    if ($wpReg.Wallpaper) { $Wallpaper = $wpReg.Wallpaper }
} catch {}

# Font smoothing (ClearType)
$ClearType = "N/A"
try {
    $ftReg = Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name FontSmoothing -ErrorAction SilentlyContinue
    if ($ftReg.FontSmoothing -eq "2") { $ClearType = "ClearType" }
    elseif ($ftReg.FontSmoothing -eq "1") { $ClearType = "Standard" }
    elseif ($ftReg.FontSmoothing -eq "0") { $ClearType = "Disabled" }
} catch {}

# Windows Defender status
$Defender = "N/A"
try {
    $defStatus = Get-CimInstance -Namespace root\Microsoft\Windows\Defender -ClassName MSFT_MpComputerStatus -ErrorAction SilentlyContinue
    if ($defStatus) {
        $rtProtection = if ($defStatus.RealTimeProtectionEnabled) { "On" } else { "Off" }
        $Defender = "Real-Time: $rtProtection"
    } else {
        # Fallback: Get-MpPreference
        try {
            $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
            if ($mpPref) {
                $rtProtection = if ($mpPref.DisableRealtimeMonitoring) { "Off" } else { "On" }
                $Defender = "Real-Time: $rtProtection"
            }
        } catch {}
    }
} catch {}

# Last Windows Update
$LastUpdate = "N/A"
try {
    $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($session) {
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $history = $searcher.QueryHistory(0, 1)
            if ($history.Count -gt 0) {
                $LastUpdate = $history[0].Date.ToString("yyyy-MM-dd")
            }
        }
    }
} catch {}

# .NET version
$DotNet = "N/A"
try {
    $ndpKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ($ndpKey -and $ndpKey.Release) {
        $rel = $ndpKey.Release
        $DotNet = if ($rel -ge 533320) { "4.8.1+" }
        elseif ($rel -ge 528040) { "4.8" }
        elseif ($rel -ge 461808) { "4.7.2" }
        elseif ($rel -ge 461308) { "4.7.1" }
        elseif ($rel -ge 460798) { "4.7" }
        elseif ($rel -ge 394802) { "4.6.2" }
        elseif ($rel -ge 394254) { "4.6.1" }
        elseif ($rel -ge 393295) { "4.6" }
        else { "4.5+" }
    }
    $dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnetCmd) {
        $runtimes = & dotnet --list-runtimes 2>$null | Select-String "Microsoft.NETCore.App" | Select-Object -Last 1
        if ($runtimes) {
            $ver = ($runtimes -split '\s+')[1]
            $DotNet = ".NET $ver (Framework $DotNet)"
        } else {
            $DotNet = ".NET Framework $DotNet"
        }
    } else {
        $DotNet = ".NET Framework $DotNet"
    }
} catch {}

# Execution policy
$ExecPolicy = (Get-ExecutionPolicy).ToString()

# --- Colors (ANSI) ---

$e = [char]27
$C  = "${e}[36m"
$BC = "${e}[1;36m"
$BB = "${e}[1;34m"
$R  = "${e}[0m"
$D  = "${e}[2m"

# Color blocks
$ColorBar1 = ""
for ($i = 0; $i -le 7; $i++) { $ColorBar1 += "${e}[4${i}m   " }
$ColorBar1 += $R
$ColorBar2 = ""
for ($i = 0; $i -le 7; $i++) { $ColorBar2 += "${e}[10${i}m   " }
$ColorBar2 += $R

# --- ASCII Art ---

$Logo = @(
    "${BB} ################  ################",
    "${BB} ################  ################",
    "${BB} ################  ################",
    "${BB} ################  ################",
    "${BB}                                   ",
    "${BB} ################  ################",
    "${BB} ################  ################",
    "${BB} ################  ################",
    "${BB} ################  ################"
)

# --- Build Info Lines ---

$InfoLines = [System.Collections.ArrayList]@()
[void]$InfoLines.Add("${BC}${UserName}${R}@${BC}${HostName}${R}")
[void]$InfoLines.Add("${D}------------------------------------${R}")
[void]$InfoLines.Add("${BC}OS${R}           $OSName (Build $OSBuild)")
[void]$InfoLines.Add("${BC}Kernel${R}       $Kernel")
[void]$InfoLines.Add("${BC}Uptime${R}       $UptimeStr")
[void]$InfoLines.Add("${BC}Packages${R}     $Packages (system)")
[void]$InfoLines.Add("${BC}Shell${R}        $ShellVersion")
[void]$InfoLines.Add("${BC}Terminal${R}     $Terminal")
[void]$InfoLines.Add("${BC}CPU${R}          $CPUName")
[void]$InfoLines.Add("${BC}Cores${R}        ${CPUCores} cores / ${CPUThreads} threads")
[void]$InfoLines.Add("${BC}CPU Load${R}     $CPUUsage")
[void]$InfoLines.Add("${BC}GPU${R}          $GPUName")
[void]$InfoLines.Add("${BC}Memory${R}       $MemStr")
[void]$InfoLines.Add("${BC}Disk ($($env:SystemDrive))${R}    $DiskStr")
[void]$InfoLines.Add("${BC}Disk Type${R}    $DiskType")
[void]$InfoLines.Add("${BC}Board${R}        $MoboStr")
[void]$InfoLines.Add("${BC}Resolution${R}   $Resolution")
[void]$InfoLines.Add("${BC}Boot Mode${R}    $BootMode")
[void]$InfoLines.Add("${BC}Local IP${R}     $LocalIP")
[void]$InfoLines.Add("${BC}Public IP${R}    ***.***.***.*** ${D}[press P to reveal]${R}")
[void]$InfoLines.Add("${BC}Network${R}      $NetAdapter")
if ($BatteryStr) {
    [void]$InfoLines.Add("${BC}Battery${R}      $BatteryStr")
}
[void]$InfoLines.Add("${BC}Locale${R}       $Locale")
[void]$InfoLines.Add("${BC}Theme${R}        $Theme")
[void]$InfoLines.Add("${BC}Activation${R}   $Activation")
[void]$InfoLines.Add("${BC}Defender${R}     $Defender")
[void]$InfoLines.Add("${BC}.NET${R}         $DotNet")
[void]$InfoLines.Add("${BC}Exec Policy${R}  $ExecPolicy")
[void]$InfoLines.Add("${BC}ClearType${R}    $ClearType")
[void]$InfoLines.Add("${BC}Last Update${R}  $LastUpdate")
[void]$InfoLines.Add("${BC}Wallpaper${R}    $Wallpaper")
[void]$InfoLines.Add("")
[void]$InfoLines.Add($ColorBar1)
[void]$InfoLines.Add($ColorBar2)

# --- Render ---

Write-Host ""
$maxLines = [Math]::Max($Logo.Count, $InfoLines.Count)
for ($i = 0; $i -lt $maxLines; $i++) {
    $art = if ($i -lt $Logo.Count) { $Logo[$i] } else { "                                   " }
    $info = if ($i -lt $InfoLines.Count) { $InfoLines[$i] } else { "" }
    Write-Host "$art   $info"
}
Write-Host ""

# --- Interactive prompt ---

Write-Host "${D}Press [P] to reveal Public IP, or any other key to exit.${R}" -NoNewline
$key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""
if ($key.Character -eq 'p' -or $key.Character -eq 'P') {
    Write-Host "${BC}Public IP${R}    $PublicIP"
    Write-Host ""
    Write-Host "${D}Press any key to exit.${R}" -NoNewline
    [void]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
}
