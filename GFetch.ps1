<#
.SYNOPSIS
    GFetch - A Neofetch/Winfetch style system info script for Windows
    Author: Gorstak (gorstak.eu)
    Compatible with Windows 10+ (PowerShell 5.1+)
.DESCRIPTION
    Displays system information in a visually appealing format including OS, CPU, GPU,
    memory, disk, network, battery, .NET version, Defender status, and more.
    Interactive utility, no persistence needed.
#>

# --- Gather System Info ---

$OS = Get-CimInstance Win32_OperatingSystem
$CPU = Get-CimInstance Win32_Processor | Select-Object -First 1
$GPU = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Basic' } | Select-Object -First 1
if (-not $GPU) { $GPU = Get-CimInstance Win32_VideoController | Select-Object -First 1 }
$CS = Get-CimInstance Win32_ComputerSystem
$Baseboard = Get-CimInstance Win32_BaseBoard

# User and Host
$UserName = $env:USERNAME
$HostName = $env:COMPUTERNAME

# OS
$OSName = $OS.Caption -replace 'Microsoft ', ''
$OSBuild = $OS.BuildNumber
$OSVersion = $OS.Version

# Kernel
$Kernel = "NT $OSVersion"

# Uptime
$Uptime = (Get-Date) - $OS.LastBootUpTime
$UptimeStr = ""
if ($Uptime.Days -gt 0) { $UptimeStr += "$($Uptime.Days)d " }
if ($Uptime.Hours -gt 0) { $UptimeStr += "$($Uptime.Hours)h " }
$UptimeStr += "$($Uptime.Minutes)m"

# Shell
$ShellVersion = "PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"

# Terminal
$Terminal = $null
try {
    $parentId = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
    if ($parentId) {
        $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" -ErrorAction SilentlyContinue
        if ($parentProc) {
            $termName = [System.IO.Path]::GetFileNameWithoutExtension($parentProc.Name)
            $Terminal = switch ($termName) {
                'WindowsTerminal'   { 'Windows Terminal' }
                'cmd'               { 'CMD' }
                'powershell'        { 'Windows PowerShell' }
                'pwsh'              { 'PowerShell Core' }
                'ConEmuC64'         { 'ConEmu' }
                'ConEmuC'           { 'ConEmu' }
                default             { $termName }
            }
        }
    }
} catch {}
if (-not $Terminal) { $Terminal = "Unknown" }

# CPU
$CPUName = ($CPU.Name -replace '\s+', ' ').Trim()
$CPUCores = $CPU.NumberOfCores
$CPUThreads = $CPU.NumberOfLogicalProcessors
$CPUUsage = $CPU.LoadPercentage
if ($null -eq $CPUUsage) { $CPUUsage = "N/A" } else { $CPUUsage = "${CPUUsage}%" }

# GPU
$GPUName = if ($GPU) { $GPU.Name } else { "N/A" }

# Memory
$TotalMem = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 1)
$UsedMem = [math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1MB, 1)
$MemPercent = [math]::Round(($UsedMem / $TotalMem) * 100)
$MemStr = "${UsedMem} GB / ${TotalMem} GB (${MemPercent}%)"

# Disk
$Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
$DiskTotal = [math]::Round($Disk.Size / 1GB, 1)
$DiskUsed = [math]::Round(($Disk.Size - $Disk.FreeSpace) / 1GB, 1)
$DiskPercent = [math]::Round(($DiskUsed / $DiskTotal) * 100)
$DiskStr = "${DiskUsed} GB / ${DiskTotal} GB (${DiskPercent}%)"

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

# Motherboard
$MoboStr = "$($Baseboard.Manufacturer) $($Baseboard.Product)"

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
    $adapter = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.IPAddress } | Select-Object -First 1
    if ($adapter) { $LocalIP = ($adapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) }
} catch {}

# Public IP
$PublicIP = "N/A"
try {
    $PublicIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 3 -ErrorAction SilentlyContinue)
} catch {}

# Network adapter
$NetAdapter = "N/A"
try {
    $na = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1
    if ($na) { $NetAdapter = $na.Name }
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
    $lic = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 } | Select-Object -First 1
    if ($lic) { $Activation = "Activated" } else { $Activation = "Not Activated" }
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
    # Also check for .NET Core / 5+
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
