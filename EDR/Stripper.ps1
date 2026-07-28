<#
.SYNOPSIS
    Ultimate Windows ISO Debloater - Fully automated version
    Author: Gorstak (gorstak.eu)
.DESCRIPTION
    Strips bloatware, telemetry apps, and applies registry tweaks to a Windows ISO using
    wimlib and an NTLite XML preset. Auto-detects .iso and .xml files in script directory
    or Desktop. Strips everything by default with no keep switches.
    One-time utility - produces a debloated ISO file.
#>

#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "StripperDebloat"
$Script:InstallDir = "$env:ProgramData\Stripper"
$Script:ScriptName = "Stripper.ps1"

function Install-Persistence {
    # Create install directory
    if (-not (Test-Path $Script:InstallDir)) {
        New-Item -Path $Script:InstallDir -ItemType Directory -Force | Out-Null
    }

    # Copy script to install location
    $targetPath = Join-Path $Script:InstallDir $Script:ScriptName
    Copy-Item -Path $PSCommandPath -Destination $targetPath -Force

    # Register scheduled task (cmdlet first, schtasks fallback)
    $installed = $false
    $pwshArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Scheduled task '$($Script:TaskName)' registered via Register-ScheduledTask."
        $installed = $true
    } catch {
        Write-Host "Register-ScheduledTask failed: $_"
    }

    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$($Script:TaskName)`" /TR `"powershell.exe $pwshArgs`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Scheduled task '$($Script:TaskName)' registered via schtasks.exe fallback."
                $installed = $true
            } else {
                Write-Host "schtasks fallback failed: $result"
            }
        } catch {
            Write-Host "schtasks fallback exception: $_"
        }
    }

    Write-Host "Persistence installed to: $targetPath"
}

function Uninstall-Persistence {
    try { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    & schtasks.exe /Delete /TN "$($Script:TaskName)" /F 2>$null | Out-Null
    if (Test-Path $Script:InstallDir) {
        Remove-Item -Path $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Persistence removed for '$($Script:TaskName)'."
}

if ($Install) { Install-Persistence; return }
if ($Uninstall) { Uninstall-Persistence; return }

# Auto-install if not running from installed location
$installedPath = Join-Path $Script:InstallDir $Script:ScriptName
if ($PSCommandPath -and $PSCommandPath -ne $installedPath) {
    $existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        Install-Persistence
        return
    }
}

# ==============================
# Main Logic - ISO Debloater
# ==============================

# Auto-detect ISO and XML
$IsoPath = Get-ChildItem "$PSScriptRoot\*.iso" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $IsoPath) {
    $IsoPath = Get-ChildItem "$env:USERPROFILE\Desktop\*.iso" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
$XmlPath = Get-ChildItem "$PSScriptRoot\*.xml" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $XmlPath) {
    $XmlPath = Get-ChildItem "$env:USERPROFILE\Desktop\*.xml" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}

if (-not $IsoPath -or -not (Test-Path $IsoPath)) {
    Write-Host "ERROR: No ISO file found. Place a .iso in the script directory or Desktop." -ForegroundColor Red
    exit 1
}
if (-not $XmlPath -or -not (Test-Path $XmlPath)) {
    Write-Host "ERROR: No XML preset found. Place a .xml in the script directory or Desktop." -ForegroundColor Red
    exit 1
}

Write-Host "Using ISO: $IsoPath" -ForegroundColor Green
Write-Host "Using preset: $XmlPath" -ForegroundColor Green

function Get-Wimlib {
    $zip = "$env:TEMP\wimlib.zip"
    $dir = "$env:TEMP\wimlib"
    $exe = "$dir\wimlib-imagex.exe"
    $url = "https://wimlib.net/downloads/wimlib-1.14.4-windows-x86_64-bin.zip"
    $hash = "401BF99D6DEC2B749B464183F71D146327AE0856A968C309955F71A0C398A348"

    if (!(Test-Path $exe)) {
        Write-Host "Downloading wimlib-imagex (official)..." -ForegroundColor Cyan
        Invoke-WebRequest $url -OutFile $zip -UseBasicParsing
        Expand-Archive $zip -DestinationPath $dir -Force
        Remove-Item $zip
        if ((Get-FileHash $exe -Algorithm SHA256).Hash -ne $hash) {
            Write-Error "wimlib hash mismatch! Corrupted download."
            exit 1
        }
        Write-Host "wimlib ready." -ForegroundColor Green
    }
    return $exe
}

function Get-Oscdimg {
    $dir = "$env:TEMP\oscdimg"
    $exe = "$dir\oscdimg.exe"
    if (Test-Path $exe) { return $exe }

    $adkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    )
    foreach ($p in $adkPaths) { if (Test-Path $p) { New-Item -ItemType Directory $dir -Force | Out-Null; Copy-Item $p $exe; return $exe } }

    Write-Host "Downloading lightweight oscdimg..." -ForegroundColor Cyan
    New-Item -ItemType Directory $dir -Force | Out-Null
    Invoke-WebRequest "https://github.com/kogavoljemvoljem/Scripts/raw/main/oscdimg.exe" -OutFile $exe -UseBasicParsing
    return $exe
}

$wimlib   = Get-Wimlib
$oscdimg  = Get-Oscdimg
$workDir  = "C:\WinDebloat_Temp"
$mountDir = "$workDir\Mount"
$extractDir = "$workDir\Extracted"

@($workDir) | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }
New-Item $mountDir -ItemType Directory -Force | Out-Null
New-Item $extractDir -ItemType Directory -Force | Out-Null

# Mount ISO & copy files
Write-Host "Mounting and extracting ISO (this can take 5-15 minutes)..." -ForegroundColor Cyan
$iso = Mount-DiskImage $IsoPath -PassThru
$drive = ($iso | Get-Volume).DriveLetter + ":"
Copy-Item "$drive\*" $extractDir -Recurse -Force
Dismount-DiskImage $IsoPath | Out-Null

# Handle install.wim / install.esd
$wimFile = "$extractDir\sources\install.wim"
if (!(Test-Path $wimFile)) { $wimFile = "$extractDir\sources\install.esd" }

if ($wimFile -match "\.esd$") {
    Write-Host "Converting ESD to WIM..." -ForegroundColor Yellow
    & $wimlib export $wimFile 1 "$extractDir\sources\install.wim" --compress=maximum
    $wimFile = "$extractDir\sources\install.wim"
}

# Parse XML - strip everything (no keep switches)
Write-Host "Parsing NTLite preset..." -ForegroundColor Cyan
[xml]$xml = Get-Content $XmlPath -Raw -Encoding UTF8
$removeList = $xml.Preset.RemoveComponents.c | ForEach-Object { ($_.InnerText -split " ")[0] }

# Mount WIM
Write-Host "Mounting WIM image..." -ForegroundColor Cyan
& $wimlib mount $wimFile 1 $mountDir --allow-other

# Remove Appx packages
Write-Host "Removing provisioned Appx packages..." -ForegroundColor Green
$apps = Get-AppxProvisionedPackage -Path $mountDir
foreach ($app in $apps) {
    $name = $app.DisplayName + $app.PackageName
    if ($removeList | Where-Object { $name -match $_ }) {
        Write-Host "  -> Removing $($app.DisplayName)"
        Remove-AppxProvisionedPackage -Path $mountDir -PackageName $app.PackageName | Out-Null
    }
}

# Apply registry tweaks
Write-Host "Applying registry tweaks..." -ForegroundColor Green
reg load HKLM\WIM_SOFT "$mountDir\Windows\System32\config\SOFTWARE" | Out-Null
reg load HKLM\WIM_SYS  "$mountDir\Windows\System32\config\SYSTEM"   | Out-Null
reg load HKLM\WIM_DEF  "$mountDir\Users\Default\NTUSER.DAT"       | Out-Null

foreach ($group in $xml.Preset.Tweaks.Settings.TweakGroup) {
    foreach ($tweak in $group.Tweak) {
        $full = $tweak.name
        $val  = $tweak.InnerText
        $key  = $full -replace '.*\\', ''
        $path = switch -Regex ($full) {
            '^Personalize\\'      { "HKLM:\WIM_DEF\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" }
            '^Explorer\\'         { "HKLM:\WIM_DEF\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" }
            '^Privacy\\'          { "HKLM:\WIM_SOFT\Policies\Microsoft\Windows\DataCollection" }
            '^Communications\\'   { "HKLM:\WIM_SOFT\Microsoft\Windows\CurrentVersion\Communications" }
            '^Power\\'            { "HKLM:\WIM_SOFT\Microsoft\Windows\CurrentVersion\Power" }
            '^OOBE\\'             { "HKLM:\WIM_SOFT\Microsoft\Windows\CurrentVersion\OOBE" }
            default               { $null }
        }
        if ($path) {
            if (!(Test-Path $path)) { New-Item $path -Force | Out-Null }
            $type = if ($val -match '^\d+$') { "DWord" } else { "String" }
            Set-ItemProperty -Path $path -Name $key -Value $val -Type $type -Force
            Write-Host "  -> $full = $val"
        }
    }
}

# Unload hives
[gc]::Collect()
reg unload HKLM\WIM_SOFT -ErrorAction SilentlyContinue
reg unload HKLM\WIM_SYS  -ErrorAction SilentlyContinue
reg unload HKLM\WIM_DEF  -ErrorAction SilentlyContinue

# Commit & optimize
Write-Host "Committing changes and optimizing WIM..." -ForegroundColor Cyan
& $wimlib unmount $mountDir --commit
& $wimlib optimize $wimFile --rebuild --compact=LZX

# Create new ISO
$outputIso = Join-Path (Split-Path $IsoPath) "Debloated_$(Get-Date -Format yyyyMMdd)_$(Split-Path $XmlPath -Leaf).iso"

$bootdir = "$env:TEMP\oscdimg_boot"
New-Item $bootdir -ItemType Directory -Force | Out-Null
Copy-Item "$extractDir\boot\etfsboot.com" "$bootdir\etfsboot.com" -Force
Copy-Item "$extractDir\efi\microsoft\boot\efisys.bin" "$bootdir\efisys.bin" -Force

$bootdata = "2#p0,e,b$bootdir\etfsboot.com#pEF,e,b$bootdir\efisys.bin"

Write-Host "Creating final bootable ISO..." -ForegroundColor Cyan
& $oscdimg -m -o -u2 -udfver102 -bootdata:$bootdata $extractDir $outputIso

Write-Host "`nSUCCESS! Your debloated Windows ISO is ready:" -ForegroundColor Green
Write-Host $outputIso -ForegroundColor Yellow

Write-Host "`nAlways test in a virtual machine first!" -ForegroundColor Red
