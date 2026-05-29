<#
.SYNOPSIS
    Ultimate Windows ISO Debloater – Fully interactive version
    Author: Gorstak
#>

#Requires -RunAsAdministrator

param (
    [switch]$KeepStore,
    [switch]$KeepXbox,
    [switch]$KeepDefender,
    [switch]$KeepEdge,
    [switch]$KeepUpdates
)

Add-Type -AssemblyName System.Windows.Forms

# ==============================
# Helper: File picker dialog
# ==============================
function Select-File($title, $filter) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $title
    $dlg.Filter = $filter
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq "OK") {
        return $dlg.FileName
    } else {
        Write-Host "Operation cancelled by user." -ForegroundColor Red
        exit
    }
}

# ==============================
# 1. Ask user for ISO
# ==============================
Write-Host "Please select your original Windows ISO..." -ForegroundColor Cyan
$IsoPath = Select-File "Select Windows ISO" "ISO files (*.iso)|*.iso"

# ==============================
# 2. Ask user for NTLite XML preset
# ==============================
Write-Host "Please select your NTLite preset XML file..." -ForegroundColor Cyan
$XmlPath = Select-File "Select NTLite Preset XML" "XML files (*.xml)|*.xml|All files (*.*)|*.*"

Write-Host "Using preset: $XmlPath" -ForegroundColor Green

# ==============================
# 3. (Rest of the script – unchanged, just slightly cleaned)
# ==============================

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
Write-Host "Mounting and extracting ISO (this can take 5–15 minutes)..." -ForegroundColor Cyan
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

# Parse XML
Write-Host "Parsing NTLite preset..." -ForegroundColor Cyan
[xml]$xml = Get-Content $XmlPath -Raw -Encoding UTF8
$removeList = $xml.Preset.RemoveComponents.c | ForEach-Object { ($_.InnerText -split " ")[0] }

# Apply keep switches
if ($KeepStore)     { $removeList = $removeList | Where-Object { $_ -notmatch "store|appinstaller|msix" } }
if ($KeepXbox)      { $removeList = $removeList | Where-Object { $_ -notmatch "xbox" } }
if ($KeepDefender)  { $removeList = $removeList | Where-Object { $_ -notmatch "defender|sechealth|securitycenter" } }
if ($KeepEdge)      { $removeList = $removeList | Where-Object { $_ -notmatch "edge|webview" } }
if ($KeepUpdates)   { $removeList = $removeList | Where-Object { $_ -notmatch "update|wu|waas|sih|medic" } }

# Mount WIM
Write-Host "Mounting WIM image..." -ForegroundColor Cyan
& $wimlib mount $wimFile 1 $mountDir --allow-other

# Remove Appx packages
Write-Host "Removing provisioned Appx packages..." -ForegroundColor Green
$apps = Get-AppxProvisionedPackage -Path $mountDir
foreach ($app in $apps) {
    $name = $app.DisplayName + $app.PackageName
    if ($removeList | Where-Object { $name -match $_ }) {
        Write-Host "  → Removing $($app.DisplayName)"
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
            Write-Host "  → $full = $val"
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
