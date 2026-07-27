# Antivirus.ps1
# Author: Gorstak

$ErrorActionPreference = "SilentlyContinue"

$Quarantine = "C:\ProgramData\CleanGuard\Quarantine"
$Backup     = "C:\ProgramData\CleanGuard\Backup"
$LogFile    = "C:\ProgramData\CleanGuard\log.txt"
$LastFile   = "C:\ProgramData\CleanGuard\Quarantine\.last"

@($Quarantine, $Backup, (Split-Path $LogFile -Parent)) | ForEach-Object {
    if(!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

function Log($msg) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Log "CleanGuard started - monitoring .exe, .dll, .sys and .winmd"

function Get-SHA256($path) {
    (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
}

function Test-KnownGood($hash) {
    try {
        $json = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 8
        return ($json.'hashlookup:trust' -gt 50)
    } catch { return $false }
}

function Test-MalwareBazaar($hash) {
    $body = @{ query = "get_info"; hash = $hash } | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "https://mb-api.abuse.ch/api/v1/" -Body $body -ContentType "application/json" -TimeoutSec 12
        return ($resp.query_status -eq "hash_found")
    } catch { return $false }
}

function Test-SignedByMicrosoft($path) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path
        if ($sig.Status -eq "Valid") {
            if ($sig.SignerCertificate.Subject -match "O=Microsoft Corporation") { return $true }
            if ($sig.SignerCertificate.Thumbprint -match "109F2DD82E0C9D1E6B2B9A46B2D4B5E4F5B9F5D6|3A2F5E8F4E5D6C8B9A1F2E3D4C5B6A7F8E9D0C1B") { return $true }
        }
    } catch {}
    return $false
}

function Move-ToQuarantine($file) {
    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force

    "$bak|$file" | Out-File $LastFile -Encoding UTF8

    Log "QUARANTINED -> $q"
    [System.Windows.Forms.MessageBox]::Show("$name`nQuarantined!", "CleanGuard", "OK", "Warning") | Out-Null
}

function Undo-LastQuarantine {
    if(!(Test-Path $LastFile)) { return }
    $line = Get-Content $LastFile
    $bak, $orig = $line.Split('|')
    if(Test-Path $orig) { Remove-Item $orig -Force }
    Move-Item $bak $orig -Force
    Remove-Item $LastFile
    Log "UNDO -> restored $name"
    [System.Windows.Forms.MessageBox]::Show("Last file restored!", "CleanGuard", "OK", "Information") | Out-Null
}

# Real-time monitoring
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    $watchers = @()
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Setting up FileSystemWatcher for drive: $root"
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
	        $watcher.NotifyFilter = "FileName,LastWrite"
    }
}

$action = {
    $path = $Event.SourceEventArgs.FullPath
    if($path -notmatch '\.(exe|dll|sys|winmd)$') { return }

    Start-Sleep -Milliseconds 1200
    if(!(Test-Path $path)) { return }

    $name = [IO.Path]::GetFileName($path)
    $hash = Get-SHA256 $path

    if(Test-KnownGood $hash) {
        Log "Known-good (CIRCL): $name"
        return
    }
    if(Test-SignedByMicrosoft $path) {
        Log "Trusted Microsoft: $name"
        return
    }
    if(Test-MalwareBazaar $hash) {
        Log "MALWARE DETECTED (MalwareBazaar): $name"
        Move-ToQuarantine $path
        return
    }

    $lower = $path.ToLower()
    if($lower -notmatch 'c:\\windows\\|c:\\program files\\|c:\\program files \(x86\)\\|c:\\windowsapps\\') {
        Log "SUSPICIOUS unsigned file: $name"
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Suspicious unsigned file detected:`n`n$path`n`nQuarantine it?", 
            "Antivirus", "YesNo", "Warning")
        if($choice -eq "Yes") { Move-ToQuarantine $path }
    }
}

Register-ObjectEvent $watcher Created  -Action $action | Out-Null
Register-ObjectEvent $watcher Changed -Action $action | Out-Null
$watcher.EnableRaisingEvents = $true

# Tray icon
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = "CleanGuard - Real-time protection ON"
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.Items.Add("Open Quarantine", $null, { explorer $Quarantine }) | Out-Null
$menu.Items.Add("Undo Last", $null, { Undo-LastQuarantine }) | Out-Null
$menu.Items.Add("Exit", $null, {
    $notify.Visible = $false
    $watcher.Dispose()
    Log "CleanGuard stopped by user"
    exit
}) | Out-Null
$notify.ContextMenuStrip = $menu

Log "Real-time protection ACTIVE"
[System.Windows.Forms.MessageBox]::Show("CleanGuard is now running!`nMonitoring .exe, .dll, .sys and .winmd files.", "CleanGuard", "OK", "Information") | Out-Null

# Keep script alive
try { while($true) { Start-Sleep -Seconds 3600 } }
finally {
    $notify.Visible = $false
    $watcher.Dispose()
}