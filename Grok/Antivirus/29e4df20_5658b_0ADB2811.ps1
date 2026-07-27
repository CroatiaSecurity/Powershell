# Antivirus by Gorstak

$ErrorActionPreference = "SilentlyContinue"
$Quarantine = "C:\Quarantine\CleanGuard"
$Backup     = "C:\ProgramData\CleanGuard\Backup"
$LogFile    = "C:\ProgramData\CleanGuard\log.txt"
$LastFile   = "C:\Quarantine\CleanGuard\.last"

@($Quarantine, $Backup, (Split-Path $LogFile -Parent)) | ForEach-Object { 
    if(!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

function Log($msg) {
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | $msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Log "CleanGuard.ps1 started – monitoring .exe, .dll, .sys and .winmd"

# Microsoft trusted thumbprints (common ones)
$TrustedThumbprints = "109F2DD82E0C9D1E6B2B9A46B2D4B5E4F5B9F5D6|3A2F5E8F4E5D6C8B9A1F2E3D4C5B6A7F8E9D0C1B|331E2041A6A0F4079C61C9E8B17B18D9D1A8F4E0"

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
            if ($sig.SignerCertificate.Thumbprint -match $TrustedThumbprints) { return $true }
        }
    } catch {}
    return $false
}

function Move-ToQuarantine($file) {
    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $bak  = Join-Path $Backup "$name`_$ts.bak"
    $q    = Join-Path $Quarantine "$name`_$ts"

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force -ErrorAction SilentlyContinue

    "$bak|$file" | Out-File $LastFile -Encoding UTF8

    Log "QUARANTINED → $q"
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("$name`n→ Quarantined", "CleanGuard", 0, 48) | Out-Null
}

function Undo-LastQuarantine {
    if(!(Test-Path $LastFile)) { return }
    $line = Get-Content $LastFile
    $bak, $orig = $line.Split('|')
    if(Test-Path $orig) { Remove-Item $orig -Force }
    Move-Item ($bak -replace '\.bak$','') $orig -Force -ErrorAction SilentlyContinue
    Remove-Item $LastFile
    Log "UNDO → restored $([IO.Path]::GetFileName($orig))"
    [System.Windows.Forms.MessageBox]::Show("Last file restored!", "CleanGuard", 0, 64) | Out-Null
}

# ─── Real-time monitoring (now includes .winmd) ───
$watcher = New-Object IO.FileSystemWatcher
$watcher.Path = "C:\"
$watcher.IncludeSubdirectories = $true
$watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite

$action = {
    $path = $Event.SourceEventArgs.FullPath
    # Now checks .exe, .dll, .sys and .winmd
    if($path -notmatch '\.(exe|dll|sys|winmd)$') { return }

    Start-Sleep -Milliseconds 1200
    if(!(Test-Path $path)) { return }

    $name = [IO.Path]::GetFileName($path)
    $hash = Get-SHA256 $path

    # 1. Known-good via CIRCL → skip
    if(Test-KnownGood $hash) {
        Log "Known-good (CIRCL): $name"
        return
    }

    # 2. Microsoft signed → trust
    if(Test-SignedByMicrosoft $path) {
        Log "Trusted Microsoft file: $name"
        return
    }

    # 3. MalwareBazaar match → instant quarantine
    if(Test-MalwareBazaar $hash) {
        Log "MALWARE DETECTED (MalwareBazaar): $name"
        Move-ToQuarantine $path
        return
    }

    # 4. Suspicious unsigned file outside system folders
    $lower = $path.ToLower()
    if($lower -notmatch 'c:\\windows\\|c:\\program files\\|c:\\program files \(x86\)\\|c:\\windowsapps\\') {
        Log "SUSPICIOUS unsigned PE/WinMD: $name → $path"
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Suspicious unsigned file detected:`n`n$path`n`nQuarantine it?", 
            "CleanGuard", 4+48, "YesNo")
        if($choice -eq "Yes") { Move-ToQuarantine $path }
    }
}

Register-ObjectEvent $watcher Created  -Action $action -ErrorAction SilentlyContinue | Out-Null
Register-ObjectEvent $watcher Changed -Action $action -ErrorAction SilentlyContinue | Out-Null
$watcher.EnableRaisingEvents = $true

# ─── Tray icon ───
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = "CleanGuard – Monitoring .exe/.dll/.sys/.winmd"
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.Items.Add("Open Quarantine", $null, { explorer $Quarantine }) | Out-Null
$menu.Items.Add("Undo Last", $null, { Undo-LastQuarantine }) | Out-Null
$menu.Items.Add("Exit", $null, { 
    $notify.Visible = $false
    $watcher.Dispose()
    Log "CleanGuard stopped"
    exit
}) | Out-Null
$notify.ContextMenuStrip = $menu

Log "Real-time protection ACTIVE (including .winmd files)"
[System.Windows.Forms.MessageBox]::Show("CleanGuard is running!`nNow monitoring .exe, .dll, .sys and .winmd files.", "CleanGuard", 0, 64) | Out-Null

# Keep alive
try { while($true) { Start-Sleep -Seconds 3600 } }
finally {
    $notify.Visible = $false
    $watcher.Dispose()
}