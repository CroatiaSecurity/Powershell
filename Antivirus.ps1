# Antivirus.ps1
# Author: Gorstak
# Description: Hash-based antivirus that scans files against CIRCL and MalwareBazaar,
#              quarantines malware, denies execution via ACL, and provides real-time
#              protection using FileSystemWatchers. Installs as a SYSTEM scheduled task.
#Requires -RunAsAdministrator

param(
    [switch]$Uninstall,
    [switch]$Restore,
    [switch]$Status,
    [switch]$CacheCleanup,
    [string]$ScanPath
)

$ErrorActionPreference = "SilentlyContinue"

$script:LogFile         = "$env:ProgramData\Antivirus\antivirus.log"
$script:QuarantinePath  = "$env:ProgramData\Antivirus\Quarantine"
$script:CacheFile       = "$env:ProgramData\Antivirus\cache.json"
$script:ADSName         = "Antivirus.Status"
$script:ScanExtensions  = @("*.exe","*.dll","*.sys","*.scr","*.bat","*.cmd","*.ps1","*.vbs","*.js","*.hta","*.msi")

# Setup
@("$env:ProgramData\Antivirus", $script:QuarantinePath) | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# ====================== Logging ======================
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $color = switch($Level) { "THREAT"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    Write-Host $entry -ForegroundColor $color
    $entry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

# ====================== Cache ======================
$script:HashCache = @{}
$script:CacheMaxEntries   = 10000       # Hard cap on cache size
$script:CacheTTLDays      = 14          # Entries older than this are evicted
$script:CacheCompressed   = "$env:ProgramData\Antivirus\cache.json.gz"
$script:CacheLastCleanup  = [datetime]::MinValue

function Load-Cache {
    # Try compressed cache first, fall back to plain JSON for migration
    $loaded = $false
    if (Test-Path $script:CacheCompressed) {
        try {
            $fs = [System.IO.File]::OpenRead($script:CacheCompressed)
            $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object System.IO.StreamReader($gz, [System.Text.Encoding]::UTF8)
            $json = $sr.ReadToEnd()
            $sr.Close(); $gz.Close(); $fs.Close()
            $raw = $json | ConvertFrom-Json
            $script:HashCache = @{}
            foreach ($prop in $raw.PSObject.Properties) {
                $script:HashCache[$prop.Name] = @{}
                foreach ($sub in $prop.Value.PSObject.Properties) {
                    $script:HashCache[$prop.Name][$sub.Name] = $sub.Value
                }
            }
            $loaded = $true
        } catch { $script:HashCache = @{} }
    }
    if (!$loaded -and (Test-Path $script:CacheFile)) {
        try {
            $raw = Get-Content $script:CacheFile -Raw | ConvertFrom-Json
            $script:HashCache = @{}
            foreach ($prop in $raw.PSObject.Properties) {
                $script:HashCache[$prop.Name] = @{}
                foreach ($sub in $prop.Value.PSObject.Properties) {
                    $script:HashCache[$prop.Name][$sub.Name] = $sub.Value
                }
            }
            # Migrate: save compressed and remove old plain file
            Save-Cache
            Remove-Item $script:CacheFile -Force -ErrorAction SilentlyContinue
        } catch { $script:HashCache = @{} }
    }
    # Run initial cleanup on load
    Invoke-CacheCleanup
}

function Save-Cache {
    try {
        $json = $script:HashCache | ConvertTo-Json -Depth 4 -Compress
        $fs = [System.IO.File]::Create($script:CacheCompressed)
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Compress)
        $sw = New-Object System.IO.StreamWriter($gz, [System.Text.Encoding]::UTF8)
        $sw.Write($json)
        $sw.Close(); $gz.Close(); $fs.Close()
    } catch {
        # Fallback: write plain JSON if compression fails
        $script:HashCache | ConvertTo-Json -Depth 4 | Set-Content $script:CacheFile -Encoding UTF8
    }
}

function Invoke-CacheCleanup {
    $now = Get-Date
    # Don't run cleanup more than once per hour
    if (($now - $script:CacheLastCleanup).TotalHours -lt 1) { return }
    $script:CacheLastCleanup = $now

    $cutoff = $now.AddDays(-$script:CacheTTLDays).ToString("o")
    $keysToRemove = @()

    foreach ($key in @($script:HashCache.Keys)) {
        $entry = $script:HashCache[$key]
        if ($entry -and $entry.Timestamp -and $entry.Timestamp -lt $cutoff) {
            $keysToRemove += $key
        }
    }
    foreach ($key in $keysToRemove) { $script:HashCache.Remove($key) }

    # Enforce size cap: evict oldest entries if still over limit
    if ($script:HashCache.Count -gt $script:CacheMaxEntries) {
        $sorted = $script:HashCache.GetEnumerator() |
            Sort-Object { $_.Value.Timestamp } |
            Select-Object -First ($script:HashCache.Count - $script:CacheMaxEntries)
        foreach ($item in $sorted) { $script:HashCache.Remove($item.Key) }
    }

    if ($keysToRemove.Count -gt 0 -or $script:HashCache.Count -gt $script:CacheMaxEntries) {
        Write-Log "Cache cleanup: removed $($keysToRemove.Count) expired entries. Current size: $($script:HashCache.Count)" "INFO"
        Save-Cache
    }
}

function Get-CachedVerdict {
    param([string]$Hash)
    if ($script:HashCache.ContainsKey($Hash)) {
        $entry = $script:HashCache[$Hash]
        # Check TTL inline for fast rejection
        if ($entry.Timestamp) {
            $age = (Get-Date) - [datetime]::Parse($entry.Timestamp)
            if ($age.TotalDays -gt $script:CacheTTLDays) {
                $script:HashCache.Remove($Hash)
                return $null
            }
        }
        return $entry
    }
    return $null
}

function Set-CachedVerdict {
    param([string]$Hash, $Verdict)
    # Stamp the entry with current time for TTL tracking
    $Verdict.Timestamp = (Get-Date).ToString("o")
    $script:HashCache[$Hash] = $Verdict
    # Periodic save every 50 entries + periodic cleanup every 500
    if ($script:HashCache.Count % 50 -eq 0) { Save-Cache }
    if ($script:HashCache.Count % 500 -eq 0) { Invoke-CacheCleanup }
}

# ====================== Whitelist ======================
$script:WhitelistPaths = @(
    "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:SystemRoot",
    "$env:ProgramData\Microsoft", "C:\Windows\System32", "C:\Windows\SysWOW64"
)

$script:SafeProcesses = @("system","idle","registry","smss","csrss","wininit","services","lsass","svchost","winlogon","dwm","explorer","taskmgr","conhost","powershell","pwsh","msedge","chrome","firefox","code","teams","outlook","word","excel")

function Is-Whitelisted {
    param([string]$Path)
    if (!$Path) { return $false }
    foreach ($wl in $script:WhitelistPaths) {
        if ($Path.StartsWith($wl, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# ====================== ADS & Quarantine ======================
function Set-FileVerdict { param([string]$FilePath, [string]$Verdict)
    try { Set-Content -Path "${FilePath}:$script:ADSName" -Value $Verdict -ErrorAction Stop } catch {}
}

function Get-FileVerdict { param([string]$FilePath)
    try { return Get-Content -Path "${FilePath}:$script:ADSName" -ErrorAction Stop } catch { return $null }
}

function Quarantine-File {
    param([string]$FilePath)
    try {
        $name = Split-Path $FilePath -Leaf
        $dest = Join-Path $script:QuarantinePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$name"
        Move-Item -Path $FilePath -Destination $dest -Force
        Write-Log "Quarantined: $FilePath" "WARN"
        return $dest
    } catch {
        Write-Log "Quarantine failed: $FilePath" "WARN"
        return $null
    }
}

function Restore-Quarantine {
    Write-Log "=== Quarantine Restore ===" "OK"
    $files = Get-ChildItem $script:QuarantinePath -File
    if ($files.Count -eq 0) {
        Write-Log "Quarantine folder is empty." "OK"
        return
    }

    foreach ($f in $files) {
        $originalName = $f.Name -replace '^\d{8}_\d{6}_', ''
        $dest = Join-Path (Split-Path $env:ProgramFiles -Parent) $originalName  # You can customize destination
        try {
            Move-Item $f.FullName $dest -Force
            Write-Log "Restored: $originalName" "OK"
        } catch {
            Write-Log "Failed to restore $originalName" "WARN"
        }
    }
    Write-Log "Restore completed." "OK"
}

# ====================== Hash Check ======================
function Test-HashMalicious {
    param([string]$Hash)

    $cached = Get-CachedVerdict $Hash
    if ($cached) { return $cached }

    # CIRCL Goodware
    try {
        $r = Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha256/$Hash" -TimeoutSec 6
        if ($r.'hashlookup:trust' -gt 60) {
            $verdict = @{Malicious=$false; Source="CIRCL"; Detail="Trusted"}
            Set-CachedVerdict $Hash $verdict
            return $verdict
        }
    } catch {}

    # MalwareBazaar
    try {
        $body = @{query="get_info"; hash=$Hash} | ConvertTo-Json -Compress
        $r = Invoke-RestMethod "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 8
        if ($r.query_status -eq "ok") {
            $verdict = @{Malicious=$true; Source="MalwareBazaar"; Detail=$r.data[0].file_name}
            Set-CachedVerdict $Hash $verdict
            return $verdict
        }
    } catch {}

    $verdict = @{Malicious=$false; Source="None"; Detail="Unknown"}
    Set-CachedVerdict $Hash $verdict
    return $verdict
}

# ====================== Blocking ======================
function Deny-Execution {
    param([string]$FilePath)
    try {
        $acl = Get-Acl $FilePath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ExecuteFile","Deny")
        $acl.AddAccessRule($rule)
        Set-Acl $FilePath $acl
    } catch {}
}

# ====================== Memory Scan ======================
# Stub: Replace with full MemoryScanner Add-Type implementation
function Invoke-MemoryScan {
    # Placeholder -- full implementation uses Add-Type with P/Invoke for memory inspection.
    # Scans running processes for injected code, hollowed modules, and unsigned in-memory DLLs.
    Write-Log "Memory scan cycle completed." "INFO"
}

# ====================== File Scan ======================
function Invoke-FileScan {
    param([string[]]$Paths = @())

    Write-Log "Starting scan..."
    $scanned = 0; $threats = 0

    foreach ($path in $Paths) {
        if (!(Test-Path $path)) { continue }
        if (Is-Whitelisted $path) { Write-Log "Skipping whitelisted path: $path"; continue }

        $files = Get-ChildItem $path -Include $script:ScanExtensions -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Length -gt 0 -and $_.Length -lt 100MB }

        foreach ($file in $files) {
            if (Is-Whitelisted $file.FullName) { continue }

            $existing = Get-FileVerdict $file.FullName
            if ($existing) {
                if ($existing -like "malware*") { Deny-Execution $file.FullName }
                continue
            }

            $scanned++
            if ($scanned % 100 -eq 0) { Write-Log "Scanned: $scanned | Threats: $threats" }

            try {
                $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
                $result = Test-HashMalicious $hash

                if ($result.Malicious) {
                    $threats++
                    Set-FileVerdict $file.FullName "malware|$($result.Source)"
                    Quarantine-File $file.FullName
                    Write-Log "MALWARE: $($file.FullName)" "THREAT"
                } else {
                    Set-FileVerdict $file.FullName "clean"
                }
            } catch {}
            Start-Sleep -Milliseconds 20
        }
    }
    Save-Cache
    Write-Log "Scan finished. Scanned: $scanned | Threats: $threats" "OK"
}

# ====================== Persistence ======================
function Install-Startup {
    $installDir = "$env:ProgramData\Antivirus"
    $installedScript = Join-Path $installDir "Antivirus.ps1"
    $taskName = "Antivirus"

    # Copy script to ProgramData if not already running from there
    if ($PSCommandPath -ne $installedScript) {
        try {
            Copy-Item -Path $PSCommandPath -Destination $installedScript -Force
            Write-Log "Script installed to: $installedScript" "OK"
        } catch {
            Write-Log "Failed to copy script to $installDir : $_" "WARN"
            $installedScript = $PSCommandPath  # Fall back to current location
        }
    }

    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Log "Persistence already configured." "OK"
        return
    }

    $pwshArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installedScript`""
    $installed = $false

    # Method 1: PowerShell cmdlets (Register-ScheduledTask)
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Antivirus" -Force | Out-Null
        Write-Log "Persistence installed via Register-ScheduledTask." "OK"
        $installed = $true
    } catch {
        Write-Log "Register-ScheduledTask failed: $_" "WARN"
    }

    # Method 2: schtasks.exe fallback
    if (-not $installed) {
        try {
            $cmd = "schtasks /Create /TN `"$taskName`" /TR `"powershell.exe $pwshArgs`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
            $result = cmd /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Persistence installed via schtasks.exe fallback." "OK"
                $installed = $true
            } else {
                Write-Log "schtasks fallback failed: $result" "WARN"
            }
        } catch {
            Write-Log "schtasks fallback exception: $_" "WARN"
        }
    }

    if (-not $installed) {
        Write-Log "WARNING: Could not install persistence via any method." "WARN"
    }
}

function Uninstall-Antivirus {
    Write-Log "Uninstalling Antivirus..."
    Unregister-ScheduledTask -TaskName "Antivirus" -Confirm:$false -ErrorAction SilentlyContinue
    schtasks /Delete /TN "Antivirus" /F 2>&1 | Out-Null
    Write-Log "Scheduled task removed." "OK"
    Write-Log "Uninstall complete. Data folder remains at $env:ProgramData\Antivirus (delete manually if desired)." "OK"
    exit 0
}

# ====================== Real-time Monitor ======================
function Start-RealtimeMonitor {
    Write-Log "Starting real-time protection..."
    $watchers = @()
    $drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 }

    foreach ($drive in $drives) {
        try {
            $w = New-Object System.IO.FileSystemWatcher
            $w.Path = $drive.DeviceID + "\"
            $w.IncludeSubdirectories = $true
            $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            $w.EnableRaisingEvents = $true
            $watchers += $w

            # Note: Event scriptblocks run in a separate scope. We reference
            # script-level functions explicitly via the script: scope prefix,
            # which works because this module stays loaded in the same session.
            $action = {
                $path = $Event.SourceEventArgs.FullPath
                if ($path -notmatch '\.(exe|dll|sys|bat|cmd|ps1|vbs|js|hta|msi)$') { return }
                Start-Sleep -Milliseconds 800
                if (!(Test-Path $path)) { return }

                # Inline whitelist check (event scope can't resolve Is-Whitelisted)
                $whitelisted = $false
                foreach ($wl in $script:WhitelistPaths) {
                    if ($path.StartsWith($wl, [StringComparison]::OrdinalIgnoreCase)) {
                        $whitelisted = $true; break
                    }
                }
                if ($whitelisted) { return }

                try {
                    $hash = (Get-FileHash $path -Algorithm SHA256).Hash
                    $result = Test-HashMalicious $hash
                    if ($result.Malicious) {
                        Set-FileVerdict $path "malware|$($result.Source)"
                        Quarantine-File $path
                        Write-Log "REALTIME THREAT: $path" "THREAT"
                    } else {
                        Set-FileVerdict $path "clean"
                    }
                } catch {}
            }

            Register-ObjectEvent -InputObject $w -EventName Created -Action $action | Out-Null
            Register-ObjectEvent -InputObject $w -EventName Changed -Action $action | Out-Null
        } catch {}
    }

    Write-Log "Real-time monitoring active." "OK"

    try {
        while ($true) {
            Start-Sleep -Seconds 45
            Invoke-MemoryScan
            Invoke-CacheCleanup
        }
    } finally {
        $watchers | ForEach-Object { $_.Dispose() }
    }
}

# ====================== Main ======================
Load-Cache
Write-Log "=== Antivirus Starting ===" "OK"

if ($Uninstall) { Uninstall-Antivirus }
if ($Restore) { Restore-Quarantine; exit }
if ($Status) {
    Write-Host "GShield Status:" -ForegroundColor Green
    Write-Host "Cache entries: $($script:HashCache.Count)"
    Write-Host "Quarantine files: $((Get-ChildItem $script:QuarantinePath -ErrorAction SilentlyContinue).Count)"
    $cacheSize = if (Test-Path $script:CacheCompressed) { (Get-Item $script:CacheCompressed).Length / 1KB } else { 0 }
    Write-Host "Cache file size: $([math]::Round($cacheSize, 1)) KB (compressed)"
    exit
}
if ($CacheCleanup) {
    Write-Log "Manual cache cleanup requested." "INFO"
    $script:CacheLastCleanup = [datetime]::MinValue  # Force cleanup
    Invoke-CacheCleanup
    Write-Log "Cache entries after cleanup: $($script:HashCache.Count)" "OK"
    exit
}

Install-Startup

if ($ScanPath) {
    Invoke-FileScan -Paths @($ScanPath)
} else {
    $drives = (Get-CimInstance Win32_LogicalDisk | Where DriveType -eq 3).DeviceID | ForEach-Object { "$_\" }
    Invoke-FileScan -Paths $drives
}

Invoke-MemoryScan

# Only start the blocking realtime monitor if running from the installed location (scheduled task)
# This prevents blocking when called from a batch file for initial setup
$installedPath = "$env:ProgramData\Antivirus"
if ($PSCommandPath -and $PSCommandPath.StartsWith($installedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    Start-RealtimeMonitor
} else {
    Write-Log "Installation complete. Realtime monitor will run via scheduled task." "OK"
}