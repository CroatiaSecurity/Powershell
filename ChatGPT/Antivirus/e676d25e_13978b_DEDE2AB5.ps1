# =====================================================================
# Antivirus.ps1
# - ASCII only
# - Implements CIRCL + MalwareBazaar online lookups
# - Scans all fixed drives, memory (process executables), network process executables
# - Quarantine + backup + logging
# - Process-kill best-effort to release file locks
# - Implements exact policy matrix from user
# =====================================================================

# -------------------------
# Configuration
# -------------------------
$Base         = "C:\ProgramData\Antivirus"
$Quarantine   = Join-Path $Base "Quarantine"
$Backup       = Join-Path $Base "Backup"
$LogFile      = Join-Path $Base "antivirus.log"
$TempFile     = Join-Path $Base "temp.json"

# Set your MalwareBazaar Auth Key here if you have one (optional)
$MalwareBazaarAuthKey = ""   # e.g. "abcd-1234-yourkey"

# CIRCL and MalwareBazaar endpoints (public)
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"   # append /<sha256>
$MalwareBazaarApi = "https://mb-api.abuse.ch/api/v1/"            # POST-based API endpoint

# Protected Windows folders - treat differently per your matrix
$WindowsFolders = @("C:\Windows","C:\Program Files","C:\Program Files (x86)")

# Whitelisted (harmless) extensions to reduce noise
$AllowedExtensions = @(
    ".tmp",".log",".txt",".json",".md",".png",".jpg",".jpeg",".gif",
    ".bmp",".ini",".db",".csv"
)

# Processes we will not attempt to kill
$ProtectedProcessNames = @(
    "System","lsass","wininit","winlogon","csrss","services","smss","Registry",
    "svchost","explorer","dwm","SearchUI","SearchIndexer"
)

# Create directories
New-Item -ItemType Directory -Path $Base -Force | Out-Null
New-Item -ItemType Directory -Path $Quarantine -Force | Out-Null
New-Item -ItemType Directory -Path $Backup -Force | Out-Null

# -------------------------
# Logging helpers
# -------------------------
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
}

# -------------------------
# Utilities
# -------------------------
function Compute-Hash($path) {
    try {
        $h = Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop
        return $h.Hash.ToLower()
    } catch {
        return $null
    }
}

function Is-InWindowsPath($path) {
    foreach ($wf in $WindowsFolders) {
        if ($path.ToLower().StartsWith($wf.ToLower())) { return $true }
    }
    return $false
}

function Is-Locked($file) {
    try {
        $stream = [System.IO.File]::Open($file,'Open','ReadWrite','None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

# Best-effort method: check process modules for matching filename
function Get-ProcessesHoldingFile($file) {
    $holders = @()
    $fileLower = $file.ToLower()
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        try {
            foreach ($m in $p.Modules) {
                if ($null -ne $m.FileName -and $m.FileName.ToLower() -eq $fileLower) {
                    $holders += $p
                    break
                }
            }
        } catch { }
    }
    return $holders | Select-Object -Unique
}

function Try-ReleaseFile($file) {
    # Try to politely close processes holding file, then force-kill if necessary
    $holders = Get-ProcessesHoldingFile $file
    if (-not $holders) { return $false }

    foreach ($p in $holders) {
        if ($ProtectedProcessNames -contains $p.Name) {
            Log "Refusing to kill protected process $($p.Name) (PID $($p.Id)) for file $file"
            continue
        }

        try {
            Log "Attempting graceful close of $($p.Name) (PID $($p.Id))"
            $p.CloseMainWindow() | Out-Null
            Start-Sleep -Milliseconds 600
        } catch { }

        if (-not $p.HasExited) {
            try {
                Log "Force killing $($p.Name) (PID $($p.Id))"
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 300
            } catch {
                Log "Failed to stop process $($p.Name) (PID $($p.Id)) : $_"
            }
        } else {
            Log "Process $($p.Name) exited after close request."
        }
    }

    return -not (Is-Locked $file)
}

# -------------------------
# API lookups
# -------------------------

function Query-CIRCL($sha256) {
    if (-not $sha256) { return $null }
    $url = "$CirclLookupBase/$sha256"
    try {
        $resp = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop
        # CIRCL returns JSON describing datasets; treat presence as "found"
        return $resp
    } catch {
        return $null
    }
}

function Query-MalwareBazaar($sha256) {
    if (-not $sha256) { return $null }
    # MalwareBazaar expects POST with form data, e.g. 'query' or 'get_file'
    $body = @{ query = $sha256 }
    if ($MalwareBazaarAuthKey -ne "") {
        $body.Add("auth_key",$MalwareBazaarAuthKey)
    }
    try {
        $resp = Invoke-RestMethod -Uri $MalwareBazaarApi -Method Post -Body $body -ErrorAction Stop
        return $resp
    } catch {
        return $null
    }
}

# -------------------------
# Decision matrix
# -------------------------
function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }

    Write-Host "Scanning: $file"
    Log "Scanning: $file"

    # quick ext whitelist
    $ext = [System.IO.Path]::GetExtension($file).ToLower()
    if ($AllowedExtensions -contains $ext) {
        Write-Host "   -> Extension $ext whitelisted; skip"
        Log "Whitelisted extension: $file"
        return
    }

    # compute hash
    $sha256 = Compute-Hash $file
    if (-not $sha256) {
        Write-Host "   -> Cannot compute hash; skipping"
        Log "Cannot compute hash for: $file"
        return
    }

    # 1) CIRCL trusted list?
    Write-Host "   -> Querying CIRCL for $sha256"
    $circl = Query-CIRCL $sha256
    if ($circl -ne $null -and $circl | Get-Member -Name 'hash' -ErrorAction SilentlyContinue) {
        # presence in CIRCL considered "trusted list"
        Write-Host "   -> Found in CIRCL trusted list; ALLOWED"
        Log "Allowed (CIRCL): $file ($sha256)"
        return
    } elseif ($circl -ne $null -and ($circl | ConvertTo-Json).Length -gt 0) {
        # Some CIRCL replies are structured differently; treat non-null as found
        Write-Host "   -> CIRCL returned data; ALLOWED"
        Log "Allowed (CIRCL): $file ($sha256)"
        return
    } else {
        Write-Host "   -> Not found in CIRCL"
    }

    # 2) Signed by Microsoft?
    Write-Host "   -> Checking digital signature"
    try {
        $sig = Get-AuthenticodeSignature -FilePath $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft Corporation') {
            Write-Host "   -> Valid Microsoft signature; ALLOWED"
            Log "Allowed (Microsoft-signed): $file ($sha256)"
            return
        } else {
            Write-Host "   -> Not Microsoft-signed (Status: $($sig.Status))"
        }
    } catch {
        Write-Host "   -> Error checking signature"
    }

    # 3) MalwareBazaar?
    Write-Host "   -> Querying MalwareBazaar for $sha256"
    $mb = Query-MalwareBazaar $sha256
    if ($mb -ne $null) {
        # MalwareBazaar returns a 'query_status' or 'data' fields; treat non-empty response as positive
        if ($mb.query_status -and $mb.query_status -eq "ok") {
            Write-Host "   -> Found on MalwareBazaar: QUARANTINE"
            Log "Quarantined (MalwareBazaar): $file ($sha256)"
            Do-Quarantine $file
            return
        } elseif ($mb.data -and $mb.data.Count -gt 0) {
            Write-Host "   -> Found on MalwareBazaar (data present): QUARANTINE"
            Log "Quarantined (MalwareBazaar-data): $file ($sha256)"
            Do-Quarantine $file
            return
        } else {
            Write-Host "   -> MalwareBazaar returned no match"
        }
    } else {
        Write-Host "   -> MalwareBazaar lookup failed or returned no match"
    }

    # 4 & 5) Unsigned -> decide based on location
    $inWindows = Is-InWindowsPath $file
    if ($inWindows) {
        Write-Host "   -> Unsigned but inside Windows/Program Files. ALLOWED (logged)"
        Log "Allowed unsigned inside Windows: $file ($sha256)"
        return
    } else {
        Write-Host "   -> Unsigned and outside Windows/Program Files. QUARANTINE"
        Log "Quarantined (unsigned outside): $file ($sha256)"
        Do-Quarantine $file
        return
    }
}

# -------------------------
# Quarantine logic
# -------------------------
function Do-Quarantine($file) {
    if (-not (Test-Path $file -PathType Leaf)) {
        Log "Do-Quarantine: file not found $file"
        return
    }

    if (Is-Locked $file) {
        Write-Host "   -> File locked; attempting to release locks"
        if (-not (Try-ReleaseFile $file)) {
            Write-Host "   -> Could not release file lock; skipping quarantine for now"
            Log "Skip quarantine (locked): $file"
            return
        }
    }

    # perform backup + move
    $name = [IO.Path]::GetFileName($file)
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q = Join-Path $Quarantine ($name + "_" + $ts)

    try {
        Copy-Item -Path $file -Destination $bak -Force -ErrorAction Stop
        Move-Item -Path $file -Destination $q -Force -ErrorAction Stop
        Write-Host "   -> Quarantined to $q (backup: $bak)"
        Log "Quarantined: $file -> $q (bak: $bak)"
    } catch {
        Write-Host "   -> ERROR during quarantine: $_"
        Log "ERROR during quarantine: $file : $_"
    }
}

# -------------------------
# Scanning primitives
# -------------------------
function Scan-Drive($root) {
    Write-Host "Starting scan on drive: $root"
    Log "Drive scan start: $root"

    try {
        # Use Get-ChildItem with error handling; avoid blowing stack on long paths
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)

        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try {
                $entries = Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop
                foreach ($e in $entries) {
                    if ($e.PSIsContainer) {
                        $stack.Push($e.FullName)
                    } else {
                        Decide-And-Act $e.FullName
                    }
                }
            } catch {
                # permission or IO errors -> log and continue
                Log "Error enumerating $dir : $_"
                continue
            }
        }
    } catch {
        Log "Scan-Drive failed for $root : $_"
    }

    Write-Host "Drive scan complete: $root"
    Log "Drive scan complete: $root"
}

function Scan-AllDrives() {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
    foreach ($d in $drives) {
        if ($d.Free -eq $null -and $d.Used -eq $null) { continue }
        # Only scan fixed drives (Type is not directly available here; instead check root exists)
        try {
            $root = $d.Root
            Scan-Drive $root
        } catch {
            Log "Skipping drive $($d.Name): $_"
        }
    }
}

# -------------------------
# Memory and network scanning
# -------------------------
function Scan-Processes() {
    Write-Host "Scanning running processes"
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        try {
            $exe = $null
            try { $exe = $p.MainModule.FileName } catch { $exe = $null }

            if ($exe -and (Test-Path $exe)) {
                Decide-And-Act $exe
            }
        } catch { }
    }
}

function Scan-NetworkProcesses() {
    Write-Host "Scanning network-connected processes (TCP)"
    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" -or $_.State -eq "Listen" }
        foreach ($c in $conns) {
            if ($null -ne $c.OwningProcess -and $c.OwningProcess -ne 0) {
                try {
                    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                    if ($p) {
                        try { $exe = $p.MainModule.FileName } catch { $exe = $null }
                        if ($exe -and (Test-Path $exe)) {
                            Decide-And-Act $exe
                        }
                    }
                } catch {}
            }
        }
    } catch {
        Log "Error scanning network processes: $_"
    }
}

# -------------------------
# Main runtime
# -------------------------
Write-Host "Antivirus script starting."
Log "Antivirus launched."

# 1) One-shot full scan across drives, memory, and network
Scan-AllDrives
Scan-Processes
Scan-NetworkProcesses

# 2) Optional: start light real-time loop scanning TEMP and newly mounted drives every 30 seconds
function Start-RealTime {
    Write-Host "Starting lightweight realtime loop (scans TEMP and new drives every 30s)"
    Log "Realtime loop started"
    while ($true) {
        try {
            # TEMP folders
            $tempPaths = @("$env:TEMP","C:\Windows\Temp")
            foreach ($tp in $tempPaths) {
                if (Test-Path $tp) { 
                    foreach ($f in Get-ChildItem -Path $tp -File -Recurse -ErrorAction SilentlyContinue) {
                        Decide-And-Act $f.FullName
                    }
                }
            }

            # Re-scan processes and network
            Scan-Processes
            Scan-NetworkProcesses
        } catch {
            Log "Realtime loop error: $_"
        }
        Start-Sleep -Seconds 30
    }
}

# Uncomment the next line to enable the realtime loop
# Start-RealTime

Write-Host "Antivirus script finished initial pass."
Log "Antivirus initial pass complete."

# End of script
