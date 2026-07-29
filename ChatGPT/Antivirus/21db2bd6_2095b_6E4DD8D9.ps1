# ================= HARD MEMORY CONTAINMENT (IMMEDIATE FIX) =================

# ---- Absolute caps ----
$global:MAX_THROTTLE_ENTRIES = 3000
$global:MAX_FS_EVENTS       = 1000

# ---- Safe capped hashtables ----
if (-not $global:PIDScanThrottle)  { $global:PIDScanThrottle  = @{} }
if (-not $global:FileScanThrottle) { $global:FileScanThrottle = @{} }

function Prune-Table {
    param([hashtable]$Table,[int]$Max)
    if ($Table.Count -le $Max) { return }
    $Table.Keys |
        Select-Object -First ($Table.Count - $Max) |
        ForEach-Object { $Table.Remove($_) }
}

# ---- Throttle wrappers (REQUIRED) ----
function Allow-PIDScan($Pid,[int]$Cooldown=300) {
    $now = Get-Date
    if ($global:PIDScanThrottle.ContainsKey($Pid) -and
        $global:PIDScanThrottle[$Pid] -gt $now.AddSeconds(-$Cooldown)) {
        return $false
    }
    $global:PIDScanThrottle[$Pid] = $now
    Prune-Table $global:PIDScanThrottle $global:MAX_THROTTLE_ENTRIES
    return $true
}

function Allow-FileScan($Path,[int]$Cooldown=600) {
    $now = Get-Date
    if ($global:FileScanThrottle.ContainsKey($Path) -and
        $global:FileScanThrottle[$Path] -gt $now.AddSeconds(-$Cooldown)) {
        return $false
    }
    $global:FileScanThrottle[$Path] = $now
    Prune-Table $global:FileScanThrottle $global:MAX_THROTTLE_ENTRIES
    return $true
}

# ---- Kill ALL leaked event subscribers from reloads ----
Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue

# ---- Bounded FileSystemWatcher queue ----
$script:FSQueue = New-Object System.Collections.Generic.Queue[string]

function Enqueue-FS {
    param($Path)
    if ($script:FSQueue.Count -ge $global:MAX_FS_EVENTS) {
        $null = $script:FSQueue.Dequeue()
    }
    $script:FSQueue.Enqueue($Path)
}

# ---- Drain job buffers periodically ----
Start-Job {
    while ($true) {
        Start-Sleep 120
        Get-Job | ForEach-Object {
            try { Receive-Job $_ -Keep | Out-Null } catch {}
        }
        [System.GC]::Collect()
    }
} | Out-Null

# ================= END HARD MEMORY CONTAINMENT =================
