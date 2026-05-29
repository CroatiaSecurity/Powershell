# Antivirus.ps1 - Minimal Antivirus
# Author: Gorstak (rewrite)
# Usage: Run as Administrator. Scans all drives, blocks malware execution via ACL.
# Memory scan included. No YARA, no bloat.
#Requires -RunAsAdministrator

param(
    [switch]$Uninstall
)

$ErrorActionPreference = "SilentlyContinue"
$script:LogFile = "$env:ProgramData\Antivirus\antivirus.log"
$script:CachePath = "$env:ProgramData\Antivirus\hashcache.json"
$script:CacheHMACPath = "$env:ProgramData\Antivirus\hashcache.hmac"
$script:FileIndexPath = "$env:ProgramData\Antivirus\fileindex.json"
$script:FileIndexHMACPath = "$env:ProgramData\Antivirus\fileindex.hmac"
$script:BlockedListPath = "$env:ProgramData\Antivirus\blocked.txt"
$script:ScanExtensions = @("*.exe", "*.dll", "*.sys", "*.scr", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js")
$script:HashCache = @{}
$script:FileIndex = @{}

# --- Setup ---
if (!(Test-Path "$env:ProgramData\Antivirus")) {
    New-Item -ItemType Directory -Path "$env:ProgramData\Antivirus" -Force | Out-Null
}

# --- Hash Cache (JSON + HMAC integrity) ---
# HMAC prevents tampering - if cache is modified externally, it's discarded.

function Get-CacheHMACKey {
    try {
        $machineSid = (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop | Select-Object -First 1).SID
        $raw = "$machineSid|$($PSCommandPath)|Antivirus2025"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
    } catch {
        $raw = "$env:COMPUTERNAME|$env:USERNAME|AntivirusFallback"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
    }
}

function Get-CacheHMAC {
    param([string]$Content)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = Get-CacheHMACKey
    $bytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Content))
    return [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()
}

function Test-CacheIntegrity {
    if (!(Test-Path $script:CachePath) -or !(Test-Path $script:CacheHMACPath)) { return $false }
    try {
        $content = Get-Content $script:CachePath -Raw -ErrorAction Stop
        $storedHmac = (Get-Content $script:CacheHMACPath -Raw -ErrorAction Stop).Trim()
        $computedHmac = Get-CacheHMAC -Content $content
        return ($storedHmac -eq $computedHmac)
    } catch { return $false }
}

function Load-HashCache {
    if (Test-Path $script:CachePath) {
        if (Test-CacheIntegrity) {
            try {
                $json = Get-Content $script:CachePath -Raw -ErrorAction Stop | ConvertFrom-Json
                $json.PSObject.Properties | ForEach-Object {
                    $script:HashCache[$_.Name] = $_.Value
                }
                Write-Log "Loaded hash cache: $($script:HashCache.Count) entries (HMAC valid)"
            } catch {
                Write-Log "Cache parse error, starting fresh." "WARN"
                $script:HashCache = @{}
            }
        } else {
            Write-Log "Cache HMAC mismatch - possible tampering. Discarding cache." "WARN"
            Remove-Item $script:CachePath -Force -ErrorAction SilentlyContinue
            Remove-Item $script:CacheHMACPath -Force -ErrorAction SilentlyContinue
            $script:HashCache = @{}
        }
    }
}

function Save-HashCache {
    try {
        $json = $script:HashCache | ConvertTo-Json -Depth 3 -Compress
        Set-Content -Path $script:CachePath -Value $json -Encoding UTF8 -Force
        $hmac = Get-CacheHMAC -Content $json
        Set-Content -Path $script:CacheHMACPath -Value $hmac -Encoding UTF8 -Force
    } catch {}
}

function Get-CachedResult {
    param([string]$Hash)
    if ($script:HashCache.ContainsKey($Hash)) {
        return $script:HashCache[$Hash]
    }
    return $null
}

function Set-CachedResult {
    param([string]$Hash, [bool]$Malicious, [string]$Source, [string]$Detail)
    $script:HashCache[$Hash] = @{
        Malicious = $Malicious
        Source = $Source
        Detail = $Detail
        CheckedAt = (Get-Date).ToString("o")
    }
}

# --- File Index (path -> LastWriteTime + Size) ---
# Tracks which files have been processed. If unchanged, skip entirely - no hash, no API.

function Load-FileIndex {
    if ((Test-Path $script:FileIndexPath) -and (Test-Path $script:FileIndexHMACPath)) {
        try {
            $content = Get-Content $script:FileIndexPath -Raw -ErrorAction Stop
            $storedHmac = (Get-Content $script:FileIndexHMACPath -Raw -ErrorAction Stop).Trim()
            $computedHmac = Get-CacheHMAC -Content $content
            if ($storedHmac -ne $computedHmac) {
                Write-Log "File index HMAC mismatch - full rescan required." "WARN"
                Remove-Item $script:FileIndexPath -Force -ErrorAction SilentlyContinue
                Remove-Item $script:FileIndexHMACPath -Force -ErrorAction SilentlyContinue
                return
            }
            $json = $content | ConvertFrom-Json
            $json.PSObject.Properties | ForEach-Object {
                $script:FileIndex[$_.Name] = $_.Value
            }
            Write-Log "Loaded file index: $($script:FileIndex.Count) entries"
        } catch {
            Write-Log "File index load error, full rescan." "WARN"
            $script:FileIndex = @{}
        }
    }
}

function Save-FileIndex {
    try {
        $json = $script:FileIndex | ConvertTo-Json -Depth 2 -Compress
        Set-Content -Path $script:FileIndexPath -Value $json -Encoding UTF8 -Force
        $hmac = Get-CacheHMAC -Content $json
        Set-Content -Path $script:FileIndexHMACPath -Value $hmac -Encoding UTF8 -Force
    } catch {}
}

function Test-FileNeedsScan {
    param([System.IO.FileInfo]$File)
    $key = $File.FullName.ToLower()
    if ($script:FileIndex.ContainsKey($key)) {
        $stored = $script:FileIndex[$key]
        if ($stored.LastWrite -eq $File.LastWriteTime.ToString("o") -and $stored.Size -eq $File.Length) {
            return $false
        }
    }
    return $true
}

function Set-FileIndexed {
    param([System.IO.FileInfo]$File, [string]$Hash)
    $key = $File.FullName.ToLower()
    $script:FileIndex[$key] = @{
        LastWrite = $File.LastWriteTime.ToString("o")
        Size = $File.Length
        Hash = $Hash
    }
}

Load-HashCache
Load-FileIndex

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    Write-Host $entry -ForegroundColor $(switch($Level) { "THREAT" {"Red"} "WARN" {"Yellow"} "OK" {"Green"} default {"Gray"} })
    $entry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

# --- API Checks ---
function Test-HashMalicious {
    param([string]$Hash)

    # 1. CIRCL Hashlookup - known good check
    try {
        $r = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$Hash" -Method Get -TimeoutSec 8 -ErrorAction Stop
        if ($r.'hashlookup:trust' -and [int]$r.'hashlookup:trust' -gt 50) {
            return @{ Malicious = $false; Source = "CIRCL"; Detail = "Trust=$($r.'hashlookup:trust')" }
        }
    } catch {}

    # 2. MalwareBazaar - known bad check
    try {
        $body = @{ query = "get_info"; hash = $Hash } | ConvertTo-Json -Compress
        $r = Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        if ($r.query_status -eq "hash_not_found") {
            # not in malware DB
        } elseif ($r.query_status -eq "ok" -or $r.query_status -eq "hash_found") {
            return @{ Malicious = $true; Source = "MalwareBazaar"; Detail = "Known malware sample" }
        }
    } catch {}

    # 3. Team Cymru MHR (DNS-based, uses SHA1/MD5 - skip for SHA256)
    # Future: add MD5 hash and query via DNS TXT

    return @{ Malicious = $false; Source = "None"; Detail = "Not found in threat databases" }
}

# --- File Scanner ---
function Invoke-FileScan {
    param([string[]]$Paths)

    Write-Log "Starting file scan across: $($Paths -join ', ')"
    $scanned = 0; $threats = 0; $skipped = 0
    $selfPath = $PSCommandPath.ToLower()
    $dataPath = "$env:ProgramData\Antivirus".ToLower()

    foreach ($scanPath in $Paths) {
        if (!(Test-Path $scanPath)) { continue }

        $files = Get-ChildItem -Path $scanPath -Include $script:ScanExtensions -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 -and $_.Length -lt 100MB -and
                           $_.FullName.ToLower() -ne $selfPath -and
                           !$_.FullName.ToLower().StartsWith($dataPath) }

        foreach ($file in $files) {
            # Tier 1: File index - skip if path+LastWrite+Size unchanged (no disk read)
            if (!(Test-FileNeedsScan -File $file)) {
                $skipped++
                continue
            }

            # Tier 2: Hash the file, check hash cache (avoids API call)
            try {
                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch { continue }

            $cached = Get-CachedResult -Hash $hash
            if ($cached) {
                # Known hash - apply verdict without API call
                if ($cached.Malicious) {
                    Deny-Execution -FilePath $file.FullName
                }
                Set-FileIndexed -File $file -Hash $hash
                $skipped++
                continue
            }

            # Tier 3: Unknown hash - hit APIs
            $scanned++
            if ($scanned % 100 -eq 0) {
                Write-Log "Progress: $scanned API-checked, $threats threats, $skipped skipped..."
                if ($scanned % 500 -eq 0) { Save-HashCache; Save-FileIndex }
            }

            $result = Test-HashMalicious -Hash $hash

            if ($result.Malicious) {
                $threats++
                Deny-Execution -FilePath $file.FullName
                Write-Log "MALWARE: $($file.FullName) [$($result.Source): $($result.Detail)]" "THREAT"
            }

            Set-CachedResult -Hash $hash -Malicious $result.Malicious -Source $result.Source -Detail $result.Detail
            Set-FileIndexed -File $file -Hash $hash
            Start-Sleep -Milliseconds 50
        }
    }

    Save-HashCache
    Save-FileIndex
    Write-Log "Scan complete. API-checked=$scanned, Threats=$threats, Skipped=$skipped" "OK"
}

# --- Execution Denial ---
function Deny-Execution {
    param([string]$FilePath)

    # Never block ourselves or our data
    $selfPath = $PSCommandPath.ToLower()
    $dataPath = "$env:ProgramData\Antivirus".ToLower()
    $targetLower = $FilePath.ToLower()
    if ($targetLower -eq $selfPath -or $targetLower.StartsWith($dataPath)) { return }

    try {
        $acl = Get-Acl -Path $FilePath
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Everyone", "ExecuteFile", "Deny"
        )
        $acl.AddAccessRule($denyRule)
        Set-Acl -Path $FilePath -AclObject $acl
        # Track blocked files for uninstall
        $FilePath | Out-File -FilePath $script:BlockedListPath -Append -Encoding UTF8
        Write-Log "Blocked execution: $FilePath" "WARN"
    } catch {
        Write-Log "Failed to block: $FilePath - $_" "WARN"
    }
}

# --- Memory Scan ---
# Behavioral heuristics - detects injected/reflective/hollowed code regardless of naming

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemoryScanner {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_READ = 0x0010;

    public static int CountRWXRegions(int pid) {
        int count = 0;
        IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (handle == IntPtr.Zero) return -1;

        try {
            IntPtr address = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION mbi;
            while (VirtualQueryEx(handle, address, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0) {
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
                    count++;
                }
                address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                if (address.ToInt64() <= mbi.BaseAddress.ToInt64()) break;
            }
        } finally {
            CloseHandle(handle);
        }
        return count;
    }
}
"@ -ErrorAction SilentlyContinue

$script:SafeProcesses = @(
    "system", "idle", "registry", "smss", "csrss", "wininit", "services",
    "lsass", "svchost", "winlogon", "dwm", "explorer", "taskmgr",
    "conhost", "fontdrvhost", "sihost", "runtimebroker", "taskhostw",
    "searchindexer", "spoolsv", "dllhost", "wudfhost", "audiodg",
    "powershell", "pwsh", "msedge", "chrome", "firefox", "code"
)

function Invoke-MemoryScan {
    Write-Log "Memory scan started..."
    $threats = 0
    $selfPath = $PSCommandPath.ToLower()

    Get-Process | Where-Object { $_.Id -notin @(0, 4, $PID) } | ForEach-Object {
        $procName = $_.ProcessName.ToLower()
        if ($script:SafeProcesses -contains $procName) { return }

        # Skip other instances of this script
        try {
            $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction Stop
            if ($wmi.CommandLine -and $wmi.CommandLine.ToLower().Contains($selfPath)) { return }
        } catch {}

        $flags = @()

        # H1: No backing file on disk
        if ([string]::IsNullOrEmpty($_.Path) -or !(Test-Path $_.Path -ErrorAction SilentlyContinue)) {
            $flags += "NoBackingFile"
        }

        # H2: Image path vs main module mismatch (process hollowing)
        try {
            if ($_.Path -and $_.Modules.Count -gt 0 -and $_.Modules[0].FileName) {
                if ($_.Modules[0].FileName.ToLower() -ne $_.Path.ToLower()) {
                    $flags += "ImageMismatch"
                }
            }
        } catch {}

        # H3: RWX private memory regions (shellcode/injection)
        try {
            $rwx = [MemoryScanner]::CountRWXRegions($_.Id)
            if ($rwx -gt 5) { $flags += "RWX($rwx)" }
        } catch {}

        # H4: High private memory with few modules (injected payload)
        if ($_.PrivateMemorySize64 -gt 800MB -and $_.Modules.Count -lt 8) {
            $flags += "HighMemLowMods"
        }

        # H5: Unsigned binary in non-standard location
        try {
            if ($_.Path -and (Test-Path $_.Path)) {
                $p = $_.Path.ToLower()
                $standard = $p.StartsWith("c:\windows\") -or $p.StartsWith("c:\program files\") -or $p.StartsWith("c:\program files (x86)\")
                if (!$standard) {
                    $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction Stop
                    if ($sig.Status -ne "Valid") { $flags += "UnsignedNonStandard" }
                }
            }
        } catch {}

        # Verdict: 2+ flags = kill
        if ($flags.Count -ge 2) {
            $threats++
            Write-Log "MEMORY THREAT: $($_.ProcessName) (PID:$($_.Id)) - $($flags -join ' | ')" "THREAT"
            try { Stop-Process -Id $_.Id -Force } catch {}
        }
    }

    Write-Log "Memory scan complete. Threats: $threats" $(if ($threats -gt 0) {"THREAT"} else {"OK"})
}

# --- Real-time Monitor ---
function Start-RealtimeMonitor {
    Write-Log "Starting real-time file monitor..."

    $drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3) }
    $watchers = @()

    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        try {
            $w = New-Object System.IO.FileSystemWatcher
            $w.Path = $root
            $w.IncludeSubdirectories = $true
            $w.NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite'
            $w.EnableRaisingEvents = $true
            $watchers += $w

            $action = {
                $path = $Event.SourceEventArgs.FullPath
                if ($path -notmatch '\.(exe|dll|sys|scr|bat|cmd|ps1|vbs|js)$') { return }
                Start-Sleep -Milliseconds 500
                if (!(Test-Path $path)) { return }

                try {
                    $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash

                    # Check hash cache first
                    $cached = Get-CachedResult -Hash $hash
                    if ($cached) {
                        if ($cached.Malicious) {
                            Deny-Execution -FilePath $path
                            Write-Log "REALTIME THREAT (cached): $path" "THREAT"
                        }
                        $fi = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                        if ($fi) { Set-FileIndexed -File $fi -Hash $hash; Save-FileIndex }
                        return
                    }

                    $result = Test-HashMalicious -Hash $hash
                    if ($result.Malicious) {
                        Deny-Execution -FilePath $path
                        Write-Log "REALTIME THREAT: $path [$($result.Source)]" "THREAT"
                    }
                    Set-CachedResult -Hash $hash -Malicious $result.Malicious -Source $result.Source -Detail $result.Detail
                    $fi = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                    if ($fi) { Set-FileIndexed -File $fi -Hash $hash }
                    Save-HashCache
                    Save-FileIndex
                } catch {}
            }

            Register-ObjectEvent -InputObject $w -EventName Created -Action $action | Out-Null
            Register-ObjectEvent -InputObject $w -EventName Changed -Action $action | Out-Null
            Write-Log "Watching: $root"
        } catch {
            Write-Log "Could not watch $root" "WARN"
        }
    }

    Write-Log "Real-time monitor active. Press Ctrl+C to stop." "OK"

    try {
        while ($true) {
            Start-Sleep -Seconds 60
            Invoke-MemoryScan
        }
    } finally {
        $watchers | ForEach-Object { $_.Dispose() }
        Write-Log "Monitor stopped."
    }
}

# --- Persistence ---
function Install-Startup {
    $scriptPath = $PSCommandPath
    $taskName = "Antivirus"

    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Already installed as scheduled task."
        return
    }

    # Method 1: PowerShell cmdlets
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description "Antivirus Monitor" -Force -ErrorAction Stop | Out-Null

        Write-Log "Installed startup task (PowerShell method)." "OK"
        return
    } catch {
        Write-Log "PowerShell task registration failed: $_ - trying schtasks..." "WARN"
    }

    # Method 2: schtasks.exe fallback
    try {
        $cmd = "schtasks /Create /TN `"$taskName`" /TR `"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"$scriptPath\`"`" /SC ONSTART /RU SYSTEM /RL HIGHEST /F"
        $result = cmd /c $cmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Installed startup task (schtasks fallback)." "OK"
        } else {
            Write-Log "schtasks also failed: $result" "WARN"
        }
    } catch {
        Write-Log "All persistence methods failed: $_" "WARN"
    }
}

function Uninstall-Antivirus {
    Write-Log "Uninstalling Antivirus..."
    $taskName = "Antivirus"

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Removed scheduled task." "OK"
    } catch {}
    try { schtasks /Delete /TN "$taskName" /F 2>&1 | Out-Null } catch {}

    # Kill other running instances
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like "*Antivirus*" } |
            ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped running instance (PID:$($_.ProcessId))" "OK"
            }
    } catch {}

    # Restore execution permissions on blocked files
    Write-Log "Restoring execution permissions on blocked files..."
    if (Test-Path $script:BlockedListPath) {
        try {
            Get-Content $script:BlockedListPath -ErrorAction Stop | ForEach-Object {
                $f = $_.Trim()
                if ($f -and (Test-Path $f)) {
                    try {
                        $acl = Get-Acl -Path $f
                        $denyRules = $acl.Access | Where-Object {
                            $_.AccessControlType -eq "Deny" -and $_.FileSystemRights -match "ExecuteFile"
                        }
                        foreach ($rule in $denyRules) { $acl.RemoveAccessRule($rule) | Out-Null }
                        Set-Acl -Path $f -AclObject $acl
                    } catch {}
                }
            }
        } catch {}
    }

    Write-Log "Uninstall complete. Data at $env:ProgramData\Antivirus can be deleted manually." "OK"
    exit 0
}

# --- Main ---
Write-Log "=== Antivirus Starting ===" "OK"

if ($Uninstall) { Uninstall-Antivirus }

Install-Startup

$drives = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }).DeviceID | ForEach-Object { "$_\" }
Invoke-FileScan -Paths $drives
Invoke-MemoryScan
Start-RealtimeMonitor
