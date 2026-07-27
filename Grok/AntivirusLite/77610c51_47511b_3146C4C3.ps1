# AntivirusLite.ps1
# Author: Gorstak

$Config = @{
    BaseDirectory           = "C:\ProgramData\Antivirus"
    QuarantineDirectory     = "C:\ProgramData\Antivirus\Quarantine"
    BackupDirectory         = "C:\ProgramData\Antivirus\Backup"
    LogFile                 = "C:\ProgramData\Antivirus\av.log"
    BlockedLogFile          = "C:\ProgramData\Antivirus\blocked.log"
    DatabaseFile            = "C:\ProgramData\Antivirus\known_files.db"
    
    MaxDatabaseEntries      = 50000
    MaxLogSizeMB            = 10
    MemoryScanIntervalSec   = 8
    MemoryScanMaxSizeMB     = 150
    ProcessTimeoutSeconds   = 30
    DatabaseCleanupDays     = 30
    
    EnableMemoryScanning    = $true
    EnableRealtimeMonitor   = $true
    EnableThreatIntel       = $true
    EnableAlerts            = $true
    AutoQuarantine          = $true
    
    MalwareBazaarApiKey     = ""
    CirclHashLookupUrl      = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl             = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl     = "https://mb-api.abuse.ch/api/v1/"
    
    CymruDetectionThreshold = 60
    SuspiciousFileSizeKB    = 3072
}

$BehaviorConfig = @{
    EnableBehaviorKill      = $true
    EnableAutoBlockC2       = $true
    DeepScanIntervalHours   = 6
    ThreatIntelUpdateDays   = 7
}

$RulesDirectory = Join-Path $Config.BaseDirectory "rules"
$KnownFilesCache = @{}

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

$AllowedSIDs = @('S-1-2-0', 'S-1-5-20')

$RiskyPaths = @('\temp\', '\downloads\', '\appdata\local\temp\', '\public\', '\windows\temp\', '\appdata\roaming\', '\desktop\')

$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1','.exif',
   
    # Extended list (unchanged from original)
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.elf','.ecf','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.command','.cnt','.cnv','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)

$ProtectedProcesses = @(
    'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass',
    'svchost', 'winlogon', 'explorer', 'dwm', 'SearchUI', 'SearchIndexer', 'fontdrvhost',
    'RuntimeBroker', 'sihost', 'taskhostw'
)

$EvilStrings = @(
    'mimikatz', 'sekurlsa::', 'kerberos::', 'lsadump::', 'wdigest', 'tspkg',
    'http-beacon', 'https-beacon', 'cobaltstrike', 'sleepmask', 'reflective',
    'amsi.dll', 'AmsiScanBuffer', 'EtwEventWrite', 'MiniDumpWriteDump',
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'ReflectiveLoader', 'sharpchrome', 'rubeus', 'safetykatz', 'sharphound',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit', 'empire'
)

New-Item -ItemType Directory -Path $Config.BaseDirectory, $Config.QuarantineDirectory, $Config.BackupDirectory, $RulesDirectory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message)
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp | $Message"
    
    try {
        $logLine | Out-File -FilePath $Config.LogFile -Append -Encoding UTF8
    } catch {
        Write-Host "[LOG ERROR] $_"
    }
    
    Write-Host $logLine
    
    if (Test-Path $Config.LogFile) {
        $logSize = (Get-Item $Config.LogFile -ErrorAction SilentlyContinue).Length
        if ($logSize -ge ($Config.MaxLogSizeMB * 1MB)) {
            $archiveName = "$($Config.BaseDirectory)\av_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                Rename-Item -Path $Config.LogFile -NewName $archiveName -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

Write-Log "=== Clean Antivirus Starting ==="
Write-Log "Admin: $IsAdmin | User: $env:USERNAME | SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

function Load-Database {
    if (Test-Path $Config.DatabaseFile) {
        try {
            $lines = Get-Content $Config.DatabaseFile -ErrorAction Stop
            $count = 0
            
            foreach ($line in $lines) {
                if ($line -match '^([0-9a-f]{64}),(true|false),(.+)$') {
                    $hash = $matches[1]
                    $safe = [bool]::Parse($matches[2])
                    $timestamp = $matches[3]
                    
                    try {
                        $entryDate = [datetime]::Parse($timestamp)
                        if ($entryDate -lt (Get-Date).AddDays(-$Config.DatabaseCleanupDays)) {
                            continue
                        }
                    } catch {}
                    
                    $KnownFilesCache[$hash] = $safe
                    $count++
                    
                    if ($count -ge $Config.MaxDatabaseEntries) {
                        break
                    }
                }
            }
            
            Write-Log "Loaded $count entries from database"
        } catch {
            Write-Log "Failed to load database: $_"
            $KnownFilesCache.Clear()
        }
    } else {
        New-Item -Path $Config.DatabaseFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Created new database file"
    }
}

function Save-ToDatabase {
    param(
        [string]$Hash,
        [bool]$IsSafe
    )
    
    if (-not $Hash) { return }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$Hash,$IsSafe,$timestamp"
    
    try {
        $entry | Out-File -FilePath $Config.DatabaseFile -Append -Encoding UTF8
        $KnownFilesCache[$Hash] = $IsSafe
    } catch {
        Write-Log "Failed to save to database: $_"
    }
    
    if ($KnownFilesCache.Count -gt $Config.MaxDatabaseEntries) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

Load-Database

function Test-ShouldExclude {
    param([string]$FilePath)
    
    $lower = $FilePath.ToLower()
    
    if ($lower -like '*\assembly\*') { return $true }
    if ($lower -like '*\winsxs\*') { return $true }
    if ($lower -like '*\microsoft.net\*') { return $true }
    if ($lower -like '*\windows\system32\config\*') { return $true }
    if ($lower -like '*ctfmon*' -or $lower -like '*msctf.dll' -or $lower -like '*msutb.dll') {
        return $true
    }
    
    return $false
}

function Get-FileHashSafe {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch {
        return $null
    }
}

function Get-FileSignatureInfo {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $hash = Get-FileHashSafe -FilePath $FilePath
        
        return [PSCustomObject]@{
            Hash          = $hash
            Status        = $signature.Status
            StatusMessage = $signature.StatusMessage
            SignerName    = $signature.SignerCertificate.Subject
        }
    } catch {
        return $null
    }
}

function Test-CirclHashLookup {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CirclHashLookupUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response) {
            Write-Log "CIRCL known-good match: $SHA256"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-CymruMalwareHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CymruApiUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response.detections -ge $Config.CymruDetectionThreshold) {
            Write-Log "CYMRU malware match: $SHA256 (detections: $($response.detections))"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-MalwareBazaarHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $body = @{
            query = 'get_info'
            hash = $SHA256
        }
        
        if ($Config.MalwareBazaarApiKey) {
            $body.api_key = $Config.MalwareBazaarApiKey
        }
        
        $response = Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $body -TimeoutSec 10 -ErrorAction Stop
        
        if ($response.query_status -eq 'ok' -or ($response.data -and $response.data.Count -gt 0)) {
            Write-Log "MalwareBazaar match: $SHA256"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-SuspiciousUnsignedDll {
    param([string]$FilePath)
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin @('.dll', '.winmd')) { return $false }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($signature.Status -eq 'Valid') { return $false }
    } catch {}
    
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $false }
    
    $fileSizeKB = $fileInfo.Length / 1KB
    $pathLower = $FilePath.ToLower()
    
    foreach ($riskyPath in $RiskyPaths) {
        if ($pathLower -like "*$riskyPath*" -and $fileSizeKB -lt $Config.SuspiciousFileSizeKB) {
            return $true
        }
    }
    
    if ($pathLower -like '*\appdata\roaming\*' -and $fileSizeKB -lt 800 -and $fileInfo.Name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

function Test-FileLocked {
    param([string]$FilePath)
    
    try {
        $stream = [IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

function Stop-ProcessesUsingFile {
    param([string]$FilePath)
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    
    try {
        Get-Process | Where-Object {
            try {
                $_.Modules.FileName -contains $FilePath
            } catch {
                $false
            }
        } | ForEach-Object {
            if ($ProtectedProcesses -notcontains $_.Name) {
                Write-Log "Stopping process $($_.Name) (PID: $($_.Id)) using file: $FilePath"
                try {
                    $_.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 500
                    if (-not $_.HasExited) {
                        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }
    } catch {
        try {
            taskkill /F /FI "MODULES eq $fileName" 2>&1 | Out-Null
        } catch {}
    }
}

function Set-FileOwnership {
    param([string]$FilePath)
    
    try {
        takeown /F $FilePath /A 2>&1 | Out-Null
        icacls $FilePath /reset 2>&1 | Out-Null
        icacls $FilePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Write-Log "Set ownership and permissions for: $FilePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership: $_"
        return $false
    }
}

function Move-ToQuarantine {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Cannot quarantine - file not found: $FilePath"
        return
    }
    
    if (Test-FileLocked -FilePath $FilePath) {
        Stop-ProcessesUsingFile -FilePath $FilePath
        Start-Sleep -Milliseconds 500
    }
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $Config.BackupDirectory "${fileName}_${timestamp}.bak"
    $quarantinePath = Join-Path $Config.QuarantineDirectory "${fileName}_${timestamp}"
    
    try {
        Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
        Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "QUARANTINED [$Reason]: $FilePath -> $quarantinePath"
        Send-ThreatAlert -Severity "HIGH" -Message "File quarantined: $Reason" -Details $FilePath
    } catch {
        Write-Log "Quarantine failed for $FilePath : $_"
        
        if (Set-FileOwnership -FilePath $FilePath) {
            try {
                Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
                Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-Log "QUARANTINED (after ownership fix) [$Reason]: $FilePath"
            } catch {
                Write-Log "Quarantine still failed after ownership fix: $_"
            }
        }
    }
}

function Block-FileExecution {
    param(
        [string]$FilePath,
        [int]$ProcessId,
        [string]$Type
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $blockEntry = "$timestamp | BLOCKED $Type | $FilePath | PID $ProcessId"
    
    try {
        $blockEntry | Out-File -FilePath $Config.BlockedLogFile -Append -Encoding UTF8
    } catch {}
    
    Write-Log "BLOCKED $Type | $FilePath | PID $ProcessId"
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process -and ($ProtectedProcesses -notcontains $process.ProcessName)) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $ProcessId"
        }
    } catch {}
    
    if (Test-Path $FilePath) {
        Move-ToQuarantine -FilePath $FilePath -Reason "Real-time $Type block"
    }
}

$global:EmailConfig = $null
$global:WebhookUrl = $null

function Send-ThreatAlert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )
    
    if (-not $Config.EnableAlerts) { return }
    
    $severityUpper = $Severity.ToUpper()
    
    $entryType = switch ($severityUpper) {
        "CRITICAL" { [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH"     { [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM"   { [System.Diagnostics.EventLogEntryType]::Warning }
        default    { [System.Diagnostics.EventLogEntryType]::Information }
    }
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Antivirus")) {
            New-EventLog -LogName Application -Source "Antivirus" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "Antivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
    
    if ($global:EmailConfig) {
        try {
            Send-MailMessage @global:EmailConfig `
                -Subject "[$severityUpper] Antivirus Alert" `
                -Body "$Message`n`nDetails: $Details" `
                -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Email alert failed: $_"
        }
    }
    
    if ($global:WebhookUrl) {
        try {
            $payload = @{
                severity  = $severityUpper
                message   = $Message
                details   = $Details
                timestamp = Get-Date -Format 'o'
                hostname  = $env:COMPUTERNAME
            } | ConvertTo-Json
            
            Invoke-WebRequest -Uri $global:WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Log "Webhook alert failed: $_"
        }
    }
}

function Update-ThreatIntelligence {
    if (-not $Config.EnableThreatIntel) { return }
    
    Write-Log "Updating threat intelligence feeds..."
    
    $yaraRules = @(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_campaign_uac.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_malware_set.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Malware.yar"
    )
    
    $hashLists = @(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest-hashes.txt"
    )
    
    foreach ($url in $yaraRules) {
        $fileName = Split-Path $url -Leaf
        $outputPath = Join-Path $RulesDirectory $fileName
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Log "Downloaded YARA rule: $fileName"
        } catch {
            Write-Log "Failed to download YARA rule $fileName : $_"
        }
    }
    
    foreach ($url in $hashLists) {
        $fileName = Split-Path $url -Leaf
        $outputPath = Join-Path $Config.BaseDirectory $fileName
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Log "Downloaded hash list: $fileName"
        } catch {
            Write-Log "Failed to download hash list $fileName : $_"
        }
    }
}

function Invoke-ThreatAnalysis {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath -PathType Leaf)) { return }
    if (Test-ShouldExclude -FilePath $FilePath) { return }
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin $MonitoredExtensions) { return }
    
    $fileHash = Get-FileHashSafe -FilePath $FilePath
    if (-not $fileHash) { return }
    
    if ($KnownFilesCache.ContainsKey($fileHash)) {
        if (-not $KnownFilesCache[$fileHash]) {
            if (Test-Path $FilePath) {
                Write-Log "Known bad file re-detected - HARD DELETING: $FilePath (hash: $fileHash)"
                try {
                    Remove-Item -Path $FilePath -Force -ErrorAction Stop
                    Write-Log "Successfully deleted known-bad file: $FilePath"
                    Send-ThreatAlert -Severity "HIGH" -Message "Known-bad file auto-deleted" -Details $FilePath
                } catch {
                    Write-Log "Delete failed - falling back to quarantine: $_"
                    Move-ToQuarantine -FilePath $FilePath -Reason "Known threat (delete failed)"
                }
            }
        }
        return
    }
    
    if (Test-CirclHashLookup -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $true
        Write-Log "ALLOWED (CIRCL known-good): $FilePath"
        return
    }
    
    if (Test-CymruMalwareHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Cymru MHR malware match (>= $($Config.CymruDetectionThreshold)% detection)"
        return
    }
    
    if (Test-MalwareBazaarHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "MalwareBazaar malware match"
        return
    }
    
    if (Test-SuspiciousUnsignedDll -FilePath $FilePath) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Suspicious unsigned DLL/WINMD in risky location"
        return
    }
    
    $signatureInfo = Get-FileSignatureInfo -FilePath $FilePath
    if ($signatureInfo) {
        $isSafe = ($signatureInfo.Status -eq 'Valid')
        Save-ToDatabase -Hash $fileHash -IsSafe $isSafe
        
        if ($isSafe) {
            Write-Log "ALLOWED (digitally signed): $FilePath"
        } else {
            Write-Log "ALLOWED (unsigned but no threat indicators): $FilePath"
        }
    }
}

function Initialize-Yara {
    param(
        [string]$BaseDir = $Config.BaseDirectory
    )

    $yaraExe     = Join-Path $BaseDir "yara64.exe"
    $yaraRuleMem = Join-Path $BaseDir "mem.yar"

    Write-Log "Initializing YARA components..."

    if (-not (Test-Path $yaraExe)) {
        Write-Log "yara64.exe not found - attempting download"

        try {
            $releaseUrl = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
            $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{"Accept"="application/vnd.github.v3+json"} -TimeoutSec 12

            $asset = $release.assets | Where-Object { $_.name -match 'yara.*win64\.zip' } | Select-Object -First 1

            if ($asset) {
                $zipUrl = $asset.browser_download_url
                $tempZip = Join-Path $BaseDir "yara-latest-win64.zip"

                Write-Log "Downloading YARA from: $zipUrl"
                Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -TimeoutSec 30 -UseBasicParsing

                Expand-Archive -Path $tempZip -DestinationPath $BaseDir -Force

                Get-ChildItem $BaseDir -Filter "*yara*64.exe" | ForEach-Object {
                    if ($_.Name -ne "yara64.exe") {
                        Rename-Item $_.FullName (Join-Path $BaseDir "yara64.exe") -Force -ErrorAction SilentlyContinue
                    }
                }

                Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

                if (Test-Path $yaraExe) {
                    Write-Log "Successfully downloaded and extracted yara64.exe"
                } else {
                    Write-Log "ERROR: yara64.exe still not found after extraction"
                }
            } else {
                Write-Log "Could not find win64 zip asset in latest release"
            }
        }
        catch {
            Write-Log "Failed to auto-download YARA: $_"
            Write-Log "You must manually place yara64.exe into $BaseDir"
            Write-Log "Download from: https://github.com/VirusTotal/yara/releases/latest"
        }
    }
    else {
        Write-Log "yara64.exe already exists"
    }

    if (-not (Test-Path $yaraRuleMem)) {
        Write-Log "Downloading memory YARA rules..."

        $ruleUrls = @(
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar"
        )

        $combinedRules = @()

        foreach ($url in $ruleUrls) {
            try {
                $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 12 | Select-Object -ExpandProperty Content
                $combinedRules += $content
                Write-Log "Downloaded rule set: $(Split-Path $url -Leaf)"
            }
            catch {
                Write-Log "Failed to download $url : $_"
            }
        }

        if ($combinedRules.Count -gt 0) {
            $combinedRules -join "`n`n" | Out-File -FilePath $yaraRuleMem -Encoding utf8 -Force
            Write-Log "Created combined memory rule file: $yaraRuleMem"
        }
        else {
            Write-Log "No memory rules could be downloaded"
        }
    }
    else {
        Write-Log "Memory YARA rules already exist"
    }

    if (Test-Path $yaraExe) {
        Write-Log "YARA setup complete - ready to use"
        return $true
    }
    else {
        Write-Log "YARA executable missing - memory YARA scanning will be DISABLED"
        return $false
    }
}

$yaraReady = Initialize-Yara

function Start-MemoryScanner {
    if (-not $Config.EnableMemoryScanning) {
        Write-Log "Memory scanning is disabled in configuration"
        return
    }
    
    Write-Log "Starting optimized memory scanner (interval: $($Config.MemoryScanIntervalSec)s, max size: $($Config.MemoryScanMaxSizeMB)MB)"
    
    Start-Job -ScriptBlock {
        $config = $using:Config
        $protected = $using:ProtectedProcesses
        $evilStrings = $using:EvilStrings
        $logFile = Join-Path $config.BaseDirectory "memory_hits.log"
        
        while ($true) {
            Start-Sleep -Seconds $config.MemoryScanIntervalSec
            
            $maxBytes = $config.MemoryScanMaxSizeMB * 1MB
            
            Get-Process | Where-Object {
                $_.WorkingSet64 -lt $maxBytes -and $protected -notcontains $_.Name
            } | ForEach-Object {
                $process = $_
                $suspicious = $false
                $reasons = @()
                
                try {
                    if (-not $process.Path -or $process.Path -eq '') {
                        $suspicious = $true
                        $reasons += "NoPath"
                    }
                } catch {}
                
                try {
                    $emptyModules = $process.Modules | Where-Object {
                        $_.FileName -eq '' -or $_.ModuleName -eq ''
                    }
                    
                    if ($emptyModules) {
                        $suspicious = $true
                        $reasons += "EmptyModule"
                    }
                } catch {}
                
                try {
                    foreach ($module in $process.Modules) {
                        foreach ($evilString in $evilStrings) {
                            if ($module.ModuleName -match $evilString -or ($module.FileName -and $module.FileName -match $evilString)) {
                                $suspicious = $true
                                $reasons += "EvilString($evilString)"
                                break
                            }
                        }
                        if ($suspicious) { break }
                    }
                } catch {}
                
                if ($suspicious) {
                    $reasonString = $reasons -join '; '
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MEMORY HIT [$reasonString] -> $($process.Name) (PID: $($process.Id)) Path: '$($process.Path)' WS: $([math]::Round($process.WorkingSet64/1MB, 2))MB"
                    
                    try {
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                    } catch {}
                    
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
            
            if ((Get-Random -Minimum 1 -Maximum 10) -eq 1) {
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }
        }
    } | Out-Null
}

function Start-YaraMemoryScanner {
    $yaraExePath = Join-Path $Config.BaseDirectory "yara64.exe"
    $yaraRulePath = Join-Path $Config.BaseDirectory "mem.yar"
    
    if (-not (Test-Path $yaraExePath) -or -not (Test-Path $yaraRulePath)) {
        Write-Log "YARA executable or rule file missing - skipping YARA memory scanner"
        return
    }

    if (-not $yaraReady) {
        Write-Log "YARA was not successfully initialized - skipping memory scanner"
        return
    }
    
    Write-Log "Starting YARA memory scanner"
    
    Start-Job -ScriptBlock {
        $yaraExe = $using:yaraExePath
        $yaraRule = $using:yaraRulePath
        $protected = $using:ProtectedProcesses
        $config = $using:Config
        $logFile = Join-Path $config.BaseDirectory "yara_memory_hits.log"
        
        while ($true) {
            Start-Sleep -Seconds $config.MemoryScanIntervalSec
            
            Get-Process | Where-Object {
                $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
            } | ForEach-Object {
                $process = $_
                
                try {
                    $result = & $yaraExe -w $yaraRule -p $process.Id 2>$null
                    
                    if ($LASTEXITCODE -eq 0 -and $result) {
                        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | YARA HIT -> $($process.Name) (PID: $($process.Id))"
                        
                        try {
                            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                        } catch {}
                        
                        if ($protected -notcontains $process.Name) {
                            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                        }
                    }
                } catch {}
            }
        }
    } | Out-Null
}

function Find-FilelessIndicators {
    $detections = @()
    
    try {
        $suspiciousPowerShell = Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -match 'encodedcommand|enc|iex|invoke-expression'
        }
        
        if ($suspiciousPowerShell) {
            $detections += [PSCustomObject]@{
                Type    = "FilelessPowerShell"
                Details = $suspiciousPowerShell | Select-Object Name, Id, MainWindowTitle
            }
            Write-Log "Fileless indicator detected: PowerShell without file"
        }
    } catch {}
    
    try {
        $wmiEvents = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Query -match 'powershell|vbscript|javascript' }
        
        if ($wmiEvents) {
            $detections += [PSCustomObject]@{
                Type    = "WMIEventSubscription"
                Details = $wmiEvents | Select-Object Name, Query
            }
            Write-Log "Fileless indicator detected: WMI event subscriptions"
        }
    } catch {}
    
    try {
        $registryKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        )
        
        foreach ($key in $registryKeys) {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                
                if ($props) {
                    $props.PSObject.Properties | Where-Object {
                        $_.MemberType -eq 'NoteProperty' -and $_.Value -match 'powershell.*-enc|mshta|regsvr32.*scrobj'
                    } | ForEach-Object {
                        $detections += [PSCustomObject]@{
                            Type    = "RegistryScript"
                            Details = "$key -> $($_.Name): $($_.Value)"
                        }
                        Write-Log "Fileless indicator detected: Registry script in $key"
                    }
                }
            }
        }
    } catch {}
    
    return $detections
}

function Find-PersistenceMechanisms {
    $suspiciousItems = @()
    
    $locations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'C:\Windows\System32\Tasks',
        'C:\Windows\Tasks',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
    )
    
    foreach ($location in $locations) {
        try {
            if ($location -match '^HK') {
                if (Test-Path $location) {
                    $props = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    
                    if ($props) {
                        $props.PSObject.Properties | Where-Object {
                            $_.MemberType -eq 'NoteProperty' -and $_.Value -match '\.(exe|dll|ps1|vbs|js|bat|cmd)$'
                        } | ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.Value
                                Type     = 'Registry'
                            }
                        }
                    }
                }
            } else {
                if (Test-Path $location) {
                    Get-ChildItem -Path $location -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -match '\.(exe|dll|lnk|ps1|vbs|js|bat|cmd)$' } |
                        ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.FullName
                                Type     = 'FileSystem'
                            }
                        }
                }
            }
        } catch {
            Write-Log "Error checking persistence location $location : $_"
        }
    }
    
    return $suspiciousItems
}

function Test-ProcessHollowing {
    param($Process)
    
    try {
        $processPath = $Process.Path
        if (-not $processPath) { return $false }
        
        $modules = $Process.Modules
        if ($modules -and $modules.Count -gt 0) {
            return ($modules[0].FileName -ne $processPath)
        }
    } catch {}
    
    return $false
}

function Test-CredentialAccessBehavior {
    param($Process)
    
    try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction SilentlyContinue).CommandLine
        
        if ($commandLine -match 'mimikatz|procdump|sekurlsa|lsadump|credential|password') {
            return $true
        }
    } catch {}
    
    if ($Process.ProcessName -match 'vaultcmd|cred') {
        return $true
    }
    
    return $false
}

function Test-LateralMovementBehavior {
    param($Process)
    
    try {
        $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
        
        $externalConnections = $connections | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)|^(::1|fe80:)' -and
            $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::'
        }
        
        return (($externalConnections | Measure-Object).Count -gt 10)
    } catch {}
    
    return $false
}

function Test-C2Communication {
    param($Connection)
    
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337)
    
    if ($Connection.RemotePort -in $suspiciousPorts) {
        try {
            $hostname = [System.Net.Dns]::GetHostEntry($Connection.RemoteAddress).HostName
            
            $c2Domains = @('pastebin', 'ddns.net', 'no-ip.org', 'duckdns.org', 'bit.ly', 'tinyurl')
            
            foreach ($domain in $c2Domains) {
                if ($hostname -like "*$domain*") {
                    return $true
                }
            }
        } catch {}
    }
    
    return $false
}

function Invoke-ProcessAndNetworkScan {
    Get-Process | ForEach-Object {
        $process = $_
        
        try {
            $exePath = $process.MainModule.FileName
            if ($exePath -and (Test-Path $exePath)) {
                Invoke-ThreatAnalysis -FilePath $exePath
            }
        } catch {}
        
        if ($BehaviorConfig.EnableBehaviorKill -and ($ProtectedProcesses -notcontains $process.Name)) {
            try {
                if (Test-ProcessHollowing -Process $process) {
                    Write-Log "BEHAVIOR: Process hollowing detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Process hollowing detected" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-CredentialAccessBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Credential access detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Credential access behavior" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-LateralMovementBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Lateral movement detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "MEDIUM" -Message "Lateral movement behavior" -Details "$($process.Name) PID: $($process.Id)"
                }
            } catch {}
        }
    }
    
    if ($BehaviorConfig.EnableAutoBlockC2) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.State -in @('Established', 'Listen')
        } | ForEach-Object {
            $connection = $_
            
            try {
                $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
                
                if ($process -and (Test-C2Communication -Connection $connection)) {
                    Write-Log "NETWORK: Suspicious C2 connection - $($process.Name) (PID: $($process.Id)) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    Send-ThreatAlert -Severity "HIGH" -Message "C2 communication detected" -Details "$($process.Name) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    
                    if ($ProtectedProcesses -notcontains $process.Name) {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    }
                    
                    try {
                        $ruleName = "Block_C2_$($connection.RemoteAddress)"
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Outbound `
                            -Protocol TCP `
                            -RemoteAddress $connection.RemoteAddress `
                            -Action Block `
                            -Enabled True `
                            -ErrorAction SilentlyContinue | Out-Null
                        
                        Write-Log "Created firewall rule to block: $($connection.RemoteAddress)"
                    } catch {}
                }
            } catch {}
        }
    }
}

Write-Log "Performing initial scan of high-risk folders"

$highRiskFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)

foreach ($folder in $highRiskFolders) {
    if (Test-Path $folder) {
        Write-Log "Scanning: $folder"
        Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Invoke-ThreatAnalysis -FilePath $_.FullName
        }
    }
}

if ($Config.EnableRealtimeMonitor) {
    Write-Log "Setting up real-time file monitoring"
    
    foreach ($folder in $highRiskFolders) {
        if (-not (Test-Path $folder)) { continue }
        
        try {
            $watcher = New-Object IO.FileSystemWatcher $folder, '*.*' -Property @{
                IncludeSubdirectories = $true
                NotifyFilter          = [IO.NotifyFilters]'FileName, LastWrite'
            }
            
            Register-ObjectEvent $watcher Created -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                $extension = [IO.Path]::GetExtension($filePath).ToLower()
                
                if ($MonitoredExtensions -contains $extension) {
                    Start-Sleep -Milliseconds 800
                    Invoke-ThreatAnalysis -FilePath $filePath
                }
            } | Out-Null
            
            $watcher.EnableRaisingEvents = $true
            Write-Log "File watcher active for: $folder"
        } catch {
            Write-Log "Failed to create file watcher for $folder : $_"
        }
    }
}

Write-Log "Registering WMI real-time execution monitors"

try {
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
        $event = $Event.SourceEventArgs.NewEvent
        $filePath = $event.ProcessName
        $processId = $event.ProcessId
        
        try {
            $ownerSid = (Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue | 
                Invoke-CimMethod -MethodName GetOwnerSid).Sid
        } catch {
            $ownerSid = "Unknown"
        }
        
        if ($AllowedSIDs -contains $ownerSid) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                if ($signature.Status -eq 'Valid') {
                    return
                }
            } catch {}
        }
        
        Block-FileExecution -FilePath $filePath -ProcessId $processId -Type "EXE"
    } | Out-Null
    
    Write-Log "WMI process start monitor registered"
} catch {
    Write-Log "Failed to register WMI process start monitor: $_"
}

try {
    Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
        $event = $Event.SourceEventArgs.NewEvent
        $filePath = $event.ImageName
        $processId = $event.ProcessId
        
        if (-not (Test-Path $filePath)) { return }
        
        try {
            $ownerSid = (Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue | 
                Invoke-CimMethod -MethodName GetOwnerSid).Sid
        } catch {
            $ownerSid = "Unknown"
        }
        
        if ($AllowedSIDs -contains $ownerSid) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                if ($signature.Status -eq 'Valid') {
                    return
                }
            } catch {}
        }
        
        Block-FileExecution -FilePath $filePath -ProcessId $processId -Type "DLL"
    } | Out-Null
    
    Write-Log "WMI module load monitor registered"
} catch {
    Write-Log "Failed to register WMI module load monitor: $_"
}

if ($Config.EnableMemoryScanning) {
    Start-MemoryScanner
    Start-YaraMemoryScanner
}

if ($IsAdmin -and $Config.EnableThreatIntel) {
    $lastUpdateFile = Join-Path $Config.BaseDirectory "last_update.txt"
    $currentTime = Get-Date
    $shouldUpdate = $false
    
    if (-not (Test-Path $lastUpdateFile)) {
        $shouldUpdate = $true
    } else {
        try {
            $lastUpdate = (Get-Item $lastUpdateFile).LastWriteTime
            if ($lastUpdate -lt $currentTime.AddDays(-$BehaviorConfig.ThreatIntelUpdateDays)) {
                $shouldUpdate = $true
            }
        } catch {
            $shouldUpdate = $true
        }
    }
    
    if ($shouldUpdate) {
        Update-ThreatIntelligence
        $currentTime | Out-File -FilePath $lastUpdateFile
    }
    
    Start-Job -ScriptBlock {
        $config = $using:Config
        $behaviorConfig = $using:BehaviorConfig
        
        while ($true) {
            Start-Sleep -Seconds (60 * 60 * $behaviorConfig.DeepScanIntervalHours)
            
            try {
                $persistence = Find-PersistenceMechanisms
                if ($persistence -and $persistence.Count -gt 0) {
                    $outputFile = Join-Path $config.BaseDirectory "persistence_scan.csv"
                    $persistence | Export-Csv -Path $outputFile -NoTypeInformation
                    Write-Log "Persistence scan found $($persistence.Count) items -> $outputFile"
                    Send-ThreatAlert -Severity "MEDIUM" -Message "Persistence mechanisms detected" -Details "Found $($persistence.Count) items"
                }
            } catch {
                Write-Log "Persistence scan error: $_"
            }
            
            try {
                $fileless = Find-FilelessIndicators
                if ($fileless -and $fileless.Count -gt 0) {
                    $outputFile = Join-Path $config.BaseDirectory "fileless_detections.xml"
                    $fileless | Export-Clixml -Path $outputFile
                    Write-Log "Fileless indicators found: $($fileless.Count) -> $outputFile"
                    Send-ThreatAlert -Severity "HIGH" -Message "Fileless malware indicators" -Details "Found $($fileless.Count) indicators"
                }
            } catch {
                Write-Log "Fileless scan error: $_"
            }
        }
    } | Out-Null
    
    Write-Log "Deep scanner job started"
}

Write-Log "All monitoring systems active"
Write-Host "`nClean Antivirus is now running" -ForegroundColor Green
Write-Host "Press [Ctrl+C] to stop" -ForegroundColor Yellow

try {
    while ($true) {
        try {
            Invoke-ProcessAndNetworkScan
            Write-Log "Periodic scan cycle completed"
        } catch {
            Write-Log "Scan cycle error: $_"
        }
        
        Start-Sleep -Seconds 30
    }
} catch {
    Write-Log "Main loop terminated: $($_.Exception.Message)"
    Write-Host "`nAntivirus stopped. Check log file: $($Config.LogFile)" -ForegroundColor Red
}