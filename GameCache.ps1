#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Multi-tier caching system for gaming performance optimization
.DESCRIPTION
    Automatically manages file caching across RAM and SSD tiers using symlinks
    Implements LRU eviction and transparent file access
.NOTES
    Author: Gorstak
    Version: 1.0
#>

param(
    [switch]$Install,
    [switch]$Uninstall
)

# Configuration
$Config = @{
    RAMCacheSizeMB = 2048          # 2GB RAM cache
    SSDCacheSizeGB = 20            # 20GB SSD cache
    MonitorIntervalSeconds = 60     # Check every minute
    LogPath = "$env:ProgramData\GameCache\cache.log"
    CacheDataPath = "$env:ProgramData\GameCache\cache_data.json"
    RAMCachePath = "$env:TEMP\GameCache_RAM"
    AccessTrackingPath = "$env:ProgramData\GameCache\access_log.json"
    MaxLRUEntries = 10000
    TargetExtensions = @('.exe', '.dll', '.pak', '.bin', '.dat', '.cache')
    GamePaths = @(
        "$env:ProgramFiles\Steam\steamapps\common",
        "$env:ProgramFiles(x86)\Steam\steamapps\common",
        "$env:ProgramFiles\Epic Games",
        "$env:LOCALAPPDATA\Programs"
    )
    InstallPath = "$env:ProgramData\GameCache"
    TaskName = "GameCache"
}

# Global cache configuration
$script:CachedDriveConfig = $null

function Test-GameCacheInstalled {
    $task = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    return $null -ne $task
}

function Install-GameCacheService {
    Write-Host "Installing GameCache..." -ForegroundColor Cyan
    
    # Create install directory
    if (!(Test-Path $Config.InstallPath)) {
        New-Item -ItemType Directory -Path $Config.InstallPath -Force | Out-Null
    }
    
    # Copy script to ProgramData
    $installedScriptPath = Join-Path $Config.InstallPath "GameCache.ps1"
    Copy-Item -Path $PSCommandPath -Destination $installedScriptPath -Force
    Write-Host "Copied script to $installedScriptPath" -ForegroundColor Gray
    
    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Removing existing task..." -ForegroundColor Gray
        Unregister-ScheduledTask -TaskName $Config.TaskName -Confirm:$false
    }
    
    # Create task action
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installedScriptPath`""
    
    # Create task trigger (at startup)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    
    # Create task principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    # Register the task
    Register-ScheduledTask -TaskName $Config.TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "GameCache - Multi-tier caching system for gaming performance (Author: Gorstak)" | Out-Null
    
    Write-Host ""
    Write-Host "[SUCCESS] GameCache installed successfully!" -ForegroundColor Green
    
    Write-Host "Starting GameCache service..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $Config.TaskName
    Start-Sleep -Seconds 2
    
    Write-Host "Service started! Check log at: $($Config.LogPath)" -ForegroundColor Green
    Write-Host ""
    
    exit 0
}

function Uninstall-GameCacheService {
    Write-Host "Uninstalling GameCache..." -ForegroundColor Cyan
    
    # Stop task if running
    $runningTask = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    if ($runningTask -and $runningTask.State -eq "Running") {
        Write-Host "Stopping running task..." -ForegroundColor Gray
        Stop-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    
    # Remove task
    $existingTask = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $Config.TaskName -Confirm:$false
        Write-Host "Task removed." -ForegroundColor Gray
    }
    
    # Clean up installation directory
    if (Test-Path $Config.InstallPath) {
        Remove-Item $Config.InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Installation files removed." -ForegroundColor Gray
    }
    
    Write-Host "Cleaning up cache files..." -ForegroundColor Gray
    
    if (Test-Path $Config.RAMCachePath) {
        Remove-Item $Config.RAMCachePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    if (Test-Path "$env:ProgramData\GameCache") {
        Remove-Item "$env:ProgramData\GameCache" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Find and remove SSD cache
    $driveConfig = Get-DriveConfiguration
    if ($driveConfig.SSDCache -and (Test-Path $driveConfig.SSDCache)) {
        Remove-Item $driveConfig.SSDCache -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Write-Host "[SUCCESS] GameCache uninstalled completely." -ForegroundColor Green
    Write-Host ""
    
    exit 0
}

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if (!(Test-Path (Split-Path $Config.LogPath))) {
        New-Item -ItemType Directory -Path (Split-Path $Config.LogPath) -Force | Out-Null
    }
    
    Add-Content -Path $Config.LogPath -Value $logMessage
    Write-Host $logMessage
}

# Detect drive types and assign tiers
function Get-DriveConfiguration {
    if ($script:CachedDriveConfig) {
        return $script:CachedDriveConfig
    }
    
    Write-Log "Detecting drive configuration..."
    
    $ssds = @()
    $hdds = @()
    
    try {
        # Get all logical disks
        $logicalDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" # Fixed disks only
        
        foreach ($disk in $logicalDisks) {
            # Get physical disk information
            $partition = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$($disk.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition"
            $physicalDisk = Get-WmiObject -Query "ASSOCIATORS OF {$($partition.__PATH)} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
            
            $isSSD = $false
            if ($physicalDisk) {
                # SCSI interface = NVMe/SSD, IDE interface = traditional HDD
                if ($physicalDisk.InterfaceType -eq "SCSI") {
                    $isSSD = $true
                    Write-Log "Detected $($disk.DeviceID) as SSD (InterfaceType: SCSI/NVMe)"
                } elseif ($physicalDisk.InterfaceType -eq "IDE") {
                    $isSSD = $false
                    Write-Log "Detected $($disk.DeviceID) as HDD (InterfaceType: $($physicalDisk.InterfaceType))"
                } else {
                    # Fallback: check model name
                    $model = $physicalDisk.Model
                    if ($model -match "SSD|Solid State|NVMe") {
                        $isSSD = $true
                    }
                }
            } else {
                # Fallback: C: drive is usually SSD on modern systems
                if ($disk.DeviceID -eq "C:") {
                    $isSSD = $true
                    Write-Log "Detected $($disk.DeviceID) as SSD (assuming system drive)"
                }
            }
            
            if ($isSSD) {
                $ssds += @{ DriveLetter = $disk.DeviceID.TrimEnd(':'); Path = $disk.DeviceID }
            } else {
                $hdds += @{ DriveLetter = $disk.DeviceID.TrimEnd(':'); Path = $disk.DeviceID }
            }
        }
    }
    catch {
        Write-Log "Warning: Could not detect drive types, assuming C: is SSD" -Level "WARN"
        # Fallback to simple detection
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Z]$' } | ForEach-Object {$' } | ForEach-Object {
            [PSCustomObject]@{
                DriveLetter = $_.Name
                MediaType = if ($_.Name -eq 'C') { 'SSD' } else { 'HDD' }
                SizeGB = [math]::Round(($_.Used + $_.Free) / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.Free / 1GB, 2)
            }
        }
        
        $drives | ForEach-Object {
            if ($_.MediaType -eq 'SSD') {
                $ssds += @{ DriveLetter = $_.DriveLetter; Path = "$($_.DriveLetter):" }
            } else {
                $hdds += @{ DriveLetter = $_.DriveLetter; Path = "$($_.DriveLetter):" }
            }
        }
    }
    
    Write-Log "Found $($ssds.Count) SSD(s) and $($hdds.Count) HDD(s)"
    
    $config = @{
        SSDs = $ssds
        HDDs = $hdds
        SSDCache = $null
    }
    
    if ($ssds.Count -gt 0) {
        $primarySSD = $ssds | Where-Object { $_.DriveLetter -ne "C" } | Select-Object -First 1
        if (!$primarySSD) { $primarySSD = $ssds[0] }
        
        $config.SSDCache = "$($primarySSD.Path)\GameCache_SSD"
        if (!(Test-Path $config.SSDCache)) {
            New-Item -ItemType Directory -Path $config.SSDCache -Force | Out-Null
            Write-Log "Created SSD cache directory: $($config.SSDCache)"
        }
    }
    
    $script:CachedDriveConfig = $config
    
    return $config
}

# Initialize cache structure
function Initialize-CacheSystem {
    Write-Log "Initializing cache system..."
    
    # Create RAM cache directory
    if (!(Test-Path $Config.RAMCachePath)) {
        New-Item -ItemType Directory -Path $Config.RAMCachePath -Force | Out-Null
        Write-Log "Created RAM cache directory: $($Config.RAMCachePath)"
    }
    
    # Create SSD cache directory
    $driveConfig = Get-DriveConfiguration
    if ($driveConfig.SSDCache) {
        if (!(Test-Path $driveConfig.SSDCache)) {
            New-Item -ItemType Directory -Path $driveConfig.SSDCache -Force | Out-Null
            Write-Log "Created SSD cache directory: $($driveConfig.SSDCache)"
        }
    }
    
    # Initialize cache metadata
    if (!(Test-Path $Config.CacheDataPath)) {
        $initialData = @{
            RAMCache = @{}
            SSDCache = @{}
            Symlinks = @{}
        }
        $initialData | ConvertTo-Json -Depth 10 | Set-Content $Config.CacheDataPath
    }
    
    # Initialize access tracking
    if (!(Test-Path $Config.AccessTrackingPath)) {
        @{} | ConvertTo-Json | Set-Content $Config.AccessTrackingPath
    }
}

# Load cache metadata
function Get-CacheData {
    if (Test-Path $Config.CacheDataPath) {
        return Get-Content $Config.CacheDataPath | ConvertFrom-Json
    }
    return @{ RAMCache = @{}; SSDCache = @{}; Symlinks = @{} }
}

# Save cache metadata
function Save-CacheData {
    param($CacheData)
    $CacheData | ConvertTo-Json -Depth 10 | Set-Content $Config.CacheDataPath
}

# Update file access time
function Update-FileAccess {
    param([string]$FilePath)
    
    $accessLog = @{}
    if (Test-Path $Config.AccessTrackingPath) {
        $jsonData = Get-Content $Config.AccessTrackingPath | ConvertFrom-Json
        if ($jsonData) {
            $jsonData.PSObject.Properties | ForEach-Object {
                $accessLog[$_.Name] = @{
                    LastAccess = $_.Value.LastAccess
                    AccessCount = $_.Value.AccessCount
                }
            }
        }
    }
    
    $accessLog[$FilePath] = @{
        LastAccess = (Get-Date).ToString('o')
        AccessCount = if ($accessLog[$FilePath]) { $accessLog[$FilePath].AccessCount + 1 } else { 1 }
    }
    
    # Limit tracking size
    if ($accessLog.Count -gt $Config.MaxLRUEntries) {
        $sorted = $accessLog.GetEnumerator() | Sort-Object { [datetime]$_.Value.LastAccess } | Select-Object -First ($Config.MaxLRUEntries * 0.7)
        $accessLog = @{}
        $sorted | ForEach-Object { $accessLog[$_.Key] = $_.Value }
    }
    
    $accessLog | ConvertTo-Json -Depth 5 | Set-Content $Config.AccessTrackingPath
}

# Calculate cache size
function Get-CacheSize {
    param([string]$Path)
    
    if (!(Test-Path $Path)) { return 0 }
    
    $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
             Measure-Object -Property Length -Sum).Sum
    
    return [math]::Round($size / 1MB, 2)
}

# Find least recently used files
function Get-LRUFiles {
    param([hashtable]$CacheEntries, [int]$CountToRemove)
    
    if (!(Test-Path $Config.AccessTrackingPath)) { return @() }
    
    $accessLog = @{}
    $jsonData = Get-Content $Config.AccessTrackingPath | ConvertFrom-Json
    if ($jsonData) {
        $jsonData.PSObject.Properties | ForEach-Object {
            $accessLog[$_.Name] = @{
                LastAccess = $_.Value.LastAccess
                AccessCount = $_.Value.AccessCount
            }
        }
    }
    
    $cacheFiles = $CacheEntries.GetEnumerator() | ForEach-Object {
        $cachedPath = $_.Value
        $accessInfo = $accessLog[$_.Key]
        
        [PSCustomObject]@{
            OriginalPath = $_.Key
            CachedPath = $cachedPath
            LastAccess = if ($accessInfo) { [datetime]$accessInfo.LastAccess } else { [datetime]::MinValue }
        }
    }
    
    return $cacheFiles | Sort-Object LastAccess | Select-Object -First $CountToRemove
}

# Evict files from cache
function Invoke-CacheEviction {
    param([string]$CacheType)
    
    $cacheData = Get-CacheData
    $driveConfig = Get-DriveConfiguration
    
    if ($CacheType -eq "RAM") {
        $currentSize = Get-CacheSize -Path $Config.RAMCachePath
        $maxSize = $Config.RAMCacheSizeMB
        
        if ($currentSize -gt $maxSize * 0.9) {
            Write-Log "RAM cache at $currentSize MB, evicting LRU files..."
            $toEvict = Get-LRUFiles -CacheEntries $cacheData.RAMCache -CountToRemove 10
            
            foreach ($file in $toEvict) {
                if (Test-Path $file.CachedPath) {
                    Remove-Item $file.CachedPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Evicted from RAM: $($file.OriginalPath)"
                }
                $cacheData.RAMCache.Remove($file.OriginalPath)
            }
        }
    }
    elseif ($CacheType -eq "SSD") {
        if (!$driveConfig.SSDCache) { return }
        
        $currentSize = Get-CacheSize -Path $driveConfig.SSDCache
        $maxSize = $Config.SSDCacheSizeGB * 1024
        
        if ($currentSize -gt $maxSize * 0.9) {
            Write-Log "SSD cache at $([math]::Round($currentSize/1024, 2)) GB, evicting LRU files..."
            $toEvict = Get-LRUFiles -CacheEntries $cacheData.SSDCache -CountToRemove 20
            
            foreach ($file in $toEvict) {
                if (Test-Path $file.CachedPath) {
                    Remove-Item $file.CachedPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Evicted from SSD: $($file.OriginalPath)"
                }
                $cacheData.SSDCache.Remove($file.OriginalPath)
            }
        }
    }
    
    Save-CacheData -CacheData $cacheData
}

# Create symbolic link
function New-CacheSymlink {
    param(
        [string]$OriginalPath,
        [string]$CachedPath
    )
    
    try {
        # Backup original if not already a symlink
        $item = Get-Item $OriginalPath -Force
        if (!$item.LinkType) {
            Copy-Item $OriginalPath $CachedPath -Force
            Remove-Item $OriginalPath -Force
        }
        
        # Create symlink
        New-Item -ItemType SymbolicLink -Path $OriginalPath -Target $CachedPath -Force -ErrorAction Stop | Out-Null
        Write-Log "Created symlink: $OriginalPath -> $CachedPath"
        return $true
    }
    catch {
        Write-Log "Failed to create symlink for $OriginalPath : $_" -Level "ERROR"
        return $false
    }
}

# Cache file to appropriate tier
function Add-FileToCache {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) { return }
    
    $fileInfo = Get-Item $FilePath
    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    
    # Skip if too large for RAM cache
    if ($fileSizeMB -gt 100) { return }
    
    $cacheData = Get-CacheData
    $driveConfig = Get-DriveConfiguration
    
    # Determine if file is on HDD (candidate for caching)
    $drive = Split-Path $FilePath -Qualifier
    $isOnHDD = $driveConfig.HDDs | Where-Object { "$($_.DriveLetter):" -eq $drive }
    
    if (!$isOnHDD) { return }
    
    # Check if already cached
    if ($cacheData.RAMCache[$FilePath] -or $cacheData.SSDCache[$FilePath]) {
        Update-FileAccess -FilePath $FilePath
        return
    }
    
    # Cache to RAM for small, frequently accessed files
    if ($fileSizeMB -lt 50) {
        Invoke-CacheEviction -CacheType "RAM"
        
        $cachedPath = Join-Path $Config.RAMCachePath $fileInfo.Name
        if (New-CacheSymlink -OriginalPath $FilePath -CachedPath $cachedPath) {
            $cacheData.RAMCache[$FilePath] = $cachedPath
            Write-Log "Cached to RAM: $FilePath ($fileSizeMB MB)"
        }
    }
    # Cache to SSD for larger files
    elseif ($driveConfig.SSDCache) {
        Invoke-CacheEviction -CacheType "SSD"
        
        $cachedPath = Join-Path $driveConfig.SSDCache $fileInfo.Name
        if (New-CacheSymlink -OriginalPath $FilePath -CachedPath $cachedPath) {
            $cacheData.SSDCache[$FilePath] = $cachedPath
            Write-Log "Cached to SSD: $FilePath ($fileSizeMB MB)"
        }
    }
    
    Update-FileAccess -FilePath $FilePath
    Save-CacheData -CacheData $cacheData
}

# Scan game directories for cacheable files
function Start-GameFileScan {
    Write-Log "Scanning game directories..."
    
    $files = @()
    foreach ($gamePath in $Config.GamePaths) {
        if (Test-Path $gamePath) {
            Write-Log "Scanning: $gamePath"
            
            $found = Get-ChildItem -Path $gamePath -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $Config.TargetExtensions -contains $_.Extension } |
                     Select-Object -First 500  # Limit initial scan
            
            $files += $found
        }
    }
    
    Write-Log "Found $($files.Count) cacheable game files"
    return $files
}

# Monitor and cache files
function Start-CacheMonitoring {
    Write-Log "Starting cache monitoring service..."
    
    while ($true) {
        try {
            # Scan for new files
            $files = Start-GameFileScan
            
            # Process most recently accessed files first
            if (Test-Path $Config.AccessTrackingPath) {
                $accessLog = @{}
                $jsonData = Get-Content $Config.AccessTrackingPath | ConvertFrom-Json
                if ($jsonData) {
                    $jsonData.PSObject.Properties | ForEach-Object {
                        $accessLog[$_.Name] = @{
                            LastAccess = $_.Value.LastAccess
                            AccessCount = $_.Value.AccessCount
                        }
                    }
                }
                
                $files = $files | Sort-Object {
                    $access = $accessLog[$_.FullName]
                    if ($access) { -$access.AccessCount } else { 0 }
                }
            }
            
            # Cache files (process in batches)
            $processed = 0
            foreach ($file in $files) {
                Add-FileToCache -FilePath $file.FullName
                $processed++
                
                if ($processed -ge 50) { break }  # Process 50 files per cycle
            }
            
            # Report cache status
            $ramSize = Get-CacheSize -Path $Config.RAMCachePath
            Write-Log "Cache status - RAM: $ramSize MB / $($Config.RAMCacheSizeMB) MB"
            
            Start-Sleep -Seconds $Config.MonitorIntervalSeconds
        }
        catch {
            Write-Log "Error in monitoring loop: $_" -Level "ERROR"
            Start-Sleep -Seconds 60
        }
    }
}

# Main execution
try {
    if (!(Test-Path (Split-Path $Config.LogPath))) {
        New-Item -ItemType Directory -Path (Split-Path $Config.LogPath) -Force | Out-Null
    }
    
    # Write startup message immediately
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] [INFO] GameCache script started" | Add-Content -Path $Config.LogPath
    
    if ($Uninstall) {
        Uninstall-GameCacheService
        # Function exits with exit 0
    }
    
    if (!(Test-GameCacheInstalled)) {
        Write-Host "GameCache is not installed. Installing now..." -ForegroundColor Yellow
        Write-Host ""
        Install-GameCacheService
        # Function exits with exit 0
    }
    
    Write-Log "=== GameCache Starting ==="
    
    # Verify admin rights
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$isAdmin) {
        Write-Log "ERROR: This script requires Administrator privileges for symlink creation" -Level "ERROR"
        exit 1
    }

    Initialize-CacheSystem
    
    Write-Log "GameCache initialized successfully. Starting monitoring..."
    Write-Log "RAM Cache: $($Config.RAMCacheSizeMB) MB"
    Write-Log "SSD Cache: $($Config.SSDCacheSizeGB) GB"
    
    Start-CacheMonitoring
}
catch {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorMsg = "[$timestamp] [ERROR] FATAL ERROR: $_"
    
    try {
        Add-Content -Path $Config.LogPath -Value $errorMsg
    } catch {
        # If logging fails, write to temp
        Add-Content -Path "$env:TEMP\GameCache_error.log" -Value $errorMsg
    }
    
    Write-Host $errorMsg -ForegroundColor Red
    exit 1
}
=======
>>>>>>> 3c479efe17479d82471b0fc670d9eb43f01e5740
