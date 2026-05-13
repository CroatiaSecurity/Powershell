#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnose and fix duplicate/phantom login account issues on Windows 10/11

.DESCRIPTION
    This script detects the type of login issue you're experiencing and
    offers targeted fixes. It shows you what it found BEFORE making changes.

.EXAMPLE
    .\DiagnoseAndFixLoginIssues.ps1
#>

$ErrorActionPreference = "SilentlyContinue"

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Finding($type, $message) {
    $color = switch ($type) {
        "INFO"  { "White" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "FIX"   { "Green" }
        default { "Gray" }
    }
    Write-Host "[$type] $message" -ForegroundColor $color
}

Write-Header "Login Issue Diagnostic Tool"
Write-Host "This tool will check for common causes of duplicate/phantom accounts." -ForegroundColor Gray

$issuesFound = @()

# ============================================================================
# CHECK 1: Cached Microsoft Account Credentials
# ============================================================================
Write-Host "`n[CHECK 1] Microsoft Account Credentials..." -ForegroundColor Yellow
$msaCreds = cmdkey /list | Select-String "MicrosoftAccount|WindowsLive"
if ($msaCreds) {
    Write-Finding "WARN" "Found cached Microsoft account credentials:"
    $msaCreds | ForEach-Object { Write-Host "          $_" -ForegroundColor Yellow }
    $issuesFound += @{ Type = "MSA_Cache"; Description = "Cached Microsoft account credentials"; Data = $msaCreds }
} else {
    Write-Finding "INFO" "No cached Microsoft account credentials found"
}

# ============================================================================
# CHECK 2: Duplicate Profile Folders
# ============================================================================
Write-Host "`n[CHECK 2] Profile Folders..." -ForegroundColor Yellow
$currentUser = $env:USERNAME
$profileFolders = Get-ChildItem C:\Users -Directory | Where-Object { 
    $_.Name -match $currentUser -or $_.Name -match "\d{3}$|\.\d+$|\.domain$|\.bak$" 
}
$duplicateProfiles = $profileFolders | Where-Object { 
    $_.Name -ne $currentUser -and $_.Name -match "^$currentUser" 
}

if ($duplicateProfiles) {
    Write-Finding "WARN" "Found duplicate profile folders:"
    $duplicateProfiles | ForEach-Object { Write-Host "          $($_.Name)" -ForegroundColor Yellow }
    $issuesFound += @{ Type = "DUPE_PROFILE"; Description = "Duplicate profile folders"; Data = $duplicateProfiles }
} else {
    Write-Finding "INFO" "No duplicate profile folders found"
}

# ============================================================================
# CHECK 3: Registry Profile List
# ============================================================================
Write-Host "`n[CHECK 3] Registry Profile List..." -ForegroundColor Yellow
$profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
    Get-ItemProperty | 
    Where-Object { $_.ProfileImagePath -match "Users" }

$userProfiles = $profiles | Where-Object { 
    $_.ProfileImagePath -match $currentUser 
}

if ($userProfiles.Count -gt 1) {
    Write-Finding "WARN" "Multiple registry entries for '$currentUser':"
    $userProfiles | ForEach-Object { 
        $sid = $_.PSChildName
        $path = $_.ProfileImagePath
        Write-Host "          SID: $sid" -ForegroundColor Yellow
        Write-Host "          Path: $path" -ForegroundColor Yellow
    }
    $issuesFound += @{ 
        Type = "REG_DUPE"; 
        Description = "Multiple registry profile entries"; 
        Data = $userProfiles 
    }
} else {
    Write-Finding "INFO" "Single profile entry found (normal)"
}

# ============================================================================
# CHECK 4: Corrupted/Bak Profiles
# ============================================================================
Write-Host "`n[CHECK 4] Corrupted Profile Backups..." -ForegroundColor Yellow
$bakProfiles = $profiles | Where-Object { $_.ProfileImagePath -match "\.bak$|\.001$|\.002$" }
if ($bakProfiles) {
    Write-Finding "WARN" "Found corrupted profile backups:"
    $bakProfiles | ForEach-Object { Write-Host "          $($_.ProfileImagePath)" -ForegroundColor Yellow }
    $issuesFound += @{ Type = "BAK_PROFILE"; Description = "Corrupted profile backups"; Data = $bakProfiles }
} else {
    Write-Finding "INFO" "No corrupted profile backups found"
}

# ============================================================================
# CHECK 5: Windows Hello / Biometric Issues
# ============================================================================
Write-Host "`n[CHECK 5] Windows Hello / Biometric Data..." -ForegroundColor Yellow
$winBioPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"
$passportPath = "HKLM:\SOFTWARE\Microsoft\PassportForWork"

$helloExists = Test-Path $winBioPath
$passportExists = Test-Path $passportPath

if ($helloExists -or $passportExists) {
    Write-Finding "WARN" "Windows Hello / Passport data exists (may cause duplicate tiles)"
    if ($helloExists) { Write-Host "          Found: $winBioPath" -ForegroundColor Yellow }
    if ($passportExists) { Write-Host "          Found: $passportPath" -ForegroundColor Yellow }
    $issuesFound += @{ 
        Type = "HELLO"; 
        Description = "Windows Hello/Passport enrollment"; 
        Data = @{ Hello = $helloExists; Passport = $passportExists }
    }
} else {
    Write-Finding "INFO" "No Windows Hello data found"
}

# ============================================================================
# CHECK 6: LogonUI Cache
# ============================================================================
Write-Host "`n[CHECK 6] LogonUI Cached Data..." -ForegroundColor Yellow
$logonUIPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
if (Test-Path $logonUIPath) {
    $logonProps = Get-ItemProperty $logonUIPath
    $cachedUsers = @()
    if ($logonProps.LastLoggedOnUser) { 
        $cachedUsers += "LastLoggedOnUser: $($logonProps.LastLoggedOnUser)"
    }
    if ($logonProps.LastLoggedOnUserSID) { 
        $cachedUsers += "LastLoggedOnUserSID: $($logonProps.LastLoggedOnUserSID)"
    }
    if ($logonProps.SelectedUserSID) { 
        $cachedUsers += "SelectedUserSID: $($logonProps.SelectedUserSID)"
    }
    
    if ($cachedUsers.Count -gt 0) {
        Write-Finding "INFO" "Cached login data found:"
        $cachedUsers | ForEach-Object { Write-Host "          $_" -ForegroundColor Gray }
    } else {
        Write-Finding "INFO" "No cached user data in LogonUI"
    }
}

# ============================================================================
# SUMMARY AND FIX OFFER
# ============================================================================
Write-Header "Diagnostic Summary"

if ($issuesFound.Count -eq 0) {
    Write-Host "`n✓ No issues detected!" -ForegroundColor Green
    Write-Host "Your login tiles should be normal." -ForegroundColor Gray
    Write-Host "`nIf you still see duplicate accounts, the issue may be:" -ForegroundColor Yellow
    Write-Host "  - A Microsoft/Work account still linked (check Settings > Accounts)" -ForegroundColor Gray
    Write-Host "  - An Azure AD join (check dsregcmd /status)" -ForegroundColor Gray
    Write-Host "  - A temporary Windows Update glitch (restart may fix)" -ForegroundColor Gray
    Read-Host "`nPress Enter to exit"
    exit 0
}

Write-Host "`nFound $($issuesFound.Count) potential issue(s):" -ForegroundColor Yellow
for ($i = 0; $i -lt $issuesFound.Count; $i++) {
    $issue = $issuesFound[$i]
    Write-Host "  $($i+1). [$($issue.Type)] $($issue.Description)" -ForegroundColor Yellow
}

Write-Host "`n----------------------------------------" -ForegroundColor Cyan
$response = Read-Host "Apply fixes for these issues? (Y/N)"

if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "`nNo changes made. Exiting." -ForegroundColor Gray
    exit 0
}

# ============================================================================
# APPLY FIXES
# ============================================================================
Write-Header "Applying Fixes"

foreach ($issue in $issuesFound) {
    Write-Host "`n" -NoNewline
    switch ($issue.Type) {
        "MSA_Cache" {
            Write-Finding "FIX" "Removing cached Microsoft account credentials..."
            cmdkey /delete:MicrosoftAccount:target=SSO_POP_Device 2>$null
            cmdkey /delete:WindowsLive:target=virtualapp/didlogical 2>$null
            Write-Host "          ✓ Cleared Microsoft account cache" -ForegroundColor Green
        }
        
        "HELLO" {
            Write-Finding "FIX" "Clearing Windows Hello/Passport data..."
            if (Test-Path $winBioPath) {
                Remove-Item -Path $winBioPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "          ✓ Cleared WinBio registry" -ForegroundColor Green
            }
            if (Test-Path $passportPath) {
                Remove-Item -Path $passportPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "          ✓ Cleared Passport registry" -ForegroundColor Green
            }
        }
        
        "REG_DUPE" {
            Write-Finding "FIX" "Note: Multiple registry entries found."
            Write-Host "          This may require manual review." -ForegroundColor Yellow
            Write-Host "          SIDs found:" -ForegroundColor Gray
            $issue.Data | ForEach-Object {
                Write-Host "            - $($_.PSChildName)" -ForegroundColor Gray
            }
            Write-Host "`n          If one is your current session and one is old," -ForegroundColor Yellow
            Write-Host "          the old one can be removed after backing up." -ForegroundColor Yellow
        }
        
        "DUPE_PROFILE" {
            Write-Finding "FIX" "Note: Duplicate profile folders found."
            Write-Host "          Folders:" -ForegroundColor Gray
            $issue.Data | ForEach-Object {
                Write-Host "            - $($_.FullName)" -ForegroundColor Gray
            }
            Write-Host "`n          You may need to manually merge or delete old profiles." -ForegroundColor Yellow
            Write-Host "          Rename .bak folders to remove extension after logging out." -ForegroundColor Yellow
        }
        
        "BAK_PROFILE" {
            Write-Finding "FIX" "Note: Corrupted profile backups found."
            Write-Host "          These may need manual cleanup." -ForegroundColor Yellow
        }
    }
}

# Common cleanup for all issues
Write-Host "`n" -NoNewline
Write-Finding "FIX" "Clearing LogonUI cache..."
$logonProps = Get-ItemProperty $logonUIPath -ErrorAction SilentlyContinue
if ($logonProps) {
    @("LastLoggedOnUser", "LastLoggedOnUserSID", "LastLoggedOnDisplayName", "SelectedUserSID") | ForEach-Object {
        Remove-ItemProperty -Path $logonUIPath -Name $_ -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "          ✓ Cleared LogonUI cache" -ForegroundColor Green

Write-Host "`n" -NoNewline
Write-Finding "FIX" "Restarting Token Broker service..."
Restart-Service -Name "TokenBroker" -Force -ErrorAction SilentlyContinue
Write-Host "          ✓ Service restarted" -ForegroundColor Green

Write-Header "Fixes Applied"
Write-Host "`n✓ All applicable fixes have been applied." -ForegroundColor Green
Write-Host "`nIMPORTANT: Restart your computer now for changes to take effect." -ForegroundColor Yellow
Write-Host "`nIf you still see duplicate accounts after restart:" -ForegroundColor Yellow
Write-Host "  1. Check Settings > Accounts > Email & accounts" -ForegroundColor Gray
Write-Host "  2. Remove any Microsoft/Work accounts you don't recognize" -ForegroundColor Gray
Write-Host "  3. Check Settings > Accounts > Access work or school" -ForegroundColor Gray
Write-Host "  4. Disconnect any unknown organization connections" -ForegroundColor Gray

Read-Host "`nPress Enter to exit"
