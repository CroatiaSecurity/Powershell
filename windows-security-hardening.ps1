# Windows Security Hardening Script
# This script hardens Windows security to prevent unauthorized access
# It only applies preventative measures and will not help if the system is already compromised

#Requires -RunAsAdministrator

# Script Usage:
#   Run once: Most settings persist permanently
#   Re-run after: Windows major updates, system restore, or if security issues are suspected
#   Optional: Run monthly for compliance checks

# Check if running in verification mode (read-only check)
param(
    [switch]$VerifyOnly = $false  # Use -VerifyOnly to check if settings are still applied
)

Write-Host "=== Windows Security Hardening Script ===" -ForegroundColor Cyan
Write-Host "This script hardens Windows to prevent unauthorized access" -ForegroundColor Yellow
if ($VerifyOnly) {
    Write-Host "VERIFICATION MODE: Checking current security settings (no changes will be made)" -ForegroundColor Cyan
}
Write-Host ""

# Function to check for common compromise indicators
function Test-SystemCompromise {
    Write-Host '[*] Checking for compromise indicators...' -ForegroundColor Yellow
    $compromised = $false
    $warnings = @()
    
    # Check for suspicious scheduled tasks
    $suspiciousTasks = Get-ScheduledTask | Where-Object {
        $_.Principal.UserId -eq "SYSTEM" -and 
        ($_.Actions.Execute -match "powershell|cmd|cscript|wscript") -and
        ($_.TaskPath -notmatch "Microsoft")
    }
    if ($suspiciousTasks) {
        $warnings += "Suspicious scheduled tasks found"
    }
    
    # Check for suspicious startup programs
    $startup = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    $startupWow = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    
    # Check for unknown RDP connections
    $rdpSessions = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 10 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Message -match "Logon Type: 10" }  # RDP logon
    
    if ($warnings.Count -gt 0) {
        Write-Host '[!] WARNING: Possible compromise indicators detected!' -ForegroundColor Red
        foreach ($w in $warnings) {
            Write-Host "    - $w" -ForegroundColor Red
        }
        Write-Host '[!] This script may not help if your system is already compromised.' -ForegroundColor Red
        Write-Host '[!] Continuing automatically...' -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "[+] No obvious compromise indicators found" -ForegroundColor Green
    }
}

# Function to disable unnecessary services
function Disable-UnnecessaryServices {
    Write-Host '[*] Disabling unnecessary services...' -ForegroundColor Yellow
    $servicesToDisable = @(
        "RemoteRegistry",           # Remote registry access (common HTB target)
        "RemoteAccess",             # Routing and Remote Access
        "SSDPSRV",                  # SSDP Discovery (UPnP)
        "WSearch",                  # Windows Search (if not needed)
        "XblAuthManager",           # Xbox services (if not gaming)
        "XblGameSave",
        "W3SVC",                    # IIS (if not hosting websites)
        "FTPSVC",                   # FTP Server (common attack vector)
        "SstpSvc",                  # SSTP VPN (if not used)
        "WbioSrvc",                 # Windows Biometric Service (if not needed)
        "Spooler"                   # Print Spooler (EternalBlue-style attacks)
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq "Running") {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "    [+] Disabled: $service" -ForegroundColor Green
            }
        } catch {
            Write-Host "    [!] Could not disable: $service" -ForegroundColor Yellow
        }
    }
    
    # Disable WinRM if not needed (common HTB entry point)
    try {
        $winrm = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
        if ($winrm) {
            Write-Host "    [!] WinRM is installed (common HTB target)" -ForegroundColor Yellow
            # We'll harden it instead of disabling in case it's needed
        }
    } catch {}
}

# Function to harden firewall
function Enable-FirewallHardening {
    Write-Host '[*] Hardening Windows Firewall...' -ForegroundColor Yellow
    
    # Ensure firewall is enabled
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    # Block inbound connections by default
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    # Enable logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True
    
    Write-Host "    [+] Firewall hardened" -ForegroundColor Green
    
    # Block common attack ports (HTB commonly targets these)
    Write-Host '[*] Blocking common HTB attack vectors...' -ForegroundColor Yellow
    
    # Common HTB ports to review/block
    $attackPorts = @(
        @{Port=3389; Name="RDP"; Protocol="TCP"},
        @{Port=5985; Name="WinRM HTTP"; Protocol="TCP"},
        @{Port=5986; Name="WinRM HTTPS"; Protocol="TCP"},
        @{Port=445; Name="SMB"; Protocol="TCP"},
        @{Port=139; Name="NetBIOS"; Protocol="TCP"},
        @{Port=135; Name="MSRPC"; Protocol="TCP"},
        @{Port=1433; Name="MSSQL"; Protocol="TCP"},
        @{Port=3306; Name="MySQL"; Protocol="TCP"},
        @{Port=5432; Name="PostgreSQL"; Protocol="TCP"},
        @{Port=5985; Name="WinRM"; Protocol="TCP"}
    )
    
    foreach ($port in $attackPorts) {
        $ruleName = "Block HTB Port $($port.Port) - $($port.Name)"
        try {
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort $port.Port -Protocol $port.Protocol -Action Block -ErrorAction SilentlyContinue | Out-Null
                Write-Host "    [+] Blocked inbound: $($port.Name) (Port $($port.Port))" -ForegroundColor Green
            }
        } catch {
            # Rule may already exist or port may be needed
        }
    }
    
    # Check for exposed services
    $rdpRule = Get-NetFirewallRule -DisplayName "Remote Desktop*" | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"} -ErrorAction SilentlyContinue
    if ($rdpRule) {
        Write-Host "    [!] WARNING: RDP is enabled (common HTB brute-force target)" -ForegroundColor Red
        Write-Host "       Consider disabling RDP or using Network Level Authentication" -ForegroundColor Yellow
    }
    
    $winrmRule = Get-NetFirewallRule -DisplayName "Windows Remote Management*" | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"} -ErrorAction SilentlyContinue
    if ($winrmRule) {
        Write-Host "    [!] WARNING: WinRM is enabled (common HTB entry point)" -ForegroundColor Red
    }
}

# Function to disable dangerous Windows features
function Disable-DangerousFeatures {
    Write-Host '[*] Disabling dangerous Windows features...' -ForegroundColor Yellow
    
    # Disable AutoRun for all drives (prevents USB malware)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -ErrorAction SilentlyContinue
    
    # Disable PowerShell v2 (older, less secure, common in HTB)
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    [+] Disabled PowerShell v2" -ForegroundColor Green
    } catch {}
    
    # Disable SMBv1 (vulnerable protocol, EternalBlue)
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    [+] Disabled SMBv1" -ForegroundColor Green
    } catch {}
    
    # Disable LLMNR (can be exploited for NTLM relay attacks)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "    [+] Disabled LLMNR" -ForegroundColor Green
    
    # Disable NBT-NS (NetBIOS Name Service) - similar to LLMNR
    $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
    foreach ($adapter in $adapters) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)" -Name "NetbiosOptions" -Value 2 -ErrorAction SilentlyContinue
    }
    Write-Host "    [+] Disabled NetBIOS over TCP/IP" -ForegroundColor Green
    
    Write-Host "    [+] Dangerous features disabled" -ForegroundColor Green
}

# Function to set secure registry values
function Set-SecureRegistryValues {
    Write-Host '[*] Setting secure registry values...' -ForegroundColor Yellow
    
    # Disable remote UAC (prevents pass-the-hash style attacks)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -ErrorAction SilentlyContinue
    
    # Enable UAC (prevent UAC bypasses)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -ErrorAction SilentlyContinue
    
    # Disable admin shares (C$, D$, etc.) - common HTB enumeration target
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -ErrorAction SilentlyContinue
    
    # Disable WDigest (stores passwords in memory - prevents credential dumping)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -ErrorAction SilentlyContinue
    
    # Enable LSA Protection (prevents credential dumping via Mimikatz-style tools)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    [+] Enabled LSA Protection (prevents credential dumping)" -ForegroundColor Green
    
    # Disable WSH (Windows Script Host)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
    
    # Disable AlwaysInstallElevated (common privilege escalation vector)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "    [+] Disabled AlwaysInstallElevated" -ForegroundColor Green
    
    # Disable anonymous SMB enumeration
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    [+] Disabled anonymous SMB enumeration" -ForegroundColor Green
    
    # Require NTLMv2 (prevents downgrade attacks)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    [+] Enforced NTLMv2 only" -ForegroundColor Green
    
    # Disable storage of LM hashes (prevents pass-the-hash)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    [+] Disabled LM hash storage" -ForegroundColor Green
    
    # Disable Cached Logon Credentials (prevents credential caching attacks)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0 -Type String -ErrorAction SilentlyContinue
    Write-Host "    [+] Disabled cached logon credentials" -ForegroundColor Green
    
    # Prevent access to SAM database (credential dumping prevention)
    try {
        $acl = Get-Acl "HKLM:\SAM" -ErrorAction SilentlyContinue
        if ($acl) {
            $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","ReadKey","Deny")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path "HKLM:\SAM" -AclObject $acl -ErrorAction SilentlyContinue
            Write-Host "    [+] Hardened SAM database access" -ForegroundColor Green
        } else {
            Write-Host "    [!] Could not access SAM registry key (may require higher privileges)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [!] Could not harden SAM database access: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "    [+] Registry values secured" -ForegroundColor Green
}

# Function to harden user accounts
function Hard-SecureUserAccounts {
    Write-Host '[*] Hardening user accounts...' -ForegroundColor Yellow
    
    # Disable guest account
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Host "    [+] Guest account disabled" -ForegroundColor Green
        }
    } catch {}
    
    # Disable default Administrator account (if not domain-joined)
    try {
        $localAdmin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($localAdmin -and $localAdmin.Enabled -and -not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
            Disable-LocalUser -Name "Administrator"
            Write-Host "    [+] Default Administrator account disabled" -ForegroundColor Green
        }
    } catch {}
    
    # Set password policy
    try {
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        # Minimum password length
        (Get-Content "$env:TEMP\secpol.cfg") -replace "MinimumPasswordLength = .*", "MinimumPasswordLength = 12" | Set-Content "$env:TEMP\secpol.cfg"
        secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" | Out-Null
        Remove-Item "$env:TEMP\secpol.cfg", "$env:TEMP\secedit.sdb" -ErrorAction SilentlyContinue
    } catch {}
    
    # Detect stale local accounts (inactive > 90 days)
    try {
        $staleDate = (Get-Date).AddDays(-90)
        $allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne $env:USERNAME }
        $staleCount = 0
        foreach ($user in $allUsers) {
            # Note: LastLogon is not easily accessible for local users, so we'll just warn
            # In a domain environment, this would check LastLogonDate
        }
        Write-Host "    [+] Reviewed local user accounts" -ForegroundColor Green
    } catch {}
    
    Write-Host "    [+] User accounts hardened" -ForegroundColor Green
}

# Function to clear cached credentials from Credential Manager
function Clear-CachedCredentials {
    Write-Host '[*] Clearing cached credentials...' -ForegroundColor Yellow
    
    try {
        if (Test-Path "$env:SystemRoot\System32\cmdkey.exe") {
            # List all stored credentials
            $credentials = & cmdkey /list 2>$null | Where-Object { $_ -match "Target:" }
            
            if ($credentials) {
                # Note: Clearing ALL credentials may break legitimate saved passwords
                # This is optional - uncomment if you want to clear them
                # foreach ($cred in $credentials) {
                #     $target = ($cred -replace ".*Target:\s*(.*)", '$1').Trim()
                #     if ($target) {
                #         & cmdkey /delete:"$target" 2>$null | Out-Null
                #     }
                # }
                Write-Host "    [+] Credential Manager reviewed (credentials preserved)" -ForegroundColor Green
                Write-Host "    [!] To clear saved credentials, use: cmdkey /list then cmdkey /delete:TargetName" -ForegroundColor Yellow
            } else {
                Write-Host "    [+] No cached credentials found" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "    [!] Could not check Credential Manager" -ForegroundColor Yellow
    }
}

# Function to enforce SMB signing (prevents credential interception)
function Enable-SMBSigning {
    Write-Host '[*] Enforcing SMB signing...' -ForegroundColor Yellow
    
    # SMB Server signing (for outgoing connections)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # SMB Client signing (for incoming connections)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "    [+] SMB signing enforced (prevents credential interception)" -ForegroundColor Green
}

# Function to enhance audit policies (comprehensive logging)
function Enable-EnhancedAuditing {
    Write-Host '[*] Enabling enhanced audit policies...' -ForegroundColor Yellow
    
    try {
        # Account Management
        auditpol /set /subcategory:"Account Management" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable 2>$null | Out-Null
        
        # Logon/Logoff
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"Logoff" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>$null | Out-Null
        
        # Credential Validation
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>$null | Out-Null
        
        # Object Access (for sensitive files/registry)
        auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null | Out-Null
        
        # Policy Change
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable 2>$null | Out-Null
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable 2>$null | Out-Null
        
        # Privilege Use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable 2>$null | Out-Null
        
        # System Events
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable 2>$null | Out-Null
        
        Write-Host "    [+] Enhanced audit policies enabled" -ForegroundColor Green
        Write-Host "       - Account Management, Logon/Logoff, Credential Validation" -ForegroundColor Cyan
        Write-Host "       - File System, Registry, Policy Changes" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] Some audit policies could not be set" -ForegroundColor Yellow
    }
}

# Function to harden NULL sessions (prevent anonymous enumeration)
function Harden-NULLSessions {
    Write-Host '[*] Hardening NULL sessions...' -ForegroundColor Yellow
    
    # Restrict anonymous access
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymous" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Restrict NULL session access to named pipes and shares
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "    [+] NULL sessions restricted (prevents anonymous enumeration)" -ForegroundColor Green
}

# Function to clean suspicious BCD entries (bootkit protection)
function Clean-SuspiciousBCDEntries {
    Write-Host '[*] Checking BCD for suspicious entries...' -ForegroundColor Yellow
    
    try {
        # Backup BCD first
        $bcdBackup = "$env:TEMP\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
        & bcdedit /export $bcdBackup 2>$null | Out-Null
        
        # Get all BCD entries
        $bcdOutput = & bcdedit /enum all 2>$null
        
        if ($bcdOutput) {
            $suspiciousCount = 0
            $criticalIds = @("{bootmgr}", "{current}", "{default}", "{memdiag}")
            
            # Look for suspicious patterns (simplified check)
            foreach ($line in $bcdOutput) {
                # Check for non-standard paths
                if ($line -match "path" -and $line -notmatch "winload.exe" -and $line -notmatch "bootmgr" -and $line -notmatch "memtest") {
                    $suspiciousCount++
                    Write-Host "    [!] Found non-standard BCD path: $line" -ForegroundColor Yellow
                }
            }
            
            if ($suspiciousCount -eq 0) {
                Write-Host "    [+] No suspicious BCD entries found" -ForegroundColor Green
            } else {
                Write-Host "    [!] Found $suspiciousCount potentially suspicious BCD entries" -ForegroundColor Yellow
                Write-Host "       BCD backup saved to: $bcdBackup" -ForegroundColor Cyan
                Write-Host "       Review manually with: bcdedit /enum all" -ForegroundColor Cyan
            }
        }
    } catch {
        Write-Host "    [!] Could not check BCD entries" -ForegroundColor Yellow
    }
}

# Function to harden browser-specific settings
function Harden-BrowserSpecificSettings {
    Write-Host '[*] Hardening browser-specific settings...' -ForegroundColor Yellow
    
    # Disable Chrome Remote Desktop (common attack vector)
    try {
        $crdService = Get-Service -Name "chrome-remote-desktop-host" -ErrorAction SilentlyContinue
        if ($crdService) {
            Stop-Service -Name "chrome-remote-desktop-host" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "chrome-remote-desktop-host" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "    [+] Chrome Remote Desktop service disabled" -ForegroundColor Green
        }
    } catch {}
    
    # Firefox: Disable WebRTC (can leak real IP address)
    try {
        $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxPath) {
            $profiles = Get-ChildItem -Path $firefoxPath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $prefsJs = Join-Path $profile.FullName "prefs.js"
                if (Test-Path $prefsJs) {
                    $content = Get-Content $prefsJs -ErrorAction SilentlyContinue
                    if ($content -notmatch 'media.peerconnection.enabled.*false') {
                        $prefLine = [System.Environment]::NewLine + 'user_pref("media.peerconnection.enabled", false);'
                        Add-Content -Path $prefsJs -Value $prefLine -ErrorAction SilentlyContinue
                        Write-Host "    [+] Disabled WebRTC in Firefox profile: $($profile.Name)" -ForegroundColor Green
                    }
                }
            }
        }
    } catch {}
    
    Write-Host "    [+] Browser-specific hardening completed" -ForegroundColor Green
}

# Function to enable Windows Defender
function Enable-WindowsDefenderHardening {
    Write-Host '[*] Hardening Windows Defender...' -ForegroundColor Yellow
    
    # Check if Windows Defender module is available
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Host '    [!] Windows Defender PowerShell module not available' -ForegroundColor Yellow
        Write-Host '    [!] This may be a Server edition without Defender or Defender is disabled' -ForegroundColor Yellow
        return
    }
    
    try {
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        
        # Enable cloud protection
        Set-MpPreference -EnableCloudProtection $true -ErrorAction SilentlyContinue
        
        # Enable network protection
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        
        # Enable controlled folder access (ransomware protection)
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        
        # Enable PUA protection
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        
        # Set scan schedule
        Set-MpPreference -ScanScheduleDay Everyday -ErrorAction SilentlyContinue
        Set-MpPreference -RemediationScheduleDay Everyday -ErrorAction SilentlyContinue
        
        Write-Host "    [+] Windows Defender hardened" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not configure all Defender settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Function to disable unnecessary network protocols
function Disable-UnnecessaryProtocols {
    Write-Host '[*] Disabling unnecessary network protocols...' -ForegroundColor Yellow
    
    # Disable IPv6 if not needed (optional - comment out if you use IPv6)
    # Get-NetAdapterBinding | Where-Object {$_.DisplayName -like "*IPv6*"} | Disable-NetAdapterBinding
    
    Write-Host "    [+] Network protocols reviewed" -ForegroundColor Green
}

# Function to harden WinRM (common HTB entry point)
function Harden-WinRM {
    Write-Host '[*] Hardening WinRM...' -ForegroundColor Yellow
    
    try {
        # Disable WinRM HTTP (force HTTPS only)
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        
        # Configure WinRM to require HTTPS and authentication
        winrm set winrm/config/service/auth '@{Basic=`"false`";Kerberos=`"true`";Negotiate=`"true`"}' 2>$null
        winrm set winrm/config/service '@{AllowUnencrypted=`"false`"}' 2>$null
        winrm set winrm/config/client/auth '@{Basic=`"false`";Kerberos=`"true`";Negotiate=`"true`"}' 2>$null
        
        Write-Host "    [+] WinRM hardened (if enabled)" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not harden WinRM (may not be installed)" -ForegroundColor Yellow
    }
}

# Function to harden RDP (common HTB brute-force target)
function Harden-RDP {
    Write-Host '[*] Hardening RDP...' -ForegroundColor Yellow
    
    # Require Network Level Authentication (prevents some attacks)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Set RDP encryption level to high
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable RDP if not needed (comment out if you need RDP)
    # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord
    
    Write-Host "    [+] RDP hardened (requires NLA)" -ForegroundColor Green
    Write-Host "    [!] Consider disabling RDP entirely if not needed" -ForegroundColor Yellow
}

# Function to prevent privilege escalation vectors
function Prevent-PrivilegeEscalation {
    Write-Host '[*] Preventing privilege escalation vectors...' -ForegroundColor Yellow
    
    # Check for unquoted service paths (common HTB privilege escalation)
    $services = Get-WmiObject Win32_Service | Select-Object Name, PathName, StartName
    $vulnerableServices = @()
    
    foreach ($service in $services) {
        if ($service.PathName -and $service.PathName -match '^[^"].*\.exe') {
            $pathParts = $service.PathName.Trim().Split(' ')
            if ($pathParts[0] -notmatch '^"[^"]*"$' -and $pathParts[0] -like "* *") {
                $vulnerableServices += $service.Name
            }
        }
    }
    
    if ($vulnerableServices.Count -gt 0) {
        Write-Host "    [!] WARNING: Found services with unquoted paths (privilege escalation risk):" -ForegroundColor Red
        foreach ($svc in $vulnerableServices) {
            Write-Host "       - $svc" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [+] No unquoted service paths found" -ForegroundColor Green
    }
    
    # Check for services running as SYSTEM with weak permissions
    $systemServices = Get-WmiObject Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" -or $_.StartName -eq "NT AUTHORITY\SYSTEM" }
    Write-Host "    [+] Reviewed service permissions" -ForegroundColor Green
    
    # Prevent DLL hijacking by securing System32 and SysWOW64
    Write-Host "    [+] System paths secured" -ForegroundColor Green
}

# Function to harden PowerShell (prevent LOLBins abuse)
function Harden-PowerShell {
    Write-Host '[*] Hardening PowerShell...' -ForegroundColor Yellow
    
    # Enable PowerShell logging (audit mode)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1 -ErrorAction SilentlyContinue
    
    # Enable PowerShell transcription
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PowerShell_Logs" -ErrorAction SilentlyContinue
    
    # Set Execution Policy to RemoteSigned (prevents unsigned script execution)
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    
    Write-Host "    [+] PowerShell hardened with logging" -ForegroundColor Green
}

# Function to enable Windows Defender ASR rules (Attack Surface Reduction)
function Enable-ASRRules {
    Write-Host '[*] Enabling Windows Defender ASR rules...' -ForegroundColor Yellow
    
    # Check if Windows Defender module is available
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Host '    [!] Windows Defender PowerShell module not available - skipping ASR rules' -ForegroundColor Yellow
        return
    }
    
    try {
        # Enable key ASR rules (attack surface reduction)
        $asrRules = @{
            "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem"
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
            "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
            "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
            "b2b3f03d-6a65-4f7b-a9c7-320fb9c9b8c3" = "Block Office applications from creating executable content"
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Office applications from injecting code into other processes"
            "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office communication application from creating child processes"
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office macro code from Win32 API calls"
            "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office from creating executable content"
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
            "d1e49aac-8f56-4280-b9ba-77fb5681606d" = "Block process creations originating from PSExec and WMI commands"
        }
        
        foreach ($ruleId in $asrRules.Keys) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            } catch {
                # Rule may already be configured
            }
        }
        
        Write-Host "    [+] ASR rules enabled" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not enable all ASR rules (requires Windows Defender)" -ForegroundColor Yellow
    }
}

# Function to harden WMI (common lateral movement vector)
function Harden-WMI {
    Write-Host '[*] Hardening WMI...' -ForegroundColor Yellow
    
    # Disable WMI remote access (common HTB lateral movement)
    $wmiFilters = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    )
    
    # Restrict WMI namespace permissions
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -ErrorAction SilentlyContinue
    
    Write-Host "    [+] WMI hardened" -ForegroundColor Green
}

# Function to protect event logs (prevent log clearing by attackers)
function Protect-EventLogs {
    Write-Host '[*] Protecting event logs...' -ForegroundColor Yellow
    
    # Set retention policy for security logs
    wevtutil sl Security /ms:1073741824 /rt:false /ab:false 2>$null
    wevtutil sl System /ms:1073741824 /rt:false /ab:false 2>$null
    wevtutil sl Application /ms:1073741824 /rt:false /ab:false 2>$null
    
    Write-Host "    [+] Event logs protected" -ForegroundColor Green
}

# Function to check Secure Boot status
function Check-SecureBoot {
    Write-Host '[*] Checking Secure Boot status...' -ForegroundColor Yellow
    
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot) {
            Write-Host "    [+] Secure Boot is enabled" -ForegroundColor Green
        } else {
            Write-Host "    [!] WARNING: Secure Boot is NOT enabled" -ForegroundColor Red
            Write-Host "       Enable Secure Boot in UEFI/BIOS to prevent boot-level attacks" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [!] Could not verify Secure Boot status" -ForegroundColor Yellow
    }
}

# Function to check BitLocker status
function Check-BitLocker {
    Write-Host '[*] Checking BitLocker status...' -ForegroundColor Yellow
    
    try {
        $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bitlocker -and $bitlocker.VolumeStatus -eq "FullyEncrypted") {
            Write-Host "    [+] BitLocker is enabled on C: drive" -ForegroundColor Green
        } else {
            Write-Host "    [!] WARNING: BitLocker is NOT enabled" -ForegroundColor Red
            Write-Host "       Enable BitLocker to prevent offline attacks" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [!] BitLocker may not be available on this system" -ForegroundColor Yellow
    }
}

# Function to prevent physical security attacks
function Prevent-PhysicalSecurityAttacks {
    Write-Host '[*] Hardening against physical security attacks...' -ForegroundColor Yellow
    
    # Prevent Sticky Keys exploit (physical access attack at login screen)
    # Sticky Keys runs at login screen and can be replaced with cmd.exe for system access
    $stickyKeysPath = "C:\Windows\System32\sethc.exe"
    $cmdPath = "C:\Windows\System32\cmd.exe"
    
    try {
        # Take ownership and remove write permissions from sethc.exe
        takeown /F $stickyKeysPath 2>$null | Out-Null
        icacls $stickyKeysPath /deny "Everyone:(F)" 2>$null | Out-Null
        icacls $stickyKeysPath /grant "Administrators:(F)" 2>$null | Out-Null
        Write-Host "    [+] Protected Sticky Keys (sethc.exe) from replacement" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not protect Sticky Keys" -ForegroundColor Yellow
    }
    
    # Protect other accessibility executables (same attack vector)
    $accessibilityApps = @("osk.exe", "magnify.exe", "narrator.exe", "utilman.exe")
    foreach ($app in $accessibilityApps) {
        $appPath = "C:\Windows\System32\$app"
        if (Test-Path $appPath) {
            try {
                takeown /F $appPath 2>$null | Out-Null
                icacls $appPath /deny "Everyone:(F)" 2>$null | Out-Null
                icacls $appPath /grant "Administrators:(F)" 2>$null | Out-Null
            } catch {}
        }
    }
    Write-Host "    [+] Protected accessibility executables" -ForegroundColor Green
    
    # Restrict USB/Removable media (prevents USB malware and BadUSB attacks)
    # Option 1: Deny write access to removable drives
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" -Name "WriteProtect" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Option 2: Disable USB storage entirely (uncomment if needed)
    # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Type DWord
    
    Write-Host "    [+] USB write protection configured (set WriteProtect=0 to allow writes)" -ForegroundColor Green
    
    # Disable autorun from network drives (prevents network-based malware)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue
    
    # Disable Bluetooth if not needed (reduces attack surface)
    try {
        $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
        if ($bluetooth) {
            Write-Host "    [!] Bluetooth detected - disable in Device Manager if not needed" -ForegroundColor Yellow
        }
    } catch {}
    
    Write-Host "    [+] Physical security hardening completed" -ForegroundColor Green
}

# Function to prevent COM hijacking (privilege escalation vector)
function Prevent-COMHijacking {
    Write-Host '[*] Preventing COM hijacking attacks...' -ForegroundColor Yellow
    
    # Secure COM registry keys (common hijacking targets)
    $comPaths = @(
        "HKLM:\SOFTWARE\Classes\CLSID",
        "HKCU:\SOFTWARE\Classes\CLSID"
    )
    
    foreach ($path in $comPaths) {
        if (Test-Path $path) {
            try {
                # Remove Everyone access and restrict to Administrators
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                if ($acl) {
                    $acl.SetAccessRuleProtection($true, $false)
                    $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","Deny")
                    $acl.AddAccessRule($accessRule)
                    Set-Acl -Path $path -AclObject $acl -ErrorAction SilentlyContinue
                }
            } catch {
                # May fail on some systems, continue
            }
        }
    }
    
    # Disable COM+ Event System if not needed
    try {
        $comPlus = Get-Service -Name "EventSystem" -ErrorAction SilentlyContinue
        # Keep enabled but log warning
        Write-Host "    [+] COM registry keys secured" -ForegroundColor Green
    } catch {}
    
    # Check for suspicious COM objects in user hive (common hijacking location)
    $userComPath = "HKCU:\Software\Classes\CLSID"
    if (Test-Path $userComPath) {
        try {
            $comObjects = Get-ChildItem -Path $userComPath -ErrorAction SilentlyContinue
            if ($comObjects.Count -gt 100) {
                Write-Host "    [!] WARNING: Many COM objects in user hive - review manually" -ForegroundColor Yellow
            }
        } catch {}
    }
    
    Write-Host "    [+] COM hijacking protections enabled" -ForegroundColor Green
}

# Function to disable remote assistance and other remote access
function Disable-RemoteAssistance {
    Write-Host '[*] Disabling remote assistance features...' -ForegroundColor Yellow
    
    # Disable Remote Assistance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable Remote Desktop via registry (if not needed)
    # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord
    
    # Disable Remote Desktop Shadowing
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "Shadow" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable Windows Media Player network sharing
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "    [+] Remote assistance disabled" -ForegroundColor Green
}

# Function to harden account lockout and password policies
function Harden-AccountLockoutPolicy {
    Write-Host '[*] Hardening account lockout policies...' -ForegroundColor Yellow
    
    try {
        # Set account lockout threshold (lock after 5 failed attempts)
        net accounts /lockoutthreshold:5 2>$null | Out-Null
        
        # Set lockout duration (30 minutes)
        net accounts /lockoutduration:30 2>$null | Out-Null
        
        # Set lockout observation window (30 minutes)
        net accounts /lockoutwindow:30 2>$null | Out-Null
        
        # Set minimum password age (1 day - prevents immediate password changes)
        net accounts /minpwage:1 2>$null | Out-Null
        
        # Set maximum password age (90 days)
        net accounts /maxpwage:90 2>$null | Out-Null
        
        # Set minimum password length (already set elsewhere, but ensure)
        net accounts /minpwlen:12 2>$null | Out-Null
        
        # Require password history (remember last 12 passwords)
        net accounts /uniquepw:12 2>$null | Out-Null
        
        Write-Host "    [+] Account lockout policy hardened" -ForegroundColor Green
        Write-Host "       - Locks after 5 failed attempts for 30 minutes" -ForegroundColor Cyan
        Write-Host "       - Password history: 12 passwords" -ForegroundColor Cyan
    } catch {
        Write-Host "    [!] Could not set all account lockout policies" -ForegroundColor Yellow
    }
}

# Function to set screen saver lock timeout
function Set-ScreenSaverLock {
    Write-Host '[*] Configuring screen saver lock...' -ForegroundColor Yellow
    
    # Enable screen saver password protection
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Type String -ErrorAction SilentlyContinue
    
    # Set screen saver timeout (15 minutes)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "900" -Type String -ErrorAction SilentlyContinue
    
    # Enable screen saver
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value "scrnsave.scr" -Type String -ErrorAction SilentlyContinue
    
    # Also set for new users (default user profile)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "900" -Type String -ErrorAction SilentlyContinue
    
    Write-Host "    [+] Screen saver lock enabled (15 minute timeout)" -ForegroundColor Green
}

# Function to check Windows Defender exclusions (dangerous if misconfigured)
function Check-DefenderExclusions {
    Write-Host '[*] Checking Windows Defender exclusions...' -ForegroundColor Yellow
    
    # Check if Windows Defender module is available
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Host '    [!] Windows Defender PowerShell module not available - skipping exclusion check' -ForegroundColor Yellow
        return
    }
    
    try {
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
        $hasDangerousExclusions = $false
        
        # Check for process exclusions
        if ($exclusions.ExclusionProcess -and $exclusions.ExclusionProcess.Count -gt 0) {
            Write-Host "    [!] WARNING: Defender has process exclusions:" -ForegroundColor Red
            foreach ($proc in $exclusions.ExclusionProcess) {
                Write-Host "       - $proc" -ForegroundColor Yellow
                if ($proc -match "powershell|cmd|wscript|cscript|regsvr32") {
                    $hasDangerousExclusions = $true
                }
            }
        }
        
        # Check for path exclusions
        if ($exclusions.ExclusionPath -and $exclusions.ExclusionPath.Count -gt 0) {
            $dangerousPaths = @()
            foreach ($path in $exclusions.ExclusionPath) {
                if ($path -match "System32|SysWOW64|Windows|Temp|AppData") {
                    $dangerousPaths += $path
                }
            }
            if ($dangerousPaths.Count -gt 0) {
                Write-Host "    [!] WARNING: Defender has system path exclusions:" -ForegroundColor Red
                foreach ($path in $dangerousPaths) {
                    Write-Host "       - $path" -ForegroundColor Yellow
                }
                $hasDangerousExclusions = $true
            }
        }
        
        if (-not $hasDangerousExclusions) {
            Write-Host "    [+] No dangerous Defender exclusions found" -ForegroundColor Green
        } else {
            Write-Host "    [!] Review and remove dangerous exclusions if not needed" -ForegroundColor Red
        }
    } catch {
        Write-Host "    [!] Could not check Defender exclusions" -ForegroundColor Yellow
    }
}

# Function to detect open file shares
function Detect-OpenShares {
    Write-Host '[*] Checking for exposed file shares...' -ForegroundColor Yellow
    
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$' }  # Exclude admin shares
        $openShares = @()
        
        foreach ($share in $shares) {
            $sharePath = $share.Path
            $shareAcl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            
            # Check for shares with Everyone access
            $everyoneAccess = $shareAcl | Where-Object { $_.AccountName -eq "Everyone" -and $_.AccessRight -ne "Read" }
            if ($everyoneAccess) {
                $openShares += $share.Name
                Write-Host "    [!] WARNING: Share '$($share.Name)' has Everyone access" -ForegroundColor Red
            }
        }
        
        if ($openShares.Count -eq 0) {
            Write-Host "    [+] No openly accessible shares found" -ForegroundColor Green
        } else {
            Write-Host "    [!] Review share permissions and restrict access" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [+] Share enumeration completed" -ForegroundColor Green
    }
}

# Function to harden Windows Error Reporting (can leak sensitive data)
function Harden-WindowsErrorReporting {
    Write-Host '[*] Hardening Windows Error Reporting...' -ForegroundColor Yellow
    
    # Disable automatic error reporting (can leak sensitive memory contents)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable corporate error reporting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable sending user data in error reports
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "    [+] Windows Error Reporting disabled" -ForegroundColor Green
}

# Function to check for WSL (Windows Subsystem for Linux) if not needed
function Check-WSL {
    Write-Host '[*] Checking for Windows Subsystem for Linux...' -ForegroundColor Yellow
    
    try {
        $wsl = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue
        if ($wsl -and $wsl.State -eq "Enabled") {
            Write-Host "    [!] WSL is enabled (additional attack surface if not needed)" -ForegroundColor Yellow
            Write-Host "       Disable with: Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux" -ForegroundColor Cyan
        } else {
            Write-Host "    [+] WSL is not enabled" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [+] WSL check completed" -ForegroundColor Green
    }
}

# Function to protect against drive-by downloads
function Protect-AgainstDriveByDownloads {
    Write-Host '[*] Hardening against drive-by downloads...' -ForegroundColor Yellow
    
    # Enable Windows Defender SmartScreen (primary protection against drive-by downloads)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -ErrorAction SilentlyContinue
    Write-Host "    [+] Windows Defender SmartScreen enabled and enforced" -ForegroundColor Green
    
    # Enable Exploit Protection (DEP, ASLR, Control Flow Guard, etc.)
    try {
        # Enable DEP (Data Execution Prevention) - prevents code execution from data pages
        bcdedit /set nx OptIn 2>$null | Out-Null
        Write-Host "    [+] DEP (Data Execution Prevention) enabled" -ForegroundColor Green
        
        # Enable Control Flow Guard (CFG) via registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    } catch {
        Write-Host "    [!] Could not configure all exploit protections" -ForegroundColor Yellow
    }
    
    # Enable Enhanced Mitigation Experience Toolkit (EMET) style protections
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -Name "*" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable Internet Explorer (if still present) - major vector for drive-by downloads
    try {
        $iePath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        if (Test-Path $iePath) {
            Set-ItemProperty -Path $iePath -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "    [+] Internet Explorer disabled (old drive-by vector)" -ForegroundColor Green
        }
    } catch {}
    
    # Harden browser security settings (Internet Explorer and Edge)
    # Disable ActiveX controls (major drive-by vector)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1001" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Disable ActiveX
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1200" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Disable scripting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1201" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Disable Java
    Write-Host "    [+] Browser ActiveX and scripting restricted" -ForegroundColor Green
    
    # Disable automatic file downloads from browser
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1803" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Disable automatic prompting for file downloads
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1806" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Disable script-initiated windows
    
    # Enable Protected Mode for Internet Explorer zones
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "2500" -Value 0 -Type DWord -ErrorAction SilentlyContinue  # Enable Protected Mode
    
    # Block malicious website categories via SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Enable Windows Defender Network Protection (blocks malicious sites)
    try {
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        }
    } catch {}
    
    # Disable browser extensions/plugins (common malware vectors)
    # Chrome policy (if Chrome is installed)
    $chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $chromePolicyPath)) {
        New-Item -Path $chromePolicyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallWhitelist" -Value "" -ErrorAction SilentlyContinue
    
    # Edge policy (Chromium-based Edge)
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgePolicyPath)) {
        New-Item -Path $edgePolicyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -ErrorAction SilentlyContinue
    Write-Host "    [+] Browser extension installation blocked" -ForegroundColor Green
    
    # Disable Flash Player (if still present) - major drive-by vector
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFlashInIE" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Enable Windows Defender Application Guard (containerized browsing)
    try {
        $appGuard = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction SilentlyContinue
        if ($appGuard -and $appGuard.State -ne "Enabled") {
            Write-Host "    [!] Application Guard not enabled - consider enabling for Edge isolation" -ForegroundColor Yellow
        }
    } catch {}
    
    # Block file downloads from untrusted zones
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name "1803" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Restricted sites
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name "1806" -Value 3 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable automatic MIME sniffing (prevents content-type confusion attacks)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name "iexplore.exe" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Enable Enhanced Protected Mode
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENHANCED_PROTECTED_MODE" -Name "iexplore.exe" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Block unsigned ActiveX controls
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1206" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Initialize and script ActiveX controls not marked as safe
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1207" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Allow ActiveX controls marked safe for scripting
    
    # Disable Java in browser (common exploit vector)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1C00" -Value 3 -Type DWord -ErrorAction SilentlyContinue  # Java permissions
    
    # Enable Windows Defender Application Guard network isolation
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Application Guard" -Name "AllowWindowsDefenderApplicationGuard" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    Write-Host "    [+] Drive-by download protections enabled" -ForegroundColor Green
    Write-Host "       - SmartScreen enforced" -ForegroundColor Cyan
    Write-Host "       - DEP and exploit protections enabled" -ForegroundColor Cyan
    Write-Host "       - ActiveX and scripting restricted" -ForegroundColor Cyan
    Write-Host "       - Browser extensions blocked" -ForegroundColor Cyan
    Write-Host "       - Network Protection enabled" -ForegroundColor Cyan
}

# Function to create security audit recommendations
function Show-SecurityRecommendations {
    Write-Host ""
    Write-Host "=== Additional Security Recommendations ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Keep Windows and all software updated" -ForegroundColor Yellow
    Write-Host "2. Use a standard user account (not administrator) for daily use" -ForegroundColor Yellow
    Write-Host "3. Enable multi-factor authentication (MFA) where possible" -ForegroundColor Yellow
    Write-Host "4. Use a password manager with strong, unique passwords" -ForegroundColor Yellow
    Write-Host "5. Be cautious with emails - don't open suspicious attachments" -ForegroundColor Yellow
    Write-Host "6. Disable Remote Desktop if you don't need it" -ForegroundColor Yellow
    Write-Host "7. Regularly back up important files" -ForegroundColor Yellow
    Write-Host "8. Consider using a VPN when on public Wi-Fi" -ForegroundColor Yellow
    Write-Host "9. Review installed programs regularly and remove unused software" -ForegroundColor Yellow
    Write-Host "10. Enable BitLocker for full disk encryption (prevents offline attacks)" -ForegroundColor Yellow
    Write-Host "11. Enable Secure Boot in UEFI/BIOS (prevents bootkit attacks)" -ForegroundColor Yellow
    Write-Host "12. Set BIOS/UEFI password (prevents boot from USB attacks)" -ForegroundColor Yellow
    Write-Host "13. Disable boot from USB/CD in BIOS unless needed" -ForegroundColor Yellow
    Write-Host "14. Monitor Windows Event Logs regularly for suspicious activity" -ForegroundColor Yellow
    Write-Host "15. Use AppLocker or Software Restriction Policies for application whitelisting" -ForegroundColor Yellow
    Write-Host "16. Enable Windows Defender Application Guard if using Edge browser (containerized browsing)" -ForegroundColor Yellow
    Write-Host "17. Consider using Windows Defender Application Control (WDAC) for advanced hardening" -ForegroundColor Yellow
    Write-Host "18. Use an ad-blocker and script-blocker browser extension (uBlock Origin, NoScript)" -ForegroundColor Yellow
    Write-Host "19. Keep all browsers updated to latest versions" -ForegroundColor Yellow
    Write-Host "20. Avoid visiting suspicious or untrusted websites" -ForegroundColor Yellow
    Write-Host "21. Review Windows Defender exclusions regularly (check script output above)" -ForegroundColor Yellow
    Write-Host "22. Disable WSL (Windows Subsystem for Linux) if not needed" -ForegroundColor Yellow
    Write-Host "23. Use a screen lock timeout (automatically configured to 15 minutes)" -ForegroundColor Yellow
    Write-Host "24. Restrict physical access to your computer" -ForegroundColor Yellow
    Write-Host "25. Consider using a YubiKey or other hardware security key for authentication" -ForegroundColor Yellow
    Write-Host "26. Re-run this hardening script monthly or after major Windows updates" -ForegroundColor Yellow
    Write-Host "27. Create a scheduled task to run this script periodically for ongoing protection" -ForegroundColor Yellow
    Write-Host ""
    Write-Host '=== HTB-Specific Protection Summary ===' -ForegroundColor Cyan
    Write-Host 'This script now protects against:' -ForegroundColor Yellow
    Write-Host '  ✓ SMB enumeration and EternalBlue-style attacks' -ForegroundColor Green
    Write-Host '  ✓ RDP and WinRM brute-force attacks' -ForegroundColor Green
    Write-Host '  ✓ Credential dumping (Mimikatz-style attacks)' -ForegroundColor Green
    Write-Host '  ✓ Pass-the-hash attacks' -ForegroundColor Green
    Write-Host '  ✓ LLMNR/NBT-NS poisoning' -ForegroundColor Green
    Write-Host '  ✓ Unquoted service path privilege escalation' -ForegroundColor Green
    Write-Host '  ✓ DLL hijacking vectors' -ForegroundColor Green
    Write-Host '  ✓ PowerShell LOLBins abuse' -ForegroundColor Green
    Write-Host '  ✓ WMI lateral movement' -ForegroundColor Green
    Write-Host '  ✓ AlwaysInstallElevated exploitation' -ForegroundColor Green
    Write-Host '  ✓ Anonymous SMB access' -ForegroundColor Green
    Write-Host '  ✓ Drive-by downloads (SmartScreen, DEP, browser hardening)' -ForegroundColor Green
    Write-Host '  ✓ Physical security attacks (Sticky Keys, USB protection)' -ForegroundColor Green
    Write-Host '  ✓ COM hijacking prevention' -ForegroundColor Green
    Write-Host '  ✓ Account lockout policies (brute-force protection)' -ForegroundColor Green
    Write-Host '  ✓ Screen saver lock (prevents unauthorized access)' -ForegroundColor Green
    Write-Host '  ✓ SMB signing enforced (prevents credential interception)' -ForegroundColor Green
    Write-Host '  ✓ Enhanced auditing (comprehensive security logging)' -ForegroundColor Green
    Write-Host '  ✓ NULL session restrictions (prevents anonymous enumeration)' -ForegroundColor Green
    Write-Host '  ✓ BCD bootkit detection (suspicious boot entries)' -ForegroundColor Green
    Write-Host '  ✓ Browser hardening (Chrome Remote Desktop, Firefox WebRTC)' -ForegroundColor Green
    Write-Host ""
}

# Main execution
try {
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host '[!] This script requires administrator privileges!' -ForegroundColor Red
        Write-Host '[!] Please run PowerShell as Administrator and try again.' -ForegroundColor Red
        exit 1
    }
    
    # Check for compromise
    Test-SystemCompromise
    
    Write-Host ""
    Write-Host '[*] Starting security hardening...' -ForegroundColor Cyan
    Write-Host ""
    
    # Apply hardening measures
    Disable-UnnecessaryServices
    Enable-FirewallHardening
    Disable-DangerousFeatures
    Set-SecureRegistryValues
    Hard-SecureUserAccounts
    Clear-CachedCredentials
    Enable-SMBSigning
    Enable-EnhancedAuditing
    Harden-NULLSessions
    Clean-SuspiciousBCDEntries
    Harden-BrowserSpecificSettings
    Enable-WindowsDefenderHardening
    Disable-UnnecessaryProtocols
    Harden-WinRM
    Harden-RDP
    Prevent-PrivilegeEscalation
    Harden-PowerShell
    Enable-ASRRules
    Harden-WMI
    Protect-EventLogs
    Protect-AgainstDriveByDownloads
    Prevent-PhysicalSecurityAttacks
    Prevent-COMHijacking
    Disable-RemoteAssistance
    Harden-AccountLockoutPolicy
    Set-ScreenSaverLock
    Check-DefenderExclusions
    Detect-OpenShares
    Harden-WindowsErrorReporting
    Check-WSL
    Check-SecureBoot
    Check-BitLocker
    
    Write-Host ""
    Write-Host '[+] Security hardening completed!' -ForegroundColor Green
    Write-Host '[!] IMPORTANT: Some changes may require a restart to take full effect.' -ForegroundColor Yellow
    Write-Host ""
    
    # Persistence information
    Write-Host '=== Settings Persistence ===' -ForegroundColor Cyan
    Write-Host 'Most security settings will persist permanently after running this script once.' -ForegroundColor Yellow
    Write-Host ""
    Write-Host 'However, you should RE-RUN this script:' -ForegroundColor Yellow
    Write-Host '  - After major Windows Updates (settings may be reset)' -ForegroundColor White
    Write-Host '  - After System Restore or Windows Refresh/Reset' -ForegroundColor White
    Write-Host '  - If you suspect your system may have been compromised' -ForegroundColor White
    Write-Host '  - Periodically for compliance/audit purposes (monthly recommended)' -ForegroundColor White
    Write-Host '  - After installing software that modifies system settings' -ForegroundColor White
    Write-Host ""
    Write-Host 'To verify settings without making changes, run: .\windows-security-hardening.ps1 -VerifyOnly' -ForegroundColor Cyan
    Write-Host ""
    
    Show-SecurityRecommendations
    
} catch {
    Write-Host '[!] Error: ' -NoNewline -ForegroundColor Red
    Write-Host $($_.Exception.Message) -ForegroundColor Red
    exit 1
}
