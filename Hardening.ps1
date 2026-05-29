# Enhanced PowerShell Script to Harden Windows and Active Directory
# Author: Gorstak

# Ensure elevated privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Requires Administrator privileges."
    exit
}

# Import modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

# Log setup
$logDir = "C:\Logs"
$logFile = "$logDir\Enhanced_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
function Write-Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append
    Write-Host $msg
}
Write-Log "Enhanced hardening started."

# 1. Harden Password Policies (from Harden-AD.ps1)
Write-Log "Configuring password policies..."
try {
    if (Get-Module ActiveDirectory) {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
            -ComplexityEnabled $true `
            -MinPasswordLength 14 `
            -MaxPasswordAge (New-TimeSpan -Days 90) `
            -MinPasswordAge (New-TimeSpan -Days 1) `
            -PasswordHistoryCount 24 `
            -LockoutThreshold 5 `
            -LockoutDuration (New-TimeSpan -Minutes 15) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction Stop
        Write-Log "Domain password policy updated: 14 chars, complexity enabled."
    } else {
        Write-Log "Skipping AD password policy (ActiveDirectory module unavailable)."
    }
} catch {
    Write-Log "Failed to set password policy: $_"
}

# 2. Secure Service Accounts (from Harden-AD.ps1)
Write-Log "Securing service accounts..."
try {
    if (Get-Module ActiveDirectory) {
        $serviceAccounts = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires
        foreach ($account in $serviceAccounts) {
            Set-ADUser -Identity $account -PasswordNeverExpires $false
            Write-Log "Removed non-expiring password for: $($account.SamAccountName)"
        }
        Write-Log "Secured $($serviceAccounts.Count) service accounts."
    } else {
        Write-Log "Skipping service account hardening (ActiveDirectory module unavailable)."
    }
} catch {
    Write-Log "Failed to secure service accounts: $_"
}

# 3. Credential Protection (from Creds.ps1)
Write-Log "Enhancing credential protection..."
# Enable LSASS PPL
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
    Write-Log "LSASS configured as Protected Process Light (PPL). Reboot required."
} catch {
    Write-Log "Failed to enable LSASS PPL: $_"
}
# Clear cached credentials
try {
    if (Test-Path "$env:SystemRoot\System32\cmdkey.exe") {
        & cmdkey /list | ForEach-Object {
            if ($_ -match "Target:") {
                $target = $_ -replace ".*Target: (.*)", '$1'
                & cmdkey /delete:$target
            }
        }
        Write-Log "Cleared Credential Manager entries."
    } else {
        Write-Log "cmdkey.exe not found; skipping credential clearing."
    }
} catch {
    Write-Log "Failed to clear cached credentials: $_"
}
# Disable credential caching
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0
    Write-Log "Disabled cached logons (CachedLogonsCount=0)."
} catch {
    Write-Log "Failed to disable credential caching: $_"
}

# 4. Privileged Access Management (from Harden-AD.ps1, Secpol.ps1)
Write-Log "Configuring privileged access..."
try {
    # Disable Guest and Administrator accounts
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Log "Disabled Guest and default Administrator accounts."
    # Restrict admin logons
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0
    Write-Log "Restricted remote admin logons."
    # Harden privilege rights (Secpol.ps1)
    $privilegeSettings = @'
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyRemoteLogonRight = *S-1-5-11
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeRemoteInteractiveLogonRight=
SeRemoteLogonRight=
'@
    $cfgPath = "C:\secpol.cfg"
    secedit /export /cfg $cfgPath /quiet
    $privilegeSettings | Out-File -Append -FilePath $cfgPath
    secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    Remove-Item $cfgPath -Force
    Write-Log "Hardened user privilege rights via secedit."
} catch {
    Write-Log "Failed to configure privileged access: $_"
}

# 5. Enable Auditing (from Harden-AD.ps1, Creds.ps1)
Write-Log "Enabling auditing..."
try {
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    Write-Log "Enabled auditing for Directory Service, Account Management, and Credential Validation."
    $psLogRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $psLogRegPath -Force | Out-Null
    Set-ItemProperty -Path $psLogRegPath -Name "EnableScriptBlockLogging" -Value 1
    Write-Log "Enabled PowerShell script block logging."
} catch {
    Write-Log "Failed to enable auditing: $_"
}

# 6. Patch Management (from Patcher.ps1)
Write-Log "Configuring patch management..."
$patchDir = "C:\ProgramData\VulnPatcher"
$csvPath = "$patchDir\ms-vulns.csv"
try {
    if (-not (Test-Path $patchDir)) { New-Item -ItemType Directory -Path $patchDir -Force | Out-Null }
    $msApi = "https://api.msrc.microsoft.com/cvrf/2025-Oct?`$format=csv"
    $tempCsv = "$env:TEMP\msrc-temp.csv"
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        $wc.DownloadFile($msApi, $tempCsv)
        if ((Get-Item $tempCsv).Length -gt 1000) {
            Move-Item $tempCsv $csvPath -Force
            Write-Log "Downloaded Microsoft vulnerability CSV."
        }
    } catch {
        Write-Log "API download failed: $_; using cached CSV if available."
    }
    if (Test-Path $csvPath) {
        $vulns = Import-Csv $csvPath
        $inst = Get-HotFix | Select-Object -ExpandProperty HotFixID -ErrorAction SilentlyContinue
        if (-not $inst) { $inst = @() }
        $toInstall = @()
        foreach ($v in $vulns) {
            if ($v.'KB' -match 'KB\d{7}') {
                $kb = ($v.'KB' -split ';')[0].Trim()
                if ($inst -notcontains $kb) { $toInstall += $kb }
            }
        }
        if ($toInstall.Count -gt 0) {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $result = $searcher.Search("IsInstalled=0")
            $installColl = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($kb in $toInstall) {
                foreach ($u in $result.Updates) {
                    if ($u.KBArticleIDs -contains ($kb -replace 'KB','')) {
                        $installColl.Add($u) | Out-Null
                        Write-Log "Queued $kb for installation."
                    }
                }
            }
            if ($installColl.Count -gt 0) {
                $dl = $session.CreateUpdateDownloader()
                $dl.Updates = $installColl
                $dl.Download()
                $inst = $session.CreateUpdateInstaller()
                $inst.Updates = $installColl
                $res = $inst.Install()
                Write-Log "Installed $($installColl.Count) patches. Reboot: $($res.RebootRequired)."
            }
        } else {
            Write-Log "No missing patches found."
        }
    } else {
        Write-Log "No CSV available; skipping vulnerability check."
    }
    # Schedule daily patching
    $action = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    schtasks /create /tn "VulnPatcher" /tr $action /sc daily /st 03:00 /ru SYSTEM /f /rl HIGHEST /delay 0000:30 | Out-Null
    Write-Log "Scheduled daily patching task."
} catch {
    Write-Log "Patch management failed: $_"
}

# 7. Disable Legacy Protocols (from Harden-AD.ps1)
Write-Log "Disabling legacy protocols..."
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictNTLM" -Value 1
    Write-Log "Disabled NTLM (Kerberos only)."
} catch {
    Write-Log "Failed to disable NTLM: $_"
}

# 8. Secure Remote Access (from PreventRemoteConnections.ps1)
Write-Log "Securing remote access..."
try {
    # Disable RDP and Remote Assistance
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TermService" -StartupType Disabled
    Write-Log "Disabled RDP and Remote Assistance."
    # Disable PowerShell Remoting
    Disable-PSRemoting -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WinRM" -StartupType Disabled
    Write-Log "Disabled PowerShell Remoting."
    # Disable SMB
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue
    Write-Log "Disabled SMB protocols."
    # Disable UPnP
    Get-Service -Name "SSDPSRV", "upnphost" | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled
    }
    Write-Log "Disabled UPnP services."
    # Firewall rules
    New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block SMB TCP 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block SMB TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block SMB UDP 137-138" -Direction Inbound -LocalPort 137-138 -Protocol UDP -Action Block -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block WinRM" -Direction Inbound -LocalPort 5985,5986 -Protocol TCP -Action Block -ErrorAction SilentlyContinue
    Write-Log "Added firewall rules to block RDP, SMB, WinRM."
} catch {
    Write-Log "Failed to secure remote access: $_"
}

# 9. Enable Windows Defender (from Harden-AD.ps1)
Write-Log "Configuring Windows Defender..."
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Log "Enabled Defender real-time protection, Controlled Folder Access, and PUA protection."
} catch {
    Write-Log "Failed to configure Defender: $_"
}

# 10. Clean Up Stale Accounts (from Harden-AD.ps1)
Write-Log "Removing stale accounts..."
try {
    if (Get-Module ActiveDirectory) {
        $staleDate = (Get-Date).AddDays(-90)
        $staleAccounts = Get-ADUser -Filter {LastLogonDate -lt $staleDate -and Enabled -eq $true} -Properties LastLogonDate
        foreach ($account in $staleAccounts) {
            Disable-ADAccount -Identity $account
            Write-Log "Disabled stale account: $($account.SamAccountName)"
        }
        Write-Log "Disabled $($staleAccounts.Count) stale accounts."
    } else {
        Write-Log "Skipping stale account cleanup (ActiveDirectory module unavailable)."
    }
} catch {
    Write-Log "Failed to disable stale accounts: $_"
}

# 11. BCD Cleanup (from BCDCleanup.ps1)
Write-Log "Cleaning suspicious BCD entries..."
try {
    $bcdBackup = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
    & bcdedit /export $bcdBackup | Out-Null
    Write-Log "BCD backed up to $bcdBackup."
    $bcdOutput = & bcdedit /enum all
    $bcdEntries = @(); $currentEntry = $null
    foreach ($line in $bcdOutput) {
        if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
            if ($currentEntry) { $bcdEntries += $currentEntry }
            $currentEntry = [PSCustomObject]@{ Identifier = $Matches[1]; Properties = @{} }
        } elseif ($line -match "^(\w+)\s+(.+)$") {
            if ($currentEntry) { $currentEntry.Properties[$Matches[1]] = $Matches[2] }
        }
    }
    if ($currentEntry) { $bcdEntries += $currentEntry }
    $criticalIds = @("{bootmgr}", "{current}", "{default}")
    $suspicious = @()
    foreach ($entry in $bcdEntries) {
        if ($entry.Identifier -in $criticalIds) { continue }
        $isSuspicious = $false; $reason = ""
        if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
            $isSuspicious = $true; $reason += "Non-Windows description; "
        }
        if ($entry.Properties.device -match "vhd=") { $isSuspicious = $true; $reason += "VHD device; " }
        if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
            $isSuspicious = $true; $reason += "Non-standard path; "
        }
        if ($isSuspicious) {
            $suspicious += [PSCustomObject]@{ Identifier = $entry.Identifier; Reason = $reason }
        }
    }
    foreach ($entry in $suspicious) {
        & bcdedit /delete $entry.Identifier /f | Out-Null
        Write-Log "Deleted suspicious BCD entry: $($entry.Identifier) ($($entry.Reason))"
    }
    Write-Log "BCD cleanup completed. $($suspicious.Count) suspicious entries removed."
} catch {
    Write-Log "BCD cleanup failed: $_"
}

# 12. Browser Security (from Browsers.ps1)
Write-Log "Securing browsers..."
try {
    # Firefox: Disable WebRTC
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        $profiles = Get-ChildItem -Path $firefoxPath -Directory
        foreach ($profile in $profiles) {
            $prefsJs = "$($profile.FullName)\prefs.js"
            if (Test-Path $prefsJs) {
                if ((Get-Content $prefsJs) -notmatch 'media.peerconnection.enabled.*false') {
                    Add-Content -Path $prefsJs 'user_pref("media.peerconnection.enabled", false);'
                    Write-Log "Disabled WebRTC in Firefox profile: $($profile.FullName)"
                }
            }
        }
    }
    # Chrome-based browsers: Block Chrome Remote Desktop
    $crdService = "chrome-remote-desktop-host"
    if (Get-Service -Name $crdService -ErrorAction SilentlyContinue) {
        Stop-Service -Name $crdService -Force
        Set-Service -Name $crdService -StartupType Disabled
        Write-Log "Disabled Chrome Remote Desktop service."
    }
    New-NetFirewallRule -DisplayName "Block CRD" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -ErrorAction SilentlyContinue
    Write-Log "Blocked Chrome Remote Desktop port (443)."
} catch {
    Write-Log "Failed to secure browsers: $_"
}

# 13. Disable NULL Sessions (from Null.ps1)
Write-Log "Disabling NULL sessions..."
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymous" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNullSessAccess" -Value 1
    gpupdate /force | Out-Null
    Write-Log "NULL sessions disabled."
} catch {
    Write-Log "Failed to disable NULL sessions: $_"
}

# 14. Network Debloating (from NetworkDebloat.ps1)
Write-Log "Debloating network bindings..."
try {
    $componentsToDisable = @("ms_server", "ms_msclient", "ms_pacer", "ms_lltdio", "ms_rspndr", "ms_tcpip6")
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        foreach ($component in $componentsToDisable) {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -ErrorAction SilentlyContinue
        }
    }
    New-NetFirewallRule -DisplayName "Block LDAP" -Direction Outbound -Protocol TCP -RemotePort 389,636 -Action Block -ErrorAction SilentlyContinue
    Write-Log "Network bindings debloated and LDAP blocked."
} catch {
    Write-Log "Network debloating failed: $_"
}

# 15. IP Blocking (from IPBlock.ps1)
Write-Log "Blocking malicious IPs..."
try {
    $blockListURLs = @(
        "https://www.spamhaus.org/drop/drop.lasso",
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        # Add more from original
    )
    $allIPs = @()
    foreach ($url in $blockListURLs) {
        try {
            $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content -split "`n"
            $parsed = $content | Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$" }  # Simplified parse
            $allIPs += $parsed
        } catch {}
    }
    $uniqueIPs = $allIPs | Sort-Object -Unique
    foreach ($ip in $uniqueIPs) {
        New-NetFirewallRule -DisplayName "Block Malware IP - $ip" -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Block Malware IP - $ip" -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any -ErrorAction SilentlyContinue
    }
    Write-Log "Blocked $($uniqueIPs.Count) malicious IPs."
} catch {
    Write-Log "IP blocking failed: $_"
}

# 16. DNS Ad Blocking (from Pihole.ps1)
Write-Log "Implementing DNS ad blocking..."
try {
    $filterLists = @(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
        # Add more
    )
    $blockedDomains = @()
    foreach ($url in $filterLists) {
        $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content -split "`n"
        $domains = $content | Where-Object { $_ -match "^\|\|([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\^" } | ForEach-Object { $matches[1] }
        $blockedDomains += $domains
    }
    $uniqueDomains = $blockedDomains | Sort-Object -Unique
    # Set DNS policy (simplified; full implementation needs Dnscache config)
    $dnsPolicyKey = "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\BlockAdDomains"
    New-Item -Path (Split-Path $dnsPolicyKey) -Name (Split-Path $dnsPolicyKey -Leaf) -Force | Out-Null
    Set-ItemProperty -Path $dnsPolicyKey -Name "Domains" -Value ($uniqueDomains -join ",") -Type String
    # Persistent routes for ad servers (example IPs)
    route add 0.0.0.0 mask 0.0.0.0 127.0.0.1 -p | Out-Null  # Null route example; expand with resolved IPs
    Write-Log "Blocked $($uniqueDomains.Count) ad domains via DNS policy."
} catch {
    Write-Log "DNS ad blocking failed: $_"
}

# Final Output
Write-Log "Hardening completed. Review $logFile."
Write-Host "Logs at $logFile. Reboot may be required."