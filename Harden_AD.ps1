# PowerShell Script to Harden Windows and Active Directory Against Credential Theft and AD Attacks
# Requires: Domain Admin or Local Admin privileges, ActiveDirectory module
# Run on: Windows Server 2019/2022 (DC) or Windows 10/11 (client)
# Note: Test in a lab environment before production deployment

# Ensure script runs with elevated privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrative privileges. Run as Administrator."
    exit
}

# Import ActiveDirectory module (for AD-related commands)
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Warning "ActiveDirectory module not found. Some AD-specific hardening steps will be skipped."
}

# Log file for tracking actions
$logFile = "C:\Logs\AD_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null
Write-Output "Hardening script started at $(Get-Date)" | Out-File -FilePath $logFile -Append

# 1. Harden Password Policies (Block weak passwords, enforce complexity)
Write-Output "Configuring password policies..." | Out-File -FilePath $logFile -Append
try {
    # Set domain password policy (requires Domain Admin)
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
        -ComplexityEnabled $true `
        -MinPasswordLength 14 `
        -MaxPasswordAge (New-TimeSpan -Days 90) `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -PasswordHistoryCount 24 `
        -LockoutThreshold 5 `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction Stop
    Write-Output "Domain password policy updated: 14 chars, complexity enabled, 90-day max age." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to set domain password policy. Error: $_" | Out-File -FilePath $logFile -Append
}

# 2. Secure Service Accounts (Find and fix non-expiring passwords)
Write-Output "Securing service accounts..." | Out-File -FilePath $logFile -Append
try {
    $serviceAccounts = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires
    foreach ($account in $serviceAccounts) {
        Set-ADUser -Identity $account -PasswordNeverExpires $false
        Write-Output "Removed non-expiring password for service account: $($account.SamAccountName)" | Out-File -FilePath $logFile -Append
    }
    Write-Output "Found and secured $($serviceAccounts.Count) service accounts with non-expiring passwords." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to secure service accounts. Error: $_" | Out-File -FilePath $logFile -Append
}

# 3. Limit Cached Credentials (Reduce risk of credential dumping)
Write-Output "Limiting cached credentials..." | Out-File -FilePath $logFile -Append
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "CachedLogonsCount" -Value 1 -ErrorAction SilentlyContinue
if ($?) {
    Write-Output "Cached logons limited to 1 (minimizes credential storage)." | Out-File -FilePath $logFile -Append
} else {
    Write-Warning "Failed to limit cached credentials." | Out-File -FilePath $logFile -Append
}

# 4. Privileged Access Management (Restrict admin accounts)
Write-Output "Configuring privileged access management..." | Out-File -FilePath $logFile -Append
try {
    # Disable default Guest and local Administrator accounts
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Output "Disabled Guest and default Administrator accounts." | Out-File -FilePath $logFile -Append

    # Restrict admin logons to specific systems (via GPO or local policy)
    $adminGroup = "Administrators"
    $restrictRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $restrictRegPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -ErrorAction SilentlyContinue
    Write-Output "Restricted remote admin logons (LocalAccountTokenFilterPolicy set to 0)." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to configure privileged access settings. Error: $_" | Out-File -FilePath $logFile -Append
}

# 5. Enable AD Monitoring and Auditing
Write-Output "Enabling AD monitoring and auditing..." | Out-File -FilePath $logFile -Append
try {
    # Enable advanced audit policies for AD changes
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    Write-Output "Enabled auditing for Directory Service Changes and Account Management." | Out-File -FilePath $logFile -Append

    # Enable PowerShell logging
    $psLogRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $psLogRegPath -Force | Out-Null
    Set-ItemProperty -Path $psLogRegPath -Name "EnableScriptBlockLogging" -Value 1
    Write-Output "Enabled PowerShell script block logging." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to enable auditing or logging. Error: $_" | Out-File -FilePath $logFile -Append
}

# 6. Patch Management (Check and install critical updates)
Write-Output "Checking for and installing critical updates..." | Out-File -FilePath $logFile -Append
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    if ($searchResult.Updates.Count -gt 0) {
        Write-Output "Found $($searchResult.Updates.Count) pending updates. Installing..." | Out-File -FilePath $logFile -Append
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $searchResult.Updates
        $downloader.Download()
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $searchResult.Updates
        $installResult = $installer.Install()
        Write-Output "Update installation completed. Reboot may be required." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "No critical updates pending." | Out-File -FilePath $logFile -Append
    }
} catch {
    Write-Warning "Failed to check or install updates. Error: $_" | Out-File -FilePath $logFile -Append
}

# 7. Disable Legacy Protocols (e.g., NTLM) to Prevent Relay Attacks
Write-Output "Disabling legacy protocols (NTLM)..." | Out-File -FilePath $logFile -Append
try {
    $ntlmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $ntlmRegPath -Name "LmCompatibilityLevel" -Value 5 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $ntlmRegPath -Name "RestrictNTLM" -Value 1 -ErrorAction SilentlyContinue
    Write-Output "Disabled NTLM and set LmCompatibilityLevel to 5 (Kerberos only)." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to disable NTLM. Error: $_" | Out-File -FilePath $logFile -Append
}

# 8. Enable Windows Defender and Block Suspicious Processes (Protect against malware stealing cookies/credentials)
Write-Output "Configuring Windows Defender..." | Out-File -FilePath $logFile -Append
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Output "Enabled Controlled Folder Access and PUA protection in Windows Defender." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to configure Windows Defender. Error: $_" | Out-File -FilePath $logFile -Append
}

# 9. Enforce SMB Signing (Prevent credential interception)
Write-Output "Enforcing SMB signing..." | Out-File -FilePath $logFile -Append
try {
    $smbRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $smbRegPath -Name "RequireSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $smbRegPath -Name "EnableSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Write-Output "Enabled SMB signing to prevent credential interception." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to enforce SMB signing. Error: $_" | Out-File -FilePath $logFile -Append
}

# 10. Clean Up Stale Accounts (Reduce attack surface)
Write-Output "Removing stale user accounts..." | Out-File -FilePath $logFile -Append
try {
    $staleDate = (Get-Date).AddDays(-90)
    $staleAccounts = Get-ADUser -Filter {LastLogonDate -lt $staleDate -and Enabled -eq $true} -Properties LastLogonDate
    foreach ($account in $staleAccounts) {
        Disable-ADAccount -Identity $account
        Write-Output "Disabled stale account: $($account.SamAccountName)" | Out-File -FilePath $logFile -Append
    }
    Write-Output "Disabled $($staleAccounts.Count) stale accounts (inactive > 90 days)." | Out-File -FilePath $logFile -Append
} catch {
    Write-Warning "Failed to disable stale accounts. Error: $_" | Out-File -FilePath $logFile -Append
}

# Final Output
Write-Output "Hardening script completed at $(Get-Date). Review $logFile for details." | Out-File -FilePath $logFile -Append
Write-Host "Hardening complete. Check $logFile for logs. Reboot may be required for some changes to take effect."

# Prompt for reboot if updates were installed
if ($installResult -and $installResult.RebootRequired) {
    Write-Host "A reboot is required to complete update installation. Reboot now? (Y/N)"
    $response = Read-Host
    if ($response -eq 'Y') {
        Restart-Computer -Force
    }
}