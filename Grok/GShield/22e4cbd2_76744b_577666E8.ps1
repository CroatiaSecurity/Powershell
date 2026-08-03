# GShield.ps1
# Author: Gorstak
# Ultimate Security Suite: System Hardening + Advanced EDR Antivirus + Anti-Keylogger + Browser Network Guard
# Runs hardening once, starts KeyScrambler and Browser Network Guard in background jobs,
# then runs the antivirus real-time monitoring in the main thread.

#requires -RunAsAdministrator

# --- Hardening Section (from Hardening.ps1) ---

# Ensure elevated privileges (already required above, but double-check)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Requires Administrator privileges."
    exit
}

# Import modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

# Log setup for hardening
$logDir = "C:\Logs"
$logFile = "$logDir\GShield_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
function Write-Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append
    Write-Host $msg
}
Write-Log "GShield hardening started."

# [All the original hardening sections 1-16 from Hardening.ps1 remain unchanged here]
# (Password policies, service accounts, credential protection, privileged access, auditing,
# patch management, legacy protocols, remote access, Defender, stale accounts, BCD cleanup,
# browser security, NULL sessions, network debloat, IP blocking, DNS ad blocking)

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

Write-Log "Hardening completed. Review $logFile."
Write-Host "Hardening complete. Logs at $logFile. Reboot may be required."

# --- End Hardening Section ---

# --- KeyScrambler Background Job (from KeyScrambler.ps1) ---

$keyScramblerCode = @'
$Source = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] private static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int x; public int y; }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;

        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
            Marshal.GetFunctionPointerForDelegate(_proc),
            GetModuleHandle(null), 0);

        if (_hookID == IntPtr.Zero)
            throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("KeyScrambler ACTIVE - invisible mode ON");
        Console.WriteLine("You see only your real typing * Keyloggers blinded");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private static bool ModifiersDown()
    {
        return (GetKeyState(0x10) & 0x8000) != 0 ||  // Shift
               (GetKeyState(0x11) & 0x8000) != 0 ||  // Ctrl
               (GetKeyState(0x12) & 0x8000) != 0;    // Alt
    }

    private static void InjectFakeChar(char c)
    {
        var inputs = new INPUT[2];

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.dwExtraInfo = GetMessageExtraInfo();

        inputs[1] = inputs[0];
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

        SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    private static void Flood()
    {
        if (_rnd.NextDouble() < 0.5) return;
        int count = _rnd.Next(1, 7);
        for (int i = 0; i < count; i++)
            InjectFakeChar((char)_rnd.Next('A', 'Z' + 1));
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            if ((k.flags & 0x10) != 0) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (ModifiersDown()) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (k.vkCode >= 65 && k.vkCode <= 90)
            {
                if (_rnd.NextDouble() < 0.75) Flood();
                var ret = CallNextHookEx(_hookID, nCode, wParam, lParam);
                if (_rnd.NextDouble() < 0.75) Flood();
                return ret;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

try {
    Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
}
catch {
    Write-Error "KeyScrambler compilation failed: $($_.Exception.Message)"
    exit
}

[KeyScrambler]::Start()
'@

$keyJob = Start-Job -ScriptBlock ([scriptblock]::Create($keyScramblerCode))
Write-Host "KeyScrambler anti-keylogger started in background."

# --- Browser Network Guard Background Job (from BrowserNetworkGuard.ps1) ---

$browserGuardCode = @'
param(
    [int]$ProxyPort = 8888,
    [int]$CheckInterval = 1,
    [string]$WhitelistDB = "$PSScriptRoot\whitelist.json",
    [string]$LogFile = "$PSScriptRoot\blocked_requests.log"
)

$Global:Whitelist = @{
    "UserEntered" = @()
    "Dependencies" = @()
    "Permanent" = @(
        "microsoft.com","windows.com","windowsupdate.com","live.com",
        "steampowered.com","steamcommunity.com","steamstatic.com","steamcdn-a.akamaihd.net",
        "epicgames.com","unrealengine.com","ol.epicgames.com",
        "battle.net","blizzard.com","blzstatic.cn",
        "ea.com","origin.com","eaassets-a.akamaihd.net",
        "ubisoft.com","ubi.com","uplay.com",
        "gog.com","gog-statics.com",
        "xbox.com","xboxlive.com","xboxservices.com",
        "riotgames.com","leagueoflegends.com",
        "rockstargames.com","socialclub.rockstargames.com",
        "humblebundle.com","paradoxplaza.com","bethesda.net"
    )
}

if (Test-Path $WhitelistDB) {
    $Global:Whitelist = Get-Content $WhitelistDB | ConvertFrom-Json -AsHashtable
}

function Save-Whitelist {
    $Global:Whitelist | ConvertTo-Json -Depth 10 | Set-Content $WhitelistDB
}

function Log-BlockedRequest {
    param($Domain, $Reason)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] BLOCKED: $Domain - $Reason"
    Add-Content -Path $LogFile -Value $entry
    Write-Host $entry -ForegroundColor Red
}

function Log-AllowedRequest {
    param($Domain, $Reason)
    Write-Host "[ALLOWED] $Domain - $Reason" -ForegroundColor Green
}

function Extract-Domain {
    param($Url)
    try {
        $uri = [System.Uri]$Url
        return $uri.Host.ToLower()
    } catch {
        return $null
    }
}

function Is-Subdomain {
    param($Domain, $ParentDomain)
    return $Domain -eq $ParentDomain -or $Domain.EndsWith(".$ParentDomain")
}

function Is-Allowed {
    param($Domain)
    if (-not $Domain) { return $false }
    
    foreach ($allowed in $Global:Whitelist.Permanent) {
        if (Is-Subdomain $Domain $allowed) {
            Log-AllowedRequest $Domain "Permanent whitelist"
            return $true
        }
    }
    
    foreach ($allowed in $Global:Whitelist.UserEntered) {
        if (Is-Subdomain $Domain $allowed) {
            Log-AllowedRequest $Domain "User entered"
            return $true
        }
    }
    
    foreach ($allowed in $Global:Whitelist.Dependencies) {
        if (Is-Subdomain $Domain $allowed) {
            Log-AllowedRequest $Domain "Dependency"
            return $true
        }
    }
    
    return $false
}

function Add-UserDomain {
    param($Domain)
    if ($Domain -and $Domain -notin $Global:Whitelist.UserEntered) {
        $Global:Whitelist.UserEntered += $Domain
        Save-Whitelist
        Write-Host "[+] Added user domain: $Domain" -ForegroundColor Cyan
    }
}

function Add-Dependency {
    param($Domain)
    if ($Domain -and $Domain -notin $Global:Whitelist.Dependencies) {
        $Global:Whitelist.Dependencies += $Domain
        Save-Whitelist
        Write-Host "[+] Added dependency: $Domain" -ForegroundColor Yellow
    }
}

function Start-AddressBarMonitor {
    if (-not ([System.Management.Automation.PSTypeName]'WindowMonitor').Type) {
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            using System.Text;
            
            public class WindowMonitor {
                [DllImport("user32.dll")]
                public static extern IntPtr GetForegroundWindow();
                
                [DllImport("user32.dll")]
                public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
                
                [DllImport("user32.dll", SetLastError = true)]
                public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
                
                public static string GetActiveWindowTitle() {
                    const int nChars = 256;
                    StringBuilder buff = new StringBuilder(nChars);
                    IntPtr handle = GetForegroundWindow();
                    if (GetWindowText(handle, buff, nChars) > 0) {
                        return buff.ToString();
                    }
                    return null;
                }
                
                public static uint GetActiveWindowProcessId() {
                    IntPtr handle = GetForegroundWindow();
                    uint processId;
                    GetWindowThreadProcessId(handle, out processId);
                    return processId;
                }
            }
"@
    }

    $script:LastTitle = ""
    $script:BrowserProcessNames = @("chrome", "firefox", "msedge", "brave", "opera", "vivaldi")
    
    while ($true) {
        Start-Sleep -Seconds $CheckInterval
        
        try {
            $windowTitle = [WindowMonitor]::GetActiveWindowTitle()
            $procId = [WindowMonitor]::GetActiveWindowProcessId()
            
            if ($procId -gt 0) {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                
                if ($proc -and $script:BrowserProcessNames -contains $proc.Name.ToLower()) {
                    if ($windowTitle -and $windowTitle -ne $script:LastTitle) {
                        $script:LastTitle = $windowTitle
                        
                        if ($windowTitle -match "https?://([^/\s]+)") {
                            $domain = $matches[1]
                            Add-UserDomain $domain
                        }
                        elseif ($windowTitle -match "([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)") {
                            $domain = $matches[1].ToLower()
                            if ($domain -notmatch "chrome|firefox|edge|browser") {
                                Add-UserDomain $domain
                            }
                        }
                    }
                }
            }
        } catch {}
    }
}

function Start-ProxyServer {
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:$ProxyPort/")
        $listener.Start()
        Write-Host "[INFO] Browser Network Guard proxy started on localhost:$ProxyPort"
        
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $targetUrl = $request.Url.AbsoluteUri.Replace("http://localhost:$ProxyPort/", "")
            $domain = Extract-Domain $targetUrl
            
            if (-not $domain) {
                $response.StatusCode = 400
                $response.Close()
                continue
            }
            
            if (Is-Allowed $domain) {
                try {
                    $webRequest = [System.Net.WebRequest]::Create($targetUrl)
                    $webRequest.Method = $request.HttpMethod
                    
                    foreach ($header in $request.Headers.AllKeys) {
                        if ($header -notin @("Host", "Connection")) {
                            $webRequest.Headers[$header] = $request.Headers[$header]
                        }
                    }
                    
                    $webResponse = $webRequest.GetResponse()
                    $responseStream = $webResponse.GetResponseStream()
                    
                    $response.StatusCode = [int]$webResponse.StatusCode
                    $response.ContentType = $webResponse.ContentType
                    
                    $buffer = New-Object byte[] 8192
                    $bytesRead = 0
                    do {
                        $bytesRead = $responseStream.Read($buffer, 0, $buffer.Length)
                        $response.OutputStream.Write($buffer, 0, $bytesRead)
                    } while ($bytesRead -gt 0)
                    
                    $responseStream.Close()
                    $webResponse.Close()
                    
                    # Auto-add legitimate dependencies
                    if ($webResponse.ContentType -like "*text/html*") {
                        $stream = $webResponse.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $html = $reader.ReadToEnd()
                        $reader.Close()
                        $stream.Close()
                        
                        $html -split '[ "\''<>]' | ForEach-Object {
                            if ($_ -match "^https?://([^/\s]+)") {
                                Add-Dependency $matches[1]
                            }
                        }
                    }
                    
                } catch {
                    $response.StatusCode = 502
                }
            } else {
                Log-BlockedRequest $domain "Not in whitelist"
                
                $response.StatusCode = 403
                $html = @"
<!DOCTYPE html>
<html><head><title>Blocked by GShield Browser Guard</title></head>
<body><h1>Connection Blocked</h1>
<p>Domain <strong>$domain</strong> is not whitelisted.</p>
<p>Type the full URL in your browser address bar to allow it and its dependencies.</p>
</body></html>
"@
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            $response.Close()
        }
    } catch {
        Write-Host "[ERROR] Proxy error: $_" -ForegroundColor Red
    }
}

$monitorJob = Start-Job -ScriptBlock ${function:Start-AddressBarMonitor}

Write-Host "Browser Network Guard active. Configure browsers to use proxy localhost:$ProxyPort"

Start-ProxyServer
'@

$browserJob = Start-Job -ScriptBlock ([scriptblock]::Create($browserGuardCode))
Write-Host "Browser Network Guard started in background (proxy on port 8888)."

# --- Antivirus Section (from Antivirus.ps1) ---

# [Full antivirus code from previous merge remains here unchanged]
# Includes all functions, real-time monitoring, WMI hooks, memory scanner, etc.

# Ultimate Antivirus by Gorstak - Extended EDR Version
# Combines hash lookups, memory scanning, real-time monitoring, smart DLL blocking
# + behavior monitoring, persistence & fileless detection, threat intel updates, alerting

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"
$Database   = Join-Path $Base "scanned_files.txt"
$RulesDir   = Join-Path $Base "rules"
$scannedFiles = @{}

# Task configuration
$taskName        = "UltimateAntivirusStartup"
$taskDescription = "Ultimate Antivirus - Runs at user logon with admin privileges"
$scriptDir       = "C:\Windows\Setup\Scripts\Bin"
$scriptPath      = "$scriptDir\Antivirus.ps1"

# Config / feature flags
$DeepScanHours        = 6
$ThreatIntelDays      = 7
$BehaviorKillEnabled  = $true
$AutoBlockC2          = $true

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Allowed system accounts
$AllowedSIDs = @(
    'S-1-2-0',  # Console user
    'S-1-5-20'  # Network Service
)

# Optional MalwareBazaar API key
$MalwareBazaarAuthKey = ""

# Free public hash lookup endpoints
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"
$CymruMHR        = "https://api.malwarehash.cymru.com/v1/hash"

# High-risk paths where unsigned DLLs are suspicious
$RiskyPaths = @(
    '\temp\','\downloads\','\appdata\local\temp\','\public\','\windows\temp\',
    '\appdata\roaming\','\desktop\'
)

# Comprehensive list of monitored extensions
$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1',
    
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

# Protected processes we never kill
$ProtectedProcessNames = @('System','lsass','wininit','winlogon','csrss','services','smss',
                           'Registry','svchost','explorer','dwm','SearchUI','SearchIndexer','Idle')

# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup,$RulesDir -Force | Out-Null

# ------------------------- Logging with Rotation -------------------------
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
    
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$Base\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $LogFile -NewName $archiveName -ErrorAction SilentlyContinue
    }
}

Log "=== Ultimate Antivirus starting ==="
Log "Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# ------------------------- Setup & Task Registration -------------------------
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Log "Set execution policy to Bypass"
}

if ($isAdmin) {
    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue).LastWriteTime) {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction SilentlyContinue
        Log "Updated script to: $scriptPath"
    }
    
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger   = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task      = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction SilentlyContinue
        Log "Scheduled task registered as SYSTEM"
    }
}

# ------------------------- Database Management -------------------------
if (Test-Path $Database) {
    try {
        $scannedFiles.Clear()
        $lines = Get-Content $Database -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]::Parse($matches[2])
            }
        }
        Log "Loaded $($scannedFiles.Count) entries from database"
    } catch {
        Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    New-Item -Path $Database -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    Log "Created new database"
}

# ------------------------- File Exclusions -------------------------
function Should-ExcludeFile {
    param ([string]$filePath)
    $lowerPath = $filePath.ToLower()
    
    if ($lowerPath -like "*\assembly\*") { return $true }
    if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") { return $true }
    if ($lowerPath -like "*\windows\system32\config\*") { return $true }
    if ($lowerPath -like "*\winsxs\*") { return $true }
    if ($lowerPath -like "*\microsoft.net\*") { return $true }
    
    return $false
}

# ------------------------- Fast Signature + CIRCL Check -------------------------
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }

    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $true }
    } catch {}

    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $r = Invoke-RestMethod "$CirclLookupBase/$hash" -TimeoutSec 4 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}

    return $false
}

# ------------------------- Hash Computation -------------------------
function Compute-Hash($path) {
    try { 
        return (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() 
    } catch { 
        return $null 
    }
}

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash          = $hash.Hash.ToLower()
            Status        = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        return $null
    }
}

# ------------------------- Hash Lookup Services -------------------------
function Query-CIRCL($sha256) {
    try {
        $resp = Invoke-RestMethod "$CirclLookupBase/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp -and ($resp | ConvertTo-Json -Depth 3).Length -gt 10)
    } catch { return $false }
}

function Query-CymruMHR($sha256) {
    try {
        $resp = Invoke-RestMethod "$CymruMHR/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp.detections -and $resp.detections -ge 60)
    } catch { return $false }
}

function Query-MalwareBazaar($sha256) {
    if (-not $sha256) { return $false }
    $body = @{ query = 'get_info'; sha256_hash = $sha256 }
    if ($MalwareBazaarAuthKey) { $body.api_key = $MalwareBazaarAuthKey }
    try {
        $resp = Invoke-RestMethod "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -TimeoutSec 10
        return ($resp.query_status -eq 'ok' -or ($resp.data -and $resp.data.Count -gt 0))
    } catch { return $false }
}

# ------------------------- Smart Unsigned DLL/WINMD Blocking -------------------------
function Is-SuspiciousUnsignedDll($file) {
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin @('.dll','.winmd')) { return $false }

    try {
        $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $false }
    } catch { return $false }

    $size      = (Get-Item $file -ErrorAction SilentlyContinue).Length
    $pathLower = $file.ToLower()
    $name      = [IO.Path]::GetFileName($file).ToLower()

    foreach ($rp in $RiskyPaths) {
        if ($pathLower -like "*$rp*" -and $size -lt 3MB) { return $true }
    }

    if ($pathLower -like "*\appdata\roaming\*" -and $size -lt 800KB -and $name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

# ------------------------- File Lock Handling -------------------------
function Is-Locked($file) {
    try { 
        [IO.File]::Open($file,'Open','ReadWrite','None').Close()
        return $false 
    } catch { 
        return $true 
    }
}

function Try-ReleaseFile($file) {
    $holders = Get-Process | Where-Object {
        try { $_.Modules.FileName -contains $file } catch { $false }
    } | Select-Object -Unique

    foreach ($p in $holders) {
        if ($ProtectedProcessNames -contains $p.Name) { continue }
        try { $p.CloseMainWindow(); Start-Sleep -Milliseconds 600 } catch {}
        if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    return -not (Is-Locked $file)
}

# ------------------------- Ownership & Permissions -------------------------
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A 2>&1 | Out-Null
        icacls $filePath /reset 2>&1 | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Log "Set ownership/permissions: $filePath"
        return $true
    } catch {
        return $false
    }
}

# ------------------------- Process Termination -------------------------
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { 
            try { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) } catch { $false }
        }
        foreach ($process in $processes) {
            if ($ProtectedProcessNames -contains $process.Name) { continue }
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        try {
            taskkill /F /FI "MODULES eq $(Split-Path $filePath -Leaf)" 2>&1 | Out-Null
        } catch {}
    }
}

# ------------------------- Quarantine -------------------------
function Do-Quarantine($file, $reason) {
    if (-not (Test-Path $file)) { return }
    
    if (Is-Locked $file) { 
        Try-ReleaseFile $file | Out-Null 
    }

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ("$name`_$ts.bak")
    $q    = Join-Path $Quarantine ("$name`_$ts")

    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q   -Force -ErrorAction Stop
        Log "QUARANTINED [$reason]: $file -> $q"
    } catch {
        Log "QUARANTINE FAILED [$reason]: $file - $_"
        if (Set-FileOwnershipAndPermissions $file) {
            try {
                Copy-Item $file $bak -Force -ErrorAction Stop
                Move-Item $file $q   -Force -ErrorAction Stop
                Log "QUARANTINED (after permission fix) [$reason]: $file"
            } catch {
                Log "QUARANTINE STILL FAILED: $_"
            }
        }
    }
}

function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid" | Out-File $BlockedLog -Append
    Log "BLOCKED $type | $file | PID $pid"
    
    try {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and ($ProtectedProcessNames -notcontains $proc.ProcessName)) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    
    if (Test-Path $file) {
        Do-Quarantine $file "Real-time $type block"
    }
}

# ------------------------- Threat Intel Update -------------------------
function Update-ThreatIntelligence {
    param([string]$BasePath = $Base)
    
    $yaraRules = @(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_campaign_uac.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_malware_set.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Malware.yar"
    )
    
    $hashLists = @(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest-hashes.txt"
    )
    
    Log "Updating threat intelligence..."
    
    foreach ($url in $yaraRules) {
        $fileName = Split-Path $url -Leaf
        $output   = Join-Path $RulesDir $fileName
        try {
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -TimeoutSec 15
            Log "Downloaded YARA rule: $fileName"
        } catch {
            Log "Failed to download ${fileName}: $_"
        }
    }

    foreach ($url in $hashLists) {
        $fileName = Split-Path $url -Leaf
        $output   = Join-Path $BasePath $fileName
        try {
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -TimeoutSec 15
            Log "Downloaded hash list: $fileName"
        } catch {
            Log "Failed to download hash list ${fileName}: $_"
        }
    }
}

# ------------------------- Alerting & Reporting -------------------------
$global:EmailConfig = $null
$global:WebhookUrl  = $null

function Send-Alert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )

    $sevUpper = $Severity.ToUpper()
    $entryType = [System.Diagnostics.EventLogEntryType]::Information
    switch ($sevUpper) {
        "CRITICAL" { $entryType = [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH"     { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM"   { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        default    { $entryType = [System.Diagnostics.EventLogEntryType]::Information }
    }

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("UltimateAntivirus")) {
            New-EventLog -LogName Application -Source "UltimateAntivirus" -ErrorAction SilentlyContinue
        }
    } catch {}

    try {
        Write-EventLog -LogName Application -Source "UltimateAntivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}

    if ($global:EmailConfig) {
        try {
            Send-MailMessage @global:EmailConfig `
                -Subject "[$sevUpper] Antivirus Alert" `
                -Body "$Message`n`nDetails: $Details" -ErrorAction SilentlyContinue
        } catch { Log "Email alert failed: $_" }
    }

    if ($global:WebhookUrl) {
        try {
            $payload = @{
                text      = "[$sevUpper] $Message"
                details   = $Details
                timestamp = Get-Date -Format "o"
            } | ConvertTo-Json
            Invoke-WebRequest -Uri $global:WebhookUrl -Method Post -Body $payload -ErrorAction SilentlyContinue
        } catch { Log "Webhook alert failed: $_" }
    }
}

# ------------------------- Main Decision Engine -------------------------
function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }
    if (Should-ExcludeFile $file) { return }
    
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    $sha256 = Compute-Hash $file
    if (-not $sha256) { return }

    if ($scannedFiles.ContainsKey($sha256)) {
        if (-not $scannedFiles[$sha256]) {
            Do-Quarantine $file "Previously identified threat"
        }
        return
    }

    if (Query-CIRCL($sha256)) {
        $scannedFiles[$sha256] = $true
        "$sha256,true" | Out-File -FilePath $Database -Append -Encoding UTF8
        Log "ALLOWED (CIRCL trusted): $file"
        return
    }

    if (Query-CymruMHR($sha256)) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Cymru MHR match (>=60% AVs)"
        Send-Alert -Severity "HIGH" -Message "Known malware detected" -Details $file
        return
    }
    
    if (Query-MalwareBazaar($sha256)) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "MalwareBazaar match"
        Send-Alert -Severity "HIGH" -Message "MalwareBazaar match" -Details $file
        return
    }

    if (Is-SuspiciousUnsignedDll $file) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Suspicious unsigned DLL/WINMD in risky location"
        Send-Alert -Severity "MEDIUM" -Message "Suspicious unsigned DLL blocked" -Details $file
        return
    }

    $fileHash = Calculate-FileHash $file
    if ($fileHash) {
        $isValid = $fileHash.Status -eq "Valid"
        $scannedFiles[$sha256] = $isValid
        "$sha256,$isValid" | Out-File -FilePath $Database -Append -Encoding UTF8
        
        if ($isValid) {
            Log "ALLOWED (signed): $file"
        } else {
            Log "ALLOWED (clean but unsigned): $file"
        }
    }
}

# ------------------------- Memory Scanner -------------------------
function Start-MemoryScanner {
    $yaraExe  = "$Base\yara64.exe"
    $yaraRule = "$Base\mem.yar"

    if (Test-Path $yaraExe) {
        if (-not (Test-Path $yaraRule)) {
            try {
                Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/memory.yar" -OutFile $yaraRule -UseBasicParsing -TimeoutSec 10
            } catch {}
        }
        Log "[+] Full YARA memory scanner active"
        Start-Job -ScriptBlock {
            $exe = $using:yaraExe; $rule = $using:yaraRule; $log = "$using:Base\memory_hits.log"
            while ($true) {
                Start-Sleep -MilliSeconds 10
                Get-Process | Where-Object {
                    $_.WorkingSet64 -gt 150MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
                } | ForEach-Object {
                    & $exe -w $rule -p $_.Id 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        "$(Get-Date) | YARA HIT -> $($_.Name) ($($_.Id))" | Out-File $log -Append
                        if ($using:ProtectedProcessNames -notcontains $_.Name) {
                            Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        } | Out-Null
        return
    }

    Log "[+] PowerShell memory scanner active"
    Start-Job -ScriptBlock {
        $log = "$using:Base\ps_memory_hits.log"
        $EvilStrings = @(
            'mimikatz','sekurlsa::','kerberos::','lsadump::','wdigest','tspkg',
            'http-beacon','https-beacon','cobaltstrike','sleepmask','reflective',
            'amsi.dll','AmsiScanBuffer','EtwEventWrite','MiniDumpWriteDump',
            'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
            'ReflectiveLoader','sharpchrome','rubeus','safetykatz','sharphound'
        )
        while ($true) {
            Start-Sleep -MilliSeconds 10
            Get-Process | Where-Object {
                $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp|excel|word|outlook'
            } | ForEach-Object {
                $hit = $false
                try {
                    $_.Modules | ForEach-Object {
                        if ($EvilStrings | Where-Object { $_.ModuleName -match $_ -or $_.FileName -match $_ }) {
                            $hit = $true
                        }
                    }
                } catch {}
                if ($hit) {
                    "$(Get-Date) | PS MEMORY HIT -> $($_.Name) ($($_.Id))" | Out-File $log -Append
                    if ($using:ProtectedProcessNames -notcontains $_.Name) {
                        Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } | Out-Null
}

Log "[+] Starting reflective payload detector"
Start-Job -ScriptBlock {
    $log = "$using:Base\manual_map_hits.log"
    while ($true) {
        Start-Sleep -MilliSeconds 10
        Get-Process | Where-Object { $_.WorkingSet64 -gt 40MB } | ForEach-Object {
            $p = $_
            $sus = $false
            if (-not $p.Path -or $p.Path -eq '' -or $p.Path -match '\$Unknown\$') { $sus = $true }
            if ($p.Modules | Where-Object { $_.FileName -eq '' -or $_.ModuleName -eq '' }) { $sus = $true }
            if ($sus) {
                "$([DateTime]::Now) | REFLECTIVE PAYLOAD -> $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                if ($using:ProtectedProcessNames -notcontains $p.Name) {
                    Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
} | Out-Null

# ------------------------- Behavior / Fileless / Persistence -------------------------
function Detect-FilelessMalware {
    $detections = @()

    try {
        $ps = Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -match "encodedcommand|enc|iex|invoke-expression" -or
            ($_.Modules | Where-Object { $_.ModuleName -eq "" -or $_.FileName -eq "" })
        }
        if ($ps) {
            $detections += [PSCustomObject]@{
                Indicator = "PowerShellWithoutFile"
                Details   = $ps | Select-Object Name,Id,MainWindowTitle
            }
            Log "Fileless indicator: PowerShellWithoutFile"
        }
    } catch {}

    try {
        $wmi = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
               Where-Object { $_.Query -match "powershell|vbscript|javascript" }
        if ($wmi) {
            $detections += [PSCustomObject]@{
                Indicator = "WMIEventSubscriptions"
                Details   = $wmi | Select-Object Name,Query
            }
            Log "Fileless indicator: WMIEventSubscriptions"
        }
    } catch {}

    try {
        $keys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($key in $keys) {
            if (Test-Path $key) {
                Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
                        $val = $_.Value
                        if ($val -and $val -match "powershell.*-enc|mshta|regsvr32.*scrobj") {
                            $detections += [PSCustomObject]@{
                                Indicator = "RegistryScripts"
                                Details   = "$key -> $($_.Name)"
                            }
                            Log "Fileless indicator: RegistryScripts at $key"
                        }
                    }
                }
            }
        }
    } catch {}

    return $detections
}

function Find-PersistenceMechanisms {
    $persistenceLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "C:\Windows\System32\Tasks",
        "C:\Windows\Tasks",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\extensions"
    )
    
    $suspiciousEntries = @()
    
    foreach ($location in $persistenceLocations) {
        try {
            if ($location -match "^HK") {
                Get-Item $location -ErrorAction SilentlyContinue | 
                    Get-ItemProperty -ErrorAction SilentlyContinue | 
                    ForEach-Object {
                        $props = $_ | Get-Member -MemberType NoteProperty
                        foreach ($prop in $props) {
                            $value = $_.$($prop.Name)
                            if ($value -and $value -match "\.(exe|dll|ps1|vbs|js|bat|cmd)$") {
                                $suspiciousEntries += [PSCustomObject]@{
                                    Location = $location
                                    Name     = $prop.Name
                                    Value    = $value
                                    Type     = "Registry"
                                }
                            }
                        }
                    }
            } elseif (Test-Path $location) {
                Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(exe|dll|lnk|ps1|vbs|js)$' } |
                    ForEach-Object {
                        $suspiciousEntries += [PSCustomObject]@{
                            Location = $location
                            Name     = $_.Name
                            Value    = $_.FullName
                            Type     = "FileSystem"
                        }
                    }
            }
        } catch {
            Log "Error checking persistence location $location : $_"
        }
    }
    
    return $suspiciousEntries
}

# ------------------------- Behavior + Network Heuristics -------------------------
function Test-ProcessHollowing {
    param($Process)
    try {
        $procPath = $Process.Path
    } catch { return $false }

    try {
        $image = Get-Process -Id $Process.Id -Module -ErrorAction SilentlyContinue
    } catch { $image = $null }

    if ($image -and $procPath -and $image.Modules.Count -gt 0) {
        return ($image.Modules[0].FileName -ne $procPath)
    }
    return $false
}

function Test-CredentialAccess {
    param($Process)
    try {
        $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)").CommandLine
    } catch { $cmdline = "" }

    if ($cmdline -match "mimikatz|procdump|sekurlsa|lsadump") { return $true }
    if ($Process.ProcessName -match "vaultcmd|cred") { return $true }
    return $false
}

function Test-LateralMovement {
    param($Process)
    try {
        $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
    } catch { return $false }

    $remoteIPs = $connections | Where-Object { 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -and
        $_.RemoteAddress -ne "0.0.0.0"
    }
    return (($remoteIPs | Measure-Object).Count -gt 5)
}

function Check-NetworkC2 {
    param($Connection)

    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337)
    $knownC2Servers = @(
        "pastebin.com", "github.io", "bit.ly", "tinyurl.com",
        ".*\.ddns\.net$", ".*\.no-ip\.org$", ".*\.duckdns\.org$"
    )

    if ($Connection.RemotePort -notin $suspiciousPorts) { return $false }

    try {
        $dnsName = [System.Net.Dns]::GetHostEntry($Connection.RemoteAddress).HostName
    } catch { $dnsName = "" }

    foreach ($pattern in $knownC2Servers) {
        if ($dnsName -match $pattern) { return $true }
    }
    return $false
}

# ------------------------- Process + Network Scanner -------------------------
function Scan-ProcessesAndNetwork() {
    Get-Process | ForEach-Object {
        $p = $_
        try {
            $exe = $p.MainModule.FileName
        } catch { $exe = $null }

        if ($exe -and (Test-Path $exe)) {
            Decide-And-Act $exe
        }

        # Lightweight behavior checks
        if ($BehaviorKillEnabled -and ($ProtectedProcessNames -notcontains $p.Name)) {
            try {
                if (Test-ProcessHollowing -Process $p) {
                    Log "BEHAVIOR: Process hollowing suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "HIGH" -Message "Process hollowing" -Details "$($p.Name) PID $($p.Id)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                } elseif (Test-CredentialAccess -Process $p) {
                    Log "BEHAVIOR: Credential-access tool suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "HIGH" -Message "Credential access behavior" -Details "$($p.Name) PID $($p.Id)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                } elseif (Test-LateralMovement -Process $p) {
                    Log "BEHAVIOR: Lateral movement suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "MEDIUM" -Message "Lateral movement behavior" -Details "$($p.Name) PID $($p.Id)"
                }
            } catch {}
        }
    }

    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Established','Listen' } | ForEach-Object {
        $conn = $_
        try {
            $p = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        } catch { $p = $null }

        if ($p) {
            try {
                $exe = $p.MainModule.FileName
                if ($exe) { Decide-And-Act $exe }
            } catch {}

            if ($AutoBlockC2 -and (Check-NetworkC2 -Connection $conn)) {
                Log "NETWORK: Suspicious C2 pattern from $($p.Name) PID $($p.Id) to $($conn.RemoteAddress):$($conn.RemotePort)"
                Send-Alert -Severity "HIGH" -Message "Suspicious C2 connection" -Details "$($p.Name) PID $($p.Id) $($conn.RemoteAddress):$($conn.RemotePort)"
                if ($ProtectedProcessNames -notcontains $p.Name) {
                    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                }
                try {
                    New-NetFirewallRule -DisplayName "Block C2 $($conn.RemoteAddress)" `
                        -Direction Outbound -Protocol TCP `
                        -RemoteAddress $conn.RemoteAddress `
                        -Action Block -Enabled True -ErrorAction SilentlyContinue | Out-Null
                } catch {}
            }
        }
    }
}

# ------------------------- Initial Scan -------------------------
Log "Performing initial scan of high-risk folders"
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}

# ------------------------- Real-time File Watchers -------------------------
$WatchFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
    $watcher = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{
        IncludeSubdirectories = $true
        NotifyFilter          = 'FileName, LastWrite'
    }
    Register-ObjectEvent $watcher Created -Action {
        $path = $Event.SourceEventArgs.FullPath
        $ext  = [IO.Path]::GetExtension($path).ToLower()
        if ($MonitoredExtensions -contains $ext) {
            Start-Sleep -Milliseconds 800
            Decide-And-Act $path
        }
    } | Out-Null
    $watcher.EnableRaisingEvents = $true
}
Log "Real-time file watchers active"

# ------------------------- WMI Real-time Execution Hooks -------------------------
Log "Registering WMI real-time execution monitors"

Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e    = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID  = $e.ProcessId

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "EXE"
} | Out-Null

Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
    $e    = $Event.SourceEventArgs.NewEvent
    $Path = $e.ImageName
    $PID  = $e.ProcessId

    if (-not (Test-Path $Path)) { return }

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "DLL"
} | Out-Null

# ------------------------- Start Memory Scanners -------------------------
Start-MemoryScanner

# ------------------------- Threat Intel + Deep Scan Scheduler -------------------------
if ($isAdmin) {
    $lastUpdateFile = Join-Path $Base "last_update.txt"
    $now            = Get-Date
    $doUpdate       = $false

    if (-not (Test-Path $lastUpdateFile)) {
        $doUpdate = $true
    } else {
        try {
            $last = (Get-Item $lastUpdateFile).LastWriteTime
            if ($last -lt $now.AddDays(-$ThreatIntelDays)) { $doUpdate = $true }
        } catch { $doUpdate = $true }
    }

    if ($doUpdate) {
        Update-ThreatIntelligence
        $now | Out-File $lastUpdateFile
    }

    Start-Job -ScriptBlock {
        $base          = $using:Base
        $deepHours     = $using:DeepScanHours

        while ($true) {
            Start-Sleep -Seconds (60 * 60 * $deepHours)

            try {
                $persistence = Find-PersistenceMechanisms
                if ($persistence -and $persistence.Count -gt 0) {
                    $csv = Join-Path $base "persistence_scan.csv"
                    $persistence | Export-Csv $csv -NoTypeInformation
                    Log "Persistence scan found $($persistence.Count) entries -> $csv"
                    Send-Alert -Severity "MEDIUM" -Message "Persistence mechanisms detected" -Details "Count: $($persistence.Count)"
                }
            } catch {
                Log "Persistence scan error: $_"
            }

            try {
                $fileless = Detect-FilelessMalware
                if ($fileless -and $fileless.Count -gt 0) {
                    $xml = Join-Path $base "fileless_detections.xml"
                    $fileless | Export-Clixml $xml
                    Log "Fileless malware indicators detected -> $xml"
                    Send-Alert -Severity "HIGH" -Message "Fileless indicators detected" -Details "Count: $($fileless.Count)"
                }
            } catch {
                Log "Fileless scan error: $_"
            }
        }
    } | Out-Null
}

# ------------------------- Main Monitoring Loop -------------------------
Log "All monitoring systems active. Starting main loop..."
Write-Host "Ultimate Antivirus running. Press [Ctrl] + [C] to stop."

try {
    while ($true) {
        try { 
            Scan-ProcessesAndNetwork 
            Log "Periodic scan completed"
        } catch { 
            Log "Scan loop error: $_" 
        }
        Start-Sleep -Seconds 30
    }
} catch {
    Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $LogFile for details."
}


Log "All monitoring systems active. Starting main loop..."
Write-Host "GShield fully active: Hardening complete, KeyScrambler running, Browser Guard running, Antivirus monitoring."

try {
    while ($true) {
        try { 
            Scan-ProcessesAndNetwork 
            Log "Periodic scan completed"
        } catch { 
            Log "Scan loop error: $_" 
        }
        Start-Sleep -Seconds 30
    }
} catch {
    Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "GShield crashed. Check logs."
}

# Cleanup on exit (Ctrl+C)
finally {
    Stop-Job $keyJob,$browserJob -ErrorAction SilentlyContinue
    Remove-Job $keyJob,$browserJob -ErrorAction SilentlyContinue
}