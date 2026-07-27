# Hide the PowerShell console window
$null = Add-Type @"
using System;
using System.Runtime.InteropServices;
public class HideConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static void Hide() {
        IntPtr hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);
    }
}
"@
[HideConsoleWindow]::Hide()

# GShield.ps1 by Gorstak

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )

    # Define paths
    $scriptSource = $PSCommandPath
    if (-not $scriptSource) {
        Write-Output "Error: Could not determine script path. Ensure the script is run from a file."
        exit 1
    }
    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script to ${targetPath}: $_"
        exit 1
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
        exit 1
    }
}

# Run the function
Register-SystemLogonScript

# Define paths and parameters
$quarantineFolder = "C:\Quarantine"
$logFileAntivirus = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$logFileES = "$env:TEMP\SessionTerminator.log"
$logFileGSecurity = "$env:TEMP\GSecurity.log"
$scannedFiles = @{} # Initialize empty hash table
$checkIntervalSeconds = 60 # Interval to check for custom controls in seconds

# Firewall rules
$script:registryContent = @"
; Firewall

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services]
"fDenyTSConnections"=dword:00000001
"fAllowTSConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Terminal Server]
"fDenyTSConnections"=dword:00000001
"fAllowTSConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy]
"PolicyVersion"=dword:00000120

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules]
"auth"="v2.33|Action=SecureServer|Name=Auth|Desc=|Active=TRUE|Auth1Set={E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE3}|Auth2Set={E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE4}|Crypto2Set={E5A5D32A-4BCE-4e4d-B07F-4AB1BA7E5FE2}|"

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"EnableFirewall"=dword:00000001

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\RemoteAdminSettings]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services]

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services\FileAndPrint]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services\RemoteDesktop]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services\UPnPFramework]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile]
"EnableFirewall"=dword:00000001

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\RemoteAdminSettings]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services]

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services\FileAndPrint]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services\RemoteDesktop]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services\UPnPFramework]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\RemoteAdminSettings]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"EnableFirewall"=dword:00000001

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services]

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services\FileAndPrint]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services\RemoteDesktop]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services\UPnPFramework]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\RemoteAdminSettings]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"EnableFirewall"=dword:00000001

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services]

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\FileAndPrint]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\RemoteDesktop]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\UPnPFramework]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]
"NETDIS-UPnPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"WFDPRINT-SPOOL-Out-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36858|Desc=@FirewallAPI.dll,-36859|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"NETDIS-SSDPSrv-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNT-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-NP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
"RemoteTask-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
"WFDPRINT-SPOOL-In-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36856|Desc=@FirewallAPI.dll,-36857|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"MSDTC-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
"RRAS-L2TP-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1701|App=System|Name=@FirewallAPI.dll,-33757|Desc=@FirewallAPI.dll,-33760|EmbedCtxt=@FirewallAPI.dll,-33752|"
"CoreNet-ICMP6-PTB-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=2:*|App=System|Name=@FirewallAPI.dll,-25002|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CDPSvc-Out-UDP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37409|Desc=@FirewallAPI.dll,-37410|EmbedCtxt=@FirewallAPI.dll,-37402|"
"FPS-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SpoolSvc-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
"PNRPMNRS-PNRP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34003|Desc=@FirewallAPI.dll,-34004|EmbedCtxt=@FirewallAPI.dll,-34002|Edge=TRUE|Defer=App|"
"NETDIS-NB_Name-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-NB_Datagram-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
"Collab-P2PHost-WSD-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32011|Desc=@FirewallAPI.dll,-32014|EmbedCtxt=@FirewallAPI.dll,-32002|"
"RemoteEventLogSvc-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
"CoreNet-IPv6-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=41|App=System|Name=@FirewallAPI.dll,-25351|Desc=@FirewallAPI.dll,-25357|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CDPSvc-WFD-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37413|Desc=@FirewallAPI.dll,-37414|EmbedCtxt=@FirewallAPI.dll,-37402|TTK2_28=WFDCDPSvc|"
"NETDIS-LLMNR-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-NP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
"MDNS-Out-UDP-Domain-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|RPort=5353|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37305|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37306|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"DeliveryOptimization-UDP-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-103|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
"FPS-ICMP6-ERQ-Out-V2"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-28684|Desc=@FirewallAPI.dll,-28685|EmbedCtxt=@FirewallAPI.dll,-28672|"
"CoreNet-ICMP6-PP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=4:*|App=System|Name=@FirewallAPI.dll,-25117|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-ICMP6-RA-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=134:*|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25012|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-ICMP4-DUFRAG-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=1|ICMP4=3:4|App=System|Name=@FirewallAPI.dll,-25251|Desc=@FirewallAPI.dll,-25257|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-DHCP-In"="v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25301|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|"
"FPS-NB_Session-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=139|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-NB_Datagram-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SpoolSvc-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28535|Desc=@FirewallAPI.dll,-28538|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-DAS-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RRAS-GRE-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=47|App=System|Name=@FirewallAPI.dll,-33769|Desc=@FirewallAPI.dll,-33772|EmbedCtxt=@FirewallAPI.dll,-33752|"
"TPMVSCMGR-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
"CoreNet-DHCPV6-In"="v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25304|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
"FPS-ICMP4-ERQ-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"MSDTC-KTMRM-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
"NETDIS-SSDPSrv-In-UDP-Teredo"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32754|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
"Wininit-Shutdown-In-Rule-TCP-RPC"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36753|Desc=@firewallapi.dll,-36754|EmbedCtxt=@firewallapi.dll,-36751|"
"NETDIS-UPnP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CDPSvc-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37405|Desc=@FirewallAPI.dll,-37406|EmbedCtxt=@FirewallAPI.dll,-37402|"
"FPS-NB_Name-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SMB-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
"MSDTC-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
"WFDPRINT-SCAN-In-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36860|Desc=@FirewallAPI.dll,-36861|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"FPS-ICMP4-ERQ-Out-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Domain|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-FDPHOST-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-RS-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=133:*|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::2|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25008|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
"NETDIS-WSDEVNT-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-NDS-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=135:*|App=System|Name=@FirewallAPI.dll,-25019|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"EventForwarder-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-36804|Desc=@FirewallAPI.dll,-36805|EmbedCtxt=@FirewallAPI.dll,-36801|"
"FPS-SMB-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SMB-In-TCP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|Name=@FirewallAPI.dll,-28673|Desc=@FirewallAPI.dll,-28674|EmbedCtxt=@FirewallAPI.dll,-28672|"
"NETDIS-UPnPHost-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNTS-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RVM-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
"NETDIS-UPnPHost-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
"CoreNet-ICMP6-LR2-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25076|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-Diag-ICMP6-EchoRequest-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-27004|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"EventForwarder-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\NetEvtFwdr.exe|Name=@FirewallAPI.dll,-36802|Desc=@FirewallAPI.dll,-36803|EmbedCtxt=@FirewallAPI.dll,-36801|"
"NVS-FrameServer-In-UDP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=5000-5020|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=FrameServer|Name=@FirewallAPI.dll,-54006|Desc=@FirewallAPI.dll,-54007|EmbedCtxt=@FirewallAPI.dll,-54001|"
"Microsoft-Windows-Enrollment-WinRT-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\\system32\\svchost.exe|Svc=DmEnrollmentSvc|Name=@FirewallAPI.dll,-37505|Desc=@FirewallAPI.dll,-37506|EmbedCtxt=@FirewallAPI.dll,-37502|"
"WMI-ASYNC-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
"CoreNet-Diag-ICMP4-EchoRequest-Out-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Domain|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-27002|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"MDNS-Out-UDP-Public-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Public|RPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37305|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37306|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"WMI-WINMGMT-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
"FPS-NB_Datagram-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
"RemoteFwAdmin-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
"PerfLogsAlerts-PLASrv-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
"WINRM-HTTP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
"DeliveryOptimization-TCP-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-102|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
"FPS-NB_Name-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
"MSDTC-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33507|Desc=@FirewallAPI.dll,-33510|EmbedCtxt=@FirewallAPI.dll,-33502|"
"NETDIS-NB_Name-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-LD-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25083|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Microsoft-Windows-DeviceManagement-CertificateInstall-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\\system32\\dmcertinst.exe|Name=@FirewallAPI.dll,-37507|Desc=@FirewallAPI.dll,-37508|EmbedCtxt=@FirewallAPI.dll,-37502|"
"RRAS-PPTP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=1723|App=System|Name=@FirewallAPI.dll,-33765|Desc=@FirewallAPI.dll,-33768|EmbedCtxt=@FirewallAPI.dll,-33752|"
"CoreNet-Teredo-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25327|Desc=@FirewallAPI.dll,-25333|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RVM-VDS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
"TPMVSCMGR-Server-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
"Microsoft-Windows-WLANSvc-ASP-CP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37377|Desc=@wlansvc.dll,-37889|EmbedCtxt=@wlansvc.dll,-36864|"
"WMI-WINMGMT-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
"NETDIS-NB_Datagram-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-RS-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=133:*|App=System|Name=@FirewallAPI.dll,-25009|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WMI-RPCSS-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
"WirelessDisplay-Infra-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7250|App=%systemroot%\\system32\\CastSrv.exe|Name=@wifidisplay.dll,-10206|Desc=@wifidisplay.dll,-10207|EmbedCtxt=@wifidisplay.dll,-100|"
"PNRPMNRS-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34009|Desc=@FirewallAPI.dll,-34010|EmbedCtxt=@FirewallAPI.dll,-34002|"
"NETDIS-FDRESPUB-WSD-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNTS-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
"FPS-NB_Session-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
"CoreNet-GP-LSASS-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\lsass.exe|Name=@FirewallAPI.dll,-25407|Desc=@FirewallAPI.dll,-25408|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RemoteTask-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
"FPS-LLMNR-In-UDP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28686|Desc=@FirewallAPI.dll,-28687|EmbedCtxt=@FirewallAPI.dll,-28672|"
"NETDIS-UPnPHost-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=2869|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"Collab-PNRP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32019|Desc=@FirewallAPI.dll,-32022|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
"FPS-LLMNR-Out-UDP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28688|Desc=@FirewallAPI.dll,-28689|EmbedCtxt=@FirewallAPI.dll,-28672|"
"DIAL-Protocol-Server-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=10247|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
"NETDIS-WSDEVNT-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5357|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteSvcAdmin-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
"WMI-ASYNC-In-TCP-NoScope"="v2.33|Action=Block|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\wbem\\unsecapp.exe|Name=@FirewallAPI.dll,-34256|Desc=@FirewallAPI.dll,-34257|EmbedCtxt=@FirewallAPI.dll,-34251|"
"NETDIS-WSDEVNT-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5357|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-FDRESPUB-WSD-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-LLMNR-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteFwAdmin-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
"WirelessDisplay-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10202|Desc=@wifidisplay.dll,-10203|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
"WirelessDisplay-Out-UDP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10204|Desc=@wifidisplay.dll,-10205|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
"FPS-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-ICMP6-ERQ-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"CoreNet-ICMP6-RA-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=134:*|LA6=fe80::/64|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::1|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25013|Desc=@FirewallAPI.dll,-25018|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Collab-P2PHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32007|Desc=@FirewallAPI.dll,-32010|EmbedCtxt=@FirewallAPI.dll,-32002|"
"NETDIS-WSDEVNTS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=5358|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-NDA-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=136:*|App=System|Name=@FirewallAPI.dll,-25026|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"CoreNet-IPHTTPS-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort2_10=IPTLSOut|RPort2_10=IPHTTPSOut|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25427|Desc=@FirewallAPI.dll,-25429|EmbedCtxt=@FirewallAPI.dll,-25000|"
"NVS-FrameServer-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=554|LPort2_10=8554-8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=FrameServer|Name=@FirewallAPI.dll,-54002|Desc=@FirewallAPI.dll,-54003|EmbedCtxt=@FirewallAPI.dll,-54001|"
"NETDIS-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32753|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteSvcAdmin-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
"RemoteSvcAdmin-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|"
"CoreNet-IGMP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=2|App=System|Name=@FirewallAPI.dll,-25377|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WINRM-HTTP-Compat-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=80|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
"FPS-NB_Name-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-28519|Desc=@FirewallAPI.dll,-28522|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SpoolSvc-In-TCP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-28677|Desc=@FirewallAPI.dll,-28678|EmbedCtxt=@FirewallAPI.dll,-28672|"
"NETDIS-DAS-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-32825|Desc=@FirewallAPI.dll,-32826|EmbedCtxt=@FirewallAPI.dll,-32752|"
"Collab-P2PHost-WSD-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32015|Desc=@FirewallAPI.dll,-32018|EmbedCtxt=@FirewallAPI.dll,-32002|"
"FPS-NB_Session-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28503|Desc=@FirewallAPI.dll,-28506|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-NB_Name-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-PP-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=4:*|App=System|Name=@FirewallAPI.dll,-25116|Desc=@FirewallAPI.dll,-25118|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"CoreNet-DNS-Out-UDP"="v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-25405|Desc=@FirewallAPI.dll,-25406|EmbedCtxt=@FirewallAPI.dll,-25000|"
"FPS-ICMP4-ERQ-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-NB_Datagram-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-NB_Datagram-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteSvcAdmin-NP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
"CoreNet-Teredo-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=Teredo|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25326|Desc=@FirewallAPI.dll,-25332|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RemoteSvcAdmin-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|"
"NVS-FrameServer-Out-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=554|RPort2_10=8554-8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=FrameServer|Name=@FirewallAPI.dll,-54004|Desc=@FirewallAPI.dll,-54005|EmbedCtxt=@FirewallAPI.dll,-54001|"
"FPS-SMB-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
"PNRPMNRS-PNRP-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-34005|Desc=@FirewallAPI.dll,-34006|EmbedCtxt=@FirewallAPI.dll,-34002|"
"MSDTC-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
"NETDIS-UPnPHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-NDA-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=136:*|App=System|Name=@FirewallAPI.dll,-25027|Desc=@FirewallAPI.dll,-25032|EmbedCtxt=@FirewallAPI.dll,-25000|"
"FPS-SMB-Out-TCP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=445|App=System|Name=@FirewallAPI.dll,-28675|Desc=@FirewallAPI.dll,-28676|EmbedCtxt=@FirewallAPI.dll,-28672|"
"AllJoyn-Router-Out-UDP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37009|Desc=@FirewallAPI.dll,-37010|EmbedCtxt=@FirewallAPI.dll,-37002|"
"RemoteFwAdmin-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|"
"RemoteSvcAdmin-NP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|"
"WiFiDirect-KM-Driver-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=System|Name=@wlansvc.dll,-37378|Desc=@wlansvc.dll,-37890|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
"WiFiDirect-KM-Driver-In-UDP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|App=System|Name=@wlansvc.dll,-37380|Desc=@wlansvc.dll,-37892|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
"Microsoft-Windows-DeviceManagement-deviceenroller-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|RPort=80|RPort=443|App=%SystemRoot%\\system32\\deviceenroller.exe|Name=@FirewallAPI.dll,-37509|Desc=@FirewallAPI.dll,-37510|EmbedCtxt=@FirewallAPI.dll,-37502|"
"CoreNet-ICMP6-LQ-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25062|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Collab-PNRP-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32031|Desc=@FirewallAPI.dll,-32034|EmbedCtxt=@FirewallAPI.dll,-32002|"
"FPS-SMB-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-28511|Desc=@FirewallAPI.dll,-28514|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-NB_Name-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|App=System|Name=@FirewallAPI.dll,-32769|Desc=@FirewallAPI.dll,-32772|EmbedCtxt=@FirewallAPI.dll,-32752|"
"FPS-ICMP6-ERQ-Out-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Domain|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"CoreNet-Diag-ICMP6-EchoRequest-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-27003|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"RVM-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
"RVM-VDSLDR-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
"TPMVSCMGR-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-36502|Desc=@FirewallAPI.dll,-36503|EmbedCtxt=@FirewallAPI.dll,-36501|"
"TPMVSCMGR-Server-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
"TPMVSCMGR-Server-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
"NETDIS-WSDEVNTS-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5358|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-LLMNR-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-UPnPHost-In-TCP-Teredo"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=System|Name=@FirewallAPI.dll,-32762|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
"NETDIS-FDRESPUB-WSD-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-TE-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25114|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|"
"NETDIS-SSDPSrv-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32753|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CDPSvc-In-UDP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37407|Desc=@FirewallAPI.dll,-37408|EmbedCtxt=@FirewallAPI.dll,-37402|"
"CDPSvc-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37403|Desc=@FirewallAPI.dll,-37404|EmbedCtxt=@FirewallAPI.dll,-37402|"
"RemoteTask-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
"MDNS-In-UDP-Private-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"AllJoyn-Router-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37005|Desc=@FirewallAPI.dll,-37006|EmbedCtxt=@FirewallAPI.dll,-37002|"
"ProximityUxHost-Sharing-Out-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36254|Desc=@FirewallAPI.dll,-36255|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
"NETDIS-LLMNR-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-LR-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25069|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
"TPMVSCMGR-Server-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36506|Desc=@FirewallAPI.dll,-36507|EmbedCtxt=@FirewallAPI.dll,-36501|"
"WFDPRINT-DAFWSD-Out-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36854|Desc=@FirewallAPI.dll,-36855|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"FPS-ICMP4-ERQ-In-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-28681|Desc=@FirewallAPI.dll,-28685|EmbedCtxt=@FirewallAPI.dll,-28672|"
"RRAS-L2TP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1701|App=System|Name=@FirewallAPI.dll,-33753|Desc=@FirewallAPI.dll,-33756|EmbedCtxt=@FirewallAPI.dll,-33752|"
"CoreNet-ICMP6-PTB-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=2:*|App=System|Name=@FirewallAPI.dll,-25001|Desc=@FirewallAPI.dll,-25007|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"CoreNet-DHCP-Out"="v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25302|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-IPHTTPS-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=IPTLSIn|LPort2_10=IPHTTPSIn|App=System|Name=@FirewallAPI.dll,-25426|Desc=@FirewallAPI.dll,-25428|EmbedCtxt=@FirewallAPI.dll,-25000|"
"NETDIS-WSDEVNT-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteFwAdmin-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
"FPS-NB_Datagram-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28531|Desc=@FirewallAPI.dll,-28534|EmbedCtxt=@FirewallAPI.dll,-28502|"
"AllJoyn-Router-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=9955|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37003|Desc=@FirewallAPI.dll,-37004|EmbedCtxt=@FirewallAPI.dll,-37002|"
"AllJoyn-Router-In-UDP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37007|Desc=@FirewallAPI.dll,-37008|EmbedCtxt=@FirewallAPI.dll,-37002|"
"CoreNet-ICMP6-LD-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25082|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WiFiDirect-KM-Driver-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=System|Name=@wlansvc.dll,-37379|Desc=@wlansvc.dll,-37891|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
"Microsoft-Windows-Unified-Telemetry-Client"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=443|App=%SystemRoot%\\system32\\svchost.exe|Svc=DiagTrack|Name=@%windir%\\system32\\diagtrack.dll,-3001|Desc=@%windir%\\system32\\diagtrack.dll,-3003|EmbedCtxt=DiagTrack|"
"NETDIS-WSDEVNTS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-DU-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=1:*|App=System|Name=@FirewallAPI.dll,-25110|Desc=@FirewallAPI.dll,-25112|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"WFDPRINT-SCAN-Out-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36862|Desc=@FirewallAPI.dll,-36863|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"NETDIS-NB_Datagram-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CDPSvc-WFD-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37411|Desc=@FirewallAPI.dll,-37412|EmbedCtxt=@FirewallAPI.dll,-37402|TTK2_28=WFDCDPSvc|"
"RemoteTask-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
"FPS-NB_Session-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=139|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-ICMP6-ERQ-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-Diag-ICMP4-EchoRequest-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|App=System|Name=@FirewallAPI.dll,-27002|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"MDNS-Out-UDP-Private-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37305|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37306|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"NETDIS-NB_Datagram-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=138|App=System|Name=@FirewallAPI.dll,-32781|Desc=@FirewallAPI.dll,-32784|EmbedCtxt=@FirewallAPI.dll,-32752|"
"PerfLogsAlerts-DCOM-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
"FPS-RPCSS-In-TCP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=Rpcss|Name=@FirewallAPI.dll,-28679|Desc=@FirewallAPI.dll,-28680|EmbedCtxt=@FirewallAPI.dll,-28672|"
"FPS-ICMP4-ERQ-Out-V2"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-28682|Desc=@FirewallAPI.dll,-28685|EmbedCtxt=@FirewallAPI.dll,-28672|"
"RRAS-PPTP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=1723|App=System|Name=@FirewallAPI.dll,-33761|Desc=@FirewallAPI.dll,-33764|EmbedCtxt=@FirewallAPI.dll,-33752|"
"PerfLogsAlerts-PLASrv-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%systemroot%\\system32\\plasrv.exe|Name=@FirewallAPI.dll,-34753|Desc=@FirewallAPI.dll,-34754|EmbedCtxt=@FirewallAPI.dll,-34752|"
"WINRM-HTTP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
"Wininit-Shutdown-In-Rule-TCP-RPC-EPMapper"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%systemroot%\\system32\\wininit.exe|Name=@firewallapi.dll,-36755|Desc=@firewallapi.dll,-36756|EmbedCtxt=@firewallapi.dll,-36751|"
"NETDIS-FDPHOST-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNT-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-NDS-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=135:*|App=System|Name=@FirewallAPI.dll,-25020|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WFDPRINT-DAFWSD-In-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\dashost.exe|Name=@FirewallAPI.dll,-36852|Desc=@FirewallAPI.dll,-36853|LUAuth=O:LSD:(A;;CC;;;S-1-5-92-3339056971-1291069075-3798698925-2882100687-0)|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"Collab-PNRP-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3540|App=%SystemRoot%\\system32\\svchost.exe|Svc=PNRPSvc|Name=@FirewallAPI.dll,-32023|Desc=@FirewallAPI.dll,-32026|EmbedCtxt=@FirewallAPI.dll,-32002|"
"WirelessDisplay-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10200|Desc=@wifidisplay.dll,-10201|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
"FPS-ICMP6-ERQ-In-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Domain|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-28545|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"PNRPMNRS-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34007|Desc=@FirewallAPI.dll,-34008|EmbedCtxt=@FirewallAPI.dll,-34002|"
"NETDIS-UPnPHost-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=2869|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
"PerfLogsAlerts-DCOM-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34755|Desc=@FirewallAPI.dll,-34756|EmbedCtxt=@FirewallAPI.dll,-34752|"
"CoreNet-IPv6-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=41|App=System|Name=@FirewallAPI.dll,-25352|Desc=@FirewallAPI.dll,-25358|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WiFiDirect-KM-Driver-Out-UDP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=System|Name=@wlansvc.dll,-37381|Desc=@wlansvc.dll,-37893|EmbedCtxt=@wlansvc.dll,-36865|TTK2_27=WFDKmDriver|"
"NETDIS-WSDEVNTS-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
"CoreNet-Diag-ICMP6-EchoRequest-Out-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Domain|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-27004|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"WMI-RPCSS-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
"MSDTC-KTMRM-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
"ProximityUxHost-Sharing-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36252|Desc=@FirewallAPI.dll,-36253|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
"NETDIS-FDRESPUB-WSD-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-IGMP-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=2|App=System|Name=@FirewallAPI.dll,-25376|Desc=@FirewallAPI.dll,-25382|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-GP-NP-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-25401|Desc=@FirewallAPI.dll,-25401|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Microsoft-Windows-WLANSvc-ASP-CP-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37376|Desc=@wlansvc.dll,-37888|EmbedCtxt=@wlansvc.dll,-36864|"
"FPS-NB_Name-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
"WMI-WINMGMT-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34254|Desc=@FirewallAPI.dll,-34255|EmbedCtxt=@FirewallAPI.dll,-34251|"
"CoreNet-ICMP6-LR2-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25075|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RVM-VDSLDR-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vdsldr.exe|Name=@FirewallAPI.dll,-34504|Desc=@FirewallAPI.dll,-34505|EmbedCtxt=@FirewallAPI.dll,-34501|"
"FPS-NB_Datagram-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=138|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28527|Desc=@FirewallAPI.dll,-28530|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-ICMP4-ERQ-In-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-28543|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-FDPHOST-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32789|Desc=@FirewallAPI.dll,-32792|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-FDPHOST-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Public|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Eventlog|Name=@FirewallAPI.dll,-29253|Desc=@FirewallAPI.dll,-29256|EmbedCtxt=@FirewallAPI.dll,-29252|"
"CoreNet-ICMP6-LQ-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=130:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25061|Desc=@FirewallAPI.dll,-25067|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Collab-PNRP-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32027|Desc=@FirewallAPI.dll,-32030|EmbedCtxt=@FirewallAPI.dll,-32002|"
"FPS-LLMNR-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28548|Desc=@FirewallAPI.dll,-28549|EmbedCtxt=@FirewallAPI.dll,-28502|"
"Microsoft-Windows-DeviceManagement-OmaDmClient-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\\system32\\omadmclient.exe|Name=@FirewallAPI.dll,-37503|Desc=@FirewallAPI.dll,-37504|EmbedCtxt=@FirewallAPI.dll,-37502|"
"CoreNet-ICMP6-LR-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=131:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25068|Desc=@FirewallAPI.dll,-25074|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-Diag-ICMP4-EchoRequest-In-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-27001|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"SSTP-IN-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=443|App=System|Name=@sstpsvc.dll,-35002|Desc=@sstpsvc.dll,-35003|EmbedCtxt=@sstpsvc.dll,-35001|"
"DIAL-Protocol-Server-HTTPSTR-In-TCP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=10247|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-37102|Desc=@FirewallAPI.dll,-37103|EmbedCtxt=@FirewallAPI.dll,-37101|"
"MSDTC-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
"CoreNet-DHCPV6-Out"="v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25305|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RVM-VDS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
"WMI-WINMGMT-Out-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
"FPS-LLMNR-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28550|Desc=@FirewallAPI.dll,-28551|EmbedCtxt=@FirewallAPI.dll,-28502|"
"CoreNet-ICMP6-TE-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25113|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"MDNS-In-UDP-Domain-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|LPort=5353|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"Collab-P2PHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32003|Desc=@FirewallAPI.dll,-32006|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
"NETDIS-UPnP-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-Diag-ICMP4-EchoRequest-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|App=System|Name=@FirewallAPI.dll,-27001|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"WINRM-HTTP-Compat-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=80|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
"NETDIS-NB_Name-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=137|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RRAS-GRE-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=47|App=System|Name=@FirewallAPI.dll,-33773|Desc=@FirewallAPI.dll,-33776|EmbedCtxt=@FirewallAPI.dll,-33752|"
"FPS-ICMP6-ERQ-In-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-28683|Desc=@FirewallAPI.dll,-28685|EmbedCtxt=@FirewallAPI.dll,-28672|"
"MSDTC-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\msdtc.exe|Name=@FirewallAPI.dll,-33503|Desc=@FirewallAPI.dll,-33506|EmbedCtxt=@FirewallAPI.dll,-33502|"
"NETDIS-NB_Name-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-32773|Desc=@FirewallAPI.dll,-32776|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-GP-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=gpsvc|Name=@FirewallAPI.dll,-25403|Desc=@FirewallAPI.dll,-25404|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-Diag-ICMP6-EchoRequest-In-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|Profile=Domain|ICMP6=128:*|App=System|Name=@FirewallAPI.dll,-27003|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"MDNS-In-UDP-Public-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|LPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"PlayTo-QWave-Out-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36016|Desc=@FirewallAPI.dll,-36017|EmbedCtxt=@FirewallAPI.dll,-36001|"
"RemoteDesktop-In-TCP-WS"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3387|App=System|Name=@FirewallAPI.dll,-28780|Desc=@FirewallAPI.dll,-28781|EmbedCtxt=@FirewallAPI.dll,-28782|"
"PlayTo-In-UDP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-HTTPSTR-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=10244|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30785|Desc=@FirewallAPI.dll,-30788|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WPDMTP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=15740|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
"MCX-QWave-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30769|Desc=@FirewallAPI.dll,-30772|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-Out-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-Out-UDP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-Prov-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcx2prov.exe|Name=@FirewallAPI.dll,-30812|Desc=@FirewallAPI.dll,-30813|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-In-UDP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-In-RTSP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=23554|LPort=23555|LPort=23556|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=7777|LPort=7778|LPort=7779|LPort=7780|LPort=7781|LPort=5004|LPort=5005|LPort=50004|LPort=50005|LPort=50006|LPort=50007|LPort=50008|LPort=50009|LPort=50010|LPort=50011|LPort=50012|LPort=50013|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30801|Desc=@FirewallAPI.dll,-30804|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WPDMTP-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=15740|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
"PlayTo-QWave-In-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36010|Desc=@FirewallAPI.dll,-36011|EmbedCtxt=@FirewallAPI.dll,-36001|"
"CloudIdSvc-Allow-HTTPS-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=443|App=%SystemRoot%\\system32\\svchost.exe|Svc=cloudidsvc|Name=@%SystemRoot%\\system32\\firewallapi.dll,-60502|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-60503|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-60501|"
"MCX-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=554|LPort=8554|LPort=8555|LPort=8556|LPort=8557|LPort=8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30761|Desc=@FirewallAPI.dll,-30764|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-QWave-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30773|Desc=@FirewallAPI.dll,-30776|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-QWave-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30781|Desc=@FirewallAPI.dll,-30784|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-QWave-Out-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36012|Desc=@FirewallAPI.dll,-36013|EmbedCtxt=@FirewallAPI.dll,-36001|"
"RemoteDesktop-In-TCP-WSS"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3392|App=System|Name=@FirewallAPI.dll,-28783|Desc=@FirewallAPI.dll,-28784|EmbedCtxt=@FirewallAPI.dll,-28782|"
"MCX-TERMSRV-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3390|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-30793|Desc=@FirewallAPI.dll,-30796|EmbedCtxt=@FirewallAPI.dll,-30752|"
"SPPSVC-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=1688|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
"WPDMTP-UPnPHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30515|Desc=@FirewallAPI.dll,-30518|EmbedCtxt=@FirewallAPI.dll,-30502|"
"WPDMTP-UPnPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30519|Desc=@FirewallAPI.dll,-30522|EmbedCtxt=@FirewallAPI.dll,-30502|"
"PlayTo-HTTPSTR-In-TCP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=10246|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-QWave-In-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36014|Desc=@FirewallAPI.dll,-36015|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30753|Desc=@FirewallAPI.dll,-30756|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-FDPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30822|Desc=@FirewallAPI.dll,-30823|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-MCX2SVC-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=mcx2svc|Name=@FirewallAPI.dll,-30810|Desc=@FirewallAPI.dll,-30811|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-SSDP-Discovery-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|LPort2_20=Ply2Disc|App=%SystemRoot%\\system32\\svchost.exe|Svc=ssdpsrv|Name=@FirewallAPI.dll,-36104|Desc=@FirewallAPI.dll,-36105|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-McrMgr-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcrmgr.exe|Name=@FirewallAPI.dll,-30818|Desc=@FirewallAPI.dll,-30819|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WPDMTP-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30507|Desc=@FirewallAPI.dll,-30510|EmbedCtxt=@FirewallAPI.dll,-30502|"
"PlayTo-Out-UDP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
"WPDMTP-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30511|Desc=@FirewallAPI.dll,-30514|EmbedCtxt=@FirewallAPI.dll,-30502|"
"WPDMTP-UPnP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30523|Desc=@FirewallAPI.dll,-30524|EmbedCtxt=@FirewallAPI.dll,-30502|"
"PlayTo-UPnP-Events-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=2869|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36106|Desc=@FirewallAPI.dll,-36107|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30765|Desc=@FirewallAPI.dll,-30768|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30805|Desc=@FirewallAPI.dll,-30808|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-PlayTo-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30820|Desc=@FirewallAPI.dll,-30821|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-In-RTSP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=23554|LPort=23555|LPort=23556|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-In-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"SPPSVC-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=1688|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
"MCX-PlayTo-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30814|Desc=@FirewallAPI.dll,-30815|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30757|Desc=@FirewallAPI.dll,-30760|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-PlayTo-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30816|Desc=@FirewallAPI.dll,-30817|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-HTTPSTR-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=10246|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-HTTPSTR-In-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=10246|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-In-RTSP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=23554|LPort=23555|LPort=23556|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-QWave-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30777|Desc=@FirewallAPI.dll,-30780|EmbedCtxt=@FirewallAPI.dll,-30752|"
"Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|Desc=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|PFN=Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|"
"Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|Desc=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|PFN=Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|"
"Microsoft.AccountsControl_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|Desc=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|PFN=Microsoft.AccountsControl_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|"
"Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|Desc=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|PFN=Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|"
"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|Desc=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|PFN=Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|"
"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|Desc=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|PFN=Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|"
"Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|Desc=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|PFN=Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|"
"Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|Desc=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|PFN=Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|"
"Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|Desc=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|PFN=Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|"
"Microsoft.XboxGameCallableUI_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|Desc=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|PFN=Microsoft.XboxGameCallableUI_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|"
"MicrosoftWindows.Client.CBS_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.CBS_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.CBS_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.CBS_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Core_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Core_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Core_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Core_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.FileExp_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.FileExp_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.OOBE_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.OOBE_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Photon_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Photon_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Photon_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Photon_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|"
"NcsiUwpApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=NcsiUwpApp|Desc=NcsiUwpApp|PFN=NcsiUwpApp_8wekyb3d8bbwe|LUOwn=S-1-5-18|EmbedCtxt=NcsiUwpApp|"
"MsiScsi-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
"MsiScsi-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
"MsiScsi-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
"MsiScsi-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
"RemoteAdmin-NP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-NP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|"
"Microsoft.StorePurchaseApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|Desc=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|PFN=Microsoft.StorePurchaseApp_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|"
"Microsoft.StorePurchaseApp_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|Desc=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|PFN=Microsoft.StorePurchaseApp_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|"
"Microsoft.WindowsStore_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=Microsoft Store|Desc=Microsoft Store|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=Microsoft Store|"
"Microsoft.WindowsStore_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Profile=Public|Name=Microsoft Store|Desc=Microsoft Store|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=Microsoft Store|Edge=TRUE|"
"{faa1ae55-2e59-4797-bf03-ab56b8bd3c76}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{be2fa8ee-ef9f-4245-81c5-6246f672a5b4}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{fd88c1e1-02d6-4c20-ae54-9f09ec655723}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Block RDP Inbound|"
"{470ea644-aed7-411b-9f54-5aeae34f4403}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=5900-5902|Name=Block VNC Inbound|"
"{88eb5b89-0018-4b89-ae6a-0476f2db748b}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=5938|Name=Block TeamViewer Inbound|"
"{89d2f07a-46ef-43e8-b28f-98111bc906ac}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7070|Name=Block AnyDesk Inbound|"
"InternetIn"="v2.33|Action=Block|Active=TRUE|Dir=In|Name=Block|Desc=Block everything incoming from Internet|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|"
"RemoteDesktop-UserMode-In-TCP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
"RemoteDesktop-UserMode-In-UDP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|"
"{111C64B9-0D47-43E4-86A2-7A16572491F3}"="v2.33|Action=Block|Active=TRUE|Dir=Out|RA42=IntrAnet|RA62=IntrAnet|Name=Block|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|"
"RemoteDesktop-Shadow-In-TCP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|"
"{72e1385d-992b-4a22-a93c-22b0dbdd087e}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{1ca69094-99b9-4e91-a3c0-842947a8092b}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{033EE74A-C306-4613-A774-FF51A5193C59}"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
"{83B5E181-8B34-4F4F-9DCF-9837E18F4DFE}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"{09c774e9-b54e-4b0c-aaef-1406bcf48236}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{b8ba4996-9b3a-4468-8548-3db7816ca937}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{029f5512-416a-4999-b0e2-c6f2c57e65f5}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{f408f81d-c94c-470f-98ec-0b758178b959}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"MicrosoftWindows.Client.AIX_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.AIX_cw5n1h2txyewy|LUOwn=S-1-5-21-3619819590-2351760732-2475584066-1000|EmbedCtxt=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|"
"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|Desc=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|PFN=Microsoft.DesktopAppInstaller_8wekyb3d8bbwe|LUOwn=S-1-5-21-3619819590-2351760732-2475584066-1001|EmbedCtxt=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|"
"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|Desc=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|PFN=Microsoft.DesktopAppInstaller_8wekyb3d8bbwe|LUOwn=S-1-5-21-3619819590-2351760732-2475584066-1001|EmbedCtxt=@{Microsoft.DesktopAppInstaller_1.26.400.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|"
"{eaaa5e56-5be6-4c76-81fc-a7c3b585434a}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{1e1746fb-eaed-4de5-9a65-37816f8977ca}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{003ea8c2-5e09-432c-9e17-cb456e1a62ed}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Block RDP Inbound|"
"{aff3286f-c279-455d-8d3e-d063ab850ff0}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=5900-5902|Name=Block VNC Inbound|"
"{4a9eb421-e424-41eb-8e5d-f20d388d669e}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=5938|Name=Block TeamViewer Inbound|"
"{0e1f748e-f962-41d2-8340-89f8f44737a2}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7070|Name=Block AnyDesk Inbound|"
"{e48dd9d3-edf1-411d-a1e3-1c6d15872b75}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{6a575a3d-bc64-4df9-a6fb-681004d7b089}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{8813D9EE-2773-4DD7-9788-54B833AEEFCD}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe|Name=Microsoft Edge (mDNS-In)|Desc=Inbound rule for Microsoft Edge to allow mDNS traffic.|EmbedCtxt=Microsoft Edge|"
"{980FEED3-0B38-4A84-A443-3F9F0FA97769}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\138.0.3351.95\\msedgewebview2.exe|Name=Microsoft Edge (mDNS-In)|Desc=Inbound rule for Microsoft Edge to allow mDNS traffic.|EmbedCtxt=Microsoft Edge WebView2 Runtime|"
"{682C106E-BF6C-45B0-88DE-FC53EEEB0B1D}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\\Program Files\\Mozilla Firefox\\firefox.exe|Name=Firefox (C:\\Program Files\\Mozilla Firefox)|"
"{B7002238-4A4E-4B2A-B088-C682BF100EAB}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App=C:\\Program Files\\Mozilla Firefox\\firefox.exe|Name=Firefox (C:\\Program Files\\Mozilla Firefox)|"
"{A6D5059E-BCF7-4E60-86D2-6C378F0A03FD}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe|Name=Brave (mDNS-In)|Desc=Inbound rule for Brave to allow mDNS traffic.|EmbedCtxt=Brave|"
"{8EAC2DBC-6D1A-49F7-98EA-6745C6749D89}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\\Program Files\\Waterfox\\waterfox.exe|Name=Waterfox (C:\\Program Files\\Waterfox)|"
"{819DBD71-82B8-4D49-AA47-C0183F314960}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App=C:\\Program Files\\Waterfox\\waterfox.exe|Name=Waterfox (C:\\Program Files\\Waterfox)|"
"{86FA9CE0-2F26-45A8-B2D8-D10F1412A2AD}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\\Program Files\\Zen Browser\\zen.exe|Name=Zen (C:\\Program Files\\Zen Browser)|"
"{2F2BFA69-E721-4453-BF71-3A18D0EE368B}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App=C:\\Program Files\\Zen Browser\\zen.exe|Name=Zen (C:\\Program Files\\Zen Browser)|"
"{A699987F-3489-4A1B-B82B-2BFE1A75E898}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=C:\\Program Files\\WindowsApps\\TheBrowserCompany.Arc_1.63.0.205_x64__ttt1ap7aakyb4\\Arc.exe|Name=Arc|Desc=Arc|EmbedCtxt={78E1CD88-49E3-476E-B926-580E596AD309}|"
"{C0F22E3E-A006-4992-88D8-78F290D13114}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|App=C:\\Program Files\\WindowsApps\\TheBrowserCompany.Arc_1.63.0.205_x64__ttt1ap7aakyb4\\Arc.exe|Name=Arc|Desc=Arc|EmbedCtxt={78E1CD88-49E3-476E-B926-580E596AD309}|"
"TheBrowserCompany.Arc_ttt1ap7aakyb4-Out-Allow-AllCapabilities"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=Arc|Desc=Arc|PFN=TheBrowserCompany.Arc_ttt1ap7aakyb4|LUOwn=S-1-5-21-728396961-3906097997-3349621496-1000|EmbedCtxt=Arc|"
"{BA43993A-56F1-4DDF-9AFA-DFF8744AE413}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe|Name=Google Chrome (mDNS-In)|Desc=Inbound rule for Google Chrome to allow mDNS traffic.|EmbedCtxt=Google Chrome|"
"@

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

# Logging Function for Antivirus with Rotation and Mutex
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"

    # Create a mutex to ensure thread-safe file access
    $mutex = New-Object System.Threading.Mutex($false, "Global\GShieldAntivirusLogMutex")
    try {
        if (-not (Test-Path $quarantineFolder)) {
            New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "Created folder: $quarantineFolder"
        }
        if ((Test-Path $logFileAntivirus) -and ((Get-Item $logFileAntivirus -ErrorAction SilentlyContinue).Length -ge 10MB)) {
            $mutex.WaitOne()
            try {
                $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                Rename-Item -Path $logFileAntivirus -NewName $archiveName -ErrorAction Stop
                Write-Host "Rotated log to: $archiveName"
            } finally {
                $mutex.ReleaseMutex()
            }
        }
        $mutex.WaitOne()
        try {
            $logEntry | Out-File -FilePath $logFileAntivirus -Append -Encoding UTF8 -ErrorAction Stop
        } finally {
            $mutex.ReleaseMutex()
        }
    } catch {
        Write-Host "Logging failed: $($_.Exception.Message)"
    } finally {
        $mutex.Dispose()
    }
}

# Logging Function for GSecurity
function Write-GSecurityLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$EntryType] $Message"

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GSecurity")) {
            New-EventLog -LogName Application -Source "GSecurity"
        }
        Write-EventLog -LogName Application -Source "GSecurity" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Add-Content -Path $logFileGSecurity -Value $logEntry
    }

    if ($Host.Name -match "ConsoleHost") {
        switch ($EntryType) {
            "Error" { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor White }
        }
    }
}

# Logging Function for ES
function Write-ESLog {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFileES -Append
}

# Logging Function for Terminate-Rootkits
function Write-RootkitLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Terminate-Rootkits")) {
            New-EventLog -LogName Application -Source "Terminate-Rootkits"
        }
        Write-EventLog -LogName Application -Source "Terminate-Rootkits" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

# Load or Reset Scanned Files Database
if (Test-Path $localDatabase) {
    try {
        $scannedFiles.Clear() # Reset hash table before loading
        $lines = Get-Content $localDatabase -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]$matches[2]
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear() # Reset on failure
    }
} else {
    $scannedFiles.Clear() # Ensure reset if no database
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-Log "Created new database: $localDatabase"
}

# Take Ownership and Modify Permissions (Aggressive)
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /reset | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d | Out-Null
        Write-Log "Forcibly set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        Write-Log "Signature status for ${filePath}: $($signature.Status) - $($signature.StatusMessage)"
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error processing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

# Quarantine File (Crash-Proof)
function Quarantine-File {
    param ([string]$filePath)
    try {
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Failed to quarantine ${filePath}: $($_.Exception.Message)"
    }
}

# Stop Processes Using DLL (Aggressive)
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)"
        try {
            $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
            foreach ($process in $processes) {
                taskkill /PID $process.Id /F | Out-Null
                Write-Log "Force-killed process $($process.Name) (PID: $($process.Id)) using taskkill"
            }
        } catch {
            Write-Log "Fallback process kill failed for ${filePath}: $($_.Exception.Message)"
        }
    }
}

# Remove Unsigned DLLs (Exclude Problem Folders)
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -Exclude @($quarantineFolder, "C:\Windows\System32\config") -ErrorAction Stop
            foreach ($dll in $dllFiles) {
                try {
                    $fileHash = Calculate-FileHash -filePath $dll.FullName
                    if ($fileHash) {
                        if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                            Write-Log "Skipping already scanned file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                            if (-not $scannedFiles[$fileHash.Hash]) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        } else {
                            $isValid = $fileHash.Status -eq "Valid" # Only "Valid" is safe
                            $scannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                            Write-Log "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error processing file $($dll.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Scan failed for drive ${root} $($_.Exception.Message)"
        }
    }
    # Explicit System32 Scan
    Write-Log "Starting explicit System32 scan."
    try {
        $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Filter *.dll -File -ErrorAction Stop
        foreach ($dll in $system32Files) {
            try {
                $fileHash = Calculate-FileHash -filePath $dll.FullName
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        Write-Log "Skipping already scanned System32 file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $scannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                        Write-Log "Scanned new System32 file: $($dll.FullName) (Valid: $isValid)"
                        if (-not $isValid) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    }
                }
            } catch {
                Write-Log "Error processing System32 file $($dll.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "System32 scan failed: $($_.Exception.Message)"
    }
}

# File System Watcher (Throttled and Crash-Proof)
function Start-FileSystemWatcher {
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $monitorPath = $drive.DeviceID + "\"
        try {
            $fileWatcher = New-Object System.IO.FileSystemWatcher
            $fileWatcher.Path = $monitorPath
            $fileWatcher.Filter = "*.dll"
            $fileWatcher.IncludeSubdirectories = $true
            $fileWatcher.EnableRaisingEvents = $true
            $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

            $action = {
                param($sender, $e)
                try {
                    if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$quarantineFolder*") {
                        Write-Log "Detected file change: $($e.FullPath)"
                        $fileHash = Calculate-FileHash -filePath $e.FullPath
                        if ($fileHash) {
                            if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                                Write-Log "Skipping already scanned file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                                if (-not $scannedFiles[$fileHash.Hash]) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            } else {
                                $isValid = $fileHash.Status -eq "Valid"
                                $scannedFiles[$fileHash.Hash] = $isValid
                                "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                                Write-Log "Added new file to database: $($e.FullPath) (Valid: $isValid)"
                                if (-not $isValid) {
                                    if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                                        Stop-ProcessUsingDLL -filePath $e.FullPath
                                        Quarantine-File -filePath $e.FullPath
                                    }
                                }
                            }
                        }
                        Start-Sleep -Milliseconds 500 # Throttle to prevent event flood
                    }
                } catch {
                    Write-Log "Watcher error for $($e.FullPath): $($_.Exception.Message)"
                }
            }

            Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action -ErrorAction Stop
            Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action -ErrorAction Stop
            Write-Log "FileSystemWatcher set up for $monitorPath"
        } catch {
            Write-Log "Failed to set up watcher for ${monitorPath} $($_.Exception.Message)"
        }
    }
}

# Terminate Rootkits
function Terminate-Rootkits {
    try {
        $connections = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.'
        }
        $lanProcIds = $connections.OwningProcess | Sort-Object -Unique

        foreach ($pid in $lanProcIds) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $exePath = $proc.Path

                if ($exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    if ($signature.Status -ne 'Valid') {
                        Write-RootkitLog "Terminating UNSIGNED process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                    } else {
                        Write-RootkitLog "Skipping signed process: $($proc.ProcessName) (PID: $pid)"
                    }
                } else {
                    Write-RootkitLog "Path unknown for process: $($proc.ProcessName) (PID: $pid)" -EntryType "Warning"
                }
            } catch {
                Write-RootkitLog "Error processing PID $pid`: $($_.ToString())" -EntryType "Warning"
            }
        }
    } catch {
        Write-RootkitLog "Error during detection: $($_.ToString())" -EntryType "Error"
    }
}

# Disable Network Briefly
function Disable-Network-Briefly {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        foreach ($adapter in $adapters) {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-GSecurityLog "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-GSecurityLog "Failed to toggle network adapters: $_" "Error"
    }
}

# Kill Process and Parent
function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-GSecurityLog "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-GSecurityLog "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-GSecurityLog "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

# ProcessLOGOUT Killer
function Start-ProcessKiller {
    while ($true) {
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-GSecurityLog "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-GSecurityLog "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
}

# XSS Watcher
function Start-XSSWatcher {
    while ($true) {
        $conns = Get-NetTCPConnection -State Established
        foreach ($conn in $conns) {
            $remoteIP = $conn.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-Network-Briefly
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -Force -ErrorAction SilentlyContinue
                    Write-GSecurityLog "XSS detected, blocked $($hostEntry.HostName) and disabled network." "Error"
                }
            } catch {}
        }
        Start-Sleep -Seconds 3
    }
}

# Kill Listeners
function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit")
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

# Terminate Non-Console Sessions
function Terminate-NonConsoleSessions {
    try {
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" }
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-ESLog "Listing all sessions:"
        $sessions | ForEach-Object { Write-ESLog $_ }

        foreach ($session in $sessionList) {
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                if ($sessionName -notin @("console")) {
                    Write-ESLog "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-ESLog "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-ESLog "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-ESLog "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-ESLog "Error processing sessions: $_"
    }
}

# Detect InProc Controls
function Detect-InProcControls {
    $basePath = "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
    $hkcrBasePath = "HKCR:\WOW6432Node\CLSID"
    $allPaths = @()
    $allPaths += Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }
    $allPaths += Get-ChildItem -Path $hkcrBasePath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}}" }

    foreach ($path in $allPaths) {
        $inProcPath = Join-Path $path.PSPath "InProcServer32"
        $inProcHandlerPath = Join-Path $path.PSPath "InprocHandler32"
        $value = $null

        if (Test-Path $inProcPath) {
            $value = (Get-ItemProperty -Path $inProcPath -ErrorAction SilentlyContinue)."(default)"
        } elseif (Test-Path $inProcHandlerPath) {
            $value = (Get-ItemProperty -Path $inProcHandlerPath -ErrorAction SilentlyContinue)."(default)"
        }

        if ($value -and (Test-Path $value)) {
            Write-Host "Detected InProc control at $path.PSPath with value $value"
            return $true, $path.PSPath, $value
        }
    }
    return $false, $null, $null
}

# Remove InProc Controls
function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path"
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $_"
        }
    }
}

# Enable LSASS as Protected Process Light
function Enable-LsassPPL {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "RunAsPPL"
        $regValue = 1

        if (-not (Test-Path $regPath)) {
            Write-Error "LSA registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -ErrorAction Stop
        Write-Host "LSASS configured to run as Protected Process Light (PPL). Reboot required."
    } catch {
        Write-Error "Failed to enable LSASS PPL: $_"
    }
}

# Clear Cached Credentials
function Clear-CachedCredentials {
    try {
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Host "Cleared cached credentials from Credential Manager using cmdkey."
        } else {
            Write-Warning "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials."
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Warning "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required."
            } catch {
                Write-Error "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager."
                return
            }
        }
    } catch {
        Write-Error "Failed to clear cached credentials: $_"
    }
}

# Disable Credential Caching
function Disable-CredentialCaching {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "CachedLogonsCount"
        $regValue = 0

        if (-not (Test-Path $regPath)) {
            Write-Error "Winlogon registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -ErrorAction Stop
        Write-Host "Disabled cached logon credentials. Set CachedLogonsCount to 0."
    } catch {
        Write-Error "Failed to disable credential caching: $_"
    }
}

# Enable Auditing for Credential Access
function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        } else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    } catch {
        Write-Error "Failed to enable auditing: $_"
    }
}

# Function to apply firewall rules from registry content
function Apply-FirewallRules {
    # Write the registry content to a temporary file
    $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
    $script:registryContent | Out-File -FilePath $tempRegFile -Encoding Unicode

    # Import the registry file to apply the firewall rules
    try {
        reg import $tempRegFile 2>&1 | Out-Null
        Write-GSecurityLog "Firewall rules applied from registry content at $(Get-Date)." "Information"
    } catch {
        Write-GSecurityLog "Error applying firewall rules: $_" "Error"
    }

    # Clean up the temporary file
    Remove-Item $tempRegFile -Force -ErrorAction SilentlyContinue
}

# Function to monitor firewall rule changes
function Start-FirewallMonitor {
    Write-GSecurityLog "Starting firewall rule monitoring..." "Information"

    # Register WMI event for firewall rule changes
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4947"
    Register-WmiEvent -Query $query -SourceIdentifier "FirewallRuleChange" -Action {
        Write-GSecurityLog "Detected firewall rule change at $(Get-Date)" "Warning"
        Apply-FirewallRules
    }

    Write-GSecurityLog "Firewall monitoring started. Running in background..." "Information"
}

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-GSecurityLog "The script is already running. Exiting." "Error"
    exit
}

# Initial log with diagnostics
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
Write-GSecurityLog "GSecurity component initialized." "Information"
Write-ESLog "ES component initialized."
Write-RootkitLog "Terminate-Rootkits component initialized."

# Initial Scans and Protections
if ($isAdmin) {
    Enable-LsassPPL
    Clear-CachedCredentials
    Disable-CredentialCaching
    Enable-CredentialAuditing
    Remove-UnsignedDLLs
    Apply-FirewallRules
    Terminate-Rootkits
} else {
    Write-Error "Administrative privileges required for LSASS PPL, credential management, DLL scanning, firewall rule application, and rootkit termination."
}

# Start Background Jobs
Start-Job -ScriptBlock {
    . $using:PSCommandPath # Reload the script to access functions
    Apply-FirewallRules
    Start-FirewallMonitor
} -Name "FirewallTasks"

Start-Job -ScriptBlock {
    . $using:PSCommandPath # Reload the script to access functions
    while ($true) {
        Kill-Listeners
        Start-ProcessKiller
        Start-XSSWatcher
        Terminate-NonConsoleSessions
        Terminate-Rootkits
        $detected, $path, $value = Detect-InProcControls
        if ($detected) {
            Remove-InProcControls -path $path -value $value
        } else {
            Write-Host "No InProc controls detected. Checking again in $using:checkIntervalSeconds seconds..."
        }
        Start-Sleep -Seconds 5
    }
} -Name "GShieldSecurityTasks"

# Initial scan
Remove-UnsignedDLLs
Start-FileSystemWatcher

# Keep script running
Write-Log "Initial scan completed. Monitoring started."
Write-Host "GShield running. Press [Ctrl] + [C] to stop."
Write-Host "Check logs at $logFileAntivirus, $logFileGSecurity, and $logFileES"
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Log "Main loop crashed: $($_.Exception.Message)"
    Write-GSecurityLog "Main loop crashed: $($_.Exception.Message)" -EntryType "Error"
    Write-ESLog "Main loop crashed: $($_.Exception.Message)"
    Write-RootkitLog "Main loop crashed: $($_.Exception.Message)" -EntryType "Error"
    Write-Host "Script crashed. Check logs for details."
}