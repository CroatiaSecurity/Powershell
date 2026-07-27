# GSecurity.ps1 - Consolidated script with all functions from provided scripts

# Define paths and parameters
$taskName = "GShieldStartup"
$taskDescription = "Runs the GShield script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\GShield.ps1"
$quarantineFolder = "C:\Quarantine"
$logFileAntivirus = "$quarantineFolder\antivirus_log.txt"
$logFile = "$env:TEMP\SessionTerminator.log"
$backupDir = "$env:ProgramData\CookieBackup"
$cookieLogPath = "$backupDir\CookieMonitor.log"
$passwordLogPath = "$backupDir\NewPassword.log"
$errorLogPath = "$backupDir\ScriptErrors.log"
$cookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
$backupPath = "$backupDir\Cookies.bak"

# Section to paste registry keys to apply and monitor
$registryContent = @"
Windows Registry Editor Version 5.00

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
"RemoteAssistance-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
"NETDIS-SSDPSrv-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32757|Desc=@FirewallAPI.dll,-32760|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNT-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32819|Desc=@FirewallAPI.dll,-32820|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-NP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
"RemoteTask-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|"
"WFDPRINT-SPOOL-In-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36856|Desc=@FirewallAPI.dll,-36857|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"RemoteAssistance-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33007|Desc=@FirewallAPI.dll,-33010|EmbedCtxt=@FirewallAPI.dll,-33002|"
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
"SNMPTRAP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=162|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@firewallapi.dll,-50327|Desc=@firewallapi.dll,-50328|EmbedCtxt=@firewallapi.dll,-50323|"
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
"MsiScsi-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
"NETDIS-UPnP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-32821|Desc=@FirewallAPI.dll,-32822|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CDPSvc-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37405|Desc=@FirewallAPI.dll,-37406|EmbedCtxt=@FirewallAPI.dll,-37402|"
"FPS-NB_Name-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=137|App=System|Name=@FirewallAPI.dll,-28523|Desc=@FirewallAPI.dll,-28526|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SMB-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
"MSDTC-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33513|Desc=@FirewallAPI.dll,-33514|EmbedCtxt=@FirewallAPI.dll,-33502|"
"WFDPRINT-SCAN-In-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=%SystemRoot%\\system32\\svchost.exe|Svc=stisvc|Name=@FirewallAPI.dll,-36860|Desc=@FirewallAPI.dll,-36861|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|"
"RemoteAssistance-PnrpSvc-UDP-OUT"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Public|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
"FPS-ICMP4-ERQ-Out-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=1|Profile=Domain|ICMP4=8:*|App=System|Name=@FirewallAPI.dll,-28544|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"NETDIS-FDPHOST-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32785|Desc=@FirewallAPI.dll,-32788|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-RS-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=133:*|RA4=LocalSubnet|RA6=LocalSubnet|RA6=ff02::2|RA6=fe80::/64|App=System|Name=@FirewallAPI.dll,-25008|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RemoteAssistance-SSDPSrv-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33023|Desc=@FirewallAPI.dll,-33026|EmbedCtxt=@FirewallAPI.dll,-33002|"
"RemoteAssistance-SSDPSrv-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33031|Desc=@FirewallAPI.dll,-33034|EmbedCtxt=@FirewallAPI.dll,-33002|"
"NETDIS-WSDEVNT-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=5357|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|Desc=@FirewallAPI.dll,-32818|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-NDS-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=135:*|App=System|Name=@FirewallAPI.dll,-25019|Desc=@FirewallAPI.dll,-25025|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"EventForwarder-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-36804|Desc=@FirewallAPI.dll,-36805|EmbedCtxt=@FirewallAPI.dll,-36801|"
"FPS-SMB-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=445|App=System|Name=@FirewallAPI.dll,-28515|Desc=@FirewallAPI.dll,-28518|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-SMB-In-TCP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|Name=@FirewallAPI.dll,-28673|Desc=@FirewallAPI.dll,-28674|EmbedCtxt=@FirewallAPI.dll,-28672|"
"RemoteAssistance-DCOM-In-TCP-NoScope-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-33035|Desc=@FirewallAPI.dll,-33036|EmbedCtxt=@FirewallAPI.dll,-33002|"
"NETDIS-UPnPHost-Out-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNTS-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32813|Desc=@FirewallAPI.dll,-32814|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RVM-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-34506|Desc=@FirewallAPI.dll,-34507|EmbedCtxt=@FirewallAPI.dll,-34501|"
"RemoteAssistance-RAServer-In-TCP-NoScope-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33011|Desc=@FirewallAPI.dll,-33014|EmbedCtxt=@FirewallAPI.dll,-33002|"
"NETDIS-UPnPHost-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32761|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|"
"RemoteEventLogSvc-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29265|Desc=@FirewallAPI.dll,-29268|EmbedCtxt=@FirewallAPI.dll,-29252|"
"CoreNet-ICMP6-LR2-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=143:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25076|Desc=@FirewallAPI.dll,-25081|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-Diag-ICMP6-EchoRequest-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-27004|Desc=@FirewallAPI.dll,-27005|EmbedCtxt=@FirewallAPI.dll,-27000|"
"EventForwarder-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\NetEvtFwdr.exe|Name=@FirewallAPI.dll,-36802|Desc=@FirewallAPI.dll,-36803|EmbedCtxt=@FirewallAPI.dll,-36801|"
"NVS-FrameServer-In-UDP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=5000-5020|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=FrameServer|Name=@FirewallAPI.dll,-54006|Desc=@FirewallAPI.dll,-54007|EmbedCtxt=@FirewallAPI.dll,-54001|"
"Microsoft-Windows-Enrollment-WinRT-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\\system32\\svchost.exe|Svc=DmEnrollmentSvc|Name=@FirewallAPI.dll,-37505|Desc=@FirewallAPI.dll,-37506|EmbedCtxt=@FirewallAPI.dll,-37502|"
"SNMPTRAP-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=162|App=%SystemRoot%\\system32\\snmptrap.exe|Svc=SNMPTRAP|Name=@firewallapi.dll,-50327|Desc=@firewallapi.dll,-50328|EmbedCtxt=@firewallapi.dll,-50323|"
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
"vm-monitoring-rpc"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=Schedule|Name=@%SystemRoot%\\system32\\icsvc.dll,-707|Desc=@%SystemRoot%\\system32\\icsvc.dll,-708|EmbedCtxt=@%SystemRoot%\\system32\\icsvc.dll,-700|"
"CoreNet-ICMP6-LD-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=132:*|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-25083|Desc=@FirewallAPI.dll,-25088|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Microsoft-Windows-DeviceManagement-CertificateInstall-TCP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\\system32\\dmcertinst.exe|Name=@FirewallAPI.dll,-37507|Desc=@FirewallAPI.dll,-37508|EmbedCtxt=@FirewallAPI.dll,-37502|"
"MsiScsi-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
"RemoteAssistance-PnrpSvc-UDP-In-EdgeScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Public|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
"RRAS-PPTP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=1723|App=System|Name=@FirewallAPI.dll,-33765|Desc=@FirewallAPI.dll,-33768|EmbedCtxt=@FirewallAPI.dll,-33752|"
"CoreNet-Teredo-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=%SystemRoot%\\system32\\svchost.exe|Svc=iphlpsvc|Name=@FirewallAPI.dll,-25327|Desc=@FirewallAPI.dll,-25333|EmbedCtxt=@FirewallAPI.dll,-25000|"
"RVM-VDS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\vds.exe|Svc=vds|Name=@FirewallAPI.dll,-34502|Desc=@FirewallAPI.dll,-34503|EmbedCtxt=@FirewallAPI.dll,-34501|"
"TPMVSCMGR-Server-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\RmtTpmVscMgrSvr.exe|Name=@FirewallAPI.dll,-36504|Desc=@FirewallAPI.dll,-36505|EmbedCtxt=@FirewallAPI.dll,-36501|"
"Microsoft-Windows-WLANSvc-ASP-CP-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|LPort=7235|RPort=7235|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=WlanSvc|Name=@wlansvc.dll,-37377|Desc=@wlansvc.dll,-37889|EmbedCtxt=@wlansvc.dll,-36864|"
"WMI-WINMGMT-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=winmgmt|Name=@FirewallAPI.dll,-34258|Desc=@FirewallAPI.dll,-34259|EmbedCtxt=@FirewallAPI.dll,-34251|"
"NETDIS-NB_Datagram-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|App=System|Name=@FirewallAPI.dll,-32777|Desc=@FirewallAPI.dll,-32780|EmbedCtxt=@FirewallAPI.dll,-32752|"
"vm-monitoring-dcom"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=135|App=%SystemRoot%\\system32\\svchost.exe|Svc=RpcSs|Name=@%SystemRoot%\\system32\\icsvc.dll,-709|Desc=@%SystemRoot%\\system32\\icsvc.dll,-710|EmbedCtxt=@%SystemRoot%\\system32\\icsvc.dll,-700|"
"CoreNet-ICMP6-RS-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=133:*|App=System|Name=@FirewallAPI.dll,-25009|Desc=@FirewallAPI.dll,-25011|EmbedCtxt=@FirewallAPI.dll,-25000|"
"WMI-RPCSS-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=135|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=rpcss|Name=@FirewallAPI.dll,-34252|Desc=@FirewallAPI.dll,-34253|EmbedCtxt=@FirewallAPI.dll,-34251|"
"WirelessDisplay-Infra-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7250|App=%systemroot%\\system32\\CastSrv.exe|Name=@wifidisplay.dll,-10206|Desc=@wifidisplay.dll,-10207|EmbedCtxt=@wifidisplay.dll,-100|"
"PNRPMNRS-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-34009|Desc=@FirewallAPI.dll,-34010|EmbedCtxt=@FirewallAPI.dll,-34002|"
"NETDIS-FDRESPUB-WSD-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32809|Desc=@FirewallAPI.dll,-32810|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-WSDEVNTS-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=5358|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
"FPS-NB_Session-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=139|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28507|Desc=@FirewallAPI.dll,-28510|EmbedCtxt=@FirewallAPI.dll,-28502|"
"CoreNet-GP-LSASS-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\lsass.exe|Name=@FirewallAPI.dll,-25407|Desc=@FirewallAPI.dll,-25408|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Microsoft-Windows-Troubleshooting-HTTP-HTTPS-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=80|RPort=443|App=%SystemRoot%\\system32\\svchost.exe|Svc=TroubleshootingSvc|Name=@%SystemRoot%\\system32\\firewallapi.dll,-53501|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-53502|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-53500|"
"RemoteTask-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
"FPS-LLMNR-In-UDP-V2"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-28686|Desc=@FirewallAPI.dll,-28687|EmbedCtxt=@FirewallAPI.dll,-28672|"
"RemoteAssistance-PnrpSvc-UDP-In-EdgeScope-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=3540|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33039|Desc=@FirewallAPI.dll,-33040|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
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
"vm-monitoring-nb-session"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=139|App=System|Name=@%SystemRoot%\\system32\\icsvc.dll,-705|Desc=@%SystemRoot%\\system32\\icsvc.dll,-706|EmbedCtxt=@%SystemRoot%\\system32\\icsvc.dll,-700|"
"RemoteFwAdmin-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|"
"WirelessDisplay-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10202|Desc=@wifidisplay.dll,-10203|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
"WirelessDisplay-Out-UDP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=%systemroot%\\system32\\WUDFHost.exe|Name=@wifidisplay.dll,-10204|Desc=@wifidisplay.dll,-10205|LUAuth=O:LSD:(A;;CC;;;UD)|EmbedCtxt=@wifidisplay.dll,-100|TTK2_22=WFDDisplay|"
"FPS-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Rpcss|Name=@FirewallAPI.dll,-28539|Desc=@FirewallAPI.dll,-28542|EmbedCtxt=@FirewallAPI.dll,-28502|"
"FPS-ICMP6-ERQ-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=58|Profile=Private|Profile=Public|ICMP6=128:*|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28546|Desc=@FirewallAPI.dll,-28547|EmbedCtxt=@FirewallAPI.dll,-28502|"
"RemoteAssistance-RAServer-Out-TCP-NoScope-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\raserver.exe|Name=@FirewallAPI.dll,-33015|Desc=@FirewallAPI.dll,-33018|EmbedCtxt=@FirewallAPI.dll,-33002|"
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
"MsiScsi-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29003|Desc=@FirewallAPI.dll,-29006|EmbedCtxt=@FirewallAPI.dll,-29002|"
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
"RemoteAssistance-SSDPSrv-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-33019|Desc=@FirewallAPI.dll,-33022|EmbedCtxt=@FirewallAPI.dll,-33002|"
"NETDIS-WSDEVNTS-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=5358|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32815|Desc=@FirewallAPI.dll,-32816|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-LLMNR-Out-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32805|Desc=@FirewallAPI.dll,-32808|EmbedCtxt=@FirewallAPI.dll,-32752|"
"NETDIS-UPnPHost-In-TCP-Teredo"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=System|Name=@FirewallAPI.dll,-32762|Desc=@FirewallAPI.dll,-32764|EmbedCtxt=@FirewallAPI.dll,-32752|TTK2_27=UPnP|"
"NETDIS-FDRESPUB-WSD-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|Profile=Public|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdrespub|Name=@FirewallAPI.dll,-32811|Desc=@FirewallAPI.dll,-32812|EmbedCtxt=@FirewallAPI.dll,-32752|"
"CoreNet-ICMP6-TE-Out"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25114|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|"
"Netlogon-NamedPipe-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|Name=@firewallapi.dll,-37682|Desc=@firewallapi.dll,-37683|EmbedCtxt=@firewallapi.dll,-37681|"
"NETDIS-SSDPSrv-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-32753|Desc=@FirewallAPI.dll,-32756|EmbedCtxt=@FirewallAPI.dll,-32752|"
"vm-monitoring-icmpv4"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|App=System|Name=@%SystemRoot%\\system32\\icsvc.dll,-701|Desc=@%SystemRoot%\\system32\\icsvc.dll,-702|EmbedCtxt=@%SystemRoot%\\system32\\icsvc.dll,-700|"
"CDPSvc-In-UDP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37407|Desc=@FirewallAPI.dll,-37408|EmbedCtxt=@FirewallAPI.dll,-37402|"
"CDPSvc-In-TCP"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=CDPSvc|Name=@FirewallAPI.dll,-37403|Desc=@FirewallAPI.dll,-37404|EmbedCtxt=@FirewallAPI.dll,-37402|"
"RemoteTask-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|"
"MDNS-In-UDP-Private-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"AllJoyn-Router-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=AJRouter|Name=@FirewallAPI.dll,-37005|Desc=@FirewallAPI.dll,-37006|EmbedCtxt=@FirewallAPI.dll,-37002|"
"RemoteAssistance-In-TCP-EdgeScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
"ProximityUxHost-Sharing-Out-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36254|Desc=@FirewallAPI.dll,-36255|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
"NETDIS-LLMNR-In-UDP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|LPort=5355|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-32801|Desc=@FirewallAPI.dll,-32804|EmbedCtxt=@FirewallAPI.dll,-32752|"
"vm-monitoring-icmpv6"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|App=System|Name=@%SystemRoot%\\system32\\icsvc.dll,-703|Desc=@%SystemRoot%\\system32\\icsvc.dll,-704|EmbedCtxt=@%SystemRoot%\\system32\\icsvc.dll,-700|"
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
"RemoteAssistance-PnrpSvc-UDP-OUT-Active"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Domain|Profile=Private|App=%systemroot%\\system32\\svchost.exe|Svc=pnrpsvc|Name=@FirewallAPI.dll,-33037|Desc=@FirewallAPI.dll,-33038|EmbedCtxt=@FirewallAPI.dll,-33002|"
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
"RemoteAssistance-SSDPSrv-In-TCP-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-33027|Desc=@FirewallAPI.dll,-33030|EmbedCtxt=@FirewallAPI.dll,-33002|"
"MSDTC-KTMRM-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=ktmrm|Name=@FirewallAPI.dll,-33511|Desc=@FirewallAPI.dll,-33512|EmbedCtxt=@FirewallAPI.dll,-33502|"
"ProximityUxHost-Sharing-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\proximityuxhost.exe|Name=@FirewallAPI.dll,-36252|Desc=@FirewallAPI.dll,-36253|EmbedCtxt=@FirewallAPI.dll,-36251|TTK=ProxSharing|"
"MsiScsi-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%SystemRoot%\\system32\\svchost.exe|Svc=Msiscsi|Name=@FirewallAPI.dll,-29007|Desc=@FirewallAPI.dll,-29010|EmbedCtxt=@FirewallAPI.dll,-29002|"
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
"Netlogon-TCP-RPC-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=RPC|App=%SystemRoot%\\System32\\lsass.exe|Name=@firewallapi.dll,-37684|Desc=@firewallapi.dll,-37685|EmbedCtxt=@firewallapi.dll,-37681|"
"CoreNet-ICMP6-TE-In"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=58|ICMP6=3:*|App=System|Name=@FirewallAPI.dll,-25113|Desc=@FirewallAPI.dll,-25115|EmbedCtxt=@FirewallAPI.dll,-25000|Edge=TRUE|"
"MDNS-In-UDP-Domain-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|LPort=5353|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@%SystemRoot%\\system32\\firewallapi.dll,-37303|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-37304|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-37302|"
"Collab-P2PHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\p2phost.exe|Name=@FirewallAPI.dll,-32003|Desc=@FirewallAPI.dll,-32006|EmbedCtxt=@FirewallAPI.dll,-32002|Edge=TRUE|Defer=App|"
"RemoteAssistance-In-TCP-EdgeScope-Active"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|App=%SystemRoot%\\system32\\msra.exe|Name=@FirewallAPI.dll,-33003|Desc=@FirewallAPI.dll,-33006|EmbedCtxt=@FirewallAPI.dll,-33002|Edge=TRUE|Defer=App|"
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
"WMPNSS-WMP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31301|Desc=@FirewallAPI.dll,-31304|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=%ProgramFiles%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31003|Desc=@FirewallAPI.dll,-31006|EmbedCtxt=@FirewallAPI.dll,-31002|"
"Microsoft-Windows-PeerDist-HostedServer-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10005|Desc=@peerdistsh.dll,-11005|EmbedCtxt=@peerdistsh.dll,-9002|"
"PlayTo-QWave-Out-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36016|Desc=@FirewallAPI.dll,-36017|EmbedCtxt=@FirewallAPI.dll,-36001|"
"RemoteDesktop-In-TCP-WS"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3387|App=System|Name=@FirewallAPI.dll,-28780|Desc=@FirewallAPI.dll,-28781|EmbedCtxt=@FirewallAPI.dll,-28782|"
"Microsoft-Windows-PeerDist-WSD-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10002|Desc=@peerdistsh.dll,-11002|EmbedCtxt=@peerdistsh.dll,-9001|"
"PlayTo-In-UDP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-HTTPSTR-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=10244|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30785|Desc=@FirewallAPI.dll,-30788|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WPDMTP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=15740|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
"MCX-QWave-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30769|Desc=@FirewallAPI.dll,-30772|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-Out-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-Out-UDP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36006|Desc=@FirewallAPI.dll,-36007|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-Prov-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%SystemRoot%\\ehome\\mcx2prov.exe|Name=@FirewallAPI.dll,-30812|Desc=@FirewallAPI.dll,-30813|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WMPNSS-QWave-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31261|Desc=@FirewallAPI.dll,-31264|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-QWave-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31253|Desc=@FirewallAPI.dll,-31256|EmbedCtxt=@FirewallAPI.dll,-31252|"
"PlayTo-In-UDP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"WMPNSS-UPnPHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-31277|Desc=@FirewallAPI.dll,-31280|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-WMP-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31297|Desc=@FirewallAPI.dll,-31300|EmbedCtxt=@FirewallAPI.dll,-31252|"
"Microsoft-Windows-PeerDist-HostedServer-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|LPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10004|Desc=@peerdistsh.dll,-11004|EmbedCtxt=@peerdistsh.dll,-9002|"
"WMPNSS-UPnP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-31321|Desc=@FirewallAPI.dll,-31322|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31305|Desc=@FirewallAPI.dll,-31308|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31313|Desc=@FirewallAPI.dll,-31316|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-QWave-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=2177|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31261|Desc=@FirewallAPI.dll,-31264|EmbedCtxt=@FirewallAPI.dll,-31252|"
"PlayTo-In-RTSP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=23554|LPort=23555|LPort=23556|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=7777|LPort=7778|LPort=7779|LPort=7780|LPort=7781|LPort=5004|LPort=5005|LPort=50004|LPort=50005|LPort=50006|LPort=50007|LPort=50008|LPort=50009|LPort=50010|LPort=50011|LPort=50012|LPort=50013|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30801|Desc=@FirewallAPI.dll,-30804|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WMP-In-UDP-x86"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=%ProgramFiles(x86)%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31023|Desc=@FirewallAPI.dll,-31006|EmbedCtxt=@FirewallAPI.dll,-31002|"
"WMPNSS-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31305|Desc=@FirewallAPI.dll,-31308|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31313|Desc=@FirewallAPI.dll,-31316|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WPDMTP-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=15740|App=%SystemRoot%\\system32\\wudfhost.exe|Name=@FirewallAPI.dll,-30503|Desc=@FirewallAPI.dll,-30506|EmbedCtxt=@FirewallAPI.dll,-30502|"
"WMPNSS-WMP-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31293|Desc=@FirewallAPI.dll,-31296|EmbedCtxt=@FirewallAPI.dll,-31252|"
"PlayTo-QWave-In-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36010|Desc=@FirewallAPI.dll,-36011|EmbedCtxt=@FirewallAPI.dll,-36001|"
"WMPNSS-HTTPSTR-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=10243|App=System|Name=@FirewallAPI.dll,-31289|Desc=@FirewallAPI.dll,-31292|EmbedCtxt=@FirewallAPI.dll,-31252|"
"CloudIdSvc-Allow-HTTPS-Out-TCP"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=443|App=%SystemRoot%\\system32\\svchost.exe|Svc=cloudidsvc|Name=@%SystemRoot%\\system32\\firewallapi.dll,-60502|Desc=@%SystemRoot%\\system32\\firewallapi.dll,-60503|EmbedCtxt=@%SystemRoot%\\system32\\firewallapi.dll,-60501|"
"WMPNSS-WMP-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31293|Desc=@FirewallAPI.dll,-31296|EmbedCtxt=@FirewallAPI.dll,-31252|"
"MCX-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=554|LPort=8554|LPort=8555|LPort=8556|LPort=8557|LPort=8558|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\ehome\\ehshell.exe|Name=@FirewallAPI.dll,-30761|Desc=@FirewallAPI.dll,-30764|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-QWave-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30773|Desc=@FirewallAPI.dll,-30776|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-QWave-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30781|Desc=@FirewallAPI.dll,-30784|EmbedCtxt=@FirewallAPI.dll,-30752|"
"PlayTo-QWave-Out-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36012|Desc=@FirewallAPI.dll,-36013|EmbedCtxt=@FirewallAPI.dll,-36001|"
"RemoteDesktop-In-TCP-WSS"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3392|App=System|Name=@FirewallAPI.dll,-28783|Desc=@FirewallAPI.dll,-28784|EmbedCtxt=@FirewallAPI.dll,-28782|"
"MCX-TERMSRV-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=3390|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-30793|Desc=@FirewallAPI.dll,-30796|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WMPNSS-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=ssdpsrv|Name=@FirewallAPI.dll,-31273|Desc=@FirewallAPI.dll,-31276|EmbedCtxt=@FirewallAPI.dll,-31252|"
"SPPSVC-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=1688|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
"WMPNSS-QWave-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31265|Desc=@FirewallAPI.dll,-31268|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-WMP-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31301|Desc=@FirewallAPI.dll,-31304|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-UPnPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-31281|Desc=@FirewallAPI.dll,-31284|EmbedCtxt=@FirewallAPI.dll,-31252|"
"FPSSMBD-iWARP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=5445|App=System|Name=@FirewallAPI.dll,-28603|Desc=@FirewallAPI.dll,-28606|EmbedCtxt=@FirewallAPI.dll,-28602|"
"WMPNSS-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=ssdpsrv|Name=@FirewallAPI.dll,-31269|Desc=@FirewallAPI.dll,-31272|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WPDMTP-UPnPHost-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30515|Desc=@FirewallAPI.dll,-30518|EmbedCtxt=@FirewallAPI.dll,-30502|"
"WMPNSS-HTTPSTR-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=10243|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-31289|Desc=@FirewallAPI.dll,-31292|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WPDMTP-UPnPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30519|Desc=@FirewallAPI.dll,-30522|EmbedCtxt=@FirewallAPI.dll,-30502|"
"WMPNSS-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31309|Desc=@FirewallAPI.dll,-31312|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-HTTPSTR-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=10243|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-31285|Desc=@FirewallAPI.dll,-31288|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-QWave-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31257|Desc=@FirewallAPI.dll,-31260|EmbedCtxt=@FirewallAPI.dll,-31252|"
"PlayTo-HTTPSTR-In-TCP-LocalSubnetScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=10246|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-QWave-In-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=2177|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-36014|Desc=@FirewallAPI.dll,-36015|EmbedCtxt=@FirewallAPI.dll,-36001|"
"MCX-SSDPSrv-In-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30753|Desc=@FirewallAPI.dll,-30756|EmbedCtxt=@FirewallAPI.dll,-30752|"
"RemoteDesktop-Shadow-In-TCP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%SystemRoot%\\system32\\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|"
"WMPNSS-QWave-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|RPort=2177|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31257|Desc=@FirewallAPI.dll,-31260|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-QWave-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|RPort=2177|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31265|Desc=@FirewallAPI.dll,-31268|EmbedCtxt=@FirewallAPI.dll,-31252|"
"MCX-FDPHost-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-30822|Desc=@FirewallAPI.dll,-30823|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-MCX2SVC-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=mcx2svc|Name=@FirewallAPI.dll,-30810|Desc=@FirewallAPI.dll,-30811|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WMPNSS-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31317|Desc=@FirewallAPI.dll,-31320|EmbedCtxt=@FirewallAPI.dll,-31252|"
"Microsoft-Windows-PeerDist-HostedClient-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|RPort=443|App=SYSTEM|Name=@peerdistsh.dll,-10006|Desc=@peerdistsh.dll,-11006|EmbedCtxt=@peerdistsh.dll,-9003|"
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
"WMPNSS-Out-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31309|Desc=@FirewallAPI.dll,-31312|EmbedCtxt=@FirewallAPI.dll,-31252|"
"PlayTo-In-UDP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36004|Desc=@FirewallAPI.dll,-36005|EmbedCtxt=@FirewallAPI.dll,-36001|"
"SPPSVC-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=1688|App=%SystemRoot%\\system32\\sppextcomobj.exe|Svc=sppsvc|Name=@FirewallAPI.dll,-28003|Desc=@FirewallAPI.dll,-28006|EmbedCtxt=@FirewallAPI.dll,-28002|"
"MCX-PlayTo-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30814|Desc=@FirewallAPI.dll,-30815|EmbedCtxt=@FirewallAPI.dll,-30752|"
"RemoteDesktop-UserMode-In-TCP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
"RemoteDesktop-UserMode-In-UDP"="v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|"
"Microsoft-Windows-PeerDist-HttpTrans-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10001|Desc=@peerdistsh.dll,-11001|EmbedCtxt=@peerdistsh.dll,-9000|"
"MCX-SSDPSrv-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Ssdpsrv|Name=@FirewallAPI.dll,-30757|Desc=@FirewallAPI.dll,-30760|EmbedCtxt=@FirewallAPI.dll,-30752|"
"MCX-PlayTo-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=upnphost|Name=@FirewallAPI.dll,-30816|Desc=@FirewallAPI.dll,-30817|EmbedCtxt=@FirewallAPI.dll,-30752|"
"WMP-Out-UDP-x86"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=%ProgramFiles(x86)%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31024|Desc=@FirewallAPI.dll,-31010|EmbedCtxt=@FirewallAPI.dll,-31002|"
"WMP-Out-TCP-x86"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%ProgramFiles(x86)%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31025|Desc=@FirewallAPI.dll,-31014|EmbedCtxt=@FirewallAPI.dll,-31002|"
"PlayTo-HTTPSTR-In-TCP-NoScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=10246|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-HTTPSTR-In-TCP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=10246|RA42=Ply2Renders|RA62=Ply2Renders|App=System|Name=@FirewallAPI.dll,-36002|Desc=@FirewallAPI.dll,-36003|EmbedCtxt=@FirewallAPI.dll,-36001|"
"PlayTo-In-RTSP-PlayToScope"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=23554|LPort=23555|LPort=23556|RA42=Ply2Renders|RA62=Ply2Renders|App=%SystemRoot%\\system32\\mdeserver.exe|Name=@FirewallAPI.dll,-36008|Desc=@FirewallAPI.dll,-36009|EmbedCtxt=@FirewallAPI.dll,-36001|"
"WMPNSS-WMP-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|Profile=Private|Profile=Public|RA4=LocalSubnet|RA6=LocalSubnet|App=%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31297|Desc=@FirewallAPI.dll,-31300|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-HTTPSTR-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=10243|App=System|Name=@FirewallAPI.dll,-31285|Desc=@FirewallAPI.dll,-31288|EmbedCtxt=@FirewallAPI.dll,-31252|"
"Microsoft-Windows-PeerDist-HttpTrans-In"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=80|App=SYSTEM|Name=@peerdistsh.dll,-10000|Desc=@peerdistsh.dll,-11000|EmbedCtxt=@peerdistsh.dll,-9000|"
"WMP-Out-UDP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=%ProgramFiles%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31007|Desc=@FirewallAPI.dll,-31010|EmbedCtxt=@FirewallAPI.dll,-31002|"
"WMP-Out-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|App=%ProgramFiles%\\Windows Media Player\\wmplayer.exe|Name=@FirewallAPI.dll,-31011|Desc=@FirewallAPI.dll,-31014|EmbedCtxt=@FirewallAPI.dll,-31002|"
"Microsoft-Windows-PeerDist-WSD-Out"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|RPort=3702|RA4=LocalSubnet|RA6=LocalSubnet|App=%systemroot%\\system32\\svchost.exe|Svc=PeerDistSvc|Name=@peerdistsh.dll,-10003|Desc=@peerdistsh.dll,-11003|EmbedCtxt=@peerdistsh.dll,-9001|"
"WMPNSS-QWave-In-UDP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=2177|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-31253|Desc=@FirewallAPI.dll,-31256|EmbedCtxt=@FirewallAPI.dll,-31252|"
"WMPNSS-Out-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Domain|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Name=@FirewallAPI.dll,-31317|Desc=@FirewallAPI.dll,-31320|EmbedCtxt=@FirewallAPI.dll,-31252|"
"MCX-QWave-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=2177|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=Qwave|Name=@FirewallAPI.dll,-30777|Desc=@FirewallAPI.dll,-30780|EmbedCtxt=@FirewallAPI.dll,-30752|"
"Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|Desc=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|PFN=Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|"
"Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|Desc=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|PFN=Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}|"
"Microsoft.AccountsControl_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|Desc=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|PFN=Microsoft.AccountsControl_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}|"
"Microsoft.LockApp_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.LockApp_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}|Desc=@{Microsoft.LockApp_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}|PFN=Microsoft.LockApp_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.LockApp_10.0.26100.1_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}|"
"Microsoft.Win32WebViewHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/DisplayName}|Desc=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/Description}|PFN=Microsoft.Win32WebViewHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/DisplayName}|"
"Microsoft.Win32WebViewHost_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/DisplayName}|Desc=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/Description}|PFN=Microsoft.Win32WebViewHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Win32WebViewHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.Win32WebViewHost/resources/DisplayName}|Edge=TRUE|"
"Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|Desc=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|PFN=Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.Apprep.ChxApp_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}|"
"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|Desc=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|PFN=Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|"
"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|Desc=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|PFN=Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.CloudExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}|"
"Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.ContentDeliveryManager_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ContentDeliveryManager/resources/AppDisplayName}|Desc=@{Microsoft.Windows.ContentDeliveryManager_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ContentDeliveryManager/resources/AppDisplayName}|PFN=Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.ContentDeliveryManager_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ContentDeliveryManager/resources/AppDisplayName}|"
"Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.OOBENetworkCaptivePortal_10.0.21302.1000_neutral__cw5n1h2txyewy?ms-resource://Microsoft.Windows.OOBENetworkCaptivePortal/Resources/AppDisplayName}|Desc=@{Microsoft.Windows.OOBENetworkCaptivePortal_10.0.21302.1000_neutral__cw5n1h2txyewy?ms-resource://Microsoft.Windows.OOBENetworkCaptivePortal/Resources/AppDisplayName}|PFN=Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.OOBENetworkCaptivePortal_10.0.21302.1000_neutral__cw5n1h2txyewy?ms-resource://Microsoft.Windows.OOBENetworkCaptivePortal/Resources/AppDisplayName}|"
"Microsoft.Windows.ParentalControls_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.ParentalControls_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ParentalControls/resources/DisplayName}|Desc=@{Microsoft.Windows.ParentalControls_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ParentalControls/resources/DisplayName}|PFN=Microsoft.Windows.ParentalControls_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.ParentalControls_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ParentalControls/resources/DisplayName}|"
"Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.PeopleExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PeopleExperienceHost/resources/PkgDisplayName}|Desc=@{Microsoft.Windows.PeopleExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PeopleExperienceHost/resources/PkgDisplayName}|PFN=Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.PeopleExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PeopleExperienceHost/resources/PkgDisplayName}|"
"Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|Desc=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|PFN=Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.PrintQueueActionCenter_1.0.2.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.PrintQueueActionCenter/Resources/AppxManifest_DisplayName}|"
"Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.SecureAssessmentBrowser_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.SecureAssessmentBrowser/Resources/PackageDisplayName}|Desc=@{Microsoft.Windows.SecureAssessmentBrowser_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.SecureAssessmentBrowser/Resources/PackageDescription}|PFN=Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.SecureAssessmentBrowser_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.SecureAssessmentBrowser/Resources/PackageDisplayName}|"
"Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|Desc=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|PFN=Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|"
"Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|Desc=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|PFN=Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.Windows.StartMenuExperienceHost_10.0.26100.1_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.StartMenuExperienceHost/StartMenuExperienceHost/PkgDisplayName}|"
"Microsoft.XboxGameCallableUI_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|Desc=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|PFN=Microsoft.XboxGameCallableUI_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}|"
"MicrosoftWindows.Client.AIX_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.AIX_cw5n1h2txyewy|LUOwn=S-1-5-21-3619819590-2351760732-2475584066-1000|EmbedCtxt=@{MicrosoftWindows.Client.AIX_1000.26100.3.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.CBS_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.CBS_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.CBS_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.CBS_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Core_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Core_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Core_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Core_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Core_1000.26100.2.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Core/Resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.FileExp_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.FileExp_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.FileExp_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.FileExp/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.OOBE_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.OOBE_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.OOBE_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.OOBE/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Photon_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Photon_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|"
"MicrosoftWindows.Client.Photon_cw5n1h2txyewy-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|Desc=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|PFN=MicrosoftWindows.Client.Photon_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{MicrosoftWindows.Client.Photon_1000.26100.1.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.Photon/resources/ProductPkgDisplayName}|"
"NcsiUwpApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=NcsiUwpApp|Desc=NcsiUwpApp|PFN=NcsiUwpApp_8wekyb3d8bbwe|LUOwn=S-1-5-18|EmbedCtxt=NcsiUwpApp|"
"Windows.PrintDialog_cw5n1h2txyewy-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Windows.PrintDialog_6.2.3.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.PrintDialog/Resources/DisplayName}|Desc=@{Windows.PrintDialog_6.2.3.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.PrintDialog/Resources/Description}|PFN=Windows.PrintDialog_cw5n1h2txyewy|LUOwn=S-1-5-18|EmbedCtxt=@{Windows.PrintDialog_6.2.3.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.PrintDialog/Resources/DisplayName}|"
"RemoteAdmin-NP-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-RPCSS-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-NP-In-TCP-NoScope"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|"
"RemoteAdmin-RPCSS-In-TCP"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|"
"{faa1ae55-2e59-4797-bf03-ab56b8bd3c76}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{be2fa8ee-ef9f-4245-81c5-6246f672a5b4}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{fd88c1e1-02d6-4c20-ae54-9f09ec655723}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Block RDP Inbound|"
"{470ea644-aed7-411b-9f54-5aeae34f4403}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=5900-5902|Name=Block VNC Inbound|"
"{88eb5b89-0018-4b89-ae6a-0476f2db748b}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=5938|Name=Block TeamViewer Inbound|"
"{89d2f07a-46ef-43e8-b28f-98111bc906ac}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=7070|Name=Block AnyDesk Inbound|"
"InternetIn"="v2.33|Action=Block|Active=TRUE|Dir=In|Name=Block|Desc=Block everything incoming from Internet|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|"
"{111C64B9-0D47-43E4-86A2-7A16572491F3}"="v2.33|Action=Block|Active=TRUE|Dir=Out|RA42=IntrAnet|RA62=IntrAnet|Name=Block|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|"
"{72e1385d-992b-4a22-a93c-22b0dbdd087e}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{1ca69094-99b9-4e91-a3c0-842947a8092b}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{033EE74A-C306-4613-A774-FF51A5193C59}"="v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|App=System|Name=@FirewallAPI.dll,-29257|Desc=@FirewallAPI.dll,-29260|EmbedCtxt=@FirewallAPI.dll,-29252|"
"{83B5E181-8B34-4F4F-9DCF-9837E18F4DFE}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|"
"{09c774e9-b54e-4b0c-aaef-1406bcf48236}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{b8ba4996-9b3a-4468-8548-3db7816ca937}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
"{029f5512-416a-4999-b0e2-c6f2c57e65f5}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=389|Name=Block LDAP Port 389|"
"{f408f81d-c94c-470f-98ec-0b758178b959}"="v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=636|Name=Block LDAP Port 636|"
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
"{E490DFC8-AFF2-44BD-BEFC-A2D6B90EDC9F}"="v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe|Name=Google Chrome (mDNS-In)|Desc=Inbound rule for Google Chrome to allow mDNS traffic.|EmbedCtxt=Google Chrome|"
"Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.Windows.NarratorQuickStart_10.0.26100.1_neutral_neutral_8wekyb3d8bbwe?ms-resource://Microsoft.Windows.NarratorQuickStart/Resources/AppDisplayName}|Desc=@{Microsoft.Windows.NarratorQuickStart_10.0.26100.1_neutral_neutral_8wekyb3d8bbwe?ms-resource://Microsoft.Windows.NarratorQuickStart/Resources/AppDescription}|PFN=Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.Windows.NarratorQuickStart_10.0.26100.1_neutral_neutral_8wekyb3d8bbwe?ms-resource://Microsoft.Windows.NarratorQuickStart/Resources/AppDisplayName}|"
"Microsoft.SecHealthUI_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}|Desc=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/ProductDescription}|PFN=Microsoft.SecHealthUI_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}|"
"Microsoft.SecHealthUI_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}|Desc=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/ProductDescription}|PFN=Microsoft.SecHealthUI_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.SecHealthUI_1000.26100.1.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}|"
"Microsoft.StorePurchaseApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|Desc=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|PFN=Microsoft.StorePurchaseApp_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|"
"Microsoft.StorePurchaseApp_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|Desc=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|PFN=Microsoft.StorePurchaseApp_8wekyb3d8bbwe|LUOwn=S-1-5-21-559777512-1942596260-2095632971-1000|EmbedCtxt=@{Microsoft.StorePurchaseApp_22505.1401.0.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.StorePurchaseApp/Resources/DisplayTitle}|"
"Microsoft.WindowsStore_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=Microsoft Store|Desc=Microsoft Store|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=Microsoft Store|Platform=2:6:2|Platform2=GTEQ|"
"Microsoft.WindowsStore_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Profile=Public|Name=Microsoft Store|Desc=Microsoft Store|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=Microsoft Store|Edge=TRUE|"
"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|Desc=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|PFN=Microsoft.DesktopAppInstaller_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|"
"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|Desc=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|PFN=Microsoft.DesktopAppInstaller_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.DesktopAppInstaller_1.26.399.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}|"
"Microsoft.WindowsCamera_8wekyb3d8bbwe-Out-Allow-AllCapabilities"="v2.33|Action=Block|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|Desc=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|PFN=Microsoft.WindowsCamera_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|"
"Microsoft.WindowsCamera_8wekyb3d8bbwe-In-Allow-ServerCapability"="v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|Desc=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|PFN=Microsoft.WindowsCamera_8wekyb3d8bbwe|LUOwn=S-1-5-21-3285726620-610888927-1395086397-1000|EmbedCtxt=@{Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName}|"
"@

# === Functions from Audio.ps1 ===
function Take-RegistryOwnership {
    param (
        [string]$RegPath
    )
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $acl = $regKey.GetAccessControl()
        $admin = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($admin)
        $regKey.SetAccessControl($acl)

        # Grant Full Control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admin, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        $regKey.SetAccessControl($acl)
        Write-Host "Ownership and Full Control granted for $RegPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to take ownership of $RegPath. Error: $_" -ForegroundColor Red
    } finally {
        if ($regKey) { $regKey.Close() }
    }
}

function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    # Get all audio devices under the Render key
    $audioDevices = Get-ChildItem -Path $renderDevicesKey

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        # Check if the FxProperties key exists, if not, create it
        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        # Take ownership and set permissions for the FxProperties key
        Take-RegistryOwnership -RegPath ($fxPropertiesKey -replace 'HKEY_LOCAL_MACHINE\\', '')

        # Define the keys and values for AEC and Noise Suppression
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1  # 1 = Enable, 0 = Disable

        # Set Acoustic Echo Cancellation (AEC)
        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue -ErrorAction Stop
                Write-Host "Acoustic Echo Cancellation set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Acoustic Echo Cancellation for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Acoustic Echo Cancellation already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }

        # Set Noise Suppression
        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            try {
                Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue -ErrorAction Stop
                Write-Host "Noise Suppression set to enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to set Noise Suppression for device: $($device.PSChildName). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Noise Suppression already enabled for device: $($device.PSChildName)" -ForegroundColor Cyan
        }
    }
}

# === Functions from BCDCleanup.ps1 ===
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

# === Functions from CookieMonitor.ps1 ===
function Log-Info($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Out-File -FilePath $cookieLogPath -Append
}

function Log-Error($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR - $msg" | Out-File -FilePath $errorLogPath -Append
}

function Initialize-Environment {
    foreach ($dir in @($logDir, $backupDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

function Install-Script {
    $targetFolder = Split-Path $taskScriptPath
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path $PSCommandPath -Destination $taskScriptPath -Force
    Log-Info "Script copied to $taskScriptPath"

    # Unregister all tasks to prevent conflicts
    $taskNames = @("MonitorCookiesLogon", "BackupCookiesOnStartup", "MonitorCookies", "ResetPasswordOnShutdown")
    foreach ($taskName in $taskNames) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # SYSTEM logon task
    $logonTaskName = "MonitorCookiesLogon"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $logonTaskName -Action $action -Trigger $trigger -Principal $principal

    # Startup backup task
    $backupTaskName = "BackupCookiesOnStartup"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Backup"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $backupTaskName -Action $action -Trigger $trigger -Principal $principal

    # Monitoring task (every 5 min)
    $monitorTaskName = "MonitorCookies"
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $trigger = $triggers.Create(1) # 1 = TimeTrigger
    $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $trigger.Repetition.Interval = "PT5M" # 5 minutes
    $trigger.Repetition.Duration = "P365D" # 365 days
    $trigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -Monitor"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($monitorTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    # Shutdown password reset
    $shutdownTaskName = "ResetPasswordOnShutdown"
    $eventTriggerQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $eventTrigger = $triggers.Create(0)
    $eventTrigger.Subscription = $eventTriggerQuery
    $eventTrigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-ExecutionPolicy Bypass -File `"$taskScriptPath`" -ResetPassword"
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($shutdownTaskName, $taskDefinition, 6, "SYSTEM", $null, 4)

    Log-Info "Scheduled tasks installed."
}

function Monitor-Cookies {
    if (-not (Test-Path $cookiePath)) {
        Log-Info "No Chrome cookies found."
        return
    }

    try {
        $currentHash = (Get-FileHash -Path $cookiePath -Algorithm SHA256).Hash
        $lastHash = if (Test-Path $cookieLogPath) { Get-Content $cookieLogPath -Last 1 } else { "" }

        if ($lastHash -and $currentHash -ne $lastHash) {
            Log-Info "Cookie hash changed. Triggering countermeasure..."
            Rotate-Password
            Restore-Cookies
        }

        $currentHash | Out-File -FilePath $cookieLogPath -Force
    } catch {
        Log-Error "Monitor-Cookies error: $_"
    }
}

function Backup-Cookies {
    try {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if (Test-Path $cookiePath) {
            Copy-Item -Path $cookiePath -Destination $backupPath -Force
            Log-Info "Cookies backed up to $backupPath"
        }
    } catch {
        Log-Error "Backup-Cookies error: $_"
    }
}

function Restore-Cookies {
    try {
        if (Test-Path $backupPath) {
            Copy-Item -Path $backupPath -Destination $cookiePath -Force
            Log-Info "Cookies restored from backup"
        }
    } catch {
        Log-Error "Restore-Cookies error: $_"
    }
}

function Rotate-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account password change."
            return
        }

        $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*')
        $password = -join ($chars | Get-Random -Count 16)
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        Set-LocalUser -Name $user -Password $securePassword
        "$((Get-Date).ToString()) - New password: $password" | Out-File -FilePath $passwordLogPath -Append
        Log-Info "Rotated local password."
    } catch {
        Log-Error "Rotate-Password error: $_"
    }
}

function Reset-Password {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $account = Get-LocalUser -Name $user
        if ($account.UserPrincipalName) {
            Log-Info "Skipping Microsoft account reset."
            return
        }

        $blank = ConvertTo-SecureString "" -AsPlainText -Force
        Set-LocalUser -Name $user -Password $blank
        Log-Info "Password reset to blank on shutdown."
    } catch {
        Log-Error "Reset-Password error: $_"
    }
}

# === Functions from Corrupt.ps1 ===
function Overwrite-File {
    param ($FilePath)
    try {
        if (Test-Path $FilePath) {
            $Size = (Get-Item $FilePath).Length
            $Junk = [byte[]]::new($Size)
            (New-Object Random).NextBytes($Junk)
            [System.IO.File]::WriteAllBytes($FilePath, $Junk)
            Write-Host "Overwrote telemetry file: $FilePath"
        } else {
            Write-Host "File not found: $FilePath"
        }
    } catch {
        Write-Host "Error overwriting ${FilePath}: $($_.Exception.Message)"
    }
}

# === Functions from GSecurity.ps1 ===
function Write-RootkitLog {
    param (
        [string]$Message,
        [string]$EntryType = "Information"
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("GShield")) {
            New-EventLog -LogName Application -Source "GShield"
        }
        Write-EventLog -LogName Application -Source "GShield" -EntryType $EntryType -EventId 1000 -Message $Message
    } catch {
        Write-Output "$EntryType`: $Message"
    }
}

function Terminate-NonConsoleSessions {
    try {
        # Run qwinsta to list sessions
        $sessions = qwinsta | Where-Object { $_ -notmatch "^\s*>" } # Exclude active session marker
        $sessionList = $sessions -split "`n" | ForEach-Object { $_.Trim() }

        Write-Log "Listing all sessions:"
        $sessions | ForEach-Object { Write-Log $_ }

        # Parse each session
        foreach ($session in $sessionList) {
            # Skip empty lines or headers
            if ($session -match "^\s*(services|console|\S+)\s+(\S+)?\s+(\d+)\s+(\S+)") {
                $sessionName = $matches[1]
                $sessionId = $matches[3]
                $sessionState = $matches[4]

                # Skip console session
                if ($sessionName -notin @("console")) {
                    Write-Log "Terminating session: ID=$sessionId, Name=$sessionName, State=$sessionState"
                    try {
                        rwinsta $sessionId
                        Write-Log "Successfully terminated session ID $sessionId"
                    } catch {
                        Write-Log "Failed to terminate session ID $sessionId : $_"
                    }
                } else {
                    Write-Log "Skipping session: ID=$sessionId, Name=$sessionName (console or services)"
                }
            }
        }
    } catch {
        Write-Log "Error processing sessions: $_"
    }
}

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
    }
    catch {
        Write-Error "Failed to enable LSASS PPL: $_"
    }
}

function Clear-CachedCredentials {
    try {
        # Check if cmdkey is available
        $cmdkeyPath = "$env:SystemRoot\System32\cmdkey.exe"
        if (Test-Path $cmdkeyPath) {
            # Clear cached credentials using cmdkey
            & $cmdkeyPath /list | ForEach-Object {
                if ($_ -match "Target:") {
                    $target = $_ -replace ".*Target: (.*)", '$1'
                    & $cmdkeyPath /delete:$target
                }
            }
            Write-Host "Cleared cached credentials from Credential Manager using cmdkey."
        }
        else {
            Write-Warning "cmdkey.exe not found at $cmdkeyPath. Attempting alternative method to clear credentials."
            try {
                $credMan = New-Object -ComObject WScript.Network
                Write-Warning "COM-based credential clearing is not fully supported in this script. Manual cleanup may be required."
            }
            catch {
                Write-Error "No suitable method available to clear cached credentials. Please clear credentials manually via Control Panel > Credential Manager."
                return
            }
        }
    }
    catch {
        Write-Error "Failed to clear cached credentials: $_"
    }
}

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
    }
    catch {
        Write-Error "Failed to disable credential caching: $_"
    }
}

function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        }
        else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    }
    catch {
        Write-Error "Failed to enable auditing: $_"
    }
}

function Detect-InProcControls {
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

function Remove-InProcControls {
    param ([string]$path, [string]$value)
    if ($path -and $value) {
        try {
            # Remove registry entry
            $parentPath = Split-Path $path -Parent
            $keyName = Split-Path $path -Leaf
            Remove-ItemProperty -Path $parentPath -Name $keyName -Force -ErrorAction Stop
            Write-Host "Removed InProc control registry entry at $path"
            # Remove associated file if it exists
            if (Test-Path $value) {
                Remove-Item -Path $value -Force -ErrorAction Stop
                Write-Host "Removed file: $value"
            }
        } catch {
            Write-Host "Error removing $path : $_"
        }
    }
}

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
        Write-Log "Network temporarily disabled and re-enabled." "Warning"
    } catch {
        Write-Log "Failed to toggle network adapters: $_" "Error"
    }
}

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Log "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Log "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

function Start-ProcessKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    Kill-Process-And-Parent -Pid $_.ProcessId
                    Write-Log "Killed unsigned/hidden process: $exePath" "Warning"
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        try {
            $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
            $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
            $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

            foreach ($pid in $hidden) {
                try {
                    $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                    if ($proc) {
                        Kill-Process-And-Parent -Pid $pid.InputObject
                        Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                    }
                } catch {}
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
}

# New function: Start-ProcessKillerEnhanced (first provided Start-ProcessKiller)
function Start-ProcessKillerEnhanced {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Log "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}

# New function: Start-ProcessKillerBasic (second provided Start-ProcessKiller)
function Start-ProcessKillerBasic {
    $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
    foreach ($name in $badNames) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

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
                    Write-Log "XSS detected, blocked $($hostEntry.HostName) and disabled network." "Error"
                }
            } catch {}
        }
        Start-Sleep -Seconds 3
    }
}

function Kill-Listeners {
    $knownServices = @("svchost", "System", "lsass", "wininit") # Safe system processes
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -notin $knownServices) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore processes that no longer exist or access-denied
        }
    }
}

function Start-CrudeKiller {
    $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
    foreach ($name in $badNames) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )
    $targetPath = "%windir%\Setup\Scripts\unattend-04.ps1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Log "Failed to register task: $($_.Exception.Message)" "Error"
        exit 1
    }
}

function Apply-FirewallRules {
    # Write the registry content to a temporary file
    $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
    $script:registryContent | Out-File -FilePath $tempRegFile -Encoding Unicode

    # Import the registry file to apply the firewall rules
    try {
        reg import $tempRegFile 2>&1 | Out-Null
        Write-Host "Firewall rules applied from registry content at $(Get-Date)."
    } catch {
        Write-Host "Error applying firewall rules: $_"
    }

    # Clean up the temporary file
    Remove-Item $tempRegFile -Force -ErrorAction SilentlyContinue
}

function Start-FirewallMonitor {
    Write-Host "Starting firewall rule monitoring..."

    # Register WMI event for firewall rule changes
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4947"
    Register-WmiEvent -Query $query -SourceIdentifier "FirewallRuleChange" -Action {
        Write-Host "Detected firewall rule change at $(Get-Date)"
        Apply-FirewallRules
    }

    Write-Host "Firewall monitoring started. Running in background..."
}

# === Main Execution Logic ===
# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting..." -ForegroundColor Red
    exit
}

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

# Initialize environment (from CookieMonitor.ps1)
Initialize-Environment

# Setup script directory and copy script (from NetworkDebloat.ps1 and others)
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled tasks from all scripts
Register-SystemLogonScript -TaskName "RunGShieldAtLogon"
Install-Script

# Execute Audio.ps1 logic
Enable-AECAndNoiseSuppression

# Execute BCDCleanup.ps1 logic
$BackupPath = "C:\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bcd"
Write-Log "Creating BCD backup at $BackupPath"
try {
    & (Join-Path $env:windir "system32\bcdedit.exe") /export $BackupPath | Out-Null
    Write-Log "BCD backup created successfully."
} catch {
    Write-Log "Error creating BCD backup: $_"
    exit 1
}
$BcdOutput = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if (-not $BcdOutput) {
    Write-Log "Error: Failed to enumerate BCD entries."
    exit 1
}
$BcdEntries = @()
$currentEntry = $null
foreach ($line in $BcdOutput) {
    if ($line -match "^identifier\s+({[0-9a-fA-F-]{36}|{[^}]+})") {
        if ($currentEntry) {
            $BcdEntries += $currentEntry
        }
        $currentEntry = [PSCustomObject]@{
            Identifier = $Matches[1]
            Properties = @{}
        }
    } elseif ($line -match "^(\w+)\s+(.+)$") {
        if ($currentEntry) {
            $currentEntry.Properties[$Matches[1]] = $Matches[2]
        }
    }
}
if ($currentEntry) {
    $BcdEntries += $currentEntry
}
$CriticalIds = @("{bootmgr}", "{current}", "{default}")
$SuspiciousEntries = @()
foreach ($entry in $BcdEntries) {
    $isSuspicious = $false
    $reason = ""
    if ($entry.Identifier -in $CriticalIds) {
        continue
    }
    if ($entry.Properties.description -and $entry.Properties.description -notmatch "Windows") {
        $isSuspicious = $true
        $reason += "Non-Windows description: $($entry.Properties.description); "
    }
    if ($entry.Properties.device -match "vhd=") {
        $isSuspicious = $true
        $reason += "Uses VHD device: $($entry.Properties.device); "
    }
    if ($entry.Properties.path -and $entry.Properties.path -notmatch "winload.exe") {
        $isSuspicious = $true
        $reason += "Non-standard boot path: $($entry.Properties.path); "
    }
    if ($isSuspicious) {
        $SuspiciousEntries += [PSCustomObject]@{
            Identifier = $entry.Identifier
            Description = $entry.Properties.description
            Device = $entry.Properties.device
            Path = $entry.Properties.path
            Reason = $reason
        }
    }
}
if ($SuspiciousEntries.Count -eq 0) {
    Write-Log "No suspicious BCD entries found."
} else {
    Write-Log "Found $($SuspiciousEntries.Count) suspicious BCD entries:"
    foreach ($entry in $SuspiciousEntries) {
        Write-Log "Identifier: $($entry.Identifier)"
        Write-Log "Description: $($entry.Description)"
        Write-Log "Device: $($entry.Device)"
        Write-Log "Path: $($entry.Path)"
        Write-Log "Reason: $($entry.Reason)"
        Write-Log "------------------------"
        Write-Log "Deleting entry: $($entry.Identifier)"
        try {
            & (Join-Path $env:windir "system32\bcdedit.exe") /delete $entry.Identifier /f | Out-Null
            Write-Log "Successfully deleted entry: $($entry.Identifier)"
        } catch {
            Write-Log "Error deleting entry $($entry.Identifier): $_"
        }
    }
}
$BcdOutputAfter = & (Join-Path $env:windir "system32\bcdedit.exe") /enum all
if ($BcdOutputAfter) {
    $BcdOutputAfter | Out-File -FilePath $LogFile -Append
    Write-Log "Cleanup complete. Review the log at $LogFile for details."
    Write-Log "BCD backup is available at $BackupPath if restoration is needed."
} else {
    Write-Log "Error: Failed to verify BCD store after cleanup."
}

# Execute CookieMonitor.ps1 logic
Backup-Cookies
Monitor-Cookies

# Execute Corrupt.ps1 logic
$CorruptTelemetry = {
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "$env:ProgramData\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
        "$env:LocalAppData\Microsoft\Edge\User Data\Default\Preferences",
        "$env:ProgramData\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
        "$env:ProgramFiles\NVIDIA Corporation\NvContainer\NvContainerTelemetry.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Local Storage\leveldb\*.log",
        "$env:LocalAppData\Google\Chrome\User Data\EventLog\*.etl",
        "$env:LocalAppData\Google\Chrome\User Data\Default\Web Data",
        "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.log",
        "$env:ProgramData\Adobe\ARM\log\ARMTelemetry.etl",
        "$env:LocalAppData\Adobe\Creative Cloud\ACC\logs\CoreSync.log",
        "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp.log",
        "$env:ProgramData\Intel\Telemetry\IntelData.etl",
        "$env:ProgramFiles\Intel\Driver Store\Telemetry\IntelGFX.etl",
        "$env:SystemRoot\System32\DriverStore\FileRepository\igdlh64.inf_amd64_*\IntelCPUTelemetry.dat",
        "$env:ProgramData\AMD\CN\AMDDiag.etl",
        "$env:LocalAppData\AMD\CN\logs\RadeonSoftware.log",
        "$env:ProgramFiles\AMD\CNext\CNext\AMDTel.db",
        "$env:ProgramFiles(x86)\Steam\logs\perf.log",
        "$env:LocalAppData\Steam\htmlcache\Cookies",
        "$env:ProgramData\Steam\SteamAnalytics.etl",
        "$env:ProgramData\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
        "$env:LocalAppData\EpicGamesLauncher\Saved\Logs\EpicGamesLauncher.log",
        "$env:LocalAppData\Discord\app-*\modules\discord_analytics\*.log",
        "$env:AppData\Discord\Local Storage\leveldb\*.ldb",
        "$env:LocalAppData\Autodesk\Autodesk Desktop App\Logs\AdskDesktopAnalytics.log",
        "$env:ProgramData\Autodesk\Adlm\Telemetry\AdlmTelemetry.etl",
        "$env:AppData\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
        "$env:LocalAppData\Mozilla\Firefox\Telemetry\Telemetry.etl",
        "$env:LocalAppData\Logitech\LogiOptions\logs\LogiAnalytics.log",
        "$env:ProgramData\Logitech\LogiSync\Telemetry.etl",
        "$env:ProgramData\Razer\Synapse3\Logs\RazerSynapse.log",
        "$env:LocalAppData\Razer\Synapse\Telemetry\RazerTelemetry.etl",
        "$env:ProgramData\Corsair\CUE\logs\iCUETelemetry.log",
        "$env:LocalAppData\Corsair\iCUE\Analytics\*.etl",
        "$env:ProgramData\Kaspersky Lab\AVP*\logs\Telemetry.etl",
        "$env:ProgramData\McAfee\Agent\logs\McTelemetry.log",
        "$env:ProgramData\Norton\Norton\Logs\NortonAnalytics.etl",
        "$env:ProgramFiles\Bitdefender\Bitdefender Security\logs\BDTelemetry.db",
        "$env:LocalAppData\Slack\logs\SlackAnalytics.log",
        "$env:ProgramData\Dropbox\client\logs\DropboxTelemetry.etl",
        "$env:LocalAppData\Zoom\logs\ZoomAnalytics.log"
    )

    while ($true) {
        $StartTime = Get-Date
        
        foreach ($File in $TargetFiles) {
            if ($File -match '\*') {
                Get-Item -Path $File -ErrorAction SilentlyContinue | ForEach-Object {
                    Overwrite-File -FilePath $_.FullName
                }
            } else {
                Overwrite-File -FilePath $File
            }
        }

        $ElapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
        $SleepSeconds = [math]::Max(3600 - $ElapsedSeconds, 0)
        Write-Host "Completed run at $(Get-Date). Sleeping for ${SleepSeconds} seconds until next hour..."
        Start-Sleep -Seconds $SleepSeconds
    }
}
Start-Job -ScriptBlock $CorruptTelemetry

# Execute DevicesFiltering.ps1 logic
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$setAclPath = Join-Path $scriptDir "SetACL.exe"
if (-not (Test-Path $setAclPath)) {
    Write-Error "SetACL.exe not found in the script's folder: $scriptDir"
    exit 1
}
Write-Host "Listing all devices..."
$devices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -ne $null } | Select-Object Name, DeviceID
$devices | Format-Table -AutoSize
$consoleLogonGroup = "S-1-2-1"
foreach ($device in $devices) {
    $deviceId = $device.DeviceID
    Write-Host "Setting permissions for device: $($device.Name) ($deviceId)"
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np" -ace "n:$consoleLogonGroup;p:full"
    & $setAclPath -on $deviceId -ot reg -actn setprot -op "dacl:np"
    & $setAclPath -on $deviceId -ot reg -actn rstchldrn -rst "dacl,sacl"
    Write-Host "Permissions updated for $deviceId"
}
Write-Host "Permissions update completed for all devices."

# Execute NetworkDebloat.ps1 logic
$componentsToDisable = @(
    "ms_server",     # File and Printer Sharing
    "ms_msclient",   # Client for Microsoft Networks
    "ms_pacer",      # QoS Packet Scheduler
    "ms_lltdio",     # Link Layer Mapper I/O Driver
    "ms_rspndr",     # Link Layer Responder
    "ms_tcpip6"      # IPv6
)
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    foreach ($component in $componentsToDisable) {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
    }
}
$ldapPorts = @(389, 636)
foreach ($port in $ldapPorts) {
    New-NetFirewallRule -DisplayName "Block LDAP Port $port" -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction SilentlyContinue
}

# Execute SecureRemoteAccess.ps1 logic
Write-Host "Starting Windows Remote Access Security Hardening..." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
Write-Host "Remote Desktop and Remote Assistance disabled."
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block VNC Inbound" -Direction Inbound -Protocol TCP -LocalPort 5900-5902 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block TeamViewer Inbound" -Direction Inbound -Protocol TCP -LocalPort 5938 -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block AnyDesk Inbound" -Direction Inbound -Protocol TCP -LocalPort 7070 -Action Block -Enabled True
Write-Host "Firewall rules added to block RDP, VNC, TeamViewer, and AnyDesk ports."
$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $gpPath)) {
    New-Item -Path $gpPath -Force | Out-Null
}
Set-ItemProperty -Path $gpPath -Name "fDenyTSConnections" -Value 1
Write-Host "Group Policy updated to disable Remote Desktop Services."
$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($adminAccount) {
    Disable-LocalUser -Name "Administrator"
    Write-Host "Default Administrator account disabled."
} else {
    Write-Host "Default Administrator account not found or already disabled."
}
$restrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $restrictPath)) {
    New-Item -Path $restrictPath -Force | Out-Null
}
$blockedApps = "TeamViewer.exe,AnyDesk.exe"
Set-ItemProperty -Path $restrictPath -Name "DisallowRun" -Value 1
New-Item -Path "$restrictPath\DisallowRun" -Force | Out-Null
$blockedApps.Split(",") | ForEach-Object { Set-ItemProperty -Path "$restrictPath\DisallowRun" -Name $_ -Value $_ }
Write-Host "Group Policy updated to block specified remote access software."
Set-Service -Name "SSDPSRV" -StartupType Disabled
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Write-Host "UPnP service disabled."
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "Windows Defender real-time protection enabled."
$rdpPort = netstat -an | Select-String "3389"
if ($rdpPort) {
    Write-Host "WARNING: Port 3389 is still listening. Please check firewall and service settings manually." -ForegroundColor Yellow
} else {
    Write-Host "RDP port 3389 is not listening."
}

# Execute GSecurity.ps1 logic
Apply-FirewallRules
Enable-LsassPPL
Clear-CachedCredentials
Disable-CredentialCaching
Enable-CredentialAuditing
Write-Log "Initial scan completed. Monitoring started."
Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
Write-Host "Check Event Viewer (Security logs) for credential access auditing."

# Start monitoring job with all process killer functions
Start-Job -Name "GShield-Monitor" -ScriptBlock {
    while ($true) {
        Start-FirewallMonitor
        Start-CrudeKiller
        Start-ProcessKillerBasic  # Call the new basic process killer
        Kill-Listeners
        Start-ProcessKiller
        Start-ProcessKillerEnhanced  # Call the new enhanced process killer
        Start-XSSWatcher
        Terminate-NonConsoleSessions
        Terminate-Rootkits
        Start-Sleep -Seconds 10
    }
}