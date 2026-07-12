# IPSecPolicy.ps1
# Author: Gorstak (gorstak.eu)
# Description: Creates and assigns a legacy IPsec policy (visible in secpol.msc) that blocks
#              inbound and outbound traffic on dangerous, unnecessary, and commonly-exploited ports.
#              Supports TCP, UDP, or both per service. Idempotent - safe to run repeatedly.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "IPSecPolicySetup"
$Script:InstallDir = "$env:ProgramData\IPSecPolicy"
$Script:ScriptName = "IPSecPolicy.ps1"

# ─────────────────────────────────────────────────────────────────────────────
# Persistence (Scheduled Task)
# ─────────────────────────────────────────────────────────────────────────────

function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "IPSec Policy Setup (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONSTART /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] IPSecPolicy uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence; exit 0 }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

# ─────────────────────────────────────────────────────────────────────────────
# OS Compatibility Check
# ─────────────────────────────────────────────────────────────────────────────

$os = Get-CimInstance Win32_OperatingSystem
$edition = $os.Caption
if ($edition -match "Home") {
    Write-Host "[WARNING] Windows Home editions have limited IPsec support." -ForegroundColor Yellow
    Write-Host "          This script may not work correctly. Pro/Enterprise/Server recommended." -ForegroundColor Yellow
}

# Verify netsh ipsec is available
$testNetsh = netsh ipsec static show policy all 2>&1
if ($LASTEXITCODE -ne 0 -and "$testNetsh" -match "not recognized|not found") {
    Write-Host "[ERROR] netsh ipsec is not available on this system." -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Port Definitions (structured table)
# Protocol: TCP, UDP, or TCPUDP (both)
# ─────────────────────────────────────────────────────────────────────────────

$PortDefinitions = @(
    # ── Legacy / File Transfer ──
    @{ Port = 21;    Name = "FTP";              Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 69;    Name = "TFTP";             Protocol = "UDP";    Category = "Legacy" }
    @{ Port = 111;   Name = "RPCBind";          Protocol = "TCPUDP"; Category = "Legacy" }
    @{ Port = 512;   Name = "rexec";            Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 513;   Name = "rlogin";           Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 514;   Name = "rsh";              Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 548;   Name = "AFP";              Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 873;   Name = "rsync";            Protocol = "TCP";    Category = "Legacy" }
    @{ Port = 2049;  Name = "NFS";              Protocol = "TCPUDP"; Category = "Legacy" }

    # ── Remote Access ──
    @{ Port = 22;    Name = "SSH";              Protocol = "TCP";    Category = "Remote Access" }
    @{ Port = 23;    Name = "Telnet";           Protocol = "TCP";    Category = "Remote Access" }
    @{ Port = 3389;  Name = "RDP";              Protocol = "TCPUDP"; Category = "Remote Access" }
    @{ Port = 5900;  Name = "VNC";              Protocol = "TCP";    Category = "Remote Access" }
    @{ Port = 5985;  Name = "WinRM_HTTP";       Protocol = "TCP";    Category = "Remote Access" }
    @{ Port = 5986;  Name = "WinRM_HTTPS";      Protocol = "TCP";    Category = "Remote Access" }

    # ── Windows Services ──
    @{ Port = 135;   Name = "RPC_DCOM";         Protocol = "TCPUDP"; Category = "Windows Services" }
    @{ Port = 137;   Name = "NetBIOS_NS";       Protocol = "TCPUDP"; Category = "Windows Services" }
    @{ Port = 138;   Name = "NetBIOS_DGM";      Protocol = "UDP";    Category = "Windows Services" }
    @{ Port = 139;   Name = "NetBIOS_SSN";      Protocol = "TCP";    Category = "Windows Services" }
    @{ Port = 445;   Name = "SMB";              Protocol = "TCP";    Category = "Windows Services" }

    # ── Discovery / Name Resolution ──
    # NOTE: DNS (53) intentionally NOT blocked — required for internet browsing
    @{ Port = 1900;  Name = "SSDP";             Protocol = "UDP";    Category = "Discovery" }
    @{ Port = 2869;  Name = "UPnP";             Protocol = "TCP";    Category = "Discovery" }
    @{ Port = 5353;  Name = "mDNS";             Protocol = "UDP";    Category = "Discovery" }
    @{ Port = 5355;  Name = "LLMNR";            Protocol = "UDP";    Category = "Discovery" }

    # ── Directory / LDAP ──
    @{ Port = 389;   Name = "LDAP";             Protocol = "TCPUDP"; Category = "Directory" }
    @{ Port = 636;   Name = "LDAPS";            Protocol = "TCP";    Category = "Directory" }

    # ── SNMP ──
    @{ Port = 161;   Name = "SNMP";             Protocol = "UDP";    Category = "SNMP" }
    @{ Port = 162;   Name = "SNMP_Trap";        Protocol = "UDP";    Category = "SNMP" }

    # ── Databases ──
    @{ Port = 1433;  Name = "MSSQL";            Protocol = "TCP";    Category = "Databases" }
    @{ Port = 1434;  Name = "MSSQL_Browser";    Protocol = "UDP";    Category = "Databases" }
    @{ Port = 1521;  Name = "OracleDB";         Protocol = "TCP";    Category = "Databases" }
    @{ Port = 3306;  Name = "MySQL";            Protocol = "TCP";    Category = "Databases" }
    @{ Port = 5432;  Name = "PostgreSQL";       Protocol = "TCP";    Category = "Databases" }
    @{ Port = 6379;  Name = "Redis";            Protocol = "TCP";    Category = "Databases" }
    @{ Port = 9042;  Name = "Cassandra";        Protocol = "TCP";    Category = "Databases" }
    @{ Port = 9200;  Name = "Elasticsearch";    Protocol = "TCP";    Category = "Databases" }
    @{ Port = 11211; Name = "Memcached";        Protocol = "TCPUDP"; Category = "Databases" }
    @{ Port = 27017; Name = "MongoDB";          Protocol = "TCP";    Category = "Databases" }

    # ── Container / DevOps ──
    @{ Port = 2375;  Name = "Docker_Unenc";     Protocol = "TCP";    Category = "Container/DevOps" }
    @{ Port = 2376;  Name = "Docker_TLS";       Protocol = "TCP";    Category = "Container/DevOps" }
    @{ Port = 5000;  Name = "DockerRegistry";   Protocol = "TCP";    Category = "Container/DevOps" }
    @{ Port = 8291;  Name = "MikroTik_Winbox";  Protocol = "TCP";    Category = "Container/DevOps" }
    @{ Port = 9090;  Name = "Prometheus";       Protocol = "TCP";    Category = "Container/DevOps" }
    @{ Port = 50070; Name = "Hadoop_HDFS";      Protocol = "TCP";    Category = "Container/DevOps" }

    # ── Management / RCE vectors ──
    @{ Port = 1099;  Name = "Java_RMI";         Protocol = "TCP";    Category = "Management" }
    @{ Port = 5601;  Name = "Kibana";           Protocol = "TCP";    Category = "Management" }
    @{ Port = 8888;  Name = "Jupyter";          Protocol = "TCP";    Category = "Management" }

    # ── Proxies ──
    @{ Port = 1080;  Name = "SOCKS";            Protocol = "TCP";    Category = "Proxies" }
    # NOTE: 8080/8443 intentionally NOT blocked — used by many legitimate web services

    # ── Known Malware / Backdoors ──
    @{ Port = 666;   Name = "Trojan_666";       Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 1234;  Name = "RAT_1234";         Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 1337;  Name = "Backdoor_1337";    Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 4444;  Name = "Meterpreter_4444"; Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 5555;  Name = "Android_ADB";      Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 6666;  Name = "IRC_Backdoor";     Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 6667;  Name = "IRC_C2";           Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 7777;  Name = "Backdoor_7777";    Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 12345; Name = "NetBus";           Protocol = "TCP";    Category = "Malware Ports" }
    @{ Port = 31337; Name = "BackOrifice";      Protocol = "TCPUDP"; Category = "Malware Ports" }
    @{ Port = 54321; Name = "BackOrifice2K";    Protocol = "TCP";    Category = "Malware Ports" }
)

# Sort by port number
$PortDefinitions = $PortDefinitions | Sort-Object { $_.Port }

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Run netsh with error checking
# ─────────────────────────────────────────────────────────────────────────────

$Script:ErrorCount = 0

function Invoke-Netsh {
    param(
        [string]$Arguments,
        [switch]$SilentFail
    )
    $result = cmd /c "netsh $Arguments 2>&1"
    if ($LASTEXITCODE -ne 0 -and -not $SilentFail) {
        $Script:ErrorCount++
        Write-Host "  [WARN] netsh $Arguments" -ForegroundColor Yellow
        Write-Host "         $result" -ForegroundColor DarkYellow
    }
    return $result
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup: Remove existing policy, rules, filter lists, and filter actions
# ─────────────────────────────────────────────────────────────────────────────

$policyName = "GSecurity"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " GSecurity IPsec Policy Builder" -ForegroundColor Cyan
Write-Host " Gorstak (gorstak.eu)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[1/5] Cleaning up previous policy objects..." -ForegroundColor White

# Delete the policy (this also removes rule associations)
Invoke-Netsh "ipsec static delete policy name=$policyName" -SilentFail

# Delete all filter lists and filter actions we may have created
foreach ($def in $PortDefinitions) {
    $name = $def.Name
    foreach ($dir in @("Inbound", "Outbound")) {
        foreach ($proto in @("TCP", "UDP")) {
            Invoke-Netsh "ipsec static delete filterlist name=${dir}_${name}_${proto}" -SilentFail
        }
    }
}

# Delete filter actions
Invoke-Netsh "ipsec static delete filteraction name=BlockAction" -SilentFail
# Remove the old unused PermitAction if it exists from previous runs
Invoke-Netsh "ipsec static delete filteraction name=PermitAction" -SilentFail

Write-Host "  Cleanup complete." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Create Policy and Filter Action
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "[2/5] Creating policy and filter action..." -ForegroundColor White

$totalPorts = $PortDefinitions.Count
$description = "Blocks $totalPorts dangerous/unnecessary ports (TCP/UDP). Managed by Gorstak IPSecPolicy.ps1"

Invoke-Netsh "ipsec static add policy name=$policyName description=`"$description`" assign=yes"
Invoke-Netsh "ipsec static add filteraction name=BlockAction action=block description=`"Block traffic`""

Write-Host "  Policy '$policyName' created." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Create Filter Lists, Filters, and Rules
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "[3/5] Creating filter lists and rules..." -ForegroundColor White

$currentCategory = ""
$counter = 0
$totalFilters = 0

# Count total filters for progress
foreach ($def in $PortDefinitions) {
    $protocols = if ($def.Protocol -eq "TCPUDP") { @("TCP", "UDP") } else { @($def.Protocol) }
    $totalFilters += ($protocols.Count * 2)  # inbound + outbound per protocol
}

foreach ($def in $PortDefinitions) {
    $port = $def.Port
    $name = $def.Name
    $category = $def.Category

    # Print category header when it changes
    if ($category -ne $currentCategory) {
        $currentCategory = $category
        Write-Host ""
        Write-Host "  ── $category ──" -ForegroundColor DarkCyan
    }

    # Determine which protocols to block
    $protocols = if ($def.Protocol -eq "TCPUDP") { @("TCP", "UDP") } else { @($def.Protocol) }

    foreach ($proto in $protocols) {
        foreach ($direction in @("Inbound", "Outbound")) {
            $counter++
            $filterListName = "${direction}_${name}_${proto}"
            $ruleName = "Block_${direction}_${name}_${proto}"

            # Determine src/dst based on direction
            if ($direction -eq "Inbound") {
                $src = "Any"; $dst = "Me"
            } else {
                $src = "Me"; $dst = "Any"
            }

            # Create filter list
            Invoke-Netsh "ipsec static add filterlist name=$filterListName description=`"$direction $name port $port ($proto)`""

            # Create filter (mirrored=no because we handle directions explicitly)
            Invoke-Netsh "ipsec static add filter filterlist=$filterListName srcaddr=$src dstaddr=$dst protocol=$proto dstport=$port mirrored=no"

            # Create rule linking filter list to block action
            Invoke-Netsh "ipsec static add rule name=$ruleName policy=$policyName filterlist=$filterListName filteraction=BlockAction"
        }
    }

    # Progress indicator per port
    $pctPort = [math]::Round(($PortDefinitions.IndexOf($def) + 1) / $totalPorts * 100)
    Write-Host "  [$counter/$totalFilters] $name (port $port, $($def.Protocol)) " -NoNewline
    Write-Host "OK" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Assign Policy
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[4/5] Assigning policy..." -ForegroundColor White
Invoke-Netsh "ipsec static set policy name=$policyName assign=yes"
Write-Host "  Policy assigned." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[5/5] Summary" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Policy:       $policyName" -ForegroundColor White
Write-Host " Total ports:  $totalPorts" -ForegroundColor White
Write-Host " Total rules:  $totalFilters (inbound + outbound, TCP + UDP)" -ForegroundColor White
Write-Host " Errors:       $($Script:ErrorCount)" -ForegroundColor $(if ($Script:ErrorCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Print blocked ports grouped by category
$grouped = $PortDefinitions | Group-Object { $_.Category }
foreach ($group in $grouped) {
    Write-Host " $($group.Name):" -ForegroundColor DarkCyan
    foreach ($item in $group.Group) {
        $protoLabel = switch ($item.Protocol) {
            "TCPUDP" { "TCP+UDP" }
            default   { $item.Protocol }
        }
        Write-Host "   $($item.Port.ToString().PadRight(6)) $($item.Name.PadRight(20)) $protoLabel"
    }
}

Write-Host ""
Write-Host "View in: secpol.msc -> IP Security Policies on Local Computer" -ForegroundColor Gray

if ($Script:ErrorCount -gt 0) {
    Write-Host ""
    Write-Host "[!] $($Script:ErrorCount) warnings occurred. Review output above." -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "--- Verification ---" -ForegroundColor Gray
netsh ipsec static show policy name=$policyName
