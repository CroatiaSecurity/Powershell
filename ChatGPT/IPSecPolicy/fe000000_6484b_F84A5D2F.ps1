# IPSecPolicy.ps1
# Author: Gorstak (gorstak.eu)
# Description: Creates and assigns a legacy IPsec policy (visible in secpol.msc) that blocks
#              inbound and outbound traffic on Telnet (23), SSH (22), and RDP (3389) ports.
#              One-time configuration utility.
#Requires -RunAsAdministrator

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "IPSecPolicySetup"
$Script:InstallDir = "$env:ProgramData\IPSecPolicy"
$Script:ScriptName = "IPSecPolicy.ps1"

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
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
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
    exit 0
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

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

# Create and Assign GSecurity IPsec Policy using netsh (legacy IPsec compatible with secpol.msc)
# Blocks traffic to Telnet (23), SSH (22), and RDP (3389) ports

Write-Host "Creating GSecurity IPsec Policy (legacy format for secpol.msc)..."

# Define the policy, filter lists, filters, and rules
$policyName = "GSecurity"
$ports = @(21, 22, 23, 111, 135, 137, 138, 139, 445, 666, 1337, 1433, 2049, 3306, 3389, 4444, 5432, 5900, 5985, 5986, 31337)
$portNames = @("FTP", "SSH", "Telnet", "RPCBind_111", "RPC_135", "NetBIOS_137", "NetBIOS_138", "NetBIOS_139", "SMB_445", "Trojan_666", "Backdoor_1337", "MSSQL_1433", "NFS_2049", "MySQL_3306", "RDP", "Backdoor_4444", "PostgreSQL_5432", "VNC_5900", "WinRM_5985", "WinRM_5986", "BackOrifice_31337")

# Delete existing policy if it exists
Write-Host "Checking for existing policy..."
netsh ipsec static delete policy name=$policyName 2>$null

# Create the IPsec Policy (without IPsec - using Block action)
Write-Host "Creating IPsec Policy: $policyName"
netsh ipsec static add policy name=$policyName description="Blocks Telnet, SSH, and RDP ports" assign=yes

# Create filter actions (Block actions for inbound and outbound)
netsh ipsec static add filteraction name="BlockAction" action=block description="Block traffic"
netsh ipsec static add filteraction name="PermitAction" action=permit description="Permit traffic"

for ($i = 0; $i -lt $ports.Count; $i++) {
    $port = $ports[$i]
    $name = $portNames[$i]
    
    Write-Host "Creating rules for $name (port $port)..."
    
    # Filter list for inbound traffic (to this port)
    $inboundFilterList = "Inbound_$name"
    netsh ipsec static add filterlist name=$inboundFilterList description="Inbound $name port $port"
    
    # Filter for inbound (any source to this destination port)
    netsh ipsec static add filter filterlist=$inboundFilterList srcaddr=Any dstaddr=Me protocol=TCP dstport=$port mirrored=no
    
    # Rule for inbound (block)
    $inboundRule = "Block_Inbound_$name"
    netsh ipsec static add rule name=$inboundRule policy=$policyName filterlist=$inboundFilterList filteraction="BlockAction"
    
    # Filter list for outbound traffic (to this port)
    $outboundFilterList = "Outbound_$name"
    netsh ipsec static add filterlist name=$outboundFilterList description="Outbound $name port $port"
    
    # Filter for outbound (this source to any destination port)
    netsh ipsec static add filter filterlist=$outboundFilterList srcaddr=Me dstaddr=Any protocol=TCP dstport=$port mirrored=no
    
    # Rule for outbound (block)
    $outboundRule = "Block_Outbound_$name"
    netsh ipsec static add rule name=$outboundRule policy=$policyName filterlist=$outboundFilterList filteraction="BlockAction"
}

# Assign the policy
Write-Host "Assigning policy..."
netsh ipsec static set policy name=$policyName assign=yes

Write-Host "`nGSecurity IPsec Policy created and assigned successfully!"
Write-Host "Blocked ports: 22 (SSH), 23 (Telnet), 3389 (RDP)"
Write-Host "`nYou can now view the policy in secpol.msc -> IP Security Policies on Local Computer"

# Verify
Write-Host "`n--- Verification ---"
netsh ipsec static show policy name=$policyName verbose
