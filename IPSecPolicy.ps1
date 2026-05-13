# Create and Assign GSecurity IPsec Policy using netsh (legacy IPsec compatible with secpol.msc)
# Blocks traffic to Telnet (23), SSH (22), and RDP (3389) ports

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Creating GSecurity IPsec Policy (legacy format for secpol.msc)..."

# Define the policy, filter lists, filters, and rules
$policyName = "GSecurity"
$ports = @(22, 23, 3389)
$portNames = @("SSH", "Telnet", "RDP")

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
