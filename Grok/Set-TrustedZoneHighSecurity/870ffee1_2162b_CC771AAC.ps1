
# Set-TrustedZoneHighSecurity.ps1
# Configures Windows Firewall to mimic ZoneAlarm's Trusted Zone High security setting
# Run as Administrator

# 1. Ensure the network is set to Private (trusted)
$network = Get-NetConnectionProfile
if ($network) {
    foreach ($net in $network) {
        if ($net.NetworkCategory -ne "Private") {
            Write-Host "Setting network '$($net.Name)' to Private profile"
            Set-NetConnectionProfile -InterfaceIndex $net.InterfaceIndex -NetworkCategory Private
        } else {
            Write-Host "Network '$($net.Name)' is already set to Private"
        }
    }
} else {
    Write-Warning "No network profiles found. Ensure you're connected to a network."
}

# 2. Set Private profile to block all inbound traffic by default
Write-Host "Configuring Private profile to block inbound traffic by default"
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# 3. Block NetBIOS and SMB (ports 137-139, 445) for Private profile
Write-Host "Creating firewall rules to block NetBIOS and SMB"
New-NetFirewallRule -DisplayName "Block NetBIOS TCP Private" -Direction Inbound -Profile Private -Action Block -Protocol TCP -LocalPort 137-139,445 -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block NetBIOS UDP Private" -Direction Inbound -Profile Private -Action Block -Protocol UDP -LocalPort 137-138 -ErrorAction SilentlyContinue

# 4. Block ICMP (ping) for stealth mode in Private profile
Write-Host "Creating firewall rule to block ICMP (ping)"
New-NetFirewallRule -DisplayName "Block ICMP Private" -Direction Inbound -Profile Private -Action Block -Protocol ICMPv4 -IcmpType 8 -ErrorAction SilentlyContinue

# 5. Allow specific trusted traffic (e.g., HTTP on port 80)
# Uncomment and modify the following line to allow specific ports or protocols
# New-NetFirewallRule -DisplayName "Allow HTTP Private" -Direction Inbound -Profile Private -Action Allow -Protocol TCP -LocalPort 80 -ErrorAction SilentlyContinue

Write-Host "Configuration complete. Private network now has High security settings."
Write-Host "Verify with: ping, file sharing, or netstat -an"
