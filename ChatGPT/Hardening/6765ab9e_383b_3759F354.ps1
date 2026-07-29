# Block all inbound listener ports shown in netstat
$ports = 135,445,500,4500,5353,49349,63422,65141

foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "Block Port $port" `
        -Direction Inbound `
        -LocalPort $port `
        -Protocol TCP,UDP `
        -Action Block `
        -Profile Any `
        -Description "Disabled by Gorstak security hardening"
}
