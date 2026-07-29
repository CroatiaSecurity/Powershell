# Stop and disable optional network services
$services = @(
    "LanmanServer",   # File and printer sharing (port 445)
    "RpcSs",          # RPC (port 135) - not recommended
    "IKEEXT",         # IPsec/IKE (UDP 500,4500)
    "Dnscache",       # DNS Client
    "FDResPub",       # Function Discovery
    "SSDPSRV",        # SSDP discovery
    "upnphost"        # UPnP host
)

foreach ($svc in $services) {
    Stop-Service -Name $svc -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
