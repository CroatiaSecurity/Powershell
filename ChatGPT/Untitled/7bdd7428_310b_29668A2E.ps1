# Delete all PersistentRoutes entries
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" -Name * -ErrorAction SilentlyContinue

# Reboot afterwards to clear them from active routing table
Write-Host "All persistent routes deleted. Please reboot your system."
