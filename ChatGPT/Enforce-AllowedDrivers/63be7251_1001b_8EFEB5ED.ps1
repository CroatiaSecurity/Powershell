function Enforce-AllowedDrivers {
    param (
        [string[]]$AllowedVendors = @(
            "Microsoft",
            "Realtek",
            "Dolby",
            "Intel",
            "Advanced Micro Devices", # AMD full name
            "NVIDIA",
            "MediaTek"
        )
    )

    Write-Host "Scanning installed drivers..." -ForegroundColor Cyan

    # Get driver info
    $drivers = Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion

    foreach ($driver in $drivers) {
        $vendor = $driver.DriverProviderName

        if ($vendor -notin $AllowedVendors) {
            Write-Warning "Unauthorized driver detected: $($driver.DeviceName) | Vendor: $vendor | Version: $($driver.DriverVersion)"

            # Uncomment this if you want to actually uninstall the driver
            # pnputil /delete-driver $driver.InfName /uninstall /force
        }
    }

    Write-Host "Driver scan completed." -ForegroundColor Green
}
