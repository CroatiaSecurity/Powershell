function Enforce-AllowedDrivers {
    param (
        [string[]]$AllowedVendors = @(
            "Microsoft",
            "Realtek",
            "Dolby",
            "Intel",
            "Advanced Micro Devices", # AMD full name
            "AMD",
            "NVIDIA",
            "MediaTek"
        )
    )

    Write-Host "Starting driver enforcement monitor..." -ForegroundColor Cyan

    Start-Job -ScriptBlock {
        param($Vendors)

        while ($true) {
            try {
                # Get driver info (include InfName for pnputil)
                $drivers = Get-WmiObject Win32_PnPSignedDriver |
                           Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion, InfName

                foreach ($driver in $drivers) {
                    $vendor = $driver.DriverProviderName

                    if ($vendor -notin $Vendors) {
                        Write-Warning "Unauthorized driver detected: $($driver.DeviceName) | Vendor: $vendor | Version: $($driver.DriverVersion)"

                        # Force delete driver package
                        try {
                            pnputil /delete-driver $driver.InfName /uninstall /force | Out-Null
                            Write-Host "Removed driver $($driver.InfName)" -ForegroundColor Yellow
                        } catch {
                            Write-Warning "Failed to remove driver $($driver.InfName)"
                        }
                    }
                }
            } catch {
                Write-Warning "Error during driver scan: $_"
            }

            # Sleep 60 seconds before next scan (adjust as needed)
            Start-Sleep -Seconds 60
        }
    } -ArgumentList ($AllowedVendors)
}
