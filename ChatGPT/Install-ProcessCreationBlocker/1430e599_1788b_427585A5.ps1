function Install-ProcessCreationBlocker {
    $FilterName   = "GShield_ProcessStart_Filter"
    $ConsumerName = "GShield_ProcessStart_Consumer"

    # Remove old instances (if any)
    Get-WmiObject -Namespace root\subscription -Class __EventFilter `
        -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue |
        Remove-WmiObject -ErrorAction SilentlyContinue

    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer `
        -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue |
        Remove-WmiObject -ErrorAction SilentlyContinue

    # Create fresh filter
    $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name = $FilterName
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM Win32_ProcessStartTrace"
    }

    # Create fresh consumer (kills newly created processes)
    $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name = $ConsumerName
        CommandLineTemplate = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { `$p = Get-Process -Id %ProcessID% -ErrorAction SilentlyContinue; if (`$p) { Stop-Process -Id `$p.Id -Force } }`""
    }

    # Check whether the binding already exists
    $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding `
        -Filter "Filter=""__EventFilter.Name='$FilterName'""" -ErrorAction SilentlyContinue

    # Only create binding if missing
    if (-not $existingBinding) {
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter   = $Filter
            Consumer = $Consumer
        }
    }
}
