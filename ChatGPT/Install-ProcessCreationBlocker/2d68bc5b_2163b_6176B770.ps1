function Install-ProcessCreationBlocker {
    $FilterName   = "GShield_ProcessStart_Filter"
    $ConsumerName = "GShield_ProcessStart_Consumer"

    # Fetch existing objects (if any)
    $ExistingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter `
        -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue

    $ExistingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer `
        -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue

    $ExistingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding `
        -ErrorAction SilentlyContinue | Where-Object {
            $_.Filter -match $FilterName -and $_.Consumer -match $ConsumerName
        }

    # If everything exists, do nothing (idempotent)
    if ($ExistingFilter -and $ExistingConsumer -and $ExistingBinding) {
        return
    }

    # Cleanup orphaned bindings first (important)
    if ($ExistingBinding) {
        $ExistingBinding | Remove-WmiObject -ErrorAction SilentlyContinue
    }

    if ($ExistingFilter) {
        $ExistingFilter | Remove-WmiObject -ErrorAction SilentlyContinue
    }

    if ($ExistingConsumer) {
        $ExistingConsumer | Remove-WmiObject -ErrorAction SilentlyContinue
    }

    # Create filter
    $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name           = $FilterName
        EventNamespace = "root\cimv2"
        QueryLanguage  = "WQL"
        Query          = "SELECT * FROM Win32_ProcessStartTrace"
    }

    # Create consumer
    $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name = $ConsumerName
        CommandLineTemplate =
            'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& { $p = Get-Process -Id %ProcessID% -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id $p.Id -Force } }"'
    }

    # Bind filter to consumer
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $Filter
        Consumer = $Consumer
    }
}
