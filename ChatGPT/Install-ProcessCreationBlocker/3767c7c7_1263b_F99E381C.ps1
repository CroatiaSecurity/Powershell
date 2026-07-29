function Install-ProcessCreationBlocker {
    $FilterName   = "GShield_ProcessStart_Filter"
    $ConsumerName = "GShield_ProcessStart_Consumer"

    # Remove old instances
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue | Remove-WmiObject

    $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name = $FilterName
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM Win32_ProcessStartTrace"
    }

    $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name = $ConsumerName
        CommandLineTemplate = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { `$p = Get-Process -Id %ProcessID% -ErrorAction SilentlyContinue; if (`$p) { Stop-Process -Id `$p.Id -Force } }`""
    }

    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $Filter
        Consumer = $Consumer
    }
}
