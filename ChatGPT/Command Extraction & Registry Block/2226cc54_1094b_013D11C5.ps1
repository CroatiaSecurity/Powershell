$FilterName = "BlockReconCommands"
$ConsumerName = "KillBadCommands"

# Create filter
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $FilterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM Win32_ProcessStartTrace"
}

# Command filter logic
$script = @'
$cmd = $Event.SourceEventArgs.NewEvent.CommandLine

$bad = @(
    "nmap",
    "gobuster",
    "enum4linux",
    "rpcclient",
    "smbclient",
    "-sC -sV",
    "-p-",
    "--top-ports",
    "whoami /all",
    "wmic service get"
)

foreach ($b in $bad) {
    if ($cmd -like "*$b*") {
        Stop-Process -Id $Event.SourceEventArgs.NewEvent.ProcessID -Force
    }
}
'@

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $ConsumerName
    CommandLineTemplate = "powershell -NoProfile -ExecutionPolicy Bypass -Command $script"
}

# Bind them
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
