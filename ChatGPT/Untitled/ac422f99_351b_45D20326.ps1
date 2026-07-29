$existingBinding = Get-WmiObject -Namespace root\subscription `
    -Class __FilterToConsumerBinding `
    -Filter "Filter=""__EventFilter.Name='$FilterName'"""

if (-not $existingBinding) {
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $Filter
        Consumer = $Consumer
    }
}
