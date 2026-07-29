function Invoke-ManagedJobsTick {
    ...
}

function Start-EDRAgent {
    Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow)
}

Start-EDRAgent
