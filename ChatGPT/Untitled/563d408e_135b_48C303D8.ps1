Invoke-ManagedJobsTick -NowUtc ([DateTime]::UtcNow) {
    param(
        [Parameter(Mandatory=$true)][DateTime]$NowUtc
    )
    ...
}
