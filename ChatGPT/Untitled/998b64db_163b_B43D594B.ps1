# Global config fallback
if (-not (Get-Variable -Name CheckIntervalSeconds -Scope Script -ErrorAction SilentlyContinue)) {
    $script:CheckIntervalSeconds = 10
}
