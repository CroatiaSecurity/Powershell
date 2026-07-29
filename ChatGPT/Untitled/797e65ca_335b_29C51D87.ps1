function Detect-XSS {
    $logPath = "C:\Logs\web_traffic.log"
    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Raw
        if ($content -match "<script.*?>|javascript:|onerror=|onload=") {
            Write-Log "XSS signature detected!" -EntryType "Warning"
            Disable-Network-Briefly
        }
    }
}
