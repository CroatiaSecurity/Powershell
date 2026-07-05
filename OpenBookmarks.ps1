# OpenBookmarks.ps1
# Author: Gorstak (gorstak.eu)
# Description: Opens all URLs from a bookmarks.html file in the default browser so the
#              browser can fetch and cache real favicons. Non-interactive batch mode.
#              One-time utility, no persistence needed.

$bookmarksFile = "$PSScriptRoot\bookmarks.html"

if (-not (Test-Path $bookmarksFile)) {
    Write-Host "Bookmarks file not found: $bookmarksFile" -ForegroundColor Red
    exit 1
}

# Extract all URLs from HREF attributes
$content = Get-Content $bookmarksFile -Raw
$urls = [regex]::Matches($content, 'HREF="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }

$total = $urls.Count
Write-Host "Found $total bookmarks. Opening in batches of 10..." -ForegroundColor Cyan

$batchSize = 10
for ($i = 0; $i -lt $total; $i += $batchSize) {
    $batch = $urls[$i..([Math]::Min($i + $batchSize - 1, $total - 1))]
    $batchNum = [Math]::Floor($i / $batchSize) + 1
    $totalBatches = [Math]::Ceiling($total / $batchSize)

    Write-Host "Batch $batchNum of $totalBatches ($($batch.Count) URLs):" -ForegroundColor Yellow
    foreach ($url in $batch) {
        Write-Host "  $url"
        Start-Process $url
        Start-Sleep -Milliseconds 300
    }

    if ($i + $batchSize -lt $total) {
        Write-Host "  Waiting 5 seconds before next batch..." -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }
}

Write-Host "Done! All $total URLs opened." -ForegroundColor Green
Write-Host "Once all pages have loaded, export your bookmarks from the browser"
Write-Host "to get the updated bookmarks.html with all favicons populated."
