# OpenBookmarks.ps1
# Author: Gorstak (gorstak.eu)
# Description: Opens all URLs from a bookmarks.html file in the default browser so the
#              browser can fetch and cache real favicons. Interactive batch/all mode.
#              One-time utility, no persistence needed.

$bookmarksFile = "$PSScriptRoot\bookmarks.html"

if (-not (Test-Path $bookmarksFile)) {
    Write-Host "Bookmarks file not found: $bookmarksFile" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Extract all URLs from HREF attributes
$content = Get-Content $bookmarksFile -Raw
$urls = [regex]::Matches($content, 'HREF="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }

$total = $urls.Count
Write-Host "Found $total bookmarks." -ForegroundColor Cyan
Write-Host ""
Write-Host "This will open all URLs in your default browser."
Write-Host "Recommended: open in batches to avoid overwhelming your system."
Write-Host ""
Write-Host "Options:"
Write-Host "  [A] Open ALL at once (not recommended for 100+ bookmarks)"
Write-Host "  [B] Open in batches of 10 (recommended)"
Write-Host "  [Q] Quit"
Write-Host ""
$choice = Read-Host "Choose [A/B/Q]"

switch ($choice.ToUpper()) {
    'A' {
        Write-Host "Opening all $total URLs..." -ForegroundColor Yellow
        foreach ($url in $urls) {
            Start-Process $url
            Start-Sleep -Milliseconds 500
        }
        Write-Host "Done! All URLs opened." -ForegroundColor Green
    }
    'B' {
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
                Write-Host ""
                Write-Host "Wait for pages to load, then press Enter for next batch..." -ForegroundColor Cyan
                Read-Host
            }
        }
        Write-Host "Done! All URLs opened." -ForegroundColor Green
    }
    default {
        Write-Host "Cancelled." -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Once all pages have loaded, export your bookmarks from the browser"
Write-Host "to get the updated bookmarks.html with all favicons populated."
Read-Host "Press Enter to exit"
