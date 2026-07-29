function Wait-ForFileComplete {
    param($path)
    $last = -1
    for ($i=0; $i -lt 6; $i++) {
        try {
            $len = (Get-Item $path).Length
            if ($len -eq $last) { return $true }
            $last = $len
        } catch {}
        Start-Sleep -Milliseconds 300
    }
    return $false
}
