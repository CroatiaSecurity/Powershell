function Get-Entropy {
    param([byte[]]$bytes)
    $freq = @{}
    foreach ($b in $bytes) { $freq[$b]++ }
    $entropy = 0
    foreach ($f in $freq.Values) {
        $p = $f / $bytes.Length
        $entropy -= $p * [Math]::Log($p,2)
    }
    return $entropy
}
