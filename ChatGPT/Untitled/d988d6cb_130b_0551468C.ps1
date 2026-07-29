$array = New-Object int[] $maxIterations
for ($i = 0; $i -lt $maxIterations; $i++) {
    $array[$i] = Get-Random -Maximum 10000
}
