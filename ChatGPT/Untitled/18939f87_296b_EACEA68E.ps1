function Collect-Evidence {
    param($Context)

    $dir = "$Base\Evidence\$($Context.PID)"
    New-Item $dir -ItemType Directory -Force | Out-Null

    Get-Process -Id $Context.PID | Export-Clixml "$dir\process.xml"
    Copy-Item $Context.Path "$dir\binary.bin" -ErrorAction SilentlyContinue
}
