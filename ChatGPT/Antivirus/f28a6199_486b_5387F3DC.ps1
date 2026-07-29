function Get-CommandLineScore {
    param([string]$Cmd)

    $score = 0
    $patterns = @{
        "EncodedCommand" = "-enc"
        "Download"       = "http"
        "IEX"            = "invoke-expression"
        "Bypass"         = "bypass"
        "Hidden"         = "-w hidden"
        "Reflection"    = "reflection"
        "AddType"       = "add-type"
    }

    foreach ($p in $patterns.Values) {
        if ($Cmd.ToLower().Contains($p)) { $score += 2 }
    }
    return $score
}
