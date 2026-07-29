$Rules = @(
    @{
        Name = "Encoded PowerShell"
        Match = "powershell -enc"
        Score = 40
    }
)

function Invoke-Rules {
    param($cmd)

    foreach ($rule in $Rules) {
        if ($cmd -match $rule.Match) {
            Add-Score $rule.Score
        }
    }
}
