function New-Detection {
    param($Type, $Source, $Details, $Score)

    [PSCustomObject]@{
        Time    = Get-Date -Format o
        Type    = $Type
        Source  = $Source
        Details = $Details
        Score   = $Score
        Host    = $env:COMPUTERNAME
        User    = $env:USERNAME
    }
}
