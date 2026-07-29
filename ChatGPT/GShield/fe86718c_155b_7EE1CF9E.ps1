if ((Get-Variable -Name PID -ErrorAction SilentlyContinue).Options -match "ReadOnly") {
    Set-Variable -Name PID -Value 0 -Force
} else {
    $PID = 0
}
