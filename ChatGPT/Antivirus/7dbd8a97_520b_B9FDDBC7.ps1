# Run in an elevated PowerShell session in the directory with your script
$path = 'C:\Users\Admin\Downloads\antivirus (2).ps1'   # change if necessary
$content = Get-Content -Path $path -Raw -ErrorAction Stop
$new = [regex]::Replace($content, '(\$)([A-Za-z_][A-Za-z0-9_]*)\:', {
    param($m)
    # $m.Groups[2].Value is the variable name without the leading $
    return '$(' + $m.Groups[2].Value + '):'
})
Set-Content -Path $path -Value $new -Force
Write-Host "Fixed $path — replaced $Var: -> $($Var): occurrences."
