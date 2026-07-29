# === Global Exclusion List ===
# Prevents issues with Text Services Framework (ctfmon.exe)
$Global:ExcludedProcesses = @(
    'ctfmon.exe',
    'msctf.dll',
    'ctfmon.exe.mui'
)

function Test-IsExcluded {
    param([string]$Target)
    foreach ($exclude in $Global:ExcludedProcesses) {
        if ($Target -match [regex]::Escape($exclude)) {
            Write-Log "Skipping excluded target: $exclude"
            return $true
        }
    }
    return $false
}
