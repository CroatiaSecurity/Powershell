$GShield_KnownLOLBins = @(
    "powershell.exe","pwsh.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","wmic.exe","cscript.exe","wscript.exe",
    "installutil.exe","msbuild.exe","forfiles.exe"
)

function Test-SignatureTrust {
    param([string]$Path)

    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') { return $false }

    # Signed but dangerous
    if ($GShield_KnownLOLBins -contains (Split-Path $Path -Leaf).ToLower()) {
        return $false
    }

    return $true
}
