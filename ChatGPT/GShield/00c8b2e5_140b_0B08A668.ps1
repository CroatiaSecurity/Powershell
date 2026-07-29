if ((Get-ItemProperty HKCU:\Software\GShield -Name EnableKeyScrambler -ErrorAction SilentlyContinue).EnableKeyScrambler -ne 1) {
    exit
}
