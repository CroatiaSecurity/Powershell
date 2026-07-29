function Get-LockedFileHash {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $fs = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hash = $sha256.ComputeHash($fs)
            return ($hash | ForEach-Object { $_.ToString("x2") }) -join ''
        } finally {
            $fs.Close()
        }
    } catch {
        return $null
    }
}
