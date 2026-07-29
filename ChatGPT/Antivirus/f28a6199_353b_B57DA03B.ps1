function Resolve-RealPath {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse point detected"
        }
        return $item.FullName
    } catch {
        return $null
    }
}
