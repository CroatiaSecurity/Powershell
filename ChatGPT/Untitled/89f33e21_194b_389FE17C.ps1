function Is-Locked($file) {
    try {
        $stream = [System.IO.File]::Open($file,'Open','ReadWrite')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}
