$ext = [System.IO.Path]::GetExtension($file).ToLower()

if ($AllowedExtensions -contains $ext) {
    Write-Host "   -> Extension whitelisted, skipping"
    continue
}
