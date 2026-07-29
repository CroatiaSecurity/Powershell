function Take-Screenie {
    param ($form)
    $screenLocation = $form.PointToScreen([System.Drawing.Point]::Empty)
    $bounds = $form.Bounds
    $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $gfx = [Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen($screenLocation, [Drawing.Point]::Empty, $bounds.Size)

    $path = "$env:USERPROFILE\Pictures\BenchmarkResult_$((Get-Date).ToString('yyyyMMdd_HHmmss')).png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    [System.Windows.Forms.Clipboard]::SetImage($bmp)

    [System.Windows.Forms.MessageBox]::Show("Screenie saved to:`n$path`nand copied to clipboard.")
}
