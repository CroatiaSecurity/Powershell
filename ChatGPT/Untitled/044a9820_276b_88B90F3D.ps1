   $trustedVendors = @("Microsoft", "Intel", "NVIDIA", "Realtek")
   $sigCheck = Get-AuthenticodeSignature -FilePath $path
   if ($sigCheck.SignerCertificate.Subject -notmatch ($trustedVendors -join "|")) {
       Write-Log "Unsigned or untrusted binary modified: $path"
   }
