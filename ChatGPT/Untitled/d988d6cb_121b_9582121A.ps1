$content = New-Object byte[] (1MB)
(new Random).NextBytes($content)
[System.IO.File]::WriteAllBytes($filePath, $content)
