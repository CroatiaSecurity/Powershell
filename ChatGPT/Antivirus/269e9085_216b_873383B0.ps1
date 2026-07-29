$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    "D:\Github\Gorstak-1979\GSecurity-main\Iso\sources\$OEM$\$$\Setup\Scripts\Bin\Antivirus.ps1",
    [ref]$null,
    [ref]$errors
)
$errors
