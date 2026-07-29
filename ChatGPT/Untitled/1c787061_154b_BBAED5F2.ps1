# Define global exclusions to prevent breaking system components
$Global:ExcludedProcesses = @(
    "ctfmon.exe",
    "msctf.dll",
    "ctfmon.exe.mui"
)
