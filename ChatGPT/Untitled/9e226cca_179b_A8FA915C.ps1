$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$scannedFilePath = Join-Path $scriptDir "scanned_files.txt"
$logPath = Join-Path $scriptDir "antivirus_log.txt"
