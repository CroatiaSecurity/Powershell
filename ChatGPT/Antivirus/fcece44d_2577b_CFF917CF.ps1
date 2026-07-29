# Simple Antivirus (Permission Removal Mode) by Gorstak

# Define logging location
$logFile = Join-Path $env:TEMP "antivirus_log.txt"
$scannedFiles = @{} # hash table memory only

# Logging Function
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host $logEntry
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

Write-Log "Script initialized. User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error hashing $filePath: $($_.Exception.Message)"
        return $null
    }
}

# Remove all permissions from file
function Strip-Permissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /inheritance:r /remove:g *S-1-1-0 Administrators SYSTEM Users Everyone | Out-Null
        Write-Log "Removed all permissions from $filePath"
    } catch {
        Write-Log "Failed to strip permissions for $filePath: $($_.Exception.Message)"
    }
}

# Scan and process DLLs
function Scan-DLLs {
    Write-Log "Starting DLL scan..."
    $system32 = "C:\Windows\System32"
    try {
        $dllFiles = Get-ChildItem -Path $system32 -Filter *.dll -File -ErrorAction Stop
        foreach ($dll in $dllFiles) {
            $fileHash = Calculate-FileHash -filePath $dll.FullName
            if ($fileHash) {
                if (-not $scannedFiles.ContainsKey($fileHash.Hash)) {
                    $isValid = $fileHash.Status -eq "Valid"
                    $scannedFiles[$fileHash.Hash] = $isValid
                    Write-Log "Scanned: $($dll.FullName) (Valid: $isValid)"
                    if (-not $isValid) {
                        Strip-Permissions -filePath $dll.FullName
                    }
                } else {
                    Write-Log "Skipping already scanned file: $($dll.FullName)"
                }
            }
        }
    } catch {
        Write-Log "Scan failed: $($_.Exception.Message)"
    }
}

# Run scan once
Scan-DLLs
Write-Log "Scan completed."
