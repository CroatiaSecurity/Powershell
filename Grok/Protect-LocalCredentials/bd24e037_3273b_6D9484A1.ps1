# Protect-LocalCredentials.ps1
# Enhances protection for local and non-domain credentials by securing LSASS and managing credential caching

# Requires administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Run PowerShell as Administrator."
    exit
}

# Function to enable LSASS as Protected Process Light (PPL)
function Enable-LsassPPL {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "RunAsPPL"
        $regValue = 1

        if (-not (Test-Path $regPath)) {
            Write-Error "LSA registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -ErrorAction Stop
        Write-Host "LSASS configured to run as Protected Process Light (PPL). Reboot required."
    }
    catch {
        Write-Error "Failed to enable LSASS PPL: $_"
    }
}

# Function to clear cached credentials
function Clear-CachedCredentials {
    try {
        # Clear cached credentials from Credential Manager
        cmdkey /list | ForEach-Object {
            if ($_ -match "Target:") {
                $target = $_ -replace ".*Target: (.*)", '$1'
                cmdkey /delete:$target
            }
        }
        Write-Host "Cleared cached credentials from Credential Manager."
    }
    catch {
        Write-Error "Failed to clear cached credentials: $_"
    }
}

# Function to disable credential caching
function Disable-CredentialCaching {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "CachedLogonsCount"
        $regValue = 0

        if (-not (Test-Path $regPath)) {
            Write-Error "Winlogon registry path not found."
            return
        }

        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -ErrorAction Stop
        Write-Host "Disabled cached logon credentials. Set CachedLogonsCount to 0."
    }
    catch {
        Write-Error "Failed to disable credential caching: $_"
    }
}

# Function to enable auditing for credential access
function Enable-CredentialAuditing {
    try {
        $auditPolicy = auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        if ($auditPolicy -match "The command was successfully executed.") {
            Write-Host "Enabled auditing for credential validation events."
        }
        else {
            Write-Error "Failed to enable auditing: $auditPolicy"
        }
    }
    catch {
        Write-Error "Failed to enable auditing: $_"
    }
}

# Main execution
Write-Host "Starting credential protection script..."

# Enable LSASS PPL
Enable-LsassPPL

# Clear cached credentials
Clear-CachedCredentials

# Disable credential caching
Disable-CredentialCaching

# Enable auditing
Enable-CredentialAuditing

Write-Host "Script completed. Reboot the system to apply LSASS PPL changes."
Write-Host "Check Event Viewer (Security logs) for credential access auditing."