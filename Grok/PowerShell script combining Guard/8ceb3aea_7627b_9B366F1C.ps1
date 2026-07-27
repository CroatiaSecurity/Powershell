

# PowerShell script combining Guard.ps1 and GShield.ps1 functionality
# Monitors and applies firewall rules, checks for suspicious processes/services, and logs activities

# Ensure the script isn't running multiple times
$currentScript = $PSCommandPath
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Output "This script requires administrative privileges. Exiting."
    exit 1
}

# Initialize logging
$logFile = "C:\Windows\Setup\Scripts\Bin\GuardShield.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Log "Set execution policy to Bypass for current process."
    } catch {
        Write-Log "Failed to set execution policy: $_"
        exit 1
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGuardShieldAtLogon"
    )

    # Define paths
    $scriptSource = $PSCommandPath
    if (-not $scriptSource) {
        Write-Log "Error: Could not determine script path. Ensure the script is run from a file."
        exit 1
    }
    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script to ${targetPath}: $_"
        exit 1
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Log "Failed to register task: $_"
        exit 1
    }
}

# Run the scheduled task registration
Register-SystemLogonScript

# Placeholder for registry-based firewall rules
$registryContent = @"
Windows Registry Editor Version 5.00

; Paste your firewall rules here
; Example format:
; [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]
; "RuleName"="v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|App=%SystemRoot%\\system32\\svchost.exe|Name=ExampleRule|Desc=ExampleDescription|"
"@

# Function to apply registry content
function Apply-RegistryContent {
    param (
        [string]$Content
    )
    $tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"
    try {
        Set-Content -Path $tempRegFile -Value $Content -ErrorAction Stop
        Write-Log "Applying registry content from temporary file: $tempRegFile"
        $regImport = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$tempRegFile`"" -NoNewWindow -Wait -PassThru
        if ($regImport.ExitCode -eq 0) {
            Write-Log "Registry content applied successfully."
        } else {
            Write-Log "Failed to apply registry content. Exit code: $($regImport.ExitCode)"
        }
    } catch {
        Write-Log "Error applying registry content: $_"
    } finally {
        if (Test-Path $tempRegFile) {
            Remove-Item $tempRegFile -Force
            Write-Log "Cleaned up temporary registry file."
        }
    }
}

# Apply the registry content initially
Apply-RegistryContent -Content $registryContent

# Function to check for suspicious processes
function Check-SuspiciousProcesses {
    $suspiciousProcesses = @("unknown.exe", "malware.exe", "suspicious.exe") # Customize as needed
    $runningProcesses = Get-Process | Select-Object -ExpandProperty Name
    foreach ($proc in $suspiciousProcesses) {
        if ($runningProcesses -contains $proc) {
            Write-Log "Suspicious process detected: $proc. Terminating."
            try {
                Stop-Process -Name $proc -Force -ErrorAction Stop
                Write-Log "Terminated process: $proc"
            } catch {
                Write-Log "Failed to terminate process $proc: $_"
            }
        }
    }
}

# Function to check for unauthorized services
function Check-UnauthorizedServices {
    $criticalServices = @("WinDefend", "wuauserv") # Example critical services
    foreach ($service in $criticalServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Log "Critical service $service is not running. Attempting to start."
            try {
                Start-Service -Name $service -ErrorAction Stop
                Write-Log "Started service: $service"
            } catch {
                Write-Log "Failed to start service $service: $_"
            }
        }
    }
}

# Main monitoring loop
$firewallRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
$lastKnownContent = $registryContent

while ($true) {
    try {
        # Monitor firewall rules
        $currentRegExport = [System.IO.Path]::GetTempFileName() + ".reg"
        Start-Process -FilePath "reg.exe" -ArgumentList "export `"$firewallRegPath`" `"$currentRegExport`" /y" -NoNewWindow -Wait
        $currentContent = Get-Content -Path $currentRegExport -Raw

        # Compare with expected content (ignoring header differences)
        $currentRules = ($currentContent -split "`n" | Where-Object { $_ -notmatch "^Windows Registry Editor Version" }).Trim()
        $expectedRules = ($lastKnownContent -split "`n" | Where-Object { $_ -notmatch "^Windows Registry Editor Version" }).Trim()

        if ($currentRules -ne $expectedRules) {
            Write-Log "Firewall rules have changed. Reapplying original rules."
            Apply-RegistryContent -Content $registryContent
            $lastKnownContent = $registryContent
        }

        # Clean up
        if (Test-Path $currentRegExport) {
            Remove-Item $currentRegExport -Force
        }

        # Perform additional security checks
        Check-SuspiciousProcesses
        Check-UnauthorizedServices

    } catch {
        Write-Log "Error during monitoring: $_"
    }

    # Wait before next check
    Start-Sleep -Seconds 60
}

