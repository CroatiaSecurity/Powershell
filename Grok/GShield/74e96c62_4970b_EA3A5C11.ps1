# GShield.ps1 by Gorstak

# Ensure the script isn't running multiple times
$currentScript = $MyInvocation.MyCommand.Path
$existingProcess = Get-Process | Where-Object {
    $_.Path -eq $currentScript -and $_.Id -ne $PID
}
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Output "Set execution policy to Bypass for current process."
    } catch {
        Write-Output "Failed to set execution policy: $_"
        exit 1
    }
}

function Register-SystemLogonScript {
    param (
        [string]$TaskName = "RunGShieldAtLogon"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    Copy-Item -Path $scriptSource -Destination $targetPath -Force
    Write-Output "Copied script to: $targetPath"

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript

function Detect-RootkitByNetstat {
    # Run netstat -ano and store the output
    $netstatOutput = netstat -ano | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+:\d+' }

    if (-not $netstatOutput) {
        Write-Warning "No network connections found via netstat -ano. Possible rootkit hiding activity."

        # Optionally: Log the suspicious event
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = "$env:TEMP\rootkit_suspected_$timestamp.log"
        "Netstat -ano returned no results. Possible rootkit activity." | Out-File -FilePath $logFile

        # Get all running processes (you could refine this)
        $processes = Get-Process | Where-Object { $_.Id -ne $PID }

        foreach ($proc in $processes) {
            try {
                # Comment this line if you want to observe first
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Output "Stopped process: $($proc.ProcessName) (PID: $($proc.Id))"
            } catch {
                Write-Warning "Could not stop process: $($proc.ProcessName) (PID: $($proc.Id))"
            }
        }
    } else {
        Write-Host "Netstat looks normal. Active connections detected."
    }
}

function Stop-AllVMs {
    $vmProcesses = @(
        "vmware-vmx", "vmware", "vmware-tray", "vmwp", "vmnat", "vmnetdhcp", "vmware-authd", 
        "vmms", "vmcompute", "vmsrvc", "vmwp", "hvhost", "vmmem", 
        "VBoxSVC", "VBoxHeadless", "VirtualBoxVM", "VBoxManage", "qemu-system-x86_64", 
        "qemu-system-i386", "qemu-system-arm", "qemu-system-aarch64", "kvm", "qemu-kvm", 
        "prl_client_app", "prl_cc", "prl_tools_service", "prl_vm_app", "bhyve", "xen", 
        "xenservice", "bochs", "dosbox", "utm", "wsl", "wslhost", "vmmem", "simics", 
        "vbox", "parallels"
    )
    $processes = Get-Process -ErrorAction SilentlyContinue
    $vmRunning = $processes | Where-Object { $vmProcesses -contains $_.Name }
    if ($vmRunning) {
        $vmRunning | Format-Table -Property Id, Name, Description -AutoSize
        foreach ($process in $vmRunning) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# Start background job
Start-Job -ScriptBlock {
    while ($true) {
        Stop-AllVMs
        Detect-RootkitByNetstat
    }
} | Out-Null