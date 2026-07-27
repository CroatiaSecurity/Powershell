# DevicesFiltering.ps1 by Gorstak (Enhanced for Console Session USB Access)

# Define scheduled task parameters
$taskName = "DevicesFilteringStartup"
$taskDescription = "Runs the DevicesFiltering script at user logon to restrict USB devices to console session."

# Define script paths
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = Join-Path $scriptDir "DevicesFiltering.ps1"
$logPath = Join-Path $scriptDir "DevicesFiltering.log"

# Ensure script directory exists
if (-not (Test-Path $scriptDir)) {
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
}

# Initialize logging
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append
    Write-Host "$timestamp - $Message"
}

# Check if running with admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "Script requires administrative privileges. Exiting."
    exit 1
}

# Create scheduled task if it doesn't exist
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask) {
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -GroupId "Administrators" -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -ErrorAction Stop
        Write-Log "Scheduled task '$taskName' created successfully."
    }
    catch {
        Write-Log "Failed to create scheduled task: $_"
        exit 1
    }
}

# List of critical device classes to exclude (never disable)
$criticalClasses = @(
    "DiskDrive",           # Storage devices
    "Volume",             # Disk volumes
    "Processor",          # CPU
    "System",             # Core system devices
    "Computer",           # Computer itself
    "USB",                # USB controllers (not hubs or devices)
    "Net",                # Network adapters
    "Display",            # Display adapters
    "Keyboard",           # Keyboards
    "Mouse"               # Mice
)

# Function to get the console session ID
function Get-ConsoleSessionId {
    try {
        # Use quser to find the active console session
        $quserOutput = quser | Where-Object { $_ -match "console" }
        if ($quserOutput -match "\s+(\d+)\s+Active\s+console") {
            return $matches[1]
        }
        # Fallback: Check Win32_LogonSession for console session
        $logonSessions = Get-WmiObject -Class Win32_LogonSession | Where-Object { $_.LogonType -eq 2 } # Interactive logon
        if ($logonSessions) {
            return $logonSessions[0].LogonId
        }
        Write-Log "No console session found."
        return $null
    }
    catch {
        Write-Log "Error getting console session ID: $_"
        return $null
    }
}

# Function to check if device is associated with the console session
function Test-DeviceSession {
    param (
        [string]$DeviceInstanceId
    )
    try {
        # Get console session ID
        $consoleSessionId = Get-ConsoleSessionId
        if (-not $consoleSessionId) {
            Write-Log "No console session ID available. Keeping device $DeviceInstanceId enabled."
            return $true
        }

        # Get current script session ID
        $currentSessionId = (Get-Process -PID $PID).SessionId

        # If running in console session, allow USB devices
        if ($currentSessionId -eq $consoleSessionId) {
            $device = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -eq $DeviceInstanceId }
            if ($device) {
                # Allow USB devices (e.g., mic, camera, flash drive, phone) in console session
                if ($device.Service -like "usb*" -or $device.PNPClass -in @("USB", "WPD", "Media", "Image", "HIDClass")) {
                    Write-Log "Device $DeviceInstanceId allowed in console session (Class: $($device.PNPClass))."
                    return $true
                }
            }
        }
        else {
            Write-Log "Device $DeviceInstanceId not in console session (Session ID: $currentSessionId)."
            return $false
        }

        # Default to false for non-console sessions
        Write-Log "Device $DeviceInstanceId not identified as console session device."
        return $false
    }
    catch {
        Write-Log "Error checking device session for $DeviceInstanceId: $_"
        return $true # Default to keeping enabled to avoid disabling critical devices
    }
}

# Get all PnP devices
$devices = Get-PnpDevice | Where-Object { $_.Present -eq $true } | Select-Object -Property Name, InstanceId, Status, Class, FriendlyName

Write-Log "Found $($devices.Count) devices."

foreach ($device in $devices) {
    $deviceId = $device.InstanceId
    $deviceClass = $device.Class
    $deviceName = $device.FriendlyName ? $device.FriendlyName : $device.Name

    # Skip if already disabled
    if ($device.Status -eq "Error" -or $device.Status -eq "Unknown") {
        Write-Log "Device '$deviceName' already disabled or not present."
        continue
    }
    
    # Skip critical device classes
    if ($criticalClasses -contains $deviceClass) {
        Write-Log "Skipping critical device: $deviceName (Class: $deviceClass)"
        continue
    }
    
    # Check if this device belongs to the console session
    $isConsoleSessionDevice = Test-DeviceSession -DeviceInstanceId $deviceId
    
    if (-not $isConsoleSessionDevice) {
        try {
            # Disable the device
            Disable-PnpDevice -InstanceId $deviceId -Confirm:$false -ErrorAction Stop
            Write-Log "Disabled device: $deviceName (Class: $deviceClass, ID: $deviceId)"
        }
        catch {
            Write-Log "Failed to disable $deviceName: $_"
        }
    }
    else {
        Write-Log "Keeping device active: $deviceName (Class: $deviceClass, ID: $deviceId)"
    }
}

# Log final device status
Write-Log "Final device status:"
$finalStatus = Get-PnpDevice | Where-Object { $_.Present -eq $true } | 
    Select-Object @{Name="Name";Expression={$_.FriendlyName ? $_.FriendlyName : $_.Name}}, Status, Class, InstanceId | 
    Format-Table -AutoSize | Out-String
Write-Log $finalStatus

Write-Log "Device restriction process completed."