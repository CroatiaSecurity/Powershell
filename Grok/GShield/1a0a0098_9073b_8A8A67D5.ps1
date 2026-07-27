# GShield Script by Gorstak
# Requires Administrative privileges

# Function to apply privilege rights
function Harden-PrivilegeRights {
    $privilegeSettings = @'
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege=
SeBackupPrivilege=
SeCreateTokenPrivilege=
SeDebugPrivilege=
SeImpersonatePrivilege=
SeLoadDriverPrivilege=
SeRemoteInteractiveLogonRight=
SeServiceLogonRight=
'@
    $cfgPath = "C:\secpol.cfg"
    secedit /export /cfg $cfgPath /quiet
    $privilegeSettings | Out-File -Append -FilePath $cfgPath
    secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    Remove-Item $cfgPath -Force
}

# Autopilot cleanup
Uninstall-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Microsoft\Provisioning" -Recurse -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" -Name "AllowUserDeviceClasses" -Value 0 -Type DWord -Force

# Set UAC to maximum level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 0 -Type DWord -Force

# Remove default users
"net user defaultuser0 /delete" | cmd
"net user defaultuser1 /delete" | cmd
"net user defaultuser100000 /delete" | cmd

# Set drive permissions
foreach ($drive in (Get-PSDrive -PSProvider FileSystem).Name) {
    if (Test-Path "$drive`:") {
        # Take ownership
        & takeown /f "$drive`:\" /r /d y
        
        # Set permissions using icacls
        & icacls "$drive`:\" /setowner "Administrators"
        & icacls "$drive`:\" /remove "Everyone"
        
        # Check if drive is removable and NTFS
        $driveType = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$drive`:"} | Select-Object -ExpandProperty DriveType
        if ($driveType -eq 2) {  # 2 = Removable drive
            $fsType = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$drive`:"} | Select-Object -ExpandProperty FileSystem
            if ($fsType -eq "NTFS") {
                & icacls "$drive`:\" /grant:r "Users:RX" /T /C
                & icacls "$drive`:\" /grant:r "System:F" /T /C
                & icacls "$drive`:\" /grant:r "Administrators:F" /T /C
                & icacls "$drive`:\" /grant:r "Authenticated Users:M" /T /C
                & icacls "$drive`:\" /remove "Everyone"
                & icacls "$drive`:\" /remove "Authenticated Users"
            }
        }
    }
}

# Desktop permissions
$paths = @("$env:SystemDrive\Users\Public\Desktop", "$env:USERPROFILE\Desktop")
foreach ($path in $paths) {
    & takeown /f $path /r /d y
    & icacls $path /inheritance:d /T /C
    $removeSids = @("INTERACTIVE", "SERVICE", "BATCH", "CREATOR OWNER", "System", "Administrators")
    foreach ($sid in $removeSids) {
        & icacls $path /remove $sid
    }
    & icacls $path /inheritance:r
}

# Remove symbolic links
foreach ($drive in (Get-PSDrive -PSProvider FileSystem).Name) {
    if (Test-Path "$drive`:") {
        Get-ChildItem -Path "$drive`:\" -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue | 
            ForEach-Object { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue }
    }
}

# Disable PXE on network adapters
Get-NetAdapter | ForEach-Object {
    $guid = $_.InterfaceGuid
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name "DisablePXE" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\$guid" -Name "DisablePXE" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
}

# Disable NetBIOS
Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableNetbios" -Value 0 -Type DWord -Force

# Registry permissions
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\gpsvc"
Stop-Service -Name "gpsvc" -Force -ErrorAction SilentlyContinue
& icacls "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /setowner "Administrators"
& icacls "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /inheritance:d
& icacls "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /grant "Administrators:F"

# Additional registry settings
$registrySettings = @{
    "HKLM:\Software\Microsoft\Ole" = @{
        "EnableDCOM" = "N"
        # Note: Binary values like DefaultLaunchPermission would need to be converted to proper format
    }
    "HKLM:\Software\Microsoft\Rpc\Internet" = @{
        "UseInternetPorts" = "N"
    }
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" = @{
        "MitigationOptions" = 49
    }
}

# Disable Services
$services = @("BTHMODEM", "gpsvc", "LanmanWorkstation", "LanmanServer", "Messenger", "NetBT", "seclogon", "upnphost", "SSDPSRV")
foreach ($service in $services) {
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$service" -Name "Start" -Value 4 -ErrorAction SilentlyContinue
}

# Set DefaultLaunchPermission
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "DefaultLaunchPermission" -Value ([byte[]](
    0x01,0x00,0x04,0x80,0x9C,0x00,0x00,0x00,0xAC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x14,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
    0x15,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,
    0x00,0x00,0x18,0x00,0x15,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,
    0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x15,0x00,0x00,0x00,
    0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
    0x0B,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,
    0x00,0x00,0x18,0x00,0x0B,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,
    0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x0B,0x00,0x00,0x00,
    0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00
)) -Type Binary -Force

# Set DefaultAccessPermission
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "DefaultAccessPermission" -Value ([byte[]](
    0x01,0x00,0x04,0x80,0x9C,0x00,0x00,0x00,0xAC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x14,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
    0x05,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0A,0x00,0x00,0x00,
    0x00,0x00,0x14,0x00,0x05,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,
    0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x05,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,
    0x03,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0A,0x00,0x00,0x00,
    0x00,0x00,0x14,0x00,0x03,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,
    0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x03,0x00,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x01,0x02,0x00,0x00,
    0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00
)) -Type Binary -Force

foreach ($path in $registrySettings.Keys) {
    foreach ($setting in $registrySettings[$path].GetEnumerator()) {
        Set-ItemProperty -Path $path -Name $setting.Name -Value $setting.Value -Force -ErrorAction SilentlyContinue
    }
}

# Apply privilege rights
Harden-PrivilegeRights