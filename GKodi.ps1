# GKodi.ps1
# Author: Gorstak (gorstak.eu)
# Description: Automated Kodi media center installer. Downloads and silently installs Kodi,
#              enables web server, adds streaming addon repositories (The Crew, Venom, Seren),
#              and launches Kodi. One-time setup utility.

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "GKodiSetup"
$Script:InstallDir = "$env:ProgramData\GKodi"
$Script:ScriptName = "GKodi.ps1"

function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "GKodi Setup (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONSTART /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] GKodi uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

# Define paths and URLs
$kodiInstallerUrl = "https://mirrors.kodi.tv/releases/windows/win64/kodi-20.2-Nexus-x64.exe"
$kodiInstallerPath = "$env:TEMP\kodi-installer.exe"
$kodiInstallDir = "$env:ProgramFiles\Kodi"
$kodiUserDataDir = "$env:APPDATA\Kodi"

# Download Kodi installer
Write-Host "Downloading Kodi installer..."
Invoke-WebRequest -Uri $kodiInstallerUrl -OutFile $kodiInstallerPath

# Install Kodi silently (non-blocking with timeout)
Write-Host "Installing Kodi..."
$proc = Start-Process -FilePath $kodiInstallerPath -ArgumentList "/S" -PassThru
$timeout = 300  # 5 minute max
$elapsed = 0
while (-not $proc.HasExited -and $elapsed -lt $timeout) {
    Start-Sleep -Seconds 5
    $elapsed += 5
}
if (-not $proc.HasExited) {
    Write-Host "Kodi installer still running after $timeout seconds, continuing..." -ForegroundColor Yellow
}

# Wait for Kodi to initialize (optional)
Start-Sleep -Seconds 10

# Create the userdata directory if it doesn't exist
$userDataDir = "$kodiUserDataDir\userdata"
if (-Not (Test-Path $userDataDir)) {
    New-Item -ItemType Directory -Path $userDataDir
}

# Enable Kodi's web server by creating advancedsettings.xml
# WARNING: Change the default password below before exposing Kodi to a network
$advancedSettingsPath = "$kodiUserDataDir\userdata\advancedsettings.xml"
$advancedSettingsContent = @"
<advancedsettings>
    <services>
        <webserver>true</webserver>
        <webserverport>8080</webserverport>
        <webserverusername>kodi</webserverusername>
        <webserverpassword>changeme</webserverpassword>
    </services>
</advancedsettings>
"@
Set-Content -Path $advancedSettingsPath -Value $advancedSettingsContent

# Add the necessary repositories
Write-Host "Adding repositories for The Crew, Venom, and Seren..."

# Define repository URLs
$crewRepoUrl = "https://team-crew.github.io"
$venomRepoUrl = "https://venom-mod.github.io"
$serenRepoUrl = "https://nixgates.github.io/packages"

# Create sources.xml if it doesn't exist
$sourcesXmlPath = "$kodiUserDataDir\userdata\sources.xml"
if (-Not (Test-Path $sourcesXmlPath)) {
    $sourcesXmlContent = @"
<sources>
    <files>
        <source>
            <name>crew</name>
            <path pathversion="1">$crewRepoUrl</path>
        </source>
        <source>
            <name>venom</name>
            <path pathversion="1">$venomRepoUrl</path>
        </source>
        <source>
            <name>seren</name>
            <path pathversion="1">$serenRepoUrl</path>
        </source>
    </files>
</sources>
"@
    Set-Content -Path $sourcesXmlPath -Value $sourcesXmlContent
}

# Install the addons
Write-Host "Installing The Crew, Venom, and Seren addons..."

# Use Kodi's JSON-RPC API to install the addons
$kodiJsonRpcUrl = "http://localhost:8080/jsonrpc"

# Function to send JSON-RPC commands
function Install-Addon {
    param (
        [string]$addonId
    )
    $jsonRpcPayload = @{
        jsonrpc = "2.0"
        method = "Addons.ExecuteAddon"
        params = @{
            addonid = $addonId
        }
        id = 1
    } | ConvertTo-Json
    Invoke-WebRequest -Uri $kodiJsonRpcUrl -Method Post -Body $jsonRpcPayload -ContentType "application/json"
}

# Install The Crew
Write-Host "Installing The Crew..."
Install-Addon -addonId "plugin.video.thecrew"

# Install Venom
Write-Host "Installing Venom..."
Install-Addon -addonId "plugin.video.venom"

# Install Seren
Write-Host "Installing Seren..."
Install-Addon -addonId "plugin.video.seren"

# Launch Kodi
Write-Host "Launching Kodi..."
Start-Process -FilePath "$kodiInstallDir\kodi.exe"

Write-Host "Setup complete! Kodi is ready to use with The Crew, Venom, and Seren addons."