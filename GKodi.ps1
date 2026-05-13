# Define paths and URLs
$kodiInstallerUrl = "https://mirrors.kodi.tv/releases/windows/win64/kodi-20.2-Nexus-x64.exe"
$kodiInstallerPath = "$env:TEMP\kodi-installer.exe"
$kodiInstallDir = "$env:ProgramFiles\Kodi"
$kodiUserDataDir = "$env:APPDATA\Kodi"

# Download Kodi installer
Write-Host "Downloading Kodi installer..."
Invoke-WebRequest -Uri $kodiInstallerUrl -OutFile $kodiInstallerPath

# Install Kodi silently
Write-Host "Installing Kodi..."
Start-Process -FilePath $kodiInstallerPath -ArgumentList "/S" -Wait

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