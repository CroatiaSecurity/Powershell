# Stripper.ps1
# Author: Gorstak (Updated for stable wimlib download from official source)

# Requires administrative privileges
#Requires -RunAsAdministrator

# Function to download and setup wimlib-imagex
function Install-Wimlib {
    # Primary: Official wimlib.net (v1.14.4, Windows x64)
    $wimlibUrl = "https://wimlib.net/downloads/wimlib-1.14.4-windows-x86_64-bin.zip"
    # Fallback: SourceForge mirror
    $fallbackUrl = "https://sourceforge.net/projects/wimlib/files/wimlib/1.14.4/wimlib-1.14.4-windows-x86_64-bin.zip/download"
    $wimlibZip = "$env:TEMP\wimlib.zip"
    $wimlibDir = "$env:TEMP\wimlib"
    $wimlibExe = "$wimlibDir\wimlib-imagex.exe"
    # SHA256 for wimlib-imagex.exe v1.14.4
    $expectedHash = "401bf99d6dec2b749b464183f71d146327ae0856a968c309955f71a0c398a348"

    if (-not (Test-Path $wimlibExe)) {
        Write-Host "Downloading wimlib-imagex (v1.14.4) from wimlib.net..."
        # Test connectivity
        try {
            $response = Invoke-WebRequest -Uri "https://wimlib.net" -Method Head -TimeoutSec 5 -ErrorAction Stop
        } catch {
            Write-Warning "Cannot reach wimlib.net. Trying SourceForge fallback..."
            $wimlibUrl = $fallbackUrl
        }

        try {
            Invoke-WebRequest -Uri $wimlibUrl -OutFile $wimlibZip -ErrorAction Stop
            Expand-Archive -Path $wimlibZip -DestinationPath $wimlibDir -Force
            Remove-Item $wimlibZip

            # Verify hash
            if (Test-Path $wimlibExe) {
                $actualHash = (Get-FileHash $wimlibExe -Algorithm SHA256).Hash
                if ($actualHash -ne $expectedHash) {
                    Write-Error "Hash mismatch for wimlib-imagex.exe. Expected: $expectedHash, Got: $actualHash. Possible corruption delete $wimlibDir and retry."
                    Remove-Item $wimlibDir -Recurse -Force
                    exit
                }
                Write-Host "wimlib verified successfully."
            } else {
                Write-Error "wimlib-imagex.exe not found after extraction."
                exit
            }
        } catch [System.Net.WebException] {
            if ($_.Exception.Response.StatusCode -eq 404) {
                Write-Warning "URL not found (404). Trying fallback..."
                try {
                    Invoke-WebRequest -Uri $fallbackUrl -OutFile $wimlibZip -ErrorAction Stop
                    Expand-Archive -Path $wimlibZip -DestinationPath $wimlibDir -Force
                    Remove-Item $wimlibZip
                } catch {
                    Write-Error "Fallback failed: $_ . Manual download required: Visit https://wimlib.net/downloads.html or https://sourceforge.net/projects/wimlib/files/ and extract wimlib-imagex.exe to $wimlibDir"
                    exit
                }
            } else {
                Write-Error "Download failed: $_"
                exit
            }
        } catch {
            Write-Error "Failed to download/setup wimlib: $_"
            exit
        }
    }
    return $wimlibExe
}

# Function to download lightweight oscdimg
function Install-OscdimgLite {
    $oscdimgDir = "$env:TEMP\oscdimg"
    $oscdimgExe = "$oscdimgDir\oscdimg.exe"
    $oscdimgUrl = "https://github.com/kogavoljemvoljem/Scripts/raw/main/oscdimg.exe"
    $fallbackUrl = "https://raw.githubusercontent.com/kogavoljemvoljem/Scripts/main/oscdimg.exe"
    $maxRetries = 3
    $retryDelay = 5
    # Placeholder SHA256 for oscdimg.exe (replace with actual hash if known)
    $expectedHash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Common ADK paths for existing installations
    $possiblePaths = @(
        "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "C:\Program Files (x86)\Windows Kits\11\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
        "C:\Program Files\Windows Kits\11\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    )

    if (-not (Test-Path $oscdimgExe)) {
        # Check installed ADK paths
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                Write-Host "Found oscdimg at $path"
                Copy-Item $path $oscdimgExe -Force
                # Copy boot files if present
                $baseDir = [System.IO.Path]::GetDirectoryName($path)
                $etfsbootInstalled = "$baseDir\etfsboot.com"
                $efisysInstalled = "$baseDir\efisys.bin"
                if (Test-Path $etfsbootInstalled) { Copy-Item $etfsbootInstalled "$oscdimgDir\etfsboot.com" -Force }
                if (Test-Path $efisysInstalled) { Copy-Item $efisysInstalled "$oscdimgDir\efisys.bin" -Force }
                Write-Host "Using oscdimg at $oscdimgExe"
                return $oscdimgExe
            }
        }

        # Download oscdimg from user-provided GitHub repo
        Write-Host "Downloading oscdimg from $oscdimgUrl..."
        New-Item -ItemType Directory -Path $oscdimgDir -Force | Out-Null
        $success = $false
        $attempt = 0
        $currentUrl = $oscdimgUrl
        while ($attempt -lt $maxRetries -and -not $success) {
            $attempt++
            try {
                Invoke-WebRequest -Uri $currentUrl -OutFile $oscdimgExe -TimeoutSec 30 -ErrorAction Stop
                # Verify hash (optional; update $expectedHash)
                if ($expectedHash -ne "0000000000000000000000000000000000000000000000000000000000000000") {
                    $actualHash = (Get-FileHash $oscdimgExe -Algorithm SHA256).Hash
                    if ($actualHash -ne $expectedHash) {
                        Write-Error "Hash mismatch for oscdimg.exe. Expected: $expectedHash, Got: $actualHash. Possible corruption delete $oscdimgExe and retry."
                        Remove-Item $oscdimgExe -Force
                        exit
                    }
                }
                $success = $true
                Write-Host "oscdimg downloaded successfully from $currentUrl"
            } catch {
                Write-Warning ("Attempt {0} failed to download from {1}: {2}" -f $attempt, $currentUrl, $_)
                if ($attempt -lt $maxRetries) {
                    Write-Host "Retrying in $retryDelay seconds..."
                    Start-Sleep -Seconds $retryDelay
                } elseif ($currentUrl -eq $oscdimgUrl) {
                    Write-Warning "Primary URL failed. Trying fallback URL..."
                    $currentUrl = $fallbackUrl
                    $attempt = 0
                }
            }
        }

        if (-not $success) {
            Write-Error "Failed to download oscdimg after $maxRetries attempts. Manual download required: Visit https://github.com/kogavoljemvoljem/Scripts/raw/main/oscdimg.exe and save to $oscdimgExe."
            exit
        }
    }
    Write-Host "Using oscdimg at $oscdimgExe"
    return $oscdimgExe
}

# Function to extract boot files from ISO
function Extract-BootFiles {
    param ($IsoMountPoint, $OscdimgDir)
    $etfsboot = Join-Path $IsoMountPoint "boot\etfsboot.com"
    $efisys = Join-Path $IsoMountPoint "efi\microsoft\boot\efisys.bin"
    $destEtfsboot = Join-Path $OscdimgDir "etfsboot.com"
    $destEfisys = Join-Path $OscdimgDir "efisys.bin"

    if (-not (Test-Path $destEtfsboot) -or -not (Test-Path $destEfisys)) {
        Write-Host "Extracting boot files from ISO..."
        try {
            Copy-Item $etfsboot $destEtfsboot -ErrorAction Stop
            Copy-Item $efisys $destEfisys -ErrorAction Stop
        } catch {
            Write-Error "Failed to extract boot files: $_"
            Write-Warning "Ensure $etfsboot and $efisys exist in ISO."
            exit
        }
    }
}

# Function to validate and mount ISO
function Mount-ISO {
    param ($IsoPath)
    try {
        $mountResult = Mount-DiskImage -ImagePath $IsoPath -PassThru
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        return "$driveLetter`:\"
    } catch {
        Write-Error "Failed to mount ISO: $_"
        exit
    }
}

# Function to get WIM file and index
function Get-WimFile {
    param ($IsoMountPoint, $WimlibExe)
    $wimFile = Join-Path $IsoMountPoint "sources\install.wim"
    if (-not (Test-Path $wimFile)) {
        Write-Error "No install.wim found in ISO."
        exit
    }
    # List indexes
    $indexes = & $WimlibExe info $wimFile | Select-String "Index: (\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
    Write-Host "Available editions in WIM:"
    foreach ($index in $indexes) {
        $name = & $WimlibExe info $wimFile $index | Select-String "Name: (.+)" | ForEach-Object { $_.Matches.Groups[1].Value }
        Write-Host "Index: $index  Name: $name"
    }
    $index = Read-Host "Enter the WIM index to modify (e.g., 1 for Pro)"
    return $wimFile, $index
}

# Function to remove components using wimlib and DISM logic
function Remove-Components {
    param ($MountDir, $WimlibExe, $WimFile, $Index, $Preset, $KeepStore, $KeepXbox, $KeepDefender, $KeepEdge, $KeepWindowsUpdate)

    # Components from NTLite preset (full list from your XML)
    $allComponents = @(
        "1527c705-839a-4832-9118-54d4bd6a0c89", "aarsvc", "accessibility", "accessibility_cursors", "accessibility_magnifier",
        "accessibility_narrator", "accounthealth", "aclui32", "actioncenter", "activedirectory", "adamclient", "afunix",
        "appv", "apxunit", "asimov", "assembly.net", "assignedaccess", "audit", "auditmode", "autochk32", "autofstx",
        "autoplay", "axinstall", "azman", "azman32", "azuread", "backgroundmediaplayer32", "backup", "bfs", "bingsearch",
        "bootmanagerpcat", "branchcacheclient", "c5e2524a-ea46-4f67-841f-6a9465d9d515", "captureservice", "cdosys",
        "ceip", "cellulartime", "certmgr32", "certutil32", "cimfs", "clip", "clipboardusersvc", "clipchamp.clipchamp",
        "clouddesktop", "clouddownload", "cloudid", "cloudnotifications", "comlegacyole32", "commmc", "commmc32",
        "compluseventsystem", "complussysapp", "compmgmt32", "componentpackagesupport", "consentux", "containers",
        "copilotpwa", "datacenterbridging", "dcsvc", "desktopactivitymoderator", "desktopimgdownldr", "devicecenter",
        "deviceguard", "devicepicker", "deviceregionmaintenance", "deviceupdatecenter", "devmgmt32", "devquerybroker",
        "dhcpclient32", "diagnostics", "directaccess", "directml", "diskdiagnosis", "diskmgmt32", "diskquota32",
        "diskraid", "diskusage", "displayswitch", "dnsclient32", "domainclientsvc", "driver_c_proximity.inf",
        "driver_hidtelephonydriver.inf", "driververifier", "driververifier32", "dvdplay", "dynamiclighting",
        "e2a4f912-2574-4a75-9bb0-0d023378592b", "easeofaccessthemes", "edgehtml32", "edgewebviewlegacy", "edit",
        "editiontransmogrifier", "editiontransmogrifier32", "efsfeature", "embeddedexperience", "embeddedmode",
        "encprovider", "enhancedstorage", "entappsvc", "enterpriseclientsync", "enterprisedataprotection", "enttempctrl",
        "errorreporting", "esentutil32", "eudcedit", "eventtracing", "eventviewer32", "explorer32",
        "f46d4000-fd22-4db4-ac8e-4e1ddde828fe", "facerecognition", "fciclient", "fclip", "fdphost", "filehistory",
        "filerevocationmanager", "filetrace", "firstlogonanim", "flipgridpwa", "folderredirection", "font_arialblack",
        "font_bahnschrift", "font_calibri", "font_cambria", "font_cambria_regular", "font_candara", "font_comicsansms",
        "font_constantia", "font_corbel", "font_courier", "font_ebrima", "font_ebrimabold", "font_fixed",
        "font_franklingothic", "font_gabriola", "font_georgia", "font_impact", "font_inkfree", "font_javanesetext",
        "font_lucidasans", "font_malgungothic", "font_malgungothicbold", "font_malgungothicsemilight",
        "font_microsofthimalaya", "font_microsoftjhengheibold", "font_microsoftjhengheilight", "font_microsoftyaheibold",
        "font_microsoftyaheilight", "font_mingliub", "font_msgothic", "font_mvboli", "font_myanmartext",
        "font_myanmartextbold", "font_newtailue", "font_newtailuebold", "font_oem", "font_palatinolinotype",
        "font_phagspa", "font_phagspabold", "font_sans_serif_collection", "font_segoe_ui_variable", "font_segoeprint",
        "font_segoeprintbold", "font_segoescript", "font_simsun", "font_simsunb", "font_sitka", "font_small",
        "font_sylfaen", "font_system", "font_taile", "font_tailebold", "font_trebuchetms", "font_vector",
        "font_verdana", "font_webdings", "font_yibaiti", "font_yugothic", "font_yugothicbold", "font_yugothiclight",
        "font_yugothicmedium", "fontpreviewer32", "frameservernet", "fsmgmt", "fsmgmt32", "gameexplorer",
        "gameinputsvc", "graphicsperfsvc", "guardedhost", "hbaapi", "help", "helpsupport", "hotpatch", "hwreqchk",
        "hwsupport_floppy", "hwsupport_infrared", "hwsupport_internetprintingclient", "hwsupport_modemsettings",
        "hwsupport_telephony", "hwsupport_tv", "hyperv", "icu32", "iis", "ikeext", "imapiv232", "inputservice32",
        "inputswitchtoasthandler", "inputviewexperience", "insiderhub", "installshieldwow64", "internetexplorer",
        "internetexplorer32", "ipt", "ipxlatcfg", "iscsi", "isoburn", "isolatedusermode", "kerberos32", "kerneldebug",
        "la57", "langafrikaans", "langalbanian", "langamharic", "langarabic", "langarmenian", "langassamese",
        "langazerbaijani", "langbasque", "langbelarusian", "langbengali_india", "langbosnian", "langbulgarian",
        "langcatalan", "langcherokee", "langchineses", "langcroatian", "langczech", "langdanish", "langdutch",
        "langenglishgb", "langestonian", "langfilipino", "langfinnish", "langfrench", "langfrenchcanadian",
        "langgalician", "langgeorgian", "langgerman", "langgreek", "langgujarati", "langhebrew", "langhindi",
        "langhungarian", "langicelandic", "langindonesian", "langirish", "langitalian", "langkannada", "langkazakh",
        "langkhmer", "langkonkani", "langlao", "langlatvian", "langlithuanian", "langluxembourgish", "langmacedonian",
        "langmalay_malaysia", "langmalayalam", "langmaltese", "langmaori", "langmarathi", "langnepali",
        "langnorwegian", "langodia", "langpersian", "langpolish", "langportuguesebr", "langportuguesept",
        "langpunjabi", "langquechua", "langromanian", "langrussian", "langscottish", "langserbian", "langslovak",
        "langslovenian", "langspanish", "langswedish", "langtamil", "langtatar", "langtelugu", "langthai",
        "langturkish", "langukrainian", "langurdu", "languyghur", "languzbek", "langvalencian", "langvietnamese",
        "langwelsh", "laps", "lcu", "livecaptions", "location", "lockscreens", "lpasvc", "lusrmgr32", "lxss",
        "manifestbackup", "mapcontrol", "mcmsvc", "mediacodec", "mediacodec32", "mediafoundation32", "mediaplayer",
        "mediaplayer32", "mediaplayernetworksharing", "mediaplayernetworksharing32", "mediastreaming",
        "mediastreamingreceiver", "mediastreamingtransmitter", "memorydiagnostic", "messagingsvc",
        "microsoft.accountscontrol", "microsoft.applicationcompatibilityenhancements", "microsoft.asynctextservice",
        "microsoft.bingnews", "microsoft.bingsearch", "microsoft.bingweather", "microsoft.creddialoghost",
        "microsoft.ecapp", "microsoft.gethelp", "microsoft.lockapp", "microsoft.microsoftedge",
        "microsoft.microsoftedge.stable", "microsoft.microsoftedgedevtoolsclient", "microsoft.microsoftofficehub",
        "microsoft.microsoftsolitairecollection", "microsoft.microsoftstickynotes", "microsoft.outlookforwindows",
        "microsoft.paint", "microsoft.powerautomatedesktop", "microsoft.screensketch", "microsoft.sechealthui",
        "microsoft.todos", "microsoft.vp9videoextensions", "microsoft.webmediaextensions", "microsoft.webpimageextension",
        "microsoft.win32webviewhost", "microsoft.windows.apprep.chxapp", "microsoft.windows.assignedaccesslockapp",
        "microsoft.windows.capturepicker", "microsoft.windows.contentdeliverymanager", "microsoft.windows.devhome",
        "microsoft.windows.narratorquickstart", "microsoft.windows.oobenetworkcaptiveportal",
        "microsoft.windows.oobenetworkconnectionflow", "microsoft.windows.parentalcontrols",
        "microsoft.windows.peopleexperiencehost", "microsoft.windows.photos", "microsoft.windows.pinningconfirmationdialog",
        "microsoft.windows.secureassessmentbrowser", "microsoft.windows.xgpuejectdialog", "microsoft.windowsalarms",
        "microsoft.windowscalculator", "microsoft.windowscamera", "microsoft.windowsfeedbackhub",
        "microsoft.windowsnotepad", "microsoft.windowssoundrecorder", "microsoft.windowsterminal", "microsoft.yourphone",
        "microsoft.zunemusic", "microsoftcorporationii.quickassist", "microsoftwindows.client.aix",
        "microsoftwindows.client.coreai", "microsoftwindows.client.webexperience", "microsoftwindows.crossdevice",
        "midi", "midi2", "migwiz", "mixedreality", "mmc32", "mmga", "mobiledevicemanagement", "mobilepc",
        "mobilepc_location", "mobilepc_networkprojection", "mobilepc_sensors", "mpe", "mpeg2splitter", "mptf",
        "msdtc", "msteams", "mtf", "multipointconnector", "naturalauthentication", "naturallanglegacy", "ncdauto",
        "ndiscap", "ndisimplat", "ndu", "netbios", "netcenter", "netcmd32", "netprofile32", "netqos", "netsh32",
        "nettopology", "nfc", "nfsclient", "notificationintelligenceplatform", "nowplaying", "offlinefiles",
        "onedrive", "openssh", "optionalfeatures", "osk_acc", "oskthemes", "otherthemes", "outlookpwa", "payments",
        "pdfreader", "penservice", "perfmon", "performancerecorder", "perftools", "phonesvc", "photocodec32",
        "photoviewer32", "pickerhost32", "picturepassword", "pimindexmaintenancesvc", "pktmon", "pla", "pluton",
        "pos", "powershellise32", "print3d32", "printmgmt", "printtopdf", "printworkflow", "projfs", "proquota",
        "proximity", "pushnotificationssvc", "pushtoinstall", "quiethours", "rasauto", "rdc", "rdmaping",
        "rdpclient32", "rdpserver", "rdpserverlic", "readyboost", "refs", "regedit32", "reliabilityanalysis",
        "remoteactivex32", "remoteassistance", "remotefx", "remoteportredirector", "remoteregistry", "retaildemo",
        "rightsmanagement", "rotationmanager", "rpclocator", "ruxim", "screensavers", "scripto", "search",
        "securestartup", "securitycenter", "sendmail", "sens", "servicesmmc32", "settingsync", "sharedexperiences",
        "sharedpc", "sharehost32", "sharemediacpl", "sharetargets32", "shellappruntime", "sihclient", "simpletcp",
        "sleepstudy", "smartactionplatform", "smbdirect", "smbv1", "smbwitnessclientapi", "sndvol", "sndvol32",
        "sorting", "soundsdefault", "soundthemes", "soundwire", "sourcessxsdir", "spellchecking", "srumon",
        "sstackwow64", "startexperiencesapp", "stepsrecorder", "storagemanagement", "storagemanagement32",
        "storageqos", "storagespaces", "sudo", "supportdir", "sustainabilityservice", "symboliclinks", "synccenter",
        "sysprep", "systemreset", "systemrestore", "tabletextservice", "tabletpc", "targetedcontent32",
        "taskmanager32", "taskschdmsc32", "telnetclient", "tempcache", "textprediction", "tftpclient",
        "tieringengine", "timetraveldebugger", "tpmmmc32", "troubleshootingsvc", "uev", "unexpectedcodepath",
        "universalprintsvc", "upnp", "userchoiceprotection", "userdatasvc", "userdeviceregistration", "vbscript32",
        "voiceaccess", "vss", "waasassessment", "wallet", "wallpapers", "warpjitsvc", "wcn", "webcamexperience",
        "webclient", "webthreatdefense", "wfmmc32", "whesvc", "widgetsplatformruntimeapp", "wificloudstore",
        "wifinetworkmanager", "winai", "windows.cbspreview", "windows.devicesflow32", "windowsglobalization32",
        "windowstogo", "windowsupdate", "wini3c", "winocr", "winre", "winresume", "winrm", "winsat", "winsxs",
        "wpdbusenum", "wuqisvc", "ztdns"
    )

    # Preset-based removal lists
    $privacyComponents = $allComponents | Where-Object { $_ -in @("asimov", "ceip", "microsoft.bingnews", "microsoft.bingweather") }
    $gamingComponents = $privacyComponents + @("mediaplayer", "microsoft.windows.photos")
    $liteComponents = $gamingComponents + @("accessibility", "internetexplorer", "onedrive")
    $ultraliteComponents = $allComponents

    # Preserve user-selected components
    if ($KeepStore) { $ultraliteComponents = $ultraliteComponents | Where-Object { $_ -notlike "*windowsstore*" } }
    if ($KeepXbox) { $ultraliteComponents = $ultraliteComponents | Where-Object { $_ -notlike "*xbox*" } }
    if ($KeepDefender) { $ultraliteComponents = $ultraliteComponents | Where-Object { $_ -notlike "*sechealthui*" } }
    if ($KeepEdge) { $ultraliteComponents = $ultraliteComponents | Where-Object { $_ -notlike "*microsoftedge*" } }
    if ($KeepWindowsUpdate) { $ultraliteComponents = $ultraliteComponents | Where-Object { $_ -notlike "*windowsupdate*" } }

    # Select components based on preset
    $componentsToRemove = switch ($Preset) {
        "Privacy" { $privacyComponents }
        "Gaming" { $gamingComponents }
        "Lite" { $liteComponents }
        "Ultralite" { $ultraliteComponents }
        default { $liteComponents }
    }

    # Map to DISM/wimlib actions
    $featureMap = @{
        "accessibility" = "Accessibility"
        "internetexplorer" = "Internet-Explorer-Optional"
        "mediaplayer" = "Media-WindowsMediaPlayer"
        "winai" = "Microsoft-Windows-MachineLearning"
        "pos" = "Microsoft-Windows-PointOfService"
        "search" = "Microsoft-Windows-SearchEngine"
        "windowsupdate" = "Microsoft-Windows-WindowsUpdateClient"
    }
    $appMap = @{
        "microsoft.bingnews" = "Microsoft.BingNews"
        "microsoft.bingweather" = "Microsoft.BingWeather"
        "microsoft.windows.photos" = "Microsoft.Windows.Photos"
        "microsoft.sechealthui" = "Microsoft.SecHealthUI"
        "microsoft.microsoftedge.stable" = "Microsoft.MicrosoftEdge.Stable"
    }
    $fileMap = @{
        "font_calibri" = "Windows\Fonts\calibri*.ttf"
        "font_verdana" = "Windows\Fonts\verdana*.ttf"
    }

    # Mount WIM with wimlib
    $mountPoint = "$MountDir\wim"
    New-Item -ItemType Directory -Path $mountPoint -Force
    Write-Host "Mounting WIM with wimlib..."
    & $WimlibExe mount $WimFile $Index $mountPoint --allow-other

    # Remove features (use DISM for compatibility)
    foreach ($component in $componentsToRemove) {
        if ($featureMap.ContainsKey($component)) {
            $featureName = $featureMap[$component]
            Write-Host "Removing feature: $featureName"
            try {
                dism /Image:$mountPoint /Disable-Feature /FeatureName:$featureName /Quiet /NoRestart
            } catch {
                Write-Warning "Failed to remove feature ${featureName}: $($_.Exception.Message)"
            }
        }
    }

    # Remove apps
    foreach ($component in $componentsToRemove) {
        if ($appMap.ContainsKey($component)) {
            $appName = $appMap[$component]
            Write-Host "Removing app: $appName"
            try {
                dism /Image:$mountPoint /Remove-ProvisionedAppxPackage /PackageName:$appName /Quiet
            } catch {
                Write-Warning "Failed to remove app ${appName}: $($_.Exception.Message)"
            }
        }
    }

    # Remove files (e.g., fonts, drivers)
    foreach ($component in $componentsToRemove) {
        if ($fileMap.ContainsKey($component)) {
            $filePattern = $fileMap[$component]
            Write-Host "Removing files: $filePattern"
            Get-ChildItem -Path "$mountPoint\$filePattern" -ErrorAction SilentlyContinue | Remove-Item -Force
        }
    }

    # Optimize WinSxS (wimlib rebuild)
    Write-Host "Optimizing WinSxS..."
    & $WimlibExe optimize $WimFile --rebuild --compact

    # Unmount WIM
    Write-Host "Unmounting WIM..."
    & $WimlibExe unmount $mountPoint --commit
}

# Function to apply registry tweaks
function Apply-Tweaks {
    param ($MountDir)

    $tweaks = @{
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization" = @{
            "AppsUseLightTheme" = 1
            "SystemUsesLightTheme" = 1
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" = @{
            "ConfigureChatAutoInstall" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Explorer" = @{
            "EnthusiastMode" = 1
            "DisableAutoplay" = 1
            "HideDrivesWithNoMedia" = 1
            "HideFileExt" = 0
            "Hidden" = 1
            "ShowSuperHidden" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Power" = @{
            "HiberbootEnabled" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\DataCollection" = @{
            "AllowTelemetry" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CloudContent" = @{
            "DisableWindowsConsumerFeatures" = 1
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
            "SilentInstalledAppsEnabled" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\TrainedDataStore" = @{
            "HarvestContacts" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Settings" = @{
            "AcceptedPrivacyPolicy" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Start" = @{
            "HideSwitchAccount" = 1
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\System" = @{
            "HideFastUserSwitching" = 1
            "EnableFirstLogonAnimation" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" = @{
            "BypassNRO" = 1
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\UserGpuPreferences" = @{
            "DirectXUserGlobalSettings" = "VRROptimizeEnable=0"
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdateTasks" = @{
            "DevHomeUpdate" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\UAC" = @{
            "ConsentPromptBehaviorUser" = 0
        }
        "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" = @{
            "SearchOrderConfig" = 0
            "ExcludeWUDriversInQualityUpdate" = 1
            "AUOptions" = 2
        }
    }

    $regPath = Join-Path $MountDir "Windows\System32\config\SOFTWARE"
    foreach ($key in $tweaks.Keys) {
        foreach ($name in $tweaks[$key].Keys) {
            Write-Host "Applying tweak: $key\$name"
            try {
                reg load HKLM\WIM_HKLM_SOFTWARE $regPath | Out-Null
                Set-ItemProperty -Path $key -Name $name -Value $tweaks[$key][$name] -ErrorAction Stop
                reg unload HKLM\WIM_HKLM_SOFTWARE | Out-Null
            } catch {
                Write-Warning "Failed to apply tweak ${key}\${name}: $($_.Exception.Message)"
            }
        }
    }
}

# Main script
Write-Host "Windows ISO Stripper Script (wimlib-based, NTLite Preset)"

# Setup tools
$wimlibExe = Install-Wimlib
$oscdimgExe = Install-OscdimgLite
$oscdimgDir = "$env:TEMP\oscdimg"

# Prompt for ISO path
$isoPath = Read-Host "Enter the full path to the Windows ISO (e.g., C:\ISOs\Win11_25H2.iso)"
if (-not (Test-Path $isoPath)) {
    Write-Error "Invalid ISO path."
    exit
}

# Prompt for preset
Write-Host "Select preset:"
Write-Host "1. Privacy (removes telemetry)"
Write-Host "2. Gaming (optimizes for performance)"
Write-Host "3. Lite (removes non-essential features)"
Write-Host "4. Ultralite (maximal stripping, ~1.5GB)"
$presetChoice = Read-Host "Enter number (1-4)"
$preset = switch ($presetChoice) {
    "1" { "Privacy" }
    "2" { "Gaming" }
    "3" { "Lite" }
    "4" { "Ultralite" }
    default { "Lite" }
}

# Prompt for components to keep
$keepStore = (Read-Host "Keep Microsoft Store? (y/n)") -eq "y"
$keepXbox = (Read-Host "Keep Xbox apps? (y/n)") -eq "y"
$keepDefender = (Read-Host "Keep Windows Defender? (y/n)") -eq "y"
$keepEdge = (Read-Host "Keep Edge Chromium? (y/n)") -eq "y"
$keepWindowsUpdate = (Read-Host "Keep Windows Update? (y/n)") -eq "y"

# Mount ISO
$isoMountPoint = Mount-ISO -IsoPath $isoPath
Extract-BootFiles -IsoMountPoint $isoMountPoint -OscdimgDir $oscdimgDir
$wimFile, $index = Get-WimFile -IsoMountPoint $isoMountPoint -WimlibExe $wimlibExe

# Create temporary mount directory
$mountDir = "C:\Mount"
if (-not (Test-Path $mountDir)) { New-Item -ItemType Directory -Path $mountDir }

# Remove components
Write-Host "Removing components based on $preset preset..."
Remove-Components -MountDir $mountDir -WimlibExe $wimlibExe -WimFile $wimFile -Index $index -Preset $preset -KeepStore $keepStore -KeepXbox $keepXbox -KeepDefender $keepDefender -KeepEdge $keepEdge -KeepWindowsUpdate $keepWindowsUpdate

# Apply tweaks
Write-Host "Applying registry tweaks..."
Apply-Tweaks -MountDir $mountDir

# Create new ISO
$newIsoPath = Join-Path (Split-Path $isoPath -Parent) "Stripped_Win11_25H2.iso"
Write-Host "Creating new ISO at $newIsoPath..."
& $oscdimgExe -m -o -u2 -udfver102 -bootdata:"2#p0,e,b$oscdimgDir\etfsboot.com#pEF,e,b$oscdimgDir\efisys.bin" $isoMountPoint $newIsoPath

# Dismount ISO
Write-Host "Dismounting ISO..."
Dismount-DiskImage -ImagePath $isoPath

Write-Host "Done! New ISO created at $newIsoPath"
Write-Warning "Test in a VM - aggressive removals may cause instability."