#Requires -RunAsAdministrator
# AdBlocker.ps1 - System-wide ad blocker for Windows using DNS policy and persistent routes
# Note: Per https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/apply-filters-on-dns-queries,
#       blocking with NXDOMAIN is preferred, but client-side DnsPolicyConfig only supports IP redirection (127.0.0.1).

# Configuration
$FilterLists = @(
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://filters.adtidy.org/windows/filters/2.txt"  # AdGuard Base filter
)
$CustomFilterDomains = @(
    # Add specific ad domains here if needed after Network tab inspection
)
$CustomIPSubnets = @(
    # Add specific ad server IP subnets if identified
)
$DnsPolicyKey = "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\BlockAdDomains"
$RouteKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
$BlockedDomains = [System.Collections.Generic.List[string]]::new()
$BlockedIPs = [System.Collections.Generic.List[string]]::new()
$UnblockedAdsLog = "$env:TEMP\UnblockedAds.txt"
$UpdateIntervalHours = 24
$LogFile = "$env:TEMP\AdBlocker.log"
$DebugMode = $true  # Enable for verbose logging

# PAC Regex Rules from BlockAds.pac
$adDomainRegex = '^(?:.*[-_.])?(ads?|adv(ert(s|ising)?)?|banners?|track(er|ing|s)?|beacons?|doubleclick|adservice|adnxs|adtech|googleads|gads|adwords|partner|sponsor(ed)?|click(s|bank|tale|through)?|pop(up|under)s?|promo(tion)?|market(ing|er)?|affiliates?|metrics?|stat(s|counter|istics)?|analytics?|pixel(s)?|campaign|traff(ic|iq)|monetize|syndicat(e|ion)|revenue|yield|impress(ion)?s?|conver(sion|t)?|audience|target(ing)?|behavior|profil(e|ing)|telemetry|survey|poll|outbrain|taboola|quantcast|scorecard|omniture|comscore|krux|bluekai|exelate|adform|adroll|rubicon|vungle|inmobi|flurry|mixpanel|heap|amplitude|optimizely|bizible|pardot|hubspot|marketo|eloqua|salesforce|media(math|net)|criteo|appnexus|turn|adbrite|admob|adsonar|adscale|zergnet|revcontent|mgid|nativeads|contentad|displayads|bannerflow|adblade|adcolony|chartbeat|newrelic|pingdom|gauges|kissmetrics|webtrends|tradedesk|bidder|auction|rtb|programmatic|splash|interstitial|overlay)\.'
$adUrlRegex = '(?:\/(?:adcontent|img\/adv|web\-ad|iframead|contentad|ad\/image|video\-ad|stats\/event|xtclicks|adscript|bannerad|googlead|adhandler|adimages|embed\-log|adconfig|tracking\/track|tracker\/track|adrequest|nativead|adman|advertisement|adframe|adcontrol|adoverlay|adserver|adsense|google\-ads|ad\-banner|banner\-ad|campaign\/advertiser|adplacement|adblockdetect|advertising|admanagement|adprovider|adrotation|ad Ascendingly |adtop|adbottom|adleft|adright|admiddle|adlarge|adsmall|admicro|adunit|adcall|adlog|adcount|adserve|adsrv|adsys|adtrack|adview|adwidget|adzone|banner\/adv|google_tag|image\/ads|sidebar\-ads|footer\-ads|top\-ads|bottom\-ads|new\-ads|search\-ads|lazy\-ads|responsive\-ads|dynamic\/ads|external\/ads|mobile\-ads|house\-ads|blog\/ads|online\/ads|pc\/ads|left\-ads|right\-ads|ads\/square|ads\/text|ads\/html|ads\/js|ads\.php|ad\.js|ad\.css|\?affiliate=|\?advertiser=|\&adspace=|\&adserver=|\&adgroupid=|\&adpageurl=|\.adserve|\.ads\d|\.adspace|\.adsense|\.adserver|\.google\-ads|\.banner\-ad|\.ad\-banner|\.adplacement|\.advertising|\.admanagement|\.adprovider|\.adrotation|\.adtop|\.adbottom|\.adleft|\.adright|\.admiddle|\.adlarge|\.adsmall|\.admicro|\.adunit|\.adcall|\.adlog|\.adcount|\.adserve|\.adsrv|\.adsys|\.adtrack|\.adview|\.adwidget|\.adzone))'
$adSubdomainRegex = '^(?:adcreative(s)?|imageserv|media(mgr)?|stats|switch|track(2|er)?|view|ad(s)?\d{0,3}|banner(s)?\d{0,3}|click(s)?\d{0,3}|count(er)?\d{0,3}|servedby\d{0,3}|toolbar\d{0,3}|pageads\d{0,3}|pops\d{0,3}|promos\d{0,3})\.'
$adWebBugRegex = '(?:\/(?:1|blank|b|clear|pixel|transp|spacer)\.gif|\.swf)$'

# Check if running as Administrator
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Logging function
function Write-Log {
    param ($Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "$Timestamp - $Message"
}

# Log unblocked ad domains for reporting
function Log-UnblockedAd {
    param ($Domain)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - Unblocked ad domain: $Domain" | Out-File -FilePath $UnblockedAdsLog -Append -Encoding UTF8
}

# Ensure DNS Client service is running
function Initialize-DnsService {
    Write-Log "Ensuring DNS Client service is running..."
    try {
        $service = Get-Service -Name Dnscache -ErrorAction Stop
        if ($service.Status -ne "Running") {
            Start-Service -Name Dnscache -ErrorAction Stop
            Set-Service -Name Dnscache -StartupType Automatic -ErrorAction Stop
        }
        Write-Log "DNS Client service is running."
    } catch {
        Write-Log "Error starting DNS Client service: $_"
    }
}

# Flush DNS cache
function Flush-DnsCache {
    Write-Log "Flushing DNS cache..."
    try {
        ipconfig /flushdns | Out-Null
        Write-Log "DNS cache flushed successfully."
    } catch {
        Write-Log "Error flushing DNS cache: $_"
    }
}

# Check scheduled task status
function Check-ScheduledTaskStatus {
    Write-Log "Checking scheduled task status..."
    try {
        $task = Get-ScheduledTask -TaskPath "\AdBlocker\" -TaskName "AdBlockerUpdate" -ErrorAction Stop
        $taskInfo = Get-ScheduledTaskInfo -TaskPath "\AdBlocker\" -TaskName "AdBlockerUpdate" -ErrorAction Stop
        Write-Log "Scheduled task 'AdBlockerUpdate' is $($task.State). Last run: $($taskInfo.LastRunTime), Result: $($taskInfo.LastTaskResult)"
    } catch {
        Write-Log "Scheduled task not found or error checking status: $_"
    }
}

# Download and parse filter lists
function Update-FilterLists {
    Write-Log "Downloading filter lists..."
    $script:BlockedDomains.Clear()
    $domainCount = 0
    $urlRuleCount = 0
    $regexRuleCount = 0
    $exceptionCount = 0
    $pacRegexCount = 0
    $exceptionDomains = [System.Collections.Generic.List[string]]::new()

    # Curated test domains for PAC regex matching (from PAC blacklist and sample ad domains)
    $testDomains = @(
        "ads.forum.hr", "track.forum.hr", "adserver123.example.com", "banner.forum.hr",
        "doubleclick.net", "googlesyndication.com", "adnxs.com", "outbrain.com",
        "ads1.example.com", "track2.example.net", "pixel.example.com"
    ) + $blacklist

    # Test URLs for adUrlRegex and adWebBugRegex
    $testUrls = @(
        "http://example.com/ads/image/ad.jpg",
        "http://forum.hr/adcontent/script.js",
        "http://example.com/pixel.gif",
        "http://example.com/banner.swf",
        "http://forum.hr/tracking/track?affiliate=123"
    )

    foreach ($url in $FilterLists) {
        Write-Log "Attempting to download: $url"
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $lines = $response.Content -split "`n"
            $lineCount = $lines.Count
            Write-Log "Processing $lineCount lines from $url..."
            $index = 0
            foreach ($line in $lines) {
                $index++
                if ($DebugMode -and ($index % 5000 -eq 0)) {
                    Write-Log "Processed $index of $lineCount lines from $url"
                }
                # Skip comments and empty lines
                if ($line -match "^\s*#" -or $line -match "^\s*!" -or $line -match "^\s*$") {
                    continue
                }
                # Exception rules (e.g., @@||domain^)
                if ($line -match "^@@\|\|([^\^/]+)\^") {
                    $domain = $Matches[1].Trim()
                    if ($domain) {
                        $exceptionDomains.Add($domain)
                        $exceptionCount++
                        if ($DebugMode) {
                            Write-Log "Added exception domain: $domain"
                        }
                    }
                }
                # Domain-based rules (e.g., ||domain^)
                elseif ($line -match "^\|\|([^\^/]+)\^") {
                    $domain = $Matches[1].Trim()
                    if ($domain -and -not $exceptionDomains.Contains($domain)) {
                        $script:BlockedDomains.Add($domain)
                        $domainCount++
                        if ($DebugMode) {
                            Write-Log "Added domain rule: $domain"
                        }
                    }
                }
                # URL-based rules (e.g., ||example.com/ads/*.js^)
                elseif ($line -match "^\|\|([^\^/]+)(/.*)?\^") {
                    $domain = $Matches[1].Trim()
                    if ($domain -and -not $exceptionDomains.Contains($domain)) {
                        $script:BlockedDomains.Add($domain)
                        $urlRuleCount++
                        if ($DebugMode) {
                            Write-Log "Added URL-based domain: $domain from rule: $line"
                        }
                    }
                }
                # Filter list regex rules (e.g., /adserver[0-9]+\./)
                elseif ($line -match "^/(.+)/") {
                    $regexPattern = $Matches[1]
                    try {
                        foreach ($testDomain in $testDomains) {
                            if ($testDomain -match $regexPattern) {
                                $domain = ($testDomain -split "\.")[1..($testDomain.Split(".").Length-1)] -join "."
                                if ($domain -and -not $exceptionDomains.Contains($domain)) {
                                    $script:BlockedDomains.Add($domain)
                                    $regexRuleCount++
                                    if ($DebugMode) {
                                        Write-Log "Added filter regex-matched domain: $domain from pattern: $regexPattern"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log "Error processing filter regex pattern ${regexPattern}: $_"
                    }
                }
            }
            Write-Log "Processed filter list: $url ($domainCount domains, $urlRuleCount URL rules, $regexRuleCount regex rules, $exceptionCount exceptions)"
        } catch {
            Write-Log "Failed to download or process ${url}: $_"
        }
    }

    # Apply PAC regex rules
    Write-Log "Applying PAC regex rules..."
    # adDomainRegex and adSubdomainRegex
    foreach ($testDomain in $testDomains) {
        try {
            if ($testDomain -match $adDomainRegex -or $testDomain -match $adSubdomainRegex) {
                $domain = ($testDomain -split "\.")[1..($testDomain.Split(".").Length-1)] -join "."
                if ($domain -and -not $exceptionDomains.Contains($domain)) {
                    $script:BlockedDomains.Add($domain)
                    $pacRegexCount++
                    if ($DebugMode) {
                        Write-Log "PAC adDomainRegex/adSubdomainRegex matched: $domain"
                    }
                }
            }
        } catch {
            Write-Log "Error processing PAC domain/subdomain regex for ${testDomain}: $_"
        }
    }

    # adUrlRegex and adWebBugRegex
    foreach ($testUrl in $testUrls) {
        try {
            if ($testUrl -match $adUrlRegex -or $testUrl -match $adWebBugRegex) {
                # Extract domain from URL
                $urlObj = [System.Uri]$testUrl
                $domain = $urlObj.Host
                if ($domain -and -not $exceptionDomains.Contains($domain)) {
                    $script:BlockedDomains.Add($domain)
                    $pacRegexCount++
                    if ($DebugMode) {
                        Write-Log "PAC adUrlRegex/adWebBugRegex matched: $domain from URL: $testUrl"
                    }
                }
            }
        } catch {
            Write-Log "Error processing PAC URL/webbug regex for ${testUrl}: $_"
        }
    }

    # Add custom filter domains
    foreach ($domain in $CustomFilterDomains) {
        if ($domain -and -not $exceptionDomains.Contains($domain)) {
            $script:BlockedDomains.Add($domain)
            $domainCount++
            Write-Log "Added custom domain: $domain"
        }
    }

    $script:BlockedDomains = [System.Linq.Enumerable]::ToList([string[]]($script:BlockedDomains | Sort-Object -Unique))
    Write-Log "Loaded $($script:BlockedDomains.Count) unique domains to block ($pacRegexCount from PAC regex rules)."
    Flush-DnsCache
}

# Resolve IPs for domains (increased to 1500 for better coverage)
function Resolve-AdServerIPs {
    Write-Log "Resolving IPs for known ad servers..."
    $script:BlockedIPs.Clear()
    $sampleDomains = $script:BlockedDomains | Select-Object -First 1500
    $index = 0
    foreach ($domain in $sampleDomains) {
        $index++
        if ($DebugMode) {
            Write-Log "Resolving IP for domain $index/$($sampleDomains.Count): $domain"
        }
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($domain) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            foreach ($ip in $ips) {
                $ipStr = $ip.ToString()
                $subnet = $ipStr -replace "\.\d+$", ".0"  # Assume /24 subnet
                $script:BlockedIPs.Add($subnet)
            }
            # Random delay to evade detection (0-100ms)
            Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 100)
        } catch {
            Write-Log "Failed to resolve IP for ${domain}: $_"
        }
    }
    # Add custom IP subnets
    foreach ($subnet in $CustomIPSubnets) {
        if ($subnet -match "^\d+\.\d+\.\d+\.\d+$") {
            $script:BlockedIPs.Add($subnet)
            Write-Log "Added custom IP subnet: $subnet"
        }
    }
    $script:BlockedIPs = [System.Linq.Enumerable]::ToList([string[]]($script:BlockedIPs | Sort-Object -Unique))
    Write-Log "Identified $($script:BlockedIPs.Count) unique IP subnets to block."
}

# Configure DNS policy in registry
function Set-DnsPolicy {
    Write-Log "Configuring DNS policy in registry..."
    try {
        # Create or clear DNS policy key
        if (-not (Test-Path $DnsPolicyKey)) {
            New-Item -Path $DnsPolicyKey -Force | Out-Null
        }
        New-Item -Path "$DnsPolicyKey\PolicyEntry" -Force | Out-Null

        # Set policy metadata
        Set-ItemProperty -Path $DnsPolicyKey -Name "Name" -Value "BlockAdDomains" -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "Key" -Value "PolicyEntry" -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "PolicyType" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "Version" -Value 2 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $DnsPolicyKey -Name "EntryType" -Value 1 -Type DWord -Force -ErrorAction Stop

        # Add sorted domains to policy
        $policyPath = "$DnsPolicyKey\PolicyEntry"
        $index = 0
        foreach ($domain in $script:BlockedDomains) {
            $index++
            if ($DebugMode -and ($index % 1000 -eq 0)) {
                Write-Log "Configured $index of $($script:BlockedDomains.Count) domains in DNS policy"
            }
            Set-ItemProperty -Path $policyPath -Name $domain -Value "127.0.0.1" -Force -ErrorAction Stop
            # Random delay to evade detection (0-200ms)
            Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 200)
        }
        Write-Log "Configured DNS policy with $($script:BlockedDomains.Count) domains."
    } catch {
        Write-Log "Error configuring DNS policy: $_"
    }
}

# Configure persistent routes
function Set-PersistentRoutes {
    Write-Log "Configuring persistent routes..."
    try {
        # Clear existing routes
        Get-Item -Path $RouteKey -ErrorAction SilentlyContinue | Get-ItemProperty | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -match "\d+\.\d+\.\d+\.\d+" } | ForEach-Object {
                Remove-ItemProperty -Path $RouteKey -Name $_.Name -ErrorAction SilentlyContinue
            }
        }

        # Add new routes
        foreach ($ip in $script:BlockedIPs) {
            $routeName = "$ip,255.255.255.0,0.0.0.0,1"
            Set-ItemProperty -Path $RouteKey -Name $routeName -Value "" -Force -ErrorAction Stop
            & route add $ip MASK 255.255.255.0 0.0.0.0 -p 2>&1 | Out-Null
        }
        Write-Log "Configured $($script:BlockedIPs.Count) persistent routes."
    } catch {
        Write-Log "Error configuring persistent routes: $_"
    }
}

# Schedule task for periodic updates
function Register-UpdateTask {
    Write-Log "Registering scheduled task for filter updates..."
    try {
        $taskName = "AdBlockerUpdate"
        $taskPath = "\AdBlocker\"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\AdBlocker.ps1`" -UpdateOnly"
        $trigger = New-ScheduledTaskTrigger -Daily -At "12:00AM"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-Log "Scheduled task registered."
    } catch {
        Write-Log "Error registering scheduled task: $_"
    }
}

# Main execution
function Main {
    param ([switch]$UpdateOnly)
    if (-not (Test-Admin)) {
        Write-Log "This script must be run as Administrator. Exiting."
        exit 1
    }
    Flush-DnsCache
    Initialize-DnsService
    Check-ScheduledTaskStatus
    Update-FilterLists
    Resolve-AdServerIPs
    Set-DnsPolicy
    Set-PersistentRoutes
    Flush-DnsCache
    if ($UpdateOnly) {
        Write-Log "Update-only mode completed. Exiting."
    } else {
        Register-UpdateTask
        Write-Log "AdBlocker initialized and configured. Exiting."
    }
}

# Check for update-only mode
if ($args -contains "-UpdateOnly") {
    Main -UpdateOnly
} else {
    Main
}

# PAC blacklist (for regex testing only, not directly added to BlockedDomains)
$blacklist = @(
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adserver.com",
    "fastclick.com", "adnxs.com", "adtech.com", "advertising.com", "atdmt.com",
    "quantserve.com", "omniture.com", "comscore.com", "scorecardresearch.com",
    "chartbeat.com", "newrelic.com", "pingdom.com", "kissmetrics.com", "webtrends.com",
    "tradedesk.com", "criteo.com", "appnexus.com", "turn.com", "adbrite.com", "admob.com",
    "adsonar.com", "adscale.com", "zergnet.com", "revcontent.com", "mgid.com",
    "nativeads.com", "contentad.com", "displayads.com", "bannerflow.com", "adblade.com",
    "adcolony.com", "outbrain.com", "taboola.com", "quantcast.com", "krux.com",
    "bluekai.com", "exelate.com", "adform.com", "adroll.com", "rubiconproject.com",
    "vungle.com", "inmobi.com", "flurry.com", "mixpanel.com", "heap.io", "amplitude.com",
    "optimizely.com", "bizible.com", "pardot.com", "hubspot.com", "marketo.com",
    "eloqua.com", "salesforce.com", "media.net", "247media.com", "247realmedia.com",
    "2o7.net", "3721.com", "180solutions.com", "zedo.com", "zango.com", "virtumundo.com",
    "valueclick.com", "vonna.com", "webtrendslive.com", "weatherbug.com", "webhancer.com",
    "websponsors.com", "xiti.com", "xxxcounter.com", "myway.com", "mysearch.com",
    "mygeek.com", "mycomputer.com", "moreover.com", "mspaceads.com", "mediaplex.com",
    "madserver.net", "netgravity.com", "networldmedia.net", "overture.com", "oingo.com",
    "ourtoolbar.com", "offeroptimizer.com", "offshoreclicks.com", "opistat.com",
    "opentracker.net", "paypopup.com", "paycounter.com", "popupsponsor.com",
    "popupmoney.com", "p2l.info", "pharmacyfarm.info", "popupad.net", "pharmacyheaven.biz",
    "qsrch.com", "quigo.com", "qckads.com", "realmedia.com", "radiate.com",
    "redsheriff.com", "realtracker.com", "readnotify.com", "searchx.cc", "sextracker.com",
    "sabela.com", "spywarequake.com", "spywarestrike.com", "searchmiracle.com",
    "starware.com", "starwave.com", "swirve.com", "spyaxe.com", "spylog.com",
    "search.com", "servik.com", "searchfuel.com", "search.com.com", "spyfalcon.com",
    "sitemeter.com", "statcounter.com", "sitestats.com", "superstats.com", "sitestat.com",
    "sexlist.com", "scaricare.ws", "speedera.net", "targetpoint.com", "tempx.cc",
    "topx.cc", "trafficsyndicate.com", "teknosurf.com", "timesink.com", "tradedoubler.com",
    "thecounter.com", "targetwords.com", "telecharger-en-francais.com",
    "trafficserverstats.com", "targetnet.com", "telecharger-soft.com", "thruport.com",
    "tdmy.com", "telecharger.ws", "tribalfusion.com", "utopiad.com", "web3000.com",
    "gratisware.com", "grandstreetinteractive.com", "gambling.com", "goclick.com",
    "gohip.com", "gator.com", "gmx.net", "hit-parade.com", "humanclick.com",
    "hotbar.com", "hpwis.com", "hitbox.com", "hpg.ig.com.br", "hpg.com.br",
    "hyperbanner.net", "hypermart.net", "intellitxt.com", "ivwbox.de", "imaginemedia.com",
    "imrworldwide.com", "inetinteractive.com", "insightexpressai.com", "inspectorclick.com",
    "internetfuel.com", "iwon.com", "imgis.com", "insightexpress.com", "intellicontact.com",
    "insightfirst.com", "just404.com", "kadserver.com", "linklist.cc", "linkexchange.com",
    "links4trade.com", "linkshare.com", "linksponsor.com", "link4ads.com", "livestat.com",
    "liveadvert.com", "linksynergy.com", "linksummary.com", "liteweb.net", "mtree.com",
    "malwarewipe.com", "marketscore.com", "maxserving.com", "mywebsearch.com",
    "nextlevel.com", "netster.com", "nastydollars.com", "pentoninteractive.com",
    "porntrack.com", "precisionclick.com", "freebannertrade.com", "focalink.com",
    "friendfinder.com", "flyswat.com", "firehunt.com", "flycast.com", "focalex.com",
    "flyingcroc.net", "falkag.net", "errorsafe.com", "esomniture.com", "eimg.com",
    "ezcybersearch.com", "erasercash.com", "extreme-dm.com", "ezgreen.com",
    "enliven.com", "eacceleration.com", "einets.com", "esthost.com", "euroclick.net",
    "clicktorrent.info", "count.cc", "click2net.com", "casalemedia.com",
    "channelintelligence.com", "clicktrade.com", "clickhype.com", "cpxinteractive.com",
    "coolwebsearch.com", "clrsch.com", "cj.com", "chickclick.com", "comclick.com",
    "cqcounter.com", "clicksor.com", "climaxbucks.com", "cometsystems.com",
    "clickfinders.com", "clickagents.com", "conducent.com", "clickability.com",
    "cjt1.net", "clickbank.net", "doubleclick.com", "direct-revenue.com",
    "decideinteractive.com", "drsnsrch.com", "directtrack.com", "dotbiz4all.com",
    "drmwrap.com", "domainsponsor.com", "download-software.us", "descarregar.net",
    "bannercommunity.de", "bpath.com", "bonzi.com", "bluestreak.com", "bannermall.com",
    "blogads.com", "bestoffersnetworks.com", "bannerhosts.com", "bfast.com", "bnex.com",
    "beesearch.info", "baixar.ws", "bannerconnect.net", "bargain-buddy.net", "atdmt.com",
    "adultadworld.com", "adlink.com", "ads360.com", "affiliatetargetad.com",
    "advertwizard.com", "adknowledge.com", "adsoftware.com", "andlotsmore.com",
    "aureate.com", "adbrite.com", "aavalue.com", "advertserve.com", "adsrve.com",
    "admaximize.com", "adultcash.com", "accessplugin.com", "adsonar.com", "adroar.com",
    "addr.com", "adrevolver.com", "akamaitechnologies.com", "amazingcounters.com",
    "allowednet.com", "ad-flow.com", "adflow.com", "alfaspace.net", "advance.net",
    "akamaitech.net", "akamai.net", "adbureau.net"
)


function Disable-DoH {
    Write-Host "Disabling DNS-over-HTTPS (DoH) for all major browsers..."

    # Chrome, Brave, Vivaldi, Opera (Chromium-based browsers using Google policies)
    $chromiumPaths = @(
        "HKLM:\Software\Policies\Google\Chrome",
        "HKLM:\Software\Policies\BraveSoftware\Brave",
        "HKLM:\Software\Policies\Vivaldi",
        "HKLM:\Software\Policies\Opera"
    )
    foreach ($path in $chromiumPaths) {
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String
    }

    # Microsoft Edge (Chromium)
    $edgePoliciesPath = "HKLM:\Software\Policies\Microsoft\Edge"
    if (!(Test-Path $edgePoliciesPath)) { New-Item -Path $edgePoliciesPath -Force | Out-Null }
    Set-ItemProperty -Path $edgePoliciesPath -Name "DnsOverHttpsMode" -Value "off" -Type String

    # Mozilla Firefox (per-profile config)
    $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilesPath) {
        Get-ChildItem -Directory $firefoxProfilesPath | ForEach-Object {
            $prefsFile = Join-Path $_.FullName "prefs.js"
            if (Test-Path $prefsFile) {
                if (-not (Select-String -Path $prefsFile -Pattern "network.trr.mode")) {
                    Add-Content -Path $prefsFile -Value 'user_pref("network.trr.mode", 5);'
                }
            }
        }
    }

    # Logging
    Write-Host "DoH has been disabled for supported browsers."
}

# Call the function
Disable-DoH
