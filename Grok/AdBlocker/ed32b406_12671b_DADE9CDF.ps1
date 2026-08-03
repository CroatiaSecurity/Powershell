#Requires -RunAsAdministrator
# AdBlocker.ps1 - System-wide ad blocker for Windows using DNS policy
# Converted from BlockAds.pac to block ads via DNS redirection to 127.0.0.1
# Author: Adapted from Gorstak's BlockAds.pac

# Configuration
$Whitelist = @(
    "forum.hr",
    "twitter.com",
    "x.com",
    "perplexity.ai",
    "mediafire.com",
    "apple.com",
    "schooner.com",
    "citibank.com",
    "ebay.com",
    "yahoo.com",
    "discord.com",
    "click.discord.com",
    "discordapp.com",
    "cdn.discordapp.com",
    "cdn.discord.app",
    "discord.gg",
    "discord.media",
    "discordapp.net",
    "media.discordapp.net",
    "discordstatus.com",
    "dis.gd",
    "discordcdn.com",
    "aliexpress.com",
    "tenor.com",
    "media.tenor.com"
)
$Blacklist = @(
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adserver.com",
    "fastclick.com",
    "adnxs.com",
    "adtech.com",
    "advertising.com",
    "atdmt.com",
    "quantserve.com",
    "omniture.com",
    "comscore.com",
    "scorecardresearch.com",
    "chartbeat.com",
    "newrelic.com",
    "pingdom.com",
    "kissmetrics.com",
    "webtrends.com",
    "tradedesk.com",
    "criteo.com",
    "appnexus.com",
    "turn.com",
    "adbrite.com",
    "admob.com",
    "adsonar.com",
    "adscale.com",
    "zergnet.com",
    "revcontent.com",
    "mgid.com",
    "nativeads.com",
    "contentad.com",
    "displayads.com",
    "bannerflow.com",
    "adblade.com",
    "adcolony.com",
    "outbrain.com",
    "taboola.com",
    "quantcast.com",
    "krux.com",
    "bluekai.com",
    "exelate.com",
    "adform.com",
    "adroll.com",
    "rubiconproject.com",
    "vungle.com",
    "inmobi.com",
    "flurry.com",
    "mixpanel.com",
    "heap.io",
    "amplitude.com",
    "optimizely.com",
    "bizible.com",
    "pardot.com",
    "hubspot.com",
    "marketo.com",
    "eloqua.com",
    "salesforce.com",
    "media.net",
    "247media.com",
    "247realmedia.com",
    "2o7.net",
    "3721.com",
    "180solutions.com",
    "zedo.com",
    "zango.com",
    "virtumundo.com",
    "valueclick.com",
    "vonna.com",
    "webtrendslive.com",
    "weatherbug.com",
    "webhancer.com",
    "websponsors.com",
    "xiti.com",
    "xxxcounter.com",
    "myway.com",
    "mysearch.com",
    "mygeek.com",
    "mycomputer.com",
    "moreover.com",
    "mspaceads.com",
    "mediaplex.com",
    "madserver.net",
    "netgravity.com",
    "networldmedia.net",
    "overture.com",
    "oingo.com",
    "ourtoolbar.com",
    "offeroptimizer.com",
    "offshoreclicks.com",
    "opistat.com",
    "opentracker.net",
    "paypopup.com",
    "paycounter.com",
    "popupsponsor.com",
    "popupmoney.com",
    "p2l.info",
    "pharmacyfarm.info",
    "popupad.net",
    "pharmacyheaven.biz",
    "qsrch.com",
    "quigo.com",
    "qckads.com",
    "realmedia.com",
    "radiate.com",
    "redsheriff.com",
    "realtracker.com",
    "readnotify.com",
    "searchx.cc",
    "sextracker.com",
    "sabela.com",
    "spywarequake.com",
    "spywarestrike.com",
    "searchmiracle.com",
    "starware.com",
    "starwave.com",
    "swirve.com",
    "spyaxe.com",
    "spylog.com",
    "search.com",
    "servik.com",
    "searchfuel.com",
    "search.com.com",
    "spyfalcon.com",
    "sitemeter.com",
    "statcounter.com",
    "sitestats.com",
    "superstats.com",
    "sitestat.com",
    "sexlist.com",
    "scaricare.ws",
    "speedera.net",
    "targetpoint.com",
    "tempx.cc",
    "topx.cc",
    "trafficsyndicate.com",
    "teknosurf.com",
    "timesink.com",
    "tradedoubler.com",
    "thecounter.com",
    "targetwords.com",
    "telecharger-en-francais.com",
    "trafficserverstats.com",
    "targetnet.com",
    "telecharger-soft.com",
    "tdmy.com",
    "telecharger.ws",
    "tribalfusion.com",
    "utopiad.com",
    "web3000.com",
    "gratisware.com",
    "grandstreetinteractive.com",
    "gambling.com",
    "goclick.com",
    "gohip.com",
    "gator.com",
    "gmx.net",
    "hit-parade.com",
    "humanclick.com",
    "hotbar.com",
    "hpwis.com",
    "hitbox.com",
    "hpg.ig.com.br",
    "hpg.com.br",
    "hyperbanner.net",
    "hypermart.net",
    "intellitxt.com",
    "ivwbox.de",
    "imaginemedia.com",
    "imrworldwide.com",
    "inetinteractive.com",
    "insightexpressai.com",
    "inspectorclick.com",
    "internetfuel.com",
    "iwon.com",
    "imgis.com",
    "insightexpress.com",
    "intellicontact.com",
    "insightfirst.com",
    "just404.com",
    "kadserver.com",
    "linklist.cc",
    "linkexchange.com",
    "links4trade.com",
    "linkshare.com",
    "linksponsor.com",
    "link4ads.com",
    "livestat.com",
    "liveadvert.com",
    "linksynergy.com",
    "linksummary.com",
    "liteweb.net",
    "mtree.com",
    "malwarewipe.com",
    "marketscore.com",
    "maxserving.com",
    "mywebsearch.com",
    "nextlevel.com",
    "netster.com",
    "nastydollars.com",
    "pentoninteractive.com",
    "porntrack.com",
    "precisionclick.com",
    "freebannertrade.com",
    "focalink.com",
    "friendfinder.com",
    "flyswat.com",
    "firehunt.com",
    "flycast.com",
    "focalex.com",
    "flyingcroc.net",
    "falkag.net",
    "errorsafe.com",
    "esomniture.com",
    "eimg.com",
    "ezcybersearch.com",
    "erasercash.com",
    "extreme-dm.com",
    "ezgreen.com",
    "enliven.com",
    "eacceleration.com",
    "einets.com",
    "esthost.com",
    "euroclick.net",
    "clicktorrent.info",
    "count.cc",
    "click2net.com",
    "casalemedia.com",
    "channelintelligence.com",
    "clicktrade.com",
    "clickhype.com",
    "cpxinteractive.com",
    "coolwebsearch.com",
    "clrsch.com",
    "cj.com",
    "chickclick.com",
    "comclick.com",
    "cqcounter.com",
    "clicksor.com",
    "climaxbucks.com",
    "cometsystems.com",
    "clickfinders.com",
    "clickagents.com",
    "conducent.com",
    "clickability.com",
    "cjt1.net",
    "clickbank.net",
    "doubleclick.com",
    "direct-revenue.com",
    "decideinteractive.com",
    "drsnsrch.com",
    "directtrack.com",
    "dotbiz4all.com",
    "drmwrap.com",
    "domainsponsor.com",
    "download-software.us",
    "descarregar.net",
    "bannercommunity.de",
    "bpath.com",
    "bonzi.com",
    "bluestreak.com",
    "bannermall.com",
    "blogads.com",
    "bestoffersnetworks.com",
    "bannerhosts.com",
    "bfast.com",
    "bnex.com",
    "beesearch.info",
    "baixar.ws",
    "bannerconnect.net",
    "bargain-buddy.net",
    "atdmt.com",
    "adultadworld.com",
    "adlink.com",
    "ads360.com",
    "affiliatetargetad.com",
    "advertwizard.com",
    "adknowledge.com",
    "adsoftware.com",
    "andlotsmore.com",
    "aureate.com",
    "adbrite.com",
    "aavalue.com",
    "advertserve.com",
    "adsrve.com",
    "admaximize.com",
    "adultcash.com",
    "accessplugin.com",
    "adsonar.com",
    "adroar.com",
    "addr.com",
    "adrevolver.com",
    "akamaitechnologies.com",
    "amazingcounters.com",
    "allowednet.com",
    "ad-flow.com",
    "adflow.com",
    "alfaspace.net",
    "advance.net",
    "akamaitech.net",
    "akamai.net",
    "adbureau.net"
)
$AdRegexes = @(
    "(?i)^(?:.*[-_.])?(ads?|adv(ert(s|ising)?)?|banners?|track(er|ing|s)?|beacons?|doubleclick|adservice|adnxs|adtech|googleads|gads|adwords|partner|sponsor(ed)?|click(s|bank|tale|through)?|pop(up|under)s?|promo(tion)?|market(ing|er)?|affiliates?|metrics?|stat(s|counter|istics)?|analytics?|pixel(s)?|campaign|traff(ic|iq)|monetize|syndicat(e|ion)|revenue|yield|impress(ion)?s?|conver(sion|t)?|audience|target(ing)?|behavior|profil(e|ing)|telemetry|survey|poll|outbrain|taboola|quantcast|scorecard|omniture|comscore|krux|bluekai|exelate|adform|adroll|rubicon|vungle|inmobi|flurry|mixpanel|heap|amplitude|optimizely|bizible|pardot|hubspot|marketo|eloqua|salesforce|media(math|net)|criteo|appnexus|turn|adbrite|admob|adsonar|adscale|zergnet|revcontent|mgid|nativeads|contentad|displayads|bannerflow|adblade|adcolony|chartbeat|newrelic|pingdom|gauges|kissmetrics|webtrends|tradedesk|bidder|auction|rtb|programmatic|splash|interstitial|overlay)\.",
    "(?i)^(?:adcreative(s)?|imageserv|media(mgr)?|stats|switch|track(2|er)?|view|ad(s)?\d{0,3}|banner(s)?\d{0,3}|click(s)?\d{0,3}|count(er)?\d{0,3}|servedby\d{0,3}|toolbar\d{0,3}|pageads\d{0,3}|pops\d{0,3}|promos\d{0,3})\."
)
$LogFile = "$env:TEMP\AdBlocker.log"
$MaxDomains = 10000  # Cap domains to reduce runtime
$DebugMode = $false

function Write-Log {
    param ($Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($DebugMode) {
        Write-Host "$Timestamp - $Message"
    }
}

$BlockedDomains = [System.Collections.Generic.List[string]]::new()

function Initialize-BlockedDomains {
    Write-Log "Initializing blocked domains from PAC blacklist and regex rules..."
    $script:BlockedDomains.Clear()
    $domainCount = 0

    # Add blacklist domains
    foreach ($domain in $Blacklist) {
        if ($domain -and $domain -notmatch "^\d+$" -and $domain -notmatch "^[a-zA-Z]$" -and $domain -notin $Whitelist -and $domainCount -lt $MaxDomains) {
            # Handle wildcard patterns in blacklist
            if ($domain -match '^\*\.') {
                $baseDomain = $domain -replace '^\*\.', ''
                $script:BlockedDomains.Add($baseDomain)
                $domainCount++
            } else {
                $script:BlockedDomains.Add($domain)
                $domainCount++
            }
        }
    }
    Write-Log "Added $domainCount domains from blacklist."

    # Optionally expand with regex (limited to avoid performance hit)
    $seedDomains = $script:BlockedDomains | Select-Object -First 1000
    foreach ($domain in $seedDomains) {
        foreach ($regex in $AdRegexes) {
            if ($domain -match $regex -and $domain -notin $Whitelist -and $domainCount -lt $MaxDomains) {
                $script:BlockedDomains.Add($domain)
                $domainCount++
            }
        }
    }
    $script:BlockedDomains = [System.Linq.Enumerable]::ToList([string[]]($script:BlockedDomains | Sort-Object -Unique))
    Write-Log "Loaded $($script:BlockedDomains.Count) unique domains."
    if ($script:BlockedDomains.Count -eq 0) {
        Write-Log "Error: No domains loaded. Aborting."
        throw "No domains loaded from PAC rules"
    }
}

function Set-DnsPolicy {
    Write-Log "Configuring DNS policy in registry..."
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    $batchSize = 1000
    $configuredCount = 0
    $batches = [math]::Ceiling($script:BlockedDomains.Count / $batchSize)
    for ($i = 0; $i -lt $batches; $i++) {
        $batch = $script:BlockedDomains | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($domain in $batch) {
            try {
                $ruleName = "AdBlocker-$domain"
                $rulePath = "$registryPath\$ruleName"
                if (-not (Test-Path $rulePath)) {
                    New-Item -Path $rulePath -Force | Out-Null
                }
                Set-ItemProperty -Path $rulePath -Name "Name" -Value $domain -Force
                Set-ItemProperty -Path $rulePath -Name "IPAddress" -Value "127.0.0.1" -Force
                Set-ItemProperty -Path $rulePath -Name "AutoConfig" -Value 0 -Type DWord -Force
                $configuredCount++
            } catch {
                Write-Log "Failed to configure DNS policy for ${domain}: $_"
            }
        }
        Write-Log "Configured $configuredCount of $($script:BlockedDomains.Count) domains in DNS policy"
    }
    Write-Log "Configured DNS policy with $configuredCount domains."
}

function Main {
    try {
        Write-Log "Starting AdBlocker..."
        Write-Host "Starting AdBlocker..."
        Initialize-BlockedDomains
        Set-DnsPolicy
        Write-Log "AdBlocker initialized and configured. Exiting."
        Write-Host "AdBlocker initialized and configured."
    } catch {
        Write-Log "Fatal error: $_"
        Write-Host "Error: $_"
        exit 1
    }
}

# Execute
Main