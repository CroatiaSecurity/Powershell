// Ads-Blocking Proxy Auto-Configuration (PAC) File
// Author: Gorstak
// Modified to block URLs containing "xss" and updated blacklist

// Configuration Variables
var normal = "DIRECT";              // Default pass-through for non-blocked traffic
var blackhole = "PROXY 127.0.0.1:3421"; // Blackhole proxy for blocked traffic
var isEnabled = 1;                  // Toggle for enabling/disabling ad-blocking (1 = enabled)
var debug = 0;                      // Debugging flag (1 = enabled)

// Whitelist: Domains explicitly allowed, bypassing all filters
var whitelist = [
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
];

// Comprehensive Regular Expression for Ad/Tracking Domains and Subdomains
var adDomainRegex = /^(?:.*[-_.])?(ads?|adv(ert(s|ising)?)?|banners?|track(er|ing|s)?|beacons?|doubleclick|adservice|adnxs|adtech|googleads|gads|adwords|partner|sponsor(ed)?|click(s|bank|tale|through)?|pop(up|under)s?|promo(tion)?|market(ing|er)?|affiliates?|metrics?|stat(s|counter|istics)?|analytics?|pixel(s)?|campaign|traff(ic|iq)|monetize|syndicat(e|ion)|revenue|yield|impress(ion)?s?|conver(sion|t)?|audience|target(ing)?|behavior|profil(e|ing)|telemetry|survey|poll|outbrain|taboola|quantcast|scorecard|omniture|comscore|krux|bluekai|exelate|adform|adroll|rubicon|vungle|inmobi|flurry|mixpanel|heap|amplitude|optimizely|bizible|pardot|hubspot|marketo|eloqua|salesforce|media(math|net)|criteo|appnexus|turn|adbrite|admob|adsonar|adscale|zergnet|revcontent|mgid|nativeads|contentad|displayads|bannerflow|adblade|adcolony|chartbeat|newrelic|pingdom|gauges|kissmetrics|webtrends|tradedesk|bidder|auction|rtb|programmatic|splash|interstitial|overlay)\./i;

// Regular Expression for Ad-Related URL Patterns and XSS Blocking
var adUrlRegex = /(?:\/(?:adcontent|img\/adv|web\-ad|iframead|contentad|ad\/image|video\-ad|stats\/event|xtclicks|adscript|bannerad|googlead|adhandler|adimages|embed\-log|adconfig|tracking\/track|tracker\/track|adrequest|nativead|adman|advertisement|adframe|adcontrol|adoverlay|adserver|adsense|google\-ads|ad\-banner|banner\-ad|campaign\/advertiser|adplacement|adblockdetect|advertising|admanagement|adprovider|adrotation|adtop|adbottom|adleft|adright|admiddle|adlarge|adsmall|admicro|adunit|adcall|adlog|adcount|adserve|adsrv|adsys|adtrack|adview|adwidget|adzone|banner\/adv|google_tag|image\/ads|sidebar\-ads|footer\-ads|top\-ads|bottom\-ads|new\-ads|search\-ads|lazy\-ads|responsive\-ads|dynamic\/ads|external\/ads|mobile\-ads|house\-ads|blog\/ads|online\/ads|pc\/ads|left\-ads|right\-ads|ads\/square|ads\/text|ads\/html|ads\/js|ads\.php|ad\.js|ad\.css|\?affiliate=|\?advertiser=|\&adspace=|\&adserver=|\&adgroupid=|\&adpageurl=|\.adserve|\.ads\d|\.adspace|\.adsense|\.adserver|\.google\-ads|\.banner\-ad|\.ad\-banner|\.adplacement|\.advertising|\.admanagement|\.adprovider|\.adrotation|\.adtop|\.adbottom|\.adleft|\.adright|\.admiddle|\.adlarge|\.adsmall|\.admicro|\.adunit|\.adcall|\.adlog|\.adcount|\.adserve|\.adsrv|\.adsys|\.adtrack|\.adview|\.adwidget|\.adzone|xss))/i;

// Regular Expression for Common Ad Subdomains
var adSubdomainRegex = /^(?:adcreative(s)?|imageserv|media(mgr)?|stats|switch|track(2|er)?|view|ad(s)?\d{0,3}|banner(s)?\d{0,3}|click(s)?\d{0,3}|count(er)?\d{0,3}|servedby\d{0,3}|toolbar\d{0,3}|pageads\d{0,3}|pops\d{0,3}|promos\d{0,3})\./i;

// Regular Expression for Web Bugs and Flash Ads
var adWebBugRegex = /(?:\/(?:1|blank|b|clear|pixel|transp|spacer)\.gif|\.swf)$/i;

// Blacklist: Explicitly blocked domains
var blacklist = [
    "ad.doubleclick.net",
    "static.doubleclick.net",
    "r4---sn-a5meknlz.googlevideo.com",
    "youtubeads.googleapis.com",
    "r3---sn-a5meknlz.googlevideo.com",
    "pubads.g.doubleclick.net",
    "googleadservices.com",
    "r9---sn-a5meknlz.googlevideo.com",
    "r8---sn-a5meknlz.googlevideo.com",
    "r7---sn-a5meknlz.googlevideo.com",
    "r6---sn-a5meknlz.googlevideo.com",
    "pagead2.googlesyndication.com",
    "r5---sn-a5meknlz.googlevideo.com",
    "r1---sn-a5meknlz.googlevideo.com",
    "googleads.g.doubleclick.net",
    "www.googletagservices.com",
    "analytics.youtube.com",
    "adservice.google.co.in",
    "ads.youtube.com",
    "partner.googleadservices.com",
    "adservice.google.com",
    "r2---sn-a5meknlz.googlevideo.com",
    "video-stats.video.google.com",
    "www.googleadservices.com"
];

// Main Proxy Auto-Configuration Function
function FindProxyForURL(url, host) {
    // Convert inputs to lowercase for case-insensitive matching
    host = host.toLowerCase();
    url = url.toLowerCase();

    // Debugging output (if enabled)
    if (debug) {
        alert("Checking...\nURL: " + url + "\nHost: " + host);
    }

    // Toggle ad-blocking on/off via special URLs
    if (host === "antiad.on") {
        isEnabled = 1;
        if (debug) alert("Ad-blocking enabled");
        return blackhole;
    } else if (host === "antiad.off") {
        isEnabled = 0;
        if (debug) alert("Ad-blocking disabled");
        return blackhole;
    }

    // If ad-blocking is disabled, pass all traffic
    if (!isEnabled) {
        return normal;
    }

    // Local network bypass (e.g., LAN, loopback)
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "127.*") ||
        dnsDomainIs(host, ".local")) {
        return normal;
    }

    // Whitelist check: Allow explicitly whitelisted domains
    for (var i = 0; i < whitelist.length; i++) {
        if (shExpMatch(host, whitelist[i])) {
            if (debug) alert("Whitelisted: " + host);
            return normal;
        }
    }

    // Ad-blocking and XSS-blocking logic
    if (
        // Match ad-related domains
        adDomainRegex.test(host) ||
        // Match ad-related URL patterns or URLs containing "xss"
        adUrlRegex.test(url) ||
        // Match common ad subdomains
        adSubdomainRegex.test(host) ||
        // Match web bugs and Flash ads
        adWebBugRegex.test(url) ||
        // Match explicitly blacklisted domains
        blacklist.indexOf(host) !== -1
    ) {
        if (debug) alert("Blocked...\nURL: " + url + "\nHost: " + host);
        return blackhole;
    }

    // Default: Pass through all non-matching traffic
    if (debug) alert("Not Blocked...\nURL: " + url + "\nHost: " + host);
    return normal;
}

// Initial load notification (if debugging is enabled)
if (debug) {
    alert("Ad-blocking PAC file loaded, isEnabled = " + isEnabled);
=======
>>>>>>> 3c479efe17479d82471b0fc670d9eb43f01e5740
}
