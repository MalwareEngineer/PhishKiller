"""Pre-compiled regex patterns for IOC extraction from phishing kit source files."""

import re
from html import unescape as html_unescape
from urllib.parse import urlparse

# ---------- Email addresses ----------
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
EMAIL_EXCLUSIONS = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "w3.org", "jquery.com", "google.com", "gmail.com", "schema.org",
    "apache.org", "mozilla.org", "php.net", "github.com",
    "wordpress.org", "gravatar.com", "fontawesome.com",
    "microsoft.com", "apple.com", "icloud.com",
    "w3schools.com", "stackoverflow.com", "npmjs.com",
    "bootstrap.com", "getbootstrap.com",
    "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "protonmail.com", "zoho.com",
}

# ---------- Telegram Bot Tokens ----------
# Format: {bot_id}:{token} where bot_id is 8-10 digits
TELEGRAM_BOT_TOKEN_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])\d{8,10}:[0-9A-Za-z_-]{35}(?![a-zA-Z0-9])",
)

# ---------- Telegram Chat IDs ----------
TELEGRAM_CHAT_ID_PATTERN = re.compile(
    r'(?:chat_id|chatid|chat)["\s:=]+(-?\d{6,14})',
    re.IGNORECASE,
)

# ---------- C2 / Exfiltration URLs ----------
C2_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,500}",
    re.IGNORECASE,
)
# Strip trailing syntax junk that the broad regex consumes
URL_TRAILING_JUNK = re.compile(r"['\";,)\]}>\\]+$")

TELEGRAM_API_PATTERN = re.compile(
    r"https?://api\.telegram\.org/bot[0-9A-Za-z_\-:/]+",
    re.IGNORECASE,
)

# Benign root domains — extract the registrable domain from a URL and check
# membership. Uses root-domain matching (e.g. "docs.google.com" → "google.com").
BENIGN_URL_ROOT_DOMAINS = frozenset({
    # Google ecosystem
    "google.com", "google.co.uk", "google.co.jp", "google.de", "google.fr",
    "google.co.in", "google.com.br", "google.com.au",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "googlesyndication.com", "googletagmanager.com", "google-analytics.com",
    "doubleclick.net", "withgoogle.com", "ggpht.com", "gvt1.com",
    "gvt2.com", "googlevideo.com", "googleadservices.com",
    # Microsoft ecosystem
    "microsoft.com", "microsoftonline.com", "windows.net", "azure.com",
    "azureedge.net", "office.com", "office365.com", "live.com",
    "outlook.com", "bing.com", "msn.com", "hotmail.com",
    "windowsupdate.com", "visualstudio.com",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "amazontrust.com", "cloudfront.net",
    "awsstatic.com",
    # CDNs
    "cloudflare.com", "cloudflare-dns.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaitechnologies.com",
    "fastly.net", "fastlycdn.com",
    "bootstrapcdn.com", "stackpath.com", "stackpathcdn.com",
    # Libraries / frameworks
    "jquery.com", "getbootstrap.com", "tailwindcss.com", "fontawesome.com",
    "reactjs.org", "vuejs.org", "angular.io",
    # Site builders / hosting platforms
    "weebly.com", "weeblysite.com", "editmysite.com",
    "wix.com", "wixsite.com", "parastorage.com", "wixmp.com", "wixpress.com",
    "strikingly.com", "mystrikingly.com",
    "squarespace.com", "sqspcdn.com",
    "wordpress.com", "wordpress.org", "wp.com", "wpcomstaging.com",
    "shopify.com", "shopifycdn.com", "shopifyanalytics.com",
    "webflow.com", "webflow.io",
    "godaddy.com", "secureserver.net",
    "hostinger.com", "bluehost.com",
    # Code hosting / docs
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    "gitlab.com", "gitlab.io",
    "gitbook.io", "gitbook.com",
    "bitbucket.org",
    "readthedocs.io", "readthedocs.org",
    # Social media
    "facebook.com", "fbcdn.net", "fbsbx.com",
    "twitter.com", "x.com", "twimg.com",
    "twitch.tv", "twitchcdn.net",
    "instagram.com", "cdninstagram.com",
    "linkedin.com", "licdn.com",
    "youtube.com", "youtu.be", "ytimg.com",
    "vimeo.com", "vimeocdn.com",
    "tiktok.com", "tiktokcdn.com",
    "reddit.com", "redditmedia.com", "redditstatic.com",
    "pinterest.com", "pinimg.com",
    "tumblr.com",
    # SaaS / productivity
    "zoom.us", "zoomcdn.com",
    "calendly.com",
    "jotform.com", "jotfor.ms",
    "typeform.com",
    "mailchimp.com",
    "slack.com", "slack-imgs.com",
    "notion.so", "notion.site",
    "canva.com",
    "figma.com",
    "atlassian.com", "atlassian.net",
    # Form / survey platforms
    "surveymonkey.com", "surveygizmo.com",
    "qualtrics.com",
    # Gaming platforms (phishing targets — their own assets aren't IOCs)
    "roblox.com", "rbxcdn.com",
    "steampowered.com", "steamcommunity.com", "steamstatic.com",
    "epicgames.com",
    "ea.com",
    # Email providers
    "yahoo.com", "yimg.com",
    "protonmail.com", "proton.me",
    "zoho.com",
    "mail.ru",
    # Payment / finance (targets, not actor infra)
    "paypal.com", "paypalobjects.com",
    "stripe.com", "stripe.network",
    "venmo.com",
    # Cloud storage (targets, not actor infra)
    "dropbox.com", "dropboxusercontent.com", "dropboxstatic.com",
    "box.com",
    "onedrive.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    # Standards / reference
    "w3.org", "w3schools.com",
    "schema.org", "json-schema.org",
    "php.net", "apache.org", "mozilla.org", "mozilla.net",
    "stackoverflow.com", "stackexchange.com",
    "npmjs.com", "yarnpkg.com",
    "quirksmode.org",
    # Captcha / anti-bot
    "recaptcha.net", "hcaptcha.com",
    "gstatic.com",
    # Analytics
    "segment.io", "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "newrelic.com",
    # Blogging / CMS
    "blogger.com", "blogspot.com",
    # Travel / booking (targets, not actor infra)
    "booking.com", "bstatic.com",
    # URL shorteners / link management
    "bitly.com", "bit.ly",
    "ead.me",  # l.ead.me link shortener
    # Security vendors
    "fortinet.com",
    # Consent / cookie management
    "cookielaw.org", "onetrust.com",
    # Monitoring / observability
    "datadoghq.com", "datadoghq-browser-agent.com",
    "newrelic.com",
    # SaaS link pages
    "flowcode.com", "campsite.bio", "campsite.to",
    # Website builders (additional)
    "webador.com",
    # Other benign
    "archive.org", "pearltrees.com",
    "gravatar.com", "wp.com",
    "cloudinary.com",
    "sentry.io",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "hubspot.com", "hsforms.com", "hubspotusercontent.com",
    "pxf.io", "shareasale.com", "impact.com",  # affiliate networks
    "tistory.com",  # Korean blogging platform
    "qr-code-generator.com",
    "n9.cl",  # URL shortener
    "offset.com",
    "edgecastcdn.net",
    "vk-portal.net",  # VK CDN
    "latofonts.com",
})

# Two-part country-code SLDs (e.g. .co.uk, .com.br) — need 3 labels for root domain
_TWO_PART_TLDS = frozenset({
    "co.uk", "co.jp", "co.kr", "co.in", "co.nz", "co.za", "co.id",
    "com.au", "com.br", "com.mx", "com.ar", "com.co", "com.tr",
    "com.sg", "com.my", "com.ph", "com.pk", "com.ng", "com.eg",
    "org.uk", "org.au", "net.au", "gov.uk", "ac.uk",
    "ne.jp", "or.jp", "go.jp",
})


def extract_root_domain(hostname: str) -> str:
    """Extract the registrable root domain from a hostname.

    Examples:
        "docs.google.com" → "google.com"
        "cdn.jsdelivr.net" → "jsdelivr.net"
        "foo.co.uk" → "foo.co.uk"
    """
    hostname = hostname.lower().rstrip(".")
    parts = hostname.split(".")
    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in _TWO_PART_TLDS:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


_HTML_ENTITY_RE = re.compile(r"&[a-zA-Z]+;?|&#[0-9]+;?|&#x[0-9a-fA-F]+;?")


def is_benign_url(url: str) -> bool:
    """Check if a URL belongs to a known benign service."""
    try:
        # Strip HTML entities that corrupt urlparse (e.g. &quot; &amp;)
        clean_url = _HTML_ENTITY_RE.sub("", url)
        hostname = urlparse(clean_url).hostname
        if not hostname:
            return False
        root = extract_root_domain(hostname)
        return root in BENIGN_URL_ROOT_DOMAINS
    except Exception:
        return False


# URL path patterns that indicate static assets (not C2)
BENIGN_URL_EXTENSIONS = frozenset({
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".map", ".min.js", ".min.css",
    ".js",  # standalone .js files are library assets, not C2 endpoints
    ".mp3", ".mp4", ".webm", ".ogg",
    ".pdf",
})

# C2/exfil keywords that boost confidence
C2_KEYWORDS = {
    "send", "post", "exfil", "result", "log", "gate",
    "receive", "submit", "upload", "steal", "grab",
    "collect", "report", "panel", "admin", "login",
    "next.php", "post.php", "done.php", "finish.php",
}

# ---------- PHP mail() function patterns ----------
PHP_MAIL_PATTERN = re.compile(
    r"mail\s*\(\s*['\"]([^'\"]+@[^'\"]+)['\"]",
    re.IGNORECASE,
)
PHP_MAIL_TO_PATTERN = re.compile(
    r"\$(?:to|recipient|email_to|sendto)\s*=\s*['\"]([^'\"]+@[^'\"]+)['\"]",
    re.IGNORECASE,
)

# ---------- IP Addresses (IPv4) ----------
IPV4_PATTERN = re.compile(
    r"(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])",
)
PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "0.", "169.254.")

# ---------- SMTP Credentials ----------
SMTP_HOST_PATTERN = re.compile(
    r"(?:\$?(?:smtp_?host|smtp_?server|mail_?host|Host))"
    r'["\s:=\']+([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
    re.IGNORECASE,
)
SMTP_USER_PATTERN = re.compile(
    r"(?:\$?(?:smtp_?user(?:name)?|mail_?user|Username))"
    r'["\s:=\']+([^\s"\';<>]+)',
    re.IGNORECASE,
)
SMTP_PASS_PATTERN = re.compile(
    r"(?:\$?(?:smtp_?pass(?:word)?|mail_?pass|Password))"
    r'["\s:=\']+([^\s"\';<>]+)',
    re.IGNORECASE,
)

# ---------- Base64 Encoded Blocks ----------
BASE64_BLOCK_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{100,}={0,2}",
)

# ---------- Cryptocurrency Wallets ----------
BITCOIN_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![a-zA-Z0-9])"
)
ETHEREUM_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])0x[0-9a-fA-F]{40}(?![a-zA-Z0-9])"
)

# ---------- Domain Names ----------
# Standalone domain references — multi-label domains like smtp.evil-mailer.org
# Lookbehind blocks alphanumeric, slashes, and URL-path chars to prevent
# matching fragments inside URLs (e.g. "orkspace.google.com" from https://workspace...)
DOMAIN_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9/\-_%.:])'
    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,6})'
    r'(?![/\w.])',
    re.IGNORECASE,
)
# File extensions that look like TLDs but aren't domains
FALSE_DOMAIN_EXTENSIONS = {
    ".php", ".js", ".css", ".html", ".htm", ".json", ".xml",
    ".txt", ".png", ".jpg", ".gif", ".svg", ".ico", ".map",
    ".min", ".inc", ".conf", ".ini", ".log", ".sql", ".bak",
}
# Real TLDs — only extract domains whose final label is in this set
VALID_TLDS = {
    # Generic
    "com", "org", "net", "edu", "gov", "mil", "int",
    # Common gTLDs
    "io", "co", "me", "info", "biz", "name", "pro", "mobi", "tel", "asia",
    "xyz", "online", "site", "store", "app", "dev", "cloud", "tech", "live",
    "shop", "club", "fun", "space", "top", "work", "click", "link", "help",
    "news", "world", "today", "life", "website", "host", "email", "page",
    "solutions", "zone", "agency", "digital", "media", "center", "network",
    # Country codes (most common)
    "us", "uk", "ca", "au", "de", "fr", "it", "es", "nl", "be", "ch", "at",
    "ru", "cn", "jp", "kr", "in", "br", "mx", "za", "ng", "ke", "eg",
    "pl", "cz", "se", "no", "dk", "fi", "pt", "ie", "nz", "sg", "hk",
    "tw", "th", "ph", "id", "my", "vn", "pk", "bd", "ar", "cl",
    "pe", "ve", "ua", "ro", "hu", "bg", "hr", "sk", "si", "lt", "lv",
    "ee", "is", "lu", "gr", "tr", "il", "ae", "sa", "qa",
    # Phishing-popular free/cheap TLDs
    "tk", "ml", "ga", "cf", "gq", "buzz", "rest", "surf", "icu",
    "cc", "ws", "pw", "to", "ly", "su", "la", "nu",
    # Additional
    "sbs", "cfd", "icu", "cyou", "best",
}
# JS property accesses that happen to have valid TLDs (e.g. navigator.online)
JS_FALSE_DOMAINS = {
    "navigator.online", "window.location", "document.domain",
    "window.top", "window.name", "self.name", "parent.top",
    "screen.info", "history.link", "location.host", "location.site",
    "window.site", "document.link", "element.click", "event.page",
    "document.page", "window.app", "window.dev",
    # Additional observed false positives
    "object.is", "x22object.is", "link.click",
    "el-descriptions--mini.is",
    "locale-dataset.countries.com",
    # Observed from production data — JS property access + ccTLD
    "window.ga", "window.console.info",
    "window.analytics.page", "window.shopifyanalytics.lib.page",
    "window.langconfig.id", "window.vk.id",
    "thirdparty.is",
    "linkel.media",
}
# JS object prefixes — any domain starting with these followed by a dot
# is almost certainly a property access, not a real domain
_JS_OBJECT_PREFIXES = (
    "this.", "self.", "window.", "document.", "navigator.",
    "element.", "event.", "error.", "screen.", "history.",
    "location.", "parent.", "caller.", "button.", "input.",
    "form.", "link.", "file.", "cookie.", "entry.",
    "source.", "asset.", "media.", "place.", "attr.",
    "attribute.", "item.", "data.", "browser.",
)
# TLDs that are overwhelmingly JS false positives when paired with
# single-word object names (e.g. this.br, caller.name, rootdiv.id)
_JS_PRONE_TLDS = frozenset({
    "name", "id", "is", "at", "br", "ml", "lt", "es", "ee",
    "no", "me", "to", "au", "in", "my", "qa", "ph", "pt",
    "ga", "info", "page", "host", "click", "link", "top",
    "center", "media",
})
# Benign domains to skip in standalone domain extraction.
# Uses root-domain matching via extract_root_domain() — so adding "google.com"
# covers docs.google.com, meet.google.com, etc.
BENIGN_DOMAINS = BENIGN_URL_ROOT_DOMAINS | EMAIL_EXCLUSIONS

# ---------- Phone Numbers ----------
PHONE_PATTERN = re.compile(
    r"(?<![0-9a-zA-Z])\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}(?![0-9a-zA-Z])"
)

# ---------- Telegram Handles ----------
TELEGRAM_HANDLE_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])@([a-zA-Z][a-zA-Z0-9_]{4,31})(?![a-zA-Z0-9_])"
)
# Common false positives for @handles (CSS/JS/email conventions)
TELEGRAM_HANDLE_EXCLUSIONS = {
    "media", "keyframes", "import", "charset", "font-face",
    "supports", "layer", "scope", "container", "property",
    "param", "return", "throws", "override", "deprecated",
    "author", "version", "license", "copyright", "since",
    "gmail", "yahoo", "outlook", "hotmail",
}
