"""Pre-compiled regex patterns for IOC extraction from phishing kit source files."""

import re

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
TELEGRAM_API_PATTERN = re.compile(
    r"https?://api\.telegram\.org/bot[0-9A-Za-z_\-:/]+",
    re.IGNORECASE,
)
# Benign URL domains to skip
BENIGN_URL_DOMAINS = {
    "jquery", "bootstrap", "cdnjs", "googleapis", "gstatic",
    "cloudflare", "jsdelivr", "unpkg", "fontawesome", "w3.org",
    "schema.org", "microsoft.com", "github.com", "github.io",
    "maxcdn", "twimg", "fbcdn", "akamai", "stackpath",
    "wordpress.org", "wp.com", "w3schools", "stackoverflow",
    "php.net", "apache.org", "mozilla.org", "apple.com",
    "windows.net", "azureedge.net", "cloudfront.net",
    "google-analytics.com", "googlesyndication", "doubleclick",
    "recaptcha", "gstatic.com", "googletagmanager",
    "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "vimeo.com", "instagram.com",
}

# URL path patterns that indicate static assets (not C2)
BENIGN_URL_EXTENSIONS = {
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".map", ".min.js", ".min.css",
}

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
DOMAIN_PATTERN = re.compile(
    r'(?<![/])'
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
}
# JS property accesses that happen to have valid TLDs (e.g. navigator.online)
JS_FALSE_DOMAINS = {
    "navigator.online", "window.location", "document.domain",
    "window.top", "window.name", "self.name", "parent.top",
    "screen.info", "history.link", "location.host", "location.site",
    "window.site", "document.link", "element.click", "event.page",
    "document.page", "window.app", "window.dev",
}
BENIGN_DOMAINS = EMAIL_EXCLUSIONS | {
    "jquery.com", "bootstrapcdn.com", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "ajax.googleapis.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com", "cdn.jsdelivr.net",
    "unpkg.com", "use.fontawesome.com",
    "google-analytics.com", "googletagmanager.com",
    "facebook.com", "twitter.com", "youtube.com",
    "linkedin.com", "instagram.com",
}

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
