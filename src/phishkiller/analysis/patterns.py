"""Pre-compiled regex patterns for IOC extraction from phishing kit source files."""

import re
from html import unescape as html_unescape
from urllib.parse import urlparse

from phishkiller.private_config import load_benign_domains

# Increment when patterns, allowlists, or extraction logic change.
# Used to identify kits that need re-analysis after updates.
PATTERN_VERSION = 2

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
    # Placeholder / template domains
    "mysite.com", "abc.com", "domain.com", "yoursite.com", "site.com",
    "email.com", "yourdomain.com", "company.com", "sampleemail.com",
}

# Placeholder email local parts — these are never real exfil targets
EMAIL_PLACEHOLDER_LOCALS = {
    "your", "user", "username", "name", "email", "test", "admin",
    "info", "support", "contact", "hello", "example", "sample",
    "your.email", "your.name", "youremail", "eg.user",
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

# CSS selector fragments that leak into URL matches (e.g. "tailwindcss.com*/*,:after,:before")
CSS_JUNK_IN_URL = re.compile(r"[*{}<>]|::?(?:before|after|hover|focus|active|visited|placeholder|root)")

# JS string concatenation boundary — URL should be truncated here
# Matches '+, "+, `,  which indicate the URL literal has ended and JS code follows
JS_CONCAT_BOUNDARY = re.compile(r"""['"]\s*\+|['"]\s*,\s*['"]""")

TELEGRAM_API_PATTERN = re.compile(
    r"https?://api\.telegram\.org/bot[0-9A-Za-z_\-:/]+",
    re.IGNORECASE,
)

# Benign root domains — loaded from private/benign_domains.txt at runtime.
# Uses root-domain matching (e.g. "docs.google.com" → "google.com").
BENIGN_URL_ROOT_DOMAINS = load_benign_domains()

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
# Require PHP variable assignment ($var = "val") or array/config key syntax
# ("key" => "val" / "key": "val").  Values must be quoted and ≥3 chars to
# filter HTML attribute junk (name=, class=, placeholder=) and short English
# words (is, to, was) that the old broad pattern captured.
SMTP_HOST_PATTERN = re.compile(
    r"""\$(?:smtp_?host|smtp_?server|mail_?host)\s*=\s*["']([a-zA-Z0-9.\-]{3,}\.[a-zA-Z]{2,})["']"""
    r"""|["'](?:smtp_?host|smtp_?server|mail_?host)["']\s*(?:=>|:)\s*["']([a-zA-Z0-9.\-]{3,}\.[a-zA-Z]{2,})["']""",
    re.IGNORECASE,
)
SMTP_USER_PATTERN = re.compile(
    r"""\$(?:smtp_?user(?:name)?|mail_?user)\s*=\s*["']([^"']{3,})["']"""
    r"""|["'](?:smtp_?user(?:name)?|mail_?user)["']\s*(?:=>|:)\s*["']([^"']{3,})["']""",
    re.IGNORECASE,
)
SMTP_PASS_PATTERN = re.compile(
    r"""\$(?:smtp_?pass(?:word)?|mail_?pass(?:word)?)\s*=\s*["']([^"']{3,})["']"""
    r"""|["'](?:smtp_?pass(?:word)?|mail_?pass(?:word)?)["']\s*(?:=>|:)\s*["']([^"']{3,})["']""",
    re.IGNORECASE,
)

# SMTP host values that are SaaS platforms or JS variables, not real SMTP hosts
SMTP_HOST_EXCLUSIONS = frozenset({
    "app.jotform.com", "jotform.com",
    "t.host", "this.host", "e.host", "a.host",  # JS variable access
})

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
    # JS builtins that look like domains
    "console.info", "console.log", "console.error",
    # HTML elements parsed as domains
    "td.info", "th.info", "tr.info", "tr.in", "td.in", "th.in",
    "tbody.in", "thead.in", "tfoot.in",
    "loc.host", "custom.host",
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
    # HTML elements that get parsed as domain prefixes
    "tbody.", "thead.", "tfoot.", "field.",
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
# Matches international format: +CC (optional area) subscriber
# Requires balanced parens; digit count validated in extractor (7-13).
PHONE_PATTERN = re.compile(
    r"(?<![0-9a-zA-Z])"
    r"\+\d{1,3}"                      # country code
    r"(?:[\s\-]?\(\d{1,4}\))??"       # optional (area) — balanced parens
    r"(?:[\s\-]?\d{1,5}){1,4}"        # subscriber groups
    r"(?![0-9a-zA-Z).])"
)

# ---------- Telegram Handles ----------
TELEGRAM_HANDLE_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9])@([a-zA-Z][a-zA-Z0-9_]{4,31})(?![a-zA-Z0-9_])"
)
# Common false positives for @handles (CSS/JS/email/JSON-LD/npm conventions)
TELEGRAM_HANDLE_EXCLUSIONS = {
    # CSS at-rules / directives
    "media", "keyframes", "import", "charset", "supports",
    "layer", "scope", "container", "property",
    "apply", "screen", "tailwind", "responsive",
    # CSS/JS event/action keywords
    "click", "start", "input", "change", "focus", "submit",
    "scroll", "resize", "error", "reset", "select", "toggle",
    "ended", "abort",
    # JSDoc / Java annotations
    "param", "return", "throws", "override", "deprecated",
    "author", "version", "license", "copyright", "since",
    # License comment markers
    "licstart", "licend",
    # Email providers
    "gmail", "yahoo", "outlook", "hotmail",
    # JSON-LD keywords
    "context", "graph", "type", "value", "vocab", "reverse", "language",
    # npm scopes / JS frameworks
    "formatjs", "babel", "types", "angular", "react", "emotion",
    "popperjs", "floating-ui",
    # JS builtins / methods
    "iterator", "generator", "asynciterator", "tostringtag",
    "toprimitive", "tostring", "valueof", "hasinstance",
    # SaaS / brand names (observed in production)
    "flowcode", "getflowcode", "newrelic", "fontawesome", "roblox",
    "prezoai", "glimitedaccount", "typedreamhq", "cakeresume",
    "aboutdotme", "ghost", "dropbox", "miricanvas", "lottiefiles",
    "activecampaign", "lemonde", "lemonde_en", "yahoo_japan_pr",
    "plesk", "wordpress", "squarespace", "hubspot", "mailchimp",
    "sendgrid", "intercom", "zendesk",
    # Generic UI / platform terms
    "overview", "conference", "widget", "forms", "formsapp",
    "everyone", "channel", "here",
    # Font-face descriptor
    "font-face",
}
