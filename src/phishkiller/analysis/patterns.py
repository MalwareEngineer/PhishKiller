"""Pre-compiled regex patterns for IOC extraction from phishing kit source files."""

import re

# ---------- Email addresses ----------
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
EMAIL_EXCLUSIONS = {
    "example.com", "example.org", "test.com", "localhost",
    "w3.org", "jquery.com", "google.com", "schema.org",
    "apache.org", "mozilla.org", "php.net", "github.com",
    "wordpress.org", "gravatar.com", "fontawesome.com",
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
    "schema.org", "microsoft.com/schemas", "github.com",
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
