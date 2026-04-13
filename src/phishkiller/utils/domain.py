"""Domain extraction utilities."""

from __future__ import annotations

from urllib.parse import urlparse

# Two-part TLDs where the eTLD+1 needs three labels
_TWO_PART_TLDS = frozenset({
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.id",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw",
    "com.ar", "com.co", "com.tr", "com.ua", "com.pk", "com.ng",
    "org.uk", "org.au", "net.au", "net.br", "ac.uk", "gov.uk",
    "edu.au", "ne.jp", "or.jp", "ac.jp",
})


def extract_etld_plus_one(url: str) -> str | None:
    """Extract the effective TLD+1 (registrable domain) from a URL.

    Uses a hardcoded list of common two-part TLDs plus a fallback
    to the last two labels.  Sufficient for phishing kit URLs which
    overwhelmingly use common TLDs.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None
        hostname = hostname.lower().rstrip(".")
        parts = hostname.split(".")
        if len(parts) < 2:
            return hostname

        # Check for two-part TLD (e.g. "co.uk" in "example.co.uk")
        if len(parts) >= 3:
            candidate_tld = f"{parts[-2]}.{parts[-1]}"
            if candidate_tld in _TWO_PART_TLDS:
                return ".".join(parts[-3:])

        return ".".join(parts[-2:])
    except Exception:
        return None
