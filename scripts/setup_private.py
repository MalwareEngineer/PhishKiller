#!/usr/bin/env python3
"""Generate starter private/ config files for PhishKiller.

Creates private/user_agents.json, private/certstream_brands.json, and
private/certstream_keywords.json with sensible defaults. Existing files
are never overwritten — delete them first if you want to regenerate.

Usage:
    python scripts/setup_private.py
"""

import json
from pathlib import Path

PRIVATE_DIR = Path(__file__).resolve().parent.parent / "private"

USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Firefox (macOS / Linux)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

CERTSTREAM_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "dropbox", "icloud", "outlook", "office365",
    "coinbase", "binance", "blockchain",
]

CERTSTREAM_KEYWORDS = [
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "banking", "paypal", "microsoft",
    "apple", "google", "amazon", "netflix",
]

FILES = {
    "user_agents.json": USER_AGENTS,
    "certstream_brands.json": CERTSTREAM_BRANDS,
    "certstream_keywords.json": CERTSTREAM_KEYWORDS,
}


def main() -> None:
    PRIVATE_DIR.mkdir(exist_ok=True)
    for filename, data in FILES.items():
        path = PRIVATE_DIR / filename
        if path.exists():
            print(f"  SKIP  {path}  (already exists)")
            continue
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"  CREATED  {path}")

    print(f"\nDone. {len(FILES)} private config files in {PRIVATE_DIR}/")
    print("You can customize these files for your deployment.")


if __name__ == "__main__":
    main()
