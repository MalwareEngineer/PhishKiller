"""Runtime loader for operationally sensitive data.

All detection signatures, allowlists, and scoring parameters are loaded from
the ``private/`` directory (gitignored) so they stay out of version control.
Each loader falls back to minimal hard-coded defaults when the file is absent
(dev/CI environments) and logs a warning so operators notice.
"""

import json
import logging
import os
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

# Resolve private dir: env var > /app/private (Docker) > relative to project root
def _resolve_private_dir() -> Path:
    if env_dir := os.environ.get("PK_PRIVATE_DIR"):
        return Path(env_dir)
    # Docker convention: /app/private/
    docker_path = Path("/app/private")
    if docker_path.is_dir():
        return docker_path
    # Local dev: relative to project root (src/phishkiller/ → ../../private/)
    return Path(__file__).resolve().parent.parent.parent / "private"


_PRIVATE_DIR = _resolve_private_dir()


def _private_path(filename: str) -> Path:
    """Resolve a file inside the private/ directory."""
    return _PRIVATE_DIR / filename


# ---------------------------------------------------------------------------
# User-Agent strings
# ---------------------------------------------------------------------------
_FALLBACK_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
]


@lru_cache(maxsize=1)
def load_user_agents() -> list[str]:
    """Load User-Agent strings from ``private/user_agents.json``.

    File format: JSON array of UA strings.
    """
    path = _private_path("user_agents.json")
    if path.exists():
        try:
            agents = json.loads(path.read_text())
            logger.info("Loaded %d User-Agent strings from %s", len(agents), path)
            return agents
        except Exception:
            logger.exception("Failed to parse %s, using fallback UAs", path)
    else:
        logger.warning("No %s found — using %d fallback UAs", path, len(_FALLBACK_USER_AGENTS))
    return list(_FALLBACK_USER_AGENTS)


# ---------------------------------------------------------------------------
# Benign domain allowlist
# ---------------------------------------------------------------------------
_FALLBACK_BENIGN_DOMAINS: frozenset[str] = frozenset({
    "google.com", "microsoft.com", "apple.com", "amazonaws.com",
    "cloudflare.com", "github.com", "facebook.com", "twitter.com",
    "w3.org", "schema.org", "jquery.com",
})


@lru_cache(maxsize=1)
def load_benign_domains() -> frozenset[str]:
    """Load benign root domains from ``private/benign_domains.txt``.

    File format: one domain per line, ``#`` comments and blank lines ignored.
    """
    path = _private_path("benign_domains.txt")
    if path.exists():
        try:
            domains = set()
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
            logger.info("Loaded %d benign domains from %s", len(domains), path)
            return frozenset(domains)
        except Exception:
            logger.exception("Failed to parse %s, using fallback domains", path)
    else:
        logger.warning("No %s found — using %d fallback benign domains", path, len(_FALLBACK_BENIGN_DOMAINS))
    return _FALLBACK_BENIGN_DOMAINS


# ---------------------------------------------------------------------------
# CertStream brands + keywords
# ---------------------------------------------------------------------------
_FALLBACK_CERTSTREAM_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon",
    "netflix", "facebook", "chase",
]


_FALLBACK_CERTSTREAM_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
]


@lru_cache(maxsize=1)
def load_certstream_keywords() -> list[str]:
    """Load CertStream suspicious keywords from ``private/certstream_keywords.json``.

    File format: JSON array of keyword strings.
    """
    path = _private_path("certstream_keywords.json")
    if path.exists():
        try:
            keywords = json.loads(path.read_text())
            logger.info("Loaded %d CertStream keywords from %s", len(keywords), path)
            return keywords
        except Exception:
            logger.exception("Failed to parse %s, using fallback keywords", path)
    else:
        logger.warning("No %s found — using %d fallback keywords", path, len(_FALLBACK_CERTSTREAM_KEYWORDS))
    return list(_FALLBACK_CERTSTREAM_KEYWORDS)


@lru_cache(maxsize=1)
def load_certstream_brands() -> list[str]:
    """Load CertStream target brand names from ``private/certstream_brands.json``.

    File format: JSON array of brand name strings.
    """
    path = _private_path("certstream_brands.json")
    if path.exists():
        try:
            brands = json.loads(path.read_text())
            logger.info("Loaded %d CertStream brands from %s", len(brands), path)
            return brands
        except Exception:
            logger.exception("Failed to parse %s, using fallback brands", path)
    else:
        logger.warning("No %s found — using %d fallback brands", path, len(_FALLBACK_CERTSTREAM_BRANDS))
    return list(_FALLBACK_CERTSTREAM_BRANDS)


# ---------------------------------------------------------------------------
# Link scorer weights
# ---------------------------------------------------------------------------
_FALLBACK_LINK_SCORE_WEIGHTS = {
    "form_action": 0.9,
    "qr_code": 0.85,
    "redirect": 0.7,
    "eml_link": 0.6,
    "eml_attachment": 0.5,
    "html_link": 0.4,
    "default": 0.3,
}


@lru_cache(maxsize=1)
def load_link_score_weights() -> dict[str, float]:
    """Load link scoring weights from ``private/link_score_weights.json``.

    File format: JSON object mapping source type → base score float.
    """
    path = _private_path("link_score_weights.json")
    if path.exists():
        try:
            weights = json.loads(path.read_text())
            logger.info("Loaded link score weights from %s", path)
            return weights
        except Exception:
            logger.exception("Failed to parse %s, using fallback weights", path)
    else:
        logger.warning("No %s found — using fallback link score weights", path)
    return dict(_FALLBACK_LINK_SCORE_WEIGHTS)


# ---------------------------------------------------------------------------
# Link scorer phishing keywords + shorteners + infra domains
# ---------------------------------------------------------------------------
_FALLBACK_PHISH_KEYWORDS = frozenset({
    "login", "signin", "verify", "account", "secure", "update", "confirm",
})

_FALLBACK_URL_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "is.gd",
})

_FALLBACK_PHISH_INFRA = frozenset[str]()


@lru_cache(maxsize=1)
def load_link_scorer_lists() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Load phishing keywords, URL shorteners, and infra domains.

    File: ``private/link_scorer_lists.json``
    Format::

        {
            "phish_keywords": ["login", "signin", ...],
            "url_shorteners": ["bit.ly", ...],
            "phish_infra_domains": ["qr-codes.io", ...]
        }

    Returns (phish_keywords, url_shorteners, phish_infra_domains).
    """
    path = _private_path("link_scorer_lists.json")
    if path.exists():
        try:
            data = json.loads(path.read_text())
            kw = frozenset(data.get("phish_keywords", []))
            sh = frozenset(data.get("url_shorteners", []))
            infra = frozenset(data.get("phish_infra_domains", []))
            logger.info(
                "Loaded link scorer lists: %d keywords, %d shorteners, %d infra",
                len(kw), len(sh), len(infra),
            )
            return kw, sh, infra
        except Exception:
            logger.exception("Failed to parse %s, using fallbacks", path)
    else:
        logger.warning("No %s found — using fallback link scorer lists", path)
    return _FALLBACK_PHISH_KEYWORDS, _FALLBACK_URL_SHORTENERS, _FALLBACK_PHISH_INFRA
