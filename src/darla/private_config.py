"""Runtime loader for operationally sensitive data.

Loads User-Agent rotation strings, CertStream brand targets, and CertStream
keywords from the ``private/`` directory (gitignored). These are the items
with real evasion value — an attacker could fingerprint our exact UAs or
avoid brand names we monitor in Certificate Transparency logs.

Run ``python scripts/setup_private.py`` to generate starter files.
Each loader falls back to minimal defaults when files are absent.
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
    # Local dev: relative to project root (src/darla/ -> ../../private/)
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
    Falls back to 3 generic UAs if file is absent.
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
        logger.warning(
            "No %s found, using %d fallback UAs. Run scripts/setup_private.py to generate.",
            path, len(_FALLBACK_USER_AGENTS),
        )
    return list(_FALLBACK_USER_AGENTS)


# ---------------------------------------------------------------------------
# CertStream target brands
# ---------------------------------------------------------------------------
_FALLBACK_CERTSTREAM_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon",
    "netflix", "facebook", "chase",
]


@lru_cache(maxsize=1)
def load_certstream_brands() -> list[str]:
    """Load CertStream target brand names from ``private/certstream_brands.json``.

    File format: JSON array of brand name strings.
    Falls back to 8 common brands if file is absent.
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
        logger.warning(
            "No %s found, using %d fallback brands. Run scripts/setup_private.py to generate.",
            path, len(_FALLBACK_CERTSTREAM_BRANDS),
        )
    return list(_FALLBACK_CERTSTREAM_BRANDS)


# ---------------------------------------------------------------------------
# CertStream suspicious keywords
# ---------------------------------------------------------------------------
_FALLBACK_CERTSTREAM_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
]


@lru_cache(maxsize=1)
def load_certstream_keywords() -> list[str]:
    """Load CertStream suspicious keywords from ``private/certstream_keywords.json``.

    File format: JSON array of keyword strings.
    Falls back to 7 common keywords if file is absent.
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
        logger.warning(
            "No %s found, using %d fallback keywords. Run scripts/setup_private.py to generate.",
            path, len(_FALLBACK_CERTSTREAM_KEYWORDS),
        )
    return list(_FALLBACK_CERTSTREAM_KEYWORDS)
