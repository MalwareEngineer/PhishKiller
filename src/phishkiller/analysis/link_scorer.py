"""Smart link scoring for phishing chain crawling.

Scores extracted links by phishing relevance to decide which to follow
as child kits. High scores = likely phishing payload; low scores = benign.
"""

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from phishkiller.analysis.patterns import BENIGN_URL_ROOT_DOMAINS, extract_root_domain

logger = logging.getLogger(__name__)


@dataclass
class ScoredLink:
    url: str
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    source: str = "unknown"  # eml_link, qr_code, html_link, form_action, redirect


# URL shortener domains — these redirect to the real payload
URL_SHORTENERS = frozenset({
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "v.gd",
    "ow.ly", "buff.ly", "rb.gy", "short.io", "cutt.ly", "lnk.to",
    "rebrand.ly", "bl.ink", "clck.ru", "n9.cl", "s.id",
})

# Keywords in URL path/query that suggest phishing
PHISH_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "authenticate",
    "password", "credential", "validate", "suspend", "unlock", "restore",
    "webmail", "portal", "banking", "wallet",
})

# Known phishing infrastructure domains
PHISH_INFRA_DOMAINS = frozenset({
    "qr-codes.io", "qr-code-generator.com",
})

# Static asset extensions — never follow these
STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
})


class LinkScorer:
    """Score URLs by phishing relevance for chain crawling."""

    def score_links(
        self,
        urls: list[str],
        context: dict | None = None,
    ) -> list[ScoredLink]:
        """Score a list of URLs. Returns scored links sorted by score descending."""
        context = context or {}
        sources = context.get("sources", {})
        parent_url = context.get("parent_url", "")
        parent_domain = self._get_domain(parent_url) if parent_url else ""

        scored = []
        seen = set()
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            link = self._score_single(url, sources.get(url, "unknown"), parent_domain)
            scored.append(link)

        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    def _score_single(
        self, url: str, source: str, parent_domain: str
    ) -> ScoredLink:
        """Score a single URL."""
        link = ScoredLink(url=url, source=source)
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        domain = self._get_domain(url)
        root_domain = extract_root_domain(url)

        # Static assets — never follow
        if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
            link.score = 0.0
            link.reasons.append("static_asset")
            return link

        # CDN / known benign — cap score
        if root_domain in BENIGN_URL_ROOT_DOMAINS:
            link.score = 0.1
            link.reasons.append("benign_domain")
            return link

        # Base score by source type
        base_scores = {
            "form_action": 0.9,
            "c2_url": 0.9,
            "qr_code": 0.85,
            "redirect": 0.7,
            "eml_link": 0.6,
            "eml_attachment": 0.5,
            "html_link": 0.4,
        }
        link.score = base_scores.get(source, 0.3)
        link.reasons.append(f"source:{source}")

        # Known phishing infrastructure
        if root_domain in PHISH_INFRA_DOMAINS or domain in PHISH_INFRA_DOMAINS:
            link.score += 0.3
            link.reasons.append("known_phish_infra")

        # URL shortener — likely hiding the real destination
        if root_domain in URL_SHORTENERS or domain in URL_SHORTENERS:
            link.score += 0.2
            link.reasons.append("url_shortener")

        # Phishing keywords in path
        path_parts = set(path_lower.replace("/", " ").replace("-", " ").replace("_", " ").split())
        keyword_hits = path_parts & PHISH_KEYWORDS
        if keyword_hits:
            link.score += 0.2
            link.reasons.append(f"keywords:{','.join(keyword_hits)}")

        # Same domain as parent — more likely to be part of the chain
        if parent_domain and domain == parent_domain:
            link.score += 0.15
            link.reasons.append("same_domain")

        # Cap at 1.0
        link.score = min(link.score, 1.0)
        link.score = round(link.score, 3)

        return link

    @staticmethod
    def _get_domain(url: str) -> str:
        """Extract domain from URL."""
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""
