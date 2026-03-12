"""CertStream monitor — watches Certificate Transparency logs for suspicious domains.

Scores newly registered domains against a keyword list using Levenshtein distance
and dispatches feed entries when the score exceeds a configurable threshold.
"""

import hashlib
import logging
import re

from Levenshtein import distance as levenshtein_distance

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.feed_entry import FeedEntry, FeedSource

logger = logging.getLogger(__name__)

# Known brand domains to compare against
TARGET_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "dropbox", "icloud", "outlook", "office365",
    "coinbase", "binance", "blockchain",
]

# Patterns that indicate suspicious certificate registrations
SUSPICIOUS_PATTERNS = [
    re.compile(r".*(?:login|signin|verify|secure|account|update|confirm).*", re.I),
    re.compile(r".*(?:\.tk|\.ml|\.ga|\.cf|\.gq)$", re.I),
    re.compile(r".*\d{3,}.*"),  # Multiple numbers in domain
]


def score_domain(domain: str) -> int:
    """Score a domain's suspiciousness (0-100).

    Scoring components:
    - Levenshtein distance to known brands (closer = more suspicious)
    - Presence of suspicious keywords
    - Suspicious TLD
    - Dash/dot count heuristics
    """
    domain_lower = domain.lower()
    score = 0

    # Remove TLD for brand comparison
    parts = domain_lower.split(".")
    base_domain = parts[0] if parts else domain_lower

    # Check Levenshtein distance to known brands
    min_distance = float("inf")
    closest_brand = ""
    for brand in TARGET_BRANDS:
        dist = levenshtein_distance(base_domain, brand)
        if dist < min_distance:
            min_distance = dist
            closest_brand = brand

    if min_distance == 0:
        # Exact match — could be a subdomain of the real brand, low score
        score += 5
    elif min_distance <= 2:
        score += 60  # Very close to a brand (typosquat)
    elif min_distance <= 4:
        score += 35  # Moderately close
    elif min_distance <= 6:
        score += 15

    # Check brand name as substring
    for brand in TARGET_BRANDS:
        if brand in base_domain and base_domain != brand:
            score += 25
            break

    settings = get_settings()
    # Check suspicious keywords
    for keyword in settings.certstream_suspicious_keywords:
        if keyword in domain_lower:
            score += 15
            break

    # Suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.match(domain_lower):
            score += 10
            break

    # Many dashes (common in phishing domains)
    dash_count = domain_lower.count("-")
    if dash_count >= 3:
        score += 10
    elif dash_count >= 2:
        score += 5

    return min(score, 100)


@celery_app.task(
    name="phishkiller.tasks.certstream_monitor.monitor_certstream",
    bind=True,
    queue="certstream",
)
def monitor_certstream(self) -> dict:
    """Connect to CertStream and process certificate transparency events.

    This is a long-running task that processes CT log entries.
    It scores domains and creates feed entries for suspicious ones.
    """
    import certstream

    settings = get_settings()
    threshold = settings.certstream_score_threshold
    processed = 0
    flagged = 0
    db = get_sync_db()

    def callback(message, context):
        nonlocal processed, flagged

        if message.get("message_type") != "certificate_update":
            return

        data = message.get("data", {})
        leaf = data.get("leaf_cert", {})
        domains = leaf.get("all_domains", [])

        for domain in domains:
            processed += 1
            domain_score = score_domain(domain)

            if domain_score >= threshold:
                flagged += 1
                url = f"https://{domain}"
                external_id = hashlib.sha256(
                    f"certstream:{domain}".encode()
                ).hexdigest()[:32]

                existing = (
                    db.query(FeedEntry)
                    .filter(
                        FeedEntry.source == FeedSource.CERTSTREAM,
                        FeedEntry.external_id == external_id,
                    )
                    .first()
                )

                if not existing:
                    entry = FeedEntry(
                        source=FeedSource.CERTSTREAM,
                        url=url,
                        external_id=external_id,
                        raw_data={
                            "domain": domain,
                            "score": domain_score,
                            "issuer": leaf.get("issuer", {}),
                            "serial": leaf.get("serial_number", ""),
                        },
                    )
                    db.add(entry)

                    if flagged % 10 == 0:
                        db.commit()

                logger.info(
                    "Suspicious domain: %s (score=%d)",
                    domain, domain_score,
                )

    try:
        logger.info(
            "Starting CertStream monitor (threshold=%d)...", threshold
        )
        certstream.listen_for_events(callback, url=settings.certstream_url)
    except KeyboardInterrupt:
        logger.info("CertStream monitor stopped by user")
    except Exception as e:
        logger.exception("CertStream error: %s", e)
    finally:
        try:
            db.commit()
        except Exception:
            pass
        db.close()

    return {"processed": processed, "flagged": flagged}
