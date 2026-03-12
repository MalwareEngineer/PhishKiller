"""Feed ingestion Celery tasks — PhishTank, URLhaus, OpenPhish."""

import hashlib
import logging

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.feed_entry import FeedEntry, FeedSource
from phishkiller.utils.http_client import get_sync_client

logger = logging.getLogger(__name__)


def _upsert_feed_entry(
    db, source: FeedSource, url: str, external_id: str,
    raw_data: dict | None = None, target_brand: str | None = None,
) -> bool:
    """Insert a feed entry if it doesn't already exist. Returns True if new."""
    existing = (
        db.query(FeedEntry)
        .filter(FeedEntry.source == source, FeedEntry.external_id == external_id)
        .first()
    )
    if existing:
        return False

    entry = FeedEntry(
        source=source,
        url=url,
        external_id=external_id,
        raw_data=raw_data,
        target_brand=target_brand,
    )
    db.add(entry)
    return True


@celery_app.task(
    name="phishkiller.tasks.feeds.ingest_phishtank",
    bind=True,
    queue="feeds",
    max_retries=3,
    default_retry_delay=300,
)
def ingest_phishtank(self) -> dict:
    """Ingest phishing URLs from PhishTank's verified online database (JSON).

    PhishTank API: http://data.phishtank.com/data/online-valid.json
    Rate limited — optional API key improves rate.
    """
    settings = get_settings()
    db = get_sync_db()
    new_count = 0
    total = 0

    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        if settings.phishtank_api_key:
            url = (
                f"http://data.phishtank.com/data/"
                f"{settings.phishtank_api_key}/online-valid.json"
            )

        logger.info("Ingesting PhishTank feed...")

        with get_sync_client(timeout=120) as client:
            response = client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            entries = response.json()

        for entry in entries:
            total += 1
            phish_url = entry.get("url", "")
            phish_id = str(entry.get("phish_id", ""))
            target = entry.get("target", "")

            if _upsert_feed_entry(
                db,
                source=FeedSource.PHISHTANK,
                url=phish_url,
                external_id=phish_id,
                raw_data=entry,
                target_brand=target if target else None,
            ):
                new_count += 1

            # Batch commit every 500
            if total % 500 == 0:
                db.commit()

        db.commit()
        logger.info("PhishTank: %d new / %d total entries", new_count, total)
        return {
            "source": "phishtank",
            "new_entries": new_count,
            "total_fetched": total,
        }

    except Exception as e:
        db.rollback()
        logger.exception("PhishTank ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.feeds.ingest_urlhaus",
    bind=True,
    queue="feeds",
    max_retries=3,
    default_retry_delay=300,
)
def ingest_urlhaus(self) -> dict:
    """Ingest malware/phishing URLs from URLhaus (abuse.ch).

    URLhaus API: https://urlhaus-api.abuse.ch/v1/urls/recent/
    """
    db = get_sync_db()
    new_count = 0
    total = 0

    try:
        logger.info("Ingesting URLhaus feed...")

        with get_sync_client(timeout=60) as client:
            response = client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()

        entries = data.get("urls", [])
        for entry in entries:
            total += 1
            entry_url = entry.get("url", "")
            entry_id = str(entry.get("id", ""))

            # Filter for phishing-related tags
            tags = entry.get("tags", []) or []
            threat = entry.get("threat", "")

            if _upsert_feed_entry(
                db,
                source=FeedSource.URLHAUS,
                url=entry_url,
                external_id=entry_id,
                raw_data=entry,
                target_brand=threat if threat else None,
            ):
                new_count += 1

            if total % 500 == 0:
                db.commit()

        db.commit()
        logger.info("URLhaus: %d new / %d total entries", new_count, total)
        return {
            "source": "urlhaus",
            "new_entries": new_count,
            "total_fetched": total,
        }

    except Exception as e:
        db.rollback()
        logger.exception("URLhaus ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.feeds.ingest_openphish",
    bind=True,
    queue="feeds",
    max_retries=3,
    default_retry_delay=600,
)
def ingest_openphish(self) -> dict:
    """Ingest phishing URLs from OpenPhish community feed.

    OpenPhish: https://openphish.com/feed.txt (one URL per line)
    No IDs — URL is used as external_id via SHA256 hash.
    """
    db = get_sync_db()
    new_count = 0
    total = 0

    try:
        logger.info("Ingesting OpenPhish feed...")

        with get_sync_client(timeout=60) as client:
            response = client.get("https://openphish.com/feed.txt")
            response.raise_for_status()
            text = response.text

        for line in text.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue

            total += 1
            # Use URL hash as external_id since OpenPhish has no IDs
            external_id = hashlib.sha256(url.encode()).hexdigest()[:32]

            if _upsert_feed_entry(
                db,
                source=FeedSource.OPENPHISH,
                url=url,
                external_id=external_id,
            ):
                new_count += 1

            if total % 500 == 0:
                db.commit()

        db.commit()
        logger.info("OpenPhish: %d new / %d total entries", new_count, total)
        return {
            "source": "openphish",
            "new_entries": new_count,
            "total_fetched": total,
        }

    except Exception as e:
        db.rollback()
        logger.exception("OpenPhish ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()
