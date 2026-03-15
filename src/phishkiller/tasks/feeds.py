"""Feed ingestion Celery tasks — PhishTank, URLhaus, OpenPhish, PhishStats, Phishing.Database."""

import hashlib
import logging
import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.feed_entry import FeedEntry, FeedSource
from phishkiller.models.kit import Kit, KitStatus
from phishkiller.utils.http_client import fetch_with_cache, get_sync_client

logger = logging.getLogger(__name__)


def _bulk_upsert_feed_entries(db, entries: list[dict]) -> int:
    """Bulk-insert feed entries, skipping duplicates via ON CONFLICT DO NOTHING.

    Each dict must contain: id, source, url, external_id, and optionally
    raw_data and target_brand.  Returns total number of rows inserted.
    """
    if not entries:
        return 0

    inserted = 0
    chunk_size = 500

    for i in range(0, len(entries), chunk_size):
        chunk = entries[i : i + chunk_size]
        stmt = (
            pg_insert(FeedEntry.__table__)
            .values(chunk)
            .on_conflict_do_nothing(
                index_elements=["source", "external_id"],
            )
        )
        result = db.execute(stmt)
        inserted += result.rowcount
        db.commit()

    return inserted


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

    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        if settings.phishtank_api_key:
            url = (
                f"http://data.phishtank.com/data/"
                f"{settings.phishtank_api_key}/online-valid.json"
            )

        logger.info("Ingesting PhishTank feed...")

        response = fetch_with_cache(
            url, timeout=120, headers={"Accept": "application/json"},
        )
        if response is None:
            return {"source": "phishtank", "new_entries": 0, "cached": True}

        raw_entries = response.json()

        entries = []
        for entry in raw_entries:
            phish_url = entry.get("url", "")
            phish_id = str(entry.get("phish_id", ""))
            target = entry.get("target", "")
            entries.append({
                "id": uuid.uuid4(),
                "source": FeedSource.PHISHTANK,
                "url": phish_url,
                "external_id": phish_id,
                "raw_data": entry,
                "target_brand": target if target else None,
            })

        new_count = _bulk_upsert_feed_entries(db, entries)
        logger.info("PhishTank: %d new / %d total entries", new_count, len(entries))
        return {
            "source": "phishtank",
            "new_entries": new_count,
            "total_fetched": len(entries),
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

    try:
        settings = get_settings()
        if not settings.urlhaus_auth_key:
            logger.warning(
                "PK_URLHAUS_AUTH_KEY not set — URLhaus API requires auth. "
                "Get a key at https://auth.abuse.ch/"
            )

        logger.info("Ingesting URLhaus feed...")

        req_headers = {"Accept": "application/json"}
        if settings.urlhaus_auth_key:
            req_headers["Auth-Key"] = settings.urlhaus_auth_key

        response = fetch_with_cache(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            timeout=60,
            headers=req_headers,
        )
        if response is None:
            return {"source": "urlhaus", "new_entries": 0, "cached": True}

        data = response.json()

        query_status = data.get("query_status", "")
        if query_status != "ok":
            raise ValueError(f"URLhaus API query_status: {query_status}")

        raw_entries = data.get("urls", [])
        entries = []
        for entry in raw_entries:
            entry_url = entry.get("url", "")
            entry_id = str(entry.get("id", ""))
            threat = entry.get("threat", "")
            entries.append({
                "id": uuid.uuid4(),
                "source": FeedSource.URLHAUS,
                "url": entry_url,
                "external_id": entry_id,
                "raw_data": entry,
                "target_brand": threat if threat else None,
            })

        new_count = _bulk_upsert_feed_entries(db, entries)
        logger.info("URLhaus: %d new / %d total entries", new_count, len(entries))
        return {
            "source": "urlhaus",
            "new_entries": new_count,
            "total_fetched": len(entries),
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
    No IDs — URL is used as external_id via full SHA256 hash.
    """
    db = get_sync_db()

    try:
        logger.info("Ingesting OpenPhish feed...")

        response = fetch_with_cache("https://openphish.com/feed.txt", timeout=60)
        if response is None:
            return {"source": "openphish", "new_entries": 0, "cached": True}

        text = response.text
        entries = []
        for line in text.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue

            external_id = hashlib.sha256(url.encode()).hexdigest()
            entries.append({
                "id": uuid.uuid4(),
                "source": FeedSource.OPENPHISH,
                "url": url,
                "external_id": external_id,
            })

        new_count = _bulk_upsert_feed_entries(db, entries)
        logger.info("OpenPhish: %d new / %d total entries", new_count, len(entries))
        return {
            "source": "openphish",
            "new_entries": new_count,
            "total_fetched": len(entries),
        }

    except Exception as e:
        db.rollback()
        logger.exception("OpenPhish ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.feeds.ingest_phishstats",
    bind=True,
    queue="feeds",
    max_retries=3,
    default_retry_delay=600,
)
def ingest_phishstats(self) -> dict:
    """Ingest phishing URLs from PhishStats CSV feed.

    PhishStats: https://phishstats.info/phish_score.csv
    CSV columns: date, score, url, ip
    Filters for score >= 5 (high confidence).
    """
    import csv
    import io

    db = get_sync_db()

    try:
        logger.info("Ingesting PhishStats feed...")

        response = fetch_with_cache(
            "https://phishstats.info/phish_score.csv", timeout=120,
        )
        if response is None:
            return {"source": "phishstats", "new_entries": 0, "cached": True}

        text = response.text
        entries = []
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("#") or row[0] == "date":
                continue
            if len(row) < 3:
                continue

            try:
                score = float(row[1])
            except (ValueError, IndexError):
                continue

            if score < 5:
                continue

            url = row[2].strip()
            if not url or not url.startswith("http"):
                continue

            external_id = hashlib.sha256(url.encode()).hexdigest()
            entries.append({
                "id": uuid.uuid4(),
                "source": FeedSource.PHISHSTATS,
                "url": url,
                "external_id": external_id,
            })

        new_count = _bulk_upsert_feed_entries(db, entries)
        logger.info("PhishStats: %d new / %d total entries", new_count, len(entries))
        return {
            "source": "phishstats",
            "new_entries": new_count,
            "total_fetched": len(entries),
        }

    except Exception as e:
        db.rollback()
        logger.exception("PhishStats ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.feeds.ingest_phishing_database",
    bind=True,
    queue="feeds",
    max_retries=3,
    default_retry_delay=600,
)
def ingest_phishing_database(self) -> dict:
    """Ingest phishing URLs from Phishing.Database (GitHub).

    Feed: https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt
    Plain text, one URL per line.
    """
    db = get_sync_db()

    try:
        logger.info("Ingesting Phishing.Database feed...")

        response = fetch_with_cache(
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database"
            "/master/phishing-links-ACTIVE.txt",
            timeout=120,
        )
        if response is None:
            return {"source": "phishing_database", "new_entries": 0, "cached": True}

        text = response.text
        entries = []
        for line in text.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue

            external_id = hashlib.sha256(url.encode()).hexdigest()
            entries.append({
                "id": uuid.uuid4(),
                "source": FeedSource.PHISHING_DATABASE,
                "url": url,
                "external_id": external_id,
            })

        new_count = _bulk_upsert_feed_entries(db, entries)
        logger.info(
            "Phishing.Database: %d new / %d total entries", new_count, len(entries),
        )
        return {
            "source": "phishing_database",
            "new_entries": new_count,
            "total_fetched": len(entries),
        }

    except Exception as e:
        db.rollback()
        logger.exception("Phishing.Database ingestion error: %s", e)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.feeds.process_feed_entries",
    bind=True,
    queue="feeds",
    max_retries=0,
)
def process_feed_entries(self, batch_size: int = 500) -> dict:
    """Pick up unprocessed feed entries and submit them as kits for analysis.

    Creates a Kit record for each entry and kicks off the full analysis chain
    (download -> hash -> extract/DOM -> IOCs). Entries are marked processed
    immediately so they won't be re-selected in the next batch.
    """
    from phishkiller.tasks.analysis import build_analysis_chain
    from phishkiller.tasks.discovery import discover_kits

    db = get_sync_db()
    processed = 0
    failed = 0
    skipped = 0

    try:
        entries = (
            db.query(FeedEntry)
            .filter(FeedEntry.is_processed == False)  # noqa: E712
            .order_by(FeedEntry.created_at)
            .limit(batch_size)
            .all()
        )

        if not entries:
            logger.info("No unprocessed feed entries found.")
            return {"processed": 0, "failed": 0, "skipped": 0}

        logger.info("Processing %d unprocessed feed entries...", len(entries))

        for entry in entries:
            try:
                # Cross-source URL dedup — skip if a non-failed Kit already exists
                existing_kit = (
                    db.query(Kit)
                    .filter(
                        Kit.source_url == entry.url,
                        Kit.status != KitStatus.FAILED,
                    )
                    .first()
                )
                if existing_kit:
                    entry.is_processed = True
                    skipped += 1
                    continue

                kit = Kit(
                    id=uuid.uuid4(),
                    source_url=entry.url,
                    source_feed=entry.source.value,
                    feed_entry_id=entry.id,
                    status=KitStatus.PENDING,
                )
                db.add(kit)
                db.flush()

                build_analysis_chain(str(kit.id)).apply_async()

                # Also probe for additional kits at this URL's host
                discover_kits.delay(str(entry.id))

                entry.is_processed = True
                processed += 1

            except Exception as e:
                logger.warning(
                    "Failed to process feed entry %s: %s", entry.id, e
                )
                entry.is_processed = True  # Mark processed to avoid retrying
                failed += 1

        db.commit()
        logger.info(
            "Feed processing complete: %d submitted, %d failed, %d skipped (dedup)",
            processed, failed, skipped,
        )
        return {"processed": processed, "failed": failed, "skipped": skipped}

    except Exception as e:
        db.rollback()
        logger.exception("Feed processing error: %s", e)
        return {"processed": processed, "failed": failed, "error": str(e)}
    finally:
        db.close()
