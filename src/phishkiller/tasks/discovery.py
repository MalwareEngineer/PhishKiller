"""Kit discovery task — probe phishing URLs for additional kit archives.

Given a feed entry URL (typically a landing page), walks up the path tree
looking for downloadable archives and open directory listings. Any discovered
kits are submitted as new Kit records with their own analysis chains.
"""

import logging
import time
import uuid

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.feed_entry import FeedEntry
from phishkiller.models.kit import Kit, KitStatus
from phishkiller.utils.directory_scraper import (
    generate_probe_urls,
    is_archive_response,
    parse_open_directory,
)
from phishkiller.utils.http_client import get_sync_client

logger = logging.getLogger(__name__)

# Safety limits
MAX_PROBES_PER_ENTRY = 20
PROBE_DELAY_SECONDS = 0.5
PROBE_TIMEOUT = 10


@celery_app.task(
    name="phishkiller.tasks.discovery.discover_kits",
    bind=True,
    max_retries=0,
    queue="downloads",
)
def discover_kits(self, feed_entry_id: str) -> dict:
    """Probe a feed entry URL for additional kit archives.

    Walks up the URL path tree, checks for open directory listings,
    and guesses common archive filenames. Any valid archives found
    are submitted as new Kit records with full analysis chains.
    """
    settings = get_settings()
    db = get_sync_db()

    probed = 0
    discovered = 0
    submitted = 0
    skipped_dup = 0

    try:
        entry = (
            db.query(FeedEntry)
            .filter(FeedEntry.id == uuid.UUID(feed_entry_id))
            .first()
        )
        if not entry:
            logger.warning("FeedEntry %s not found for discovery", feed_entry_id)
            return {"probed": 0, "discovered": 0, "submitted": 0, "skipped_dup": 0}

        url = entry.url
        source_label = f"discovery:{entry.source.value}"

        # Skip file:// uploads
        if url.startswith("file://"):
            return {"probed": 0, "discovered": 0, "submitted": 0, "skipped_dup": 0}

        probe_urls = generate_probe_urls(url)
        if not probe_urls:
            return {"probed": 0, "discovered": 0, "submitted": 0, "skipped_dup": 0}

        # Limit probes
        probe_urls = probe_urls[:MAX_PROBES_PER_ENTRY]

        discovered_urls: list[str] = []

        with get_sync_client(timeout=PROBE_TIMEOUT) as client:
            for probe in probe_urls:
                probe_url = probe["url"]
                probe_type = probe["type"]
                probed += 1

                try:
                    if probe_type == "zip_guess":
                        # HEAD request to check if it's a downloadable archive
                        response = client.head(probe_url)
                        if is_archive_response(response, settings.max_kit_size_mb):
                            logger.info(
                                "Discovery: found archive at %s (from %s)",
                                probe_url, url,
                            )
                            discovered_urls.append(probe_url)
                            discovered += 1

                    elif probe_type == "directory":
                        # GET the page and check for open directory
                        response = client.get(probe_url)
                        if response.status_code == 200:
                            content_type = response.headers.get("content-type", "")
                            if "text/html" in content_type:
                                archive_links = parse_open_directory(
                                    response.text, probe_url
                                )
                                for link in archive_links:
                                    logger.info(
                                        "Discovery: found %s in open dir %s (from %s)",
                                        link, probe_url, url,
                                    )
                                    discovered_urls.append(link)
                                    discovered += 1

                except Exception as e:
                    logger.debug(
                        "Discovery probe failed for %s: %s", probe_url, e
                    )

                # Rate limit between probes to the same host
                time.sleep(PROBE_DELAY_SECONDS)

        # Submit discovered kit URLs
        if discovered_urls:
            from phishkiller.tasks.analysis import build_analysis_chain

            for kit_url in discovered_urls:
                # URL dedup — skip if we already have this URL
                existing = (
                    db.query(Kit)
                    .filter(
                        Kit.source_url == kit_url,
                        Kit.status != KitStatus.FAILED,
                    )
                    .first()
                )
                if existing:
                    skipped_dup += 1
                    continue

                kit = Kit(
                    id=uuid.uuid4(),
                    source_url=kit_url,
                    source_feed=source_label,
                    feed_entry_id=entry.id,
                    status=KitStatus.PENDING,
                )
                db.add(kit)
                db.flush()

                build_analysis_chain(str(kit.id)).apply_async()
                submitted += 1

            db.commit()

        logger.info(
            "Discovery for %s: probed=%d discovered=%d submitted=%d skipped_dup=%d",
            url, probed, discovered, submitted, skipped_dup,
        )

    except Exception as e:
        logger.exception("Discovery failed for entry %s: %s", feed_entry_id, e)

    finally:
        db.close()

    return {
        "probed": probed,
        "discovered": discovered,
        "submitted": submitted,
        "skipped_dup": skipped_dup,
    }
