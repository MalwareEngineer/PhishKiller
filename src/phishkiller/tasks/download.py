"""Kit download Celery task."""

import logging
import uuid
from pathlib import Path

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.kit import Kit, KitStatus
from phishkiller.utils.http_client import download_file

logger = logging.getLogger(__name__)


@celery_app.task(
    name="phishkiller.tasks.download.download_kit",
    bind=True,
    max_retries=1,
    default_retry_delay=30,
    queue="downloads",
)
def download_kit(self, kit_id: str) -> dict:
    """Download a phishing kit archive from its source URL.

    Updates the kit record with file metadata and transitions
    status to DOWNLOADED or FAILED.
    """
    settings = get_settings()
    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            raise ValueError(f"Kit {kit_id} not found")

        kit.status = KitStatus.DOWNLOADING
        db.commit()

        logger.info("Downloading kit %s from %s", kit_id, kit.source_url)

        # Create per-kit download directory
        download_dir = Path(settings.kit_download_dir) / kit_id
        download_dir.mkdir(parents=True, exist_ok=True)

        filepath = download_file(
            kit.source_url,
            str(download_dir),
            max_size_mb=settings.max_kit_size_mb,
        )

        if not filepath:
            kit.status = KitStatus.FAILED
            kit.error_message = "Download failed or exceeded size limit"
            db.commit()
            return {"kit_id": kit_id, "status": "failed", "error": "download_failed"}

        # Update kit metadata
        kit.local_path = str(filepath)
        kit.filename = filepath.name
        kit.file_size = filepath.stat().st_size
        kit.status = KitStatus.DOWNLOADED

        # Guess MIME type
        suffix = filepath.suffix.lower()
        mime_map = {
            ".zip": "application/zip",
            ".gz": "application/gzip",
            ".tar": "application/x-tar",
            ".rar": "application/x-rar-compressed",
            ".php": "application/x-php",
        }
        kit.mime_type = mime_map.get(suffix, "application/octet-stream")
        db.commit()

        logger.info(
            "Kit %s downloaded: %s (%d bytes)",
            kit_id, filepath.name, kit.file_size,
        )
        return {
            "kit_id": kit_id,
            "status": "downloaded",
            "filepath": str(filepath),
            "file_size": kit.file_size,
        }

    except Exception as e:
        logger.exception("Error downloading kit %s: %s", kit_id, e)
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception:
            pass
        raise self.retry(exc=e)

    finally:
        db.close()
