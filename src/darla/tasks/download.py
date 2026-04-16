"""Kit download Celery task."""

import logging
import uuid
from pathlib import Path

from darla.analysis.redirect_tracker import RedirectTracker
from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.analysis_result import AnalysisType
from darla.tasks.analysis import upsert_analysis_result
from darla.models.kit import Kit, KitStatus
from darla.utils.http_client import download_file

logger = logging.getLogger(__name__)


@celery_app.task(
    name="darla.tasks.download.download_kit",
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

        # If file already exists on disk (e.g. manual upload), skip download
        if kit.local_path and Path(kit.local_path).exists():
            filepath = Path(kit.local_path)
            kit.file_size = filepath.stat().st_size
            kit.filename = filepath.name
            kit.status = KitStatus.DOWNLOADED
            suffix = filepath.suffix.lower()
            mime_map = {
                ".zip": "application/zip",
                ".gz": "application/gzip",
                ".tar": "application/x-tar",
                ".rar": "application/x-rar-compressed",
                ".php": "application/x-php",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".bmp": "image/bmp",
                ".webp": "image/webp",
                ".eml": "message/rfc822",
            }
            kit.mime_type = mime_map.get(suffix, "application/octet-stream")
            db.commit()
            logger.info("Kit %s already has local file, skipping download", kit_id)
            return {
                "kit_id": kit_id,
                "status": "downloaded",
                "filepath": kit.local_path,
                "file_size": kit.file_size,
            }

        kit.status = KitStatus.DOWNLOADING
        db.commit()

        logger.info("Downloading kit %s from %s", kit_id, kit.source_url)

        # Create per-kit download directory
        download_dir = Path(settings.kit_download_dir) / kit_id
        download_dir.mkdir(parents=True, exist_ok=True)

        redirect_chain_data = None

        # Investigation-mode kits use redirect tracking to capture the full chain
        if kit.investigation_id:
            tracker = RedirectTracker()
            filepath, reason, redirect_chain = tracker.download_with_redirects(
                kit.source_url,
                str(download_dir),
                max_size_mb=settings.max_kit_size_mb,
            )
            if redirect_chain.total_redirects > 0:
                redirect_chain_data = redirect_chain.to_dict()
                # Store redirect chain as an analysis result
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.REDIRECT_CHAIN,
                    result_data=redirect_chain_data,
                )
        else:
            filepath, reason = download_file(
                kit.source_url,
                str(download_dir),
                max_size_mb=settings.max_kit_size_mb,
            )

        if not filepath:
            # Dispatch to browser worker for Cloudflare-protected pages
            if settings.browser_download_enabled:
                from darla.analysis.browser_downloader import (
                    is_cloudflare_challenge,
                )

                if is_cloudflare_challenge(reason):
                    logger.info(
                        "Kit %s: httpx failed (%s), dispatching to browser worker",
                        kit_id, reason,
                    )
                    from darla.tasks.browser import browser_download_kit

                    browser_download_kit.apply_async(args=[kit_id])
                    result = {
                        "kit_id": kit_id,
                        "status": "browser_retry",
                    }
                    if redirect_chain_data:
                        result["redirect_chain"] = redirect_chain_data
                    return result

        if not filepath:
            kit.status = KitStatus.FAILED
            kit.error_message = reason
            db.commit()
            result = {"kit_id": kit_id, "status": "failed", "error": reason}
            if redirect_chain_data:
                result["redirect_chain"] = redirect_chain_data
            return result

        # Update kit metadata
        kit.local_path = str(filepath)
        kit.filename = filepath.name
        kit.file_size = filepath.stat().st_size

        # Treat 0-byte responses as download failures — the server
        # returned nothing (common with bot-gated pages).  Dispatch to
        # browser worker if enabled, otherwise mark FAILED.
        if kit.file_size == 0:
            if settings.browser_download_enabled:
                logger.info(
                    "Kit %s: 0-byte response, dispatching to browser worker",
                    kit_id,
                )
                from darla.tasks.browser import browser_download_kit

                browser_download_kit.apply_async(args=[kit_id])
                return {
                    "kit_id": kit_id,
                    "status": "browser_retry",
                }
            else:
                kit.status = KitStatus.FAILED
                kit.error_message = "Empty response (0 bytes)"
                db.commit()
                return {
                    "kit_id": kit_id,
                    "status": "failed",
                    "error": "empty_response",
                }

        kit.status = KitStatus.DOWNLOADED

        # Guess MIME type
        suffix = filepath.suffix.lower()
        mime_map = {
            ".zip": "application/zip",
            ".gz": "application/gzip",
            ".tar": "application/x-tar",
            ".rar": "application/x-rar-compressed",
            ".php": "application/x-php",
            ".eml": "message/rfc822",
        }
        kit.mime_type = mime_map.get(suffix, "application/octet-stream")
        db.commit()

        logger.info(
            "Kit %s downloaded: %s (%d bytes)",
            kit_id, filepath.name, kit.file_size,
        )
        result = {
            "kit_id": kit_id,
            "status": "downloaded",
            "filepath": str(filepath),
            "file_size": kit.file_size,
        }
        if redirect_chain_data:
            result["redirect_chain"] = redirect_chain_data
            # Only the final destination becomes a child kit — intermediate
            # hops are recorded in the redirect_chain analysis result but
            # don't spawn their own kits.
            final_url = redirect_chain_data.get("final_url", "")
            if final_url and final_url != kit.source_url:
                result["redirect_urls"] = [final_url]
            else:
                result["redirect_urls"] = []

        # Tier A: JS loader / embedded challenge detection
        # → dispatch browser render in parallel with analysis chain
        if settings.browser_download_enabled:
            is_html_like = (
                suffix in (".html", ".htm", ".bin", "")
                or kit.mime_type == "application/octet-stream"
            )
            if is_html_like:
                dispatch_browser = False

                from darla.analysis.browser_downloader import is_js_loader

                if is_js_loader(filepath):
                    logger.info(
                        "Kit %s: JS loader detected, dispatching browser render",
                        kit_id,
                    )
                    dispatch_browser = True

                # Tier A.5: Cloudflare Turnstile/challenge in HTTP 200
                # body — httpx got the page but it needs a browser to
                # solve the embedded challenge.
                if not dispatch_browser:
                    try:
                        body = filepath.read_text(
                            encoding="utf-8", errors="ignore",
                        )[:100_000]
                        _CF_BODY_MARKERS = [
                            "challenges.cloudflare.com/turnstile",
                            "cf-turnstile",
                            "data-sitekey",
                        ]
                        if any(m in body for m in _CF_BODY_MARKERS):
                            logger.info(
                                "Kit %s: Cloudflare Turnstile in response body, "
                                "dispatching browser render",
                                kit_id,
                            )
                            dispatch_browser = True
                    except Exception:
                        pass

                if dispatch_browser:
                    from darla.tasks.browser import browser_download_kit

                    browser_download_kit.apply_async(args=[kit_id])
                    result["browser_render_dispatched"] = True

        return result

    except Exception as e:
        logger.exception("Error downloading kit %s: %s", kit_id, e)
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        raise self.retry(exc=e) from e

    finally:
        db.close()
