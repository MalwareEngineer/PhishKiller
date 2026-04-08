"""Browser-based download Celery task for Cloudflare-protected pages.

Runs on the dedicated ``browser`` queue consumed by worker-browser (solo pool).
Creates a **child kit** linked to the original httpx-downloaded parent, so both
the raw JS loader and the browser-rendered credential form are preserved as
separate entities with a parent→child relationship.
"""

import logging
import uuid
from pathlib import Path

from sqlalchemy import func

from phishkiller.analysis.browser_downloader import browser_download
from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


@celery_app.task(
    name="phishkiller.tasks.browser.browser_download_kit",
    bind=True,
    max_retries=0,
    queue="browser",
)
def browser_download_kit(self, kit_id: str, consecutive_dupes: int = 0) -> dict:
    """Download a kit using the Camoufox stealth browser.

    Called by download_kit when it detects a Cloudflare challenge.
    Creates a new child kit record linked to the parent (httpx) kit,
    then dispatches the post-download analysis chain for the child.
    The parent kit is marked ANALYZED with its original JS loader content
    preserved — both artifacts exist as separate linked entities.

    Re-dispatches itself after each render to enumerate relay domain pools.
    Stops after ``browser_render_pool_stop`` consecutive TLSH duplicates
    (pool exhausted) or when ``browser_render_max_variations`` is reached.
    """
    settings = get_settings()
    db = get_sync_db()

    try:
        parent_kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not parent_kit:
            raise ValueError(f"Kit {kit_id} not found")

        # Pool exhaustion — N consecutive renders matched existing siblings
        if consecutive_dupes >= settings.browser_render_pool_stop:
            logger.info(
                "Kit %s: relay pool exhausted (%d consecutive dupes, threshold %d)",
                kit_id, consecutive_dupes, settings.browser_render_pool_stop,
            )
            return {
                "kit_id": kit_id,
                "status": "pool_exhausted",
                "consecutive_dupes": consecutive_dupes,
            }

        # Depth guard — refuse to create another child beyond max_depth
        if parent_kit.investigation_id:
            from phishkiller.models.investigation import Investigation

            investigation = db.query(Investigation).filter(
                Investigation.id == parent_kit.investigation_id
            ).first()
            if investigation:
                max_depth = min(investigation.max_depth, settings.chain_max_depth)
                if parent_kit.chain_depth >= max_depth:
                    logger.info(
                        "Kit %s at depth %d (max %d), skipping browser render",
                        kit_id, parent_kit.chain_depth, max_depth,
                    )
                    return {"kit_id": kit_id, "status": "skipped", "reason": "max_depth"}

        # Variation cap — limit total browser_render children per investigation
        if parent_kit.investigation_id:
            browser_child_count = db.query(func.count(Kit.id)).filter(
                Kit.investigation_id == parent_kit.investigation_id,
                Kit.discovery_method == "browser_render",
            ).scalar()
            if browser_child_count >= settings.browser_render_max_variations:
                logger.info(
                    "Investigation %s has %d browser_render kits (max %d), "
                    "skipping",
                    parent_kit.investigation_id, browser_child_count,
                    settings.browser_render_max_variations,
                )
                return {
                    "kit_id": kit_id,
                    "status": "skipped",
                    "reason": "max_variations",
                }

        logger.info(
            "Browser downloading kit %s from %s", kit_id, parent_kit.source_url,
        )

        # Create the child kit record before downloading
        child_kit = Kit(
            source_url=parent_kit.source_url,
            source_feed=parent_kit.source_feed,
            status=KitStatus.DOWNLOADING,
            parent_kit_id=parent_kit.id,
            investigation_id=parent_kit.investigation_id,
            chain_depth=parent_kit.chain_depth + 1,
            discovery_method="browser_render",
        )
        db.add(child_kit)
        db.flush()  # Get child ID

        child_id = str(child_kit.id)

        # Update investigation counters if this kit belongs to one
        if parent_kit.investigation_id:
            from phishkiller.models.investigation import Investigation

            investigation = db.query(Investigation).filter(
                Investigation.id == parent_kit.investigation_id
            ).first()
            if investigation:
                investigation.total_kits += 1
                new_depth = parent_kit.chain_depth + 1
                if new_depth > investigation.total_depth_reached:
                    investigation.total_depth_reached = new_depth

        db.commit()

        # Download into child kit's own directory
        download_dir = Path(settings.kit_download_dir) / child_id
        download_dir.mkdir(parents=True, exist_ok=True)

        filepath, reason, final_url = browser_download(
            parent_kit.source_url,
            str(download_dir),
            timeout=settings.browser_download_timeout,
            turnstile_timeout=settings.browser_turnstile_timeout,
        )

        if not filepath:
            child_kit.status = KitStatus.FAILED
            child_kit.error_message = f"Browser fallback failed: {reason}"
            # Mark parent as FAILED only if it hasn't already been analyzed
            # (re-renders may fail after first successful render)
            if parent_kit.status != KitStatus.ANALYZED:
                parent_kit.status = KitStatus.FAILED
                parent_kit.error_message = (
                    f"httpx: ConnectError → browser: {reason}"[:500]
                )
            db.commit()

            # Check investigation completion (both kits are now terminal)
            if parent_kit.investigation_id:
                from phishkiller.tasks.analysis import _try_complete_investigation

                _try_complete_investigation(db, parent_kit.investigation_id)

            logger.warning(
                "Browser download failed for child kit %s (parent %s): %s",
                child_id, kit_id, reason,
            )
            return {
                "kit_id": child_id,
                "parent_kit_id": kit_id,
                "status": "failed",
                "error": reason,
            }

        # Update child kit metadata
        child_kit.local_path = str(filepath)
        child_kit.filename = filepath.name
        child_kit.file_size = filepath.stat().st_size
        child_kit.status = KitStatus.DOWNLOADED

        suffix = filepath.suffix.lower()
        mime_map = {
            ".html": "text/html",
            ".htm": "text/html",
            ".zip": "application/zip",
            ".gz": "application/gzip",
            ".tar": "application/x-tar",
            ".rar": "application/x-rar-compressed",
            ".php": "application/x-php",
            ".eml": "message/rfc822",
        }
        child_kit.mime_type = mime_map.get(suffix, "text/html")

        # Update child source_url to the browser's final URL (relay domain)
        # so each child reflects where its content actually came from.
        if final_url and final_url != parent_kit.source_url:
            child_kit.source_url = final_url

        # Mark parent as ANALYZED (first render only) — it keeps its
        # httpx-downloaded content (the raw JS loader / first-stage payload)
        if parent_kit.status != KitStatus.ANALYZED:
            parent_kit.status = KitStatus.ANALYZED

        # --- Compute hashes ---
        from phishkiller.analysis.hasher import (
            compute_hashes as do_hash,
            compute_tlsh_distance,
        )

        child_hashes = do_hash(filepath)
        child_kit.sha256 = child_hashes.sha256
        child_kit.md5 = child_hashes.md5
        child_kit.sha1 = child_hashes.sha1
        child_kit.tlsh = child_hashes.tlsh

        # --- Relay domain dedup ---
        # PhaaS kits rotate relay domains per-visit, but the same domain
        # can repeat.  When the child lands on a domain we've already
        # captured, mark it FAILED (preserving files on disk) and count
        # toward pool exhaustion.
        dup_of: str | None = None
        dup_reason: str | None = None
        if final_url and child_kit.investigation_id:
            from urllib.parse import urlparse

            child_domain = urlparse(final_url).hostname
            if child_domain:
                siblings = db.query(Kit).filter(
                    Kit.investigation_id == child_kit.investigation_id,
                    Kit.id != child_kit.id,
                    Kit.discovery_method == "browser_render",
                ).all()

                for sibling in siblings:
                    sib_domain = urlparse(sibling.source_url).hostname
                    if sib_domain == child_domain:
                        dup_of = str(sibling.id)
                        dup_reason = (
                            f"Relay domain duplicate of kit {sibling.id} "
                            f"(domain: {child_domain})"
                        )
                        break

        # --- TLSH dedup ---
        # Near-identical content to a sibling (within TLSH threshold).
        # Mark FAILED and count toward pool exhaustion, but keep files.
        if not dup_of and child_hashes.tlsh and child_kit.investigation_id:
            siblings = db.query(Kit).filter(
                Kit.investigation_id == child_kit.investigation_id,
                Kit.id != child_kit.id,
                Kit.tlsh.isnot(None),
            ).all()

            for sibling in siblings:
                if not sibling.tlsh:
                    continue
                distance = compute_tlsh_distance(
                    child_hashes.tlsh, sibling.tlsh,
                )
                if (
                    distance is not None
                    and distance <= settings.browser_dedup_tlsh_threshold
                ):
                    dup_of = str(sibling.id)
                    dup_reason = (
                        f"TLSH duplicate of kit {sibling.id} "
                        f"(distance: {distance}, "
                        f"threshold: {settings.browser_dedup_tlsh_threshold})"
                    )
                    break

        # --- Apply dedup result ---
        # Duplicates are marked FAILED with a descriptive error_message
        # so they're visible in the UI but clearly flagged.  Files stay
        # on disk — nothing is deleted.
        if dup_of:
            child_kit.status = KitStatus.FAILED
            child_kit.error_message = dup_reason
            db.commit()

            logger.info(
                "Kit %s marked as duplicate: %s", child_id, dup_reason,
            )

            # Count toward pool exhaustion and schedule next re-render
            next_dupes = consecutive_dupes + 1
            if next_dupes < settings.browser_render_pool_stop:
                browser_download_kit.apply_async(
                    args=[kit_id, next_dupes],
                )

            return {
                "kit_id": child_id,
                "parent_kit_id": kit_id,
                "status": "duplicate",
                "duplicate_of": dup_of,
                "reason": dup_reason,
            }

        db.commit()

        logger.info(
            "Browser downloaded child kit %s (parent %s): %s (%d bytes)",
            child_id, kit_id, filepath.name, child_kit.file_size,
        )

        # Dispatch post-download analysis chain for unique children only.
        download_result = {
            "kit_id": child_id,
            "parent_kit_id": kit_id,
            "status": "downloaded",
            "filepath": str(filepath),
            "file_size": child_kit.file_size,
            "extract_dir": str(download_dir),
        }

        from phishkiller.tasks.analysis import build_post_download_chain

        build_post_download_chain(download_result).apply_async()

        # Re-render to discover more relay variations (reset dupe counter),
        # but only if the browser redirected to a different domain (relay
        # rotation).  If the final URL stays on the lure domain there's no
        # relay pool to enumerate.
        from urllib.parse import urlparse as _urlparse

        lure_domain = _urlparse(parent_kit.source_url).hostname
        final_domain = _urlparse(final_url).hostname if final_url else None
        if final_domain and final_domain != lure_domain:
            browser_download_kit.apply_async(args=[kit_id, 0])
            return {**download_result, "rerender_scheduled": True}

        return download_result

    except Exception as e:
        logger.exception("Browser download error for kit %s: %s", kit_id, e)
        try:
            db.rollback()
            parent_kit = db.query(Kit).filter(
                Kit.id == uuid.UUID(kit_id)
            ).first()
            if parent_kit:
                parent_kit.status = KitStatus.FAILED
                parent_kit.error_message = f"Browser error: {e!s}"[:500]
                db.commit()
        except Exception as exc:
            logger.debug(
                "Failed to mark kit as FAILED during error handling: %s", exc,
            )
        return {"kit_id": kit_id, "status": "failed", "error": str(e)}

    finally:
        db.close()
