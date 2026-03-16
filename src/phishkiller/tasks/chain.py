"""Chain crawling tasks — EML parsing, QR decoding, and link-following."""

import logging
import time
import uuid
from pathlib import Path

from celery.exceptions import SoftTimeLimitExceeded

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.analysis_result import AnalysisResult, AnalysisType
from phishkiller.models.kit import Kit

logger = logging.getLogger(__name__)

# Image extensions to scan for QR codes
IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
})


@celery_app.task(
    name="phishkiller.tasks.chain.parse_eml",
    bind=True,
    queue="analysis",
    soft_time_limit=120,
    time_limit=150,
)
def parse_eml(self, prev_result: dict) -> dict:
    """Parse .eml file: extract headers, body, links, attachments, images.

    No-op if the downloaded file is not an .eml file.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    filepath = prev_result.get("filepath", "")
    if not filepath or not filepath.lower().endswith(".eml"):
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from phishkiller.analysis.eml_parser import EMLParser

        parser = EMLParser()
        result = parser.parse(filepath)

        settings = get_settings()
        extract_dir = str(Path(settings.kit_extract_dir) / kit_id)

        # Save attachments and embedded images to disk for downstream tasks
        saved_files = parser.save_attachments(result, extract_dir)

        duration = time.time() - start

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.EML_PARSE,
            result_data={
                "headers": result.headers,
                "links_found": len(result.links),
                "attachments": len(result.attachments),
                "embedded_images": len(result.embedded_images),
                "has_html_body": result.body_html is not None,
                "has_text_body": result.body_text is not None,
                "saved_files": len(saved_files),
                "errors": result.errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=len(result.attachments) + len(result.embedded_images),
        )
        db.add(analysis)
        db.commit()

        logger.info(
            "EML parse for kit %s: %d links, %d attachments, %d images",
            kit_id, len(result.links), len(result.attachments),
            len(result.embedded_images),
        )

        return {
            **prev_result,
            "eml_links": result.links,
            "eml_headers": result.headers,
            "eml_attachment_count": len(result.attachments),
            "eml_image_count": len(result.embedded_images),
            # If we extracted attachments, set extract_dir for downstream
            "extract_dir": extract_dir if saved_files else prev_result.get("extract_dir"),
            "extracted": True if saved_files else prev_result.get("extracted", False),
        }

    except SoftTimeLimitExceeded:
        logger.warning("EML parse for kit %s hit time limit", kit_id)
        return prev_result
    except Exception as e:
        logger.exception("Error parsing EML for kit %s: %s", kit_id, e)
        return prev_result  # Non-fatal: don't fail the whole chain
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.chain.decode_qr_codes",
    bind=True,
    queue="analysis",
    soft_time_limit=120,
    time_limit=150,
)
def decode_qr_codes(self, prev_result: dict) -> dict:
    """Scan images in kit directory for QR codes and extract URLs.

    Scans both extracted archive images and EML embedded images.
    Gracefully degrades if pyzbar is not installed.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath", "")

    # No images to scan if no extraction and not an image file
    if not extract_dir and not any(filepath.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return {**prev_result, "qr_urls": []}

    try:
        from phishkiller.analysis.qr_decoder import QRDecoder
    except ImportError:
        logger.info("pyzbar not installed, skipping QR decode for kit %s", kit_id)
        return {**prev_result, "qr_urls": []}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "qr_urls": []}

        decoder = QRDecoder()

        if extract_dir:
            result = decoder.scan_directory(extract_dir)
        else:
            result = decoder.decode_file(filepath)

        duration = time.time() - start

        if result.qr_count > 0:
            analysis = AnalysisResult(
                kit_id=kit.id,
                analysis_type=AnalysisType.QR_DECODE,
                result_data={
                    "qr_codes_found": result.qr_count,
                    "urls_decoded": result.urls,
                    "errors": result.errors[:20],
                },
                duration_seconds=round(duration, 3),
            )
            db.add(analysis)
            db.commit()

        logger.info(
            "QR decode for kit %s: %d QR codes, %d URLs",
            kit_id, result.qr_count, len(result.urls),
        )

        return {
            **prev_result,
            "qr_urls": result.urls,
        }

    except SoftTimeLimitExceeded:
        logger.warning("QR decode for kit %s hit time limit", kit_id)
        return {**prev_result, "qr_urls": []}
    except Exception as e:
        logger.exception("Error decoding QR for kit %s: %s", kit_id, e)
        return {**prev_result, "qr_urls": []}
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.chain.crawl_chain",
    bind=True,
    queue="downloads",
    soft_time_limit=300,
    time_limit=330,
)
def crawl_chain(self, prev_result: dict) -> dict:
    """Score discovered links and submit high-scoring ones as child kits.

    Only fires for kits that belong to an investigation (chain mode).
    Collects links from: EML parsing, QR decoding, IOC extraction, redirect chain.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.investigation_id:
            return prev_result

        from phishkiller.models.investigation import Investigation

        investigation = db.query(Investigation).filter(
            Investigation.id == kit.investigation_id
        ).first()
        if not investigation:
            return prev_result

        # Depth check
        settings = get_settings()
        max_depth = min(investigation.max_depth, settings.chain_max_depth)
        if kit.chain_depth >= max_depth:
            logger.info(
                "Kit %s at max depth %d, not crawling further",
                kit_id, kit.chain_depth,
            )
            return {**prev_result, "chain_skipped": "max_depth"}

        if not settings.chain_enabled:
            return {**prev_result, "chain_skipped": "disabled"}

        # Collect all link sources
        all_links: list[tuple[str, str]] = []  # (url, source)

        for url in prev_result.get("eml_links", []):
            all_links.append((url, "eml_link"))
        for url in prev_result.get("qr_urls", []):
            all_links.append((url, "qr_code"))
        for url in prev_result.get("redirect_urls", []):
            all_links.append((url, "redirect"))

        if not all_links:
            return {**prev_result, "children_spawned": 0}

        from phishkiller.analysis.link_scorer import LinkScorer

        scorer = LinkScorer()
        scored = scorer.score_links(
            [url for url, _ in all_links],
            context={
                "sources": {url: src for url, src in all_links},
                "parent_url": kit.source_url,
            },
        )

        # Filter by threshold
        threshold = settings.chain_link_score_threshold
        max_children = settings.chain_max_children_per_kit
        to_follow = [s for s in scored if s.score >= threshold][:max_children]

        # Submit child kits
        from phishkiller.analysis.chain_crawler import ChainCrawler

        crawler = ChainCrawler(db)
        child_ids = crawler.submit_child_kits(
            parent_kit_id=kit.id,
            investigation_id=investigation.id,
            scored_links=to_follow,
            current_depth=kit.chain_depth,
        )

        # Update investigation stats
        investigation.total_kits += len(child_ids)
        new_depth = kit.chain_depth + 1
        if new_depth > investigation.total_depth_reached:
            investigation.total_depth_reached = new_depth

        # Record link scoring results
        start = time.time()
        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.LINK_SCORE,
            result_data={
                "total_links_collected": len(all_links),
                "links_scored": len(scored),
                "links_above_threshold": len(to_follow),
                "children_spawned": len(child_ids),
                "threshold": threshold,
                "scored_links": [
                    {"url": s.url, "score": s.score, "reasons": s.reasons, "source": s.source}
                    for s in scored[:50]
                ],
            },
            duration_seconds=round(time.time() - start, 3),
        )
        db.add(analysis)
        db.commit()

        logger.info(
            "Chain crawl for kit %s: %d links scored, %d children spawned",
            kit_id, len(scored), len(child_ids),
        )

        return {
            **prev_result,
            "children_spawned": len(child_ids),
            "child_kit_ids": [str(cid) for cid in child_ids],
        }

    except SoftTimeLimitExceeded:
        logger.warning("Chain crawl for kit %s hit time limit", kit_id)
        return prev_result
    except Exception as e:
        logger.exception("Error in chain crawl for kit %s: %s", kit_id, e)
        return prev_result
    finally:
        db.close()
