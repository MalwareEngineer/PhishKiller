"""Analysis pipeline Celery tasks — hash, extract, deobfuscate, extract IOCs."""

import logging
import time
import uuid
from pathlib import Path

from celery import chain

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.analysis_result import AnalysisResult, AnalysisType
from phishkiller.models.indicator import Indicator
from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


def build_analysis_chain(kit_id: str) -> chain:
    """Build the full analysis Celery chain for a kit."""
    from phishkiller.tasks.download import download_kit

    return chain(
        download_kit.s(kit_id),
        compute_hashes.s(),
        extract_archive.s(),
        deobfuscate_files.s(),
        extract_iocs.s(),
    )


@celery_app.task(
    name="phishkiller.tasks.analysis.compute_hashes",
    bind=True,
    queue="analysis",
)
def compute_hashes(self, prev_result: dict) -> dict:
    """Compute SHA256, MD5, SHA1, and TLSH hashes for the kit archive."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.local_path:
            return {**prev_result, "status": "failed", "error": "no_local_file"}

        kit.status = KitStatus.ANALYZING
        db.commit()

        from phishkiller.analysis.hasher import compute_hashes as do_hash

        result = do_hash(kit.local_path)

        kit.sha256 = result.sha256
        kit.md5 = result.md5
        kit.sha1 = result.sha1
        kit.tlsh = result.tlsh

        duration = time.time() - start

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.HASH,
            result_data={
                "sha256": result.sha256,
                "md5": result.md5,
                "sha1": result.sha1,
                "tlsh": result.tlsh,
                "file_size": result.file_size,
            },
            duration_seconds=round(duration, 3),
        )
        db.add(analysis)
        db.commit()

        logger.info("Hashes computed for kit %s: sha256=%s", kit_id, result.sha256[:16])
        return {
            **prev_result,
            "sha256": result.sha256,
            "hashed": True,
        }

    except Exception as e:
        logger.exception("Error hashing kit %s: %s", kit_id, e)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.analysis.extract_archive",
    bind=True,
    queue="analysis",
)
def extract_archive(self, prev_result: dict) -> dict:
    """Extract the kit archive into a directory for analysis."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    settings = get_settings()
    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.local_path:
            return {**prev_result, "status": "failed", "error": "no_local_file"}

        extract_dir = str(Path(settings.kit_extract_dir) / kit_id)

        from phishkiller.analysis.extractor import ArchiveExtractor

        extractor = ArchiveExtractor()
        result = extractor.extract(kit.local_path, extract_dir)

        duration = time.time() - start

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.IOC_EXTRACTION,
            result_data={
                "step": "extraction",
                "file_count": result.file_count,
                "total_size": result.total_size,
                "errors": result.errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=result.file_count,
        )
        db.add(analysis)
        db.commit()

        logger.info(
            "Extracted kit %s: %d files, %d bytes",
            kit_id, result.file_count, result.total_size,
        )
        return {
            **prev_result,
            "extract_dir": extract_dir,
            "file_count": result.file_count,
            "extracted": True,
        }

    except Exception as e:
        logger.exception("Error extracting kit %s: %s", kit_id, e)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.analysis.deobfuscate_files",
    bind=True,
    queue="analysis",
)
def deobfuscate_files(self, prev_result: dict) -> dict:
    """Deobfuscate PHP files in the extracted kit directory."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    if not extract_dir:
        return {**prev_result, "deobfuscated": False}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from phishkiller.analysis.deobfuscator import PHPDeobfuscator

        deobfuscator = PHPDeobfuscator()
        deob_results = []
        files_processed = 0

        for php_file in Path(extract_dir).rglob("*.php"):
            try:
                result = deobfuscator.deobfuscate_file(str(php_file))
                if result.layers_unwrapped > 0:
                    # Overwrite the file with deobfuscated content
                    php_file.write_text(
                        result.deobfuscated_content, encoding="utf-8"
                    )
                    deob_results.append({
                        "file": str(php_file.relative_to(extract_dir)),
                        "layers": result.layers_unwrapped,
                        "techniques": result.techniques_found,
                    })
                files_processed += 1
            except Exception as e:
                logger.debug("Failed to deobfuscate %s: %s", php_file, e)

        duration = time.time() - start

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.DEOBFUSCATION,
            result_data={
                "files_deobfuscated": len(deob_results),
                "details": deob_results[:50],
            },
            duration_seconds=round(duration, 3),
            files_processed=files_processed,
        )
        db.add(analysis)
        db.commit()

        logger.info(
            "Deobfuscation for kit %s: %d/%d files had obfuscation",
            kit_id, len(deob_results), files_processed,
        )
        return {
            **prev_result,
            "deobfuscated": True,
            "files_deobfuscated": len(deob_results),
        }

    except Exception as e:
        logger.exception("Error deobfuscating kit %s: %s", kit_id, e)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


@celery_app.task(
    name="phishkiller.tasks.analysis.extract_iocs",
    bind=True,
    queue="analysis",
)
def extract_iocs(self, prev_result: dict) -> dict:
    """Extract IOCs from the (deobfuscated) kit files and store them."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    if not extract_dir:
        return {**prev_result, "iocs_extracted": 0}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from phishkiller.analysis.ioc_engine import IOCExtractor

        extractor = IOCExtractor()
        result = extractor.scan_directory(extract_dir)

        # Store indicators
        for ioc in result.iocs:
            indicator = Indicator(
                type=ioc.type,
                value=ioc.value,
                context=ioc.context,
                source_file=ioc.source_file,
                confidence=ioc.confidence,
                kit_id=kit.id,
            )
            db.add(indicator)

        kit.status = KitStatus.ANALYZED

        duration = time.time() - start

        ioc_summary = {}
        for ioc in result.iocs:
            ioc_type = ioc.type.value
            ioc_summary[ioc_type] = ioc_summary.get(ioc_type, 0) + 1

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.IOC_EXTRACTION,
            result_data={
                "step": "ioc_extraction",
                "total_iocs": len(result.iocs),
                "by_type": ioc_summary,
                "files_processed": result.files_processed,
                "errors": result.errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=result.files_processed,
        )
        db.add(analysis)
        db.commit()

        logger.info(
            "IOC extraction for kit %s: %d IOCs from %d files",
            kit_id, len(result.iocs), result.files_processed,
        )
        return {
            "kit_id": kit_id,
            "status": "analyzed",
            "iocs_extracted": len(result.iocs),
            "ioc_summary": ioc_summary,
        }

    except Exception as e:
        logger.exception("Error extracting IOCs from kit %s: %s", kit_id, e)
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception:
            pass
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()
