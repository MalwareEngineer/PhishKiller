"""Analysis pipeline Celery tasks — hash, extract, deobfuscate, extract IOCs."""

import logging
import time
import uuid
from pathlib import Path

from celery import chain
from celery.exceptions import SoftTimeLimitExceeded

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

    from phishkiller.tasks.correlation import correlate_kit_actors

    return chain(
        download_kit.s(kit_id),
        compute_hashes.s(),
        extract_archive.s(),
        deobfuscate_files.s(),
        yara_scan.s(),
        extract_iocs.s(),
        compute_similarity.s(),
        correlate_kit_actors.s(),
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

        # Check for duplicate SHA256 before writing
        existing = db.query(Kit).filter(
            Kit.sha256 == result.sha256,
            Kit.id != kit.id,
        ).first()

        if existing:
            kit.status = KitStatus.FAILED
            kit.error_message = f"Duplicate of kit {existing.id} (same SHA256)"
            db.commit()
            logger.info(
                "Kit %s is duplicate of %s (sha256=%s)",
                kit_id, existing.id, result.sha256[:16],
            )
            return {**prev_result, "status": "failed", "error": "duplicate_sha256"}

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
        try:
            db.rollback()
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


@celery_app.task(
    name="phishkiller.tasks.analysis.extract_archive",
    bind=True,
    queue="analysis",
)
def extract_archive(self, prev_result: dict) -> dict:
    """Extract the kit archive into a directory for analysis.

    Skips extraction for non-archive files (HTML pages, etc.) and passes
    them through so IOC extraction can scan the raw downloaded file.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    # Skip extraction for non-archive files
    filepath = prev_result.get("filepath", "")
    if filepath:
        archive_extensions = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".rar"}
        suffixes = {s.lower() for s in Path(filepath).suffixes}
        if not suffixes & archive_extensions:
            logger.info(
                "Kit %s is not an archive, skipping extraction", kit_id
            )
            return {**prev_result, "extracted": False, "skipped_extraction": True}

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
        try:
            db.rollback()
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

    # Skip if extraction was skipped (non-archive file)
    if prev_result.get("skipped_extraction"):
        return {**prev_result, "deobfuscated": False}

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
        try:
            db.rollback()
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


@celery_app.task(
    name="phishkiller.tasks.analysis.extract_iocs",
    bind=True,
    queue="analysis",
    soft_time_limit=300,   # 5 min — raises SoftTimeLimitExceeded
    time_limit=330,        # 5.5 min — SIGKILL if soft limit is caught/ignored
)
def extract_iocs(self, prev_result: dict) -> dict:
    """Extract IOCs from kit files (extracted archive or single downloaded file)."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return {**prev_result, "iocs_extracted": 0}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from phishkiller.analysis.ioc_engine import IOCExtractor

        extractor = IOCExtractor()
        if extract_dir:
            result = extractor.scan_directory(extract_dir)
        else:
            result = extractor.scan_file(filepath)

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

    except SoftTimeLimitExceeded:
        duration = time.time() - start
        logger.warning(
            "IOC extraction for kit %s hit time limit after %.0fs, "
            "saving partial results",
            kit_id, duration,
        )
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.ANALYZED
                analysis = AnalysisResult(
                    kit_id=kit.id,
                    analysis_type=AnalysisType.IOC_EXTRACTION,
                    result_data={
                        "step": "ioc_extraction",
                        "total_iocs": 0,
                        "by_type": {},
                        "files_processed": 0,
                        "errors": [f"Time limit exceeded after {duration:.0f}s"],
                        "timed_out": True,
                    },
                    duration_seconds=round(duration, 3),
                    files_processed=0,
                )
                db.add(analysis)
                db.commit()
        except Exception:
            pass
        return {
            "kit_id": kit_id,
            "status": "analyzed",
            "iocs_extracted": 0,
            "ioc_summary": {},
            "timed_out": True,
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


# ---------------------------------------------------------------------------
# YARA Scanning
# ---------------------------------------------------------------------------

@celery_app.task(
    name="phishkiller.tasks.analysis.yara_scan",
    bind=True,
    queue="analysis",
)
def yara_scan(self, prev_result: dict) -> dict:
    """Scan kit files against YARA rules for family/technique classification."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return {**prev_result, "yara_matches": []}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "yara_matches": []}

        settings = get_settings()
        from phishkiller.analysis.yara_scanner import get_cached_scanner

        scanner = get_cached_scanner(settings.yara_rules_dir)
        rules_count = scanner.rules_loaded

        if rules_count == 0:
            logger.debug("No YARA rules loaded, skipping scan for kit %s", kit_id)
            return {**prev_result, "yara_matches": []}

        # Always scan the raw downloaded file first (t4d rules match ZIP headers)
        result = scanner.scan_file(filepath) if filepath else None

        # Also scan extracted directory if available (our custom rules match PHP/HTML content)
        if extract_dir:
            dir_result = scanner.scan_directory(extract_dir)
            if result:
                result.matches.extend(dir_result.matches)
                result.files_scanned += dir_result.files_scanned
            else:
                result = dir_result

        if not result:
            return {**prev_result, "yara_matches": []}

        duration = time.time() - start

        match_data = [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": m.tags,
                "meta": m.meta,
            }
            for m in result.matches
        ]

        # Deduplicate by rule name (same rule may match multiple files)
        seen_rules = set()
        unique_matches = []
        for m in match_data:
            if m["rule"] not in seen_rules:
                seen_rules.add(m["rule"])
                unique_matches.append(m)

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.YARA_SCAN,
            result_data={
                "rules_loaded": rules_count,
                "matches": unique_matches,
                "match_count": len(unique_matches),
                "files_scanned": result.files_scanned,
                "error": result.error,
            },
            duration_seconds=round(duration, 3),
            files_processed=result.files_scanned,
        )
        db.add(analysis)
        db.commit()

        if unique_matches:
            rule_names = [m["rule"] for m in unique_matches]
            logger.info(
                "YARA scan for kit %s: %d rules matched (%s)",
                kit_id, len(unique_matches), ", ".join(rule_names[:5]),
            )
        else:
            logger.debug("YARA scan for kit %s: no matches", kit_id)

        return {
            **prev_result,
            "yara_matches": unique_matches,
        }

    except Exception as e:
        logger.exception("Error in YARA scan for kit %s: %s", kit_id, e)
        # YARA failure is non-fatal — don't fail the kit
        return {**prev_result, "yara_matches": []}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TLSH Similarity
# ---------------------------------------------------------------------------

@celery_app.task(
    name="phishkiller.tasks.analysis.compute_similarity",
    bind=True,
    queue="analysis",
)
def compute_similarity(self, prev_result: dict) -> dict:
    """Compare kit TLSH against recent analyzed kits for similarity clustering."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.tlsh:
            return {**prev_result, "similar_kits": []}

        from phishkiller.analysis.hasher import compute_tlsh_distance
        from sqlalchemy import select

        # Compare against recent analyzed kits with TLSH (limit 500 for perf)
        candidates = db.scalars(
            select(Kit).where(
                Kit.tlsh.isnot(None),
                Kit.id != kit.id,
                Kit.status == KitStatus.ANALYZED,
            ).order_by(Kit.created_at.desc()).limit(500)
        ).all()

        threshold = 100
        similar = []
        for candidate in candidates:
            distance = compute_tlsh_distance(kit.tlsh, candidate.tlsh)
            if distance is not None and distance <= threshold:
                similar.append({
                    "kit_id": str(candidate.id),
                    "distance": distance,
                    "sha256": candidate.sha256,
                    "source_url": candidate.source_url,
                })

        similar.sort(key=lambda x: x["distance"])

        duration = time.time() - start

        analysis = AnalysisResult(
            kit_id=kit.id,
            analysis_type=AnalysisType.SIMILARITY,
            result_data={
                "similar_kits": similar[:50],  # cap stored results
                "candidates_checked": len(candidates),
                "threshold": threshold,
                "matches_found": len(similar),
            },
            duration_seconds=round(duration, 3),
        )
        db.add(analysis)
        db.commit()

        if similar:
            logger.info(
                "Similarity for kit %s: %d similar kits (closest distance=%d)",
                kit_id, len(similar), similar[0]["distance"],
            )

        return {**prev_result, "similar_kits": similar[:10]}

    except Exception as e:
        logger.exception("Error computing similarity for kit %s: %s", kit_id, e)
        # Similarity failure is non-fatal
        return {**prev_result, "similar_kits": []}
    finally:
        db.close()
