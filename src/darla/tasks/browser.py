"""Browser-based download Celery task for Cloudflare-protected pages.

Runs on the dedicated ``browser`` queue consumed by worker-browser (solo pool).
Creates a **child kit** linked to the original httpx-downloaded parent, so both
the raw JS loader and the browser-rendered credential form are preserved as
separate entities with a parent→child relationship.

Dedup strategy:
  1. **Ancestor chain** — compare child against its parent chain (parent,
     grandparent, …, root).  A match means the kit is stuck at a protection
     gate (e.g. Cloudflare Turnstile).  No re-render is scheduled.
  2. **Direct siblings** — compare child against other children of the same
     parent.  A match means the relay domain pool is repeating.  A re-render
     is scheduled with an incremented dupe counter.
  Both checks use TLSH distance with SHA256 fallback for tiny files.
  Neither check ever deletes kits — duplicates are marked FAILED with
  ``duplicate_of_kit_id`` set and files preserved on disk.
"""

import logging
import uuid
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func

from darla.analysis.browser_downloader import browser_download
from darla.analysis.hasher import compute_hashes as do_hash, compute_tlsh_distance
from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

def _walk_ancestor_chain(db, kit: Kit, max_depth: int = 5) -> list[Kit]:
    """Walk ``parent_kit_id`` links up to root.

    Returns ``[parent, grandparent, …]``.  Bounded by *max_depth* to
    prevent runaway loops.  Uses the indexed ``parent_kit_id`` FK so
    each hop is a single-row PK lookup.
    """
    ancestors: list[Kit] = []
    current = kit
    for _ in range(max_depth):
        if not current.parent_kit_id:
            break
        parent = db.query(Kit).filter(Kit.id == current.parent_kit_id).first()
        if not parent:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


def _get_direct_siblings(db, kit: Kit) -> list[Kit]:
    """Return browser-render children sharing the same parent (excluding *kit*)."""
    if not kit.parent_kit_id:
        return []
    return db.query(Kit).filter(
        Kit.parent_kit_id == kit.parent_kit_id,
        Kit.id != kit.id,
        Kit.discovery_method == "browser_render",
    ).all()


def _content_matches(
    child_tlsh: str | None,
    child_sha256: str | None,
    other_tlsh: str | None,
    other_sha256: str | None,
    threshold: int,
) -> tuple[bool, str]:
    """Compare two kits' content.  Returns ``(is_match, detail_string)``.

    Uses TLSH distance when both hashes are available, falls back to exact
    SHA256 for tiny files where TLSH is None.
    """
    if child_tlsh and other_tlsh:
        distance = compute_tlsh_distance(child_tlsh, other_tlsh)
        if distance is not None and distance <= threshold:
            return True, f"TLSH distance {distance} (threshold {threshold})"
    if child_sha256 and other_sha256 and child_sha256 == other_sha256:
        return True, "exact SHA256 match"
    return False, ""


@celery_app.task(
    name="darla.tasks.browser.browser_download_kit",
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
            from darla.models.investigation import Investigation

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
            from darla.models.investigation import Investigation

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
                from darla.tasks.analysis import _try_complete_investigation

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
        child_hashes = do_hash(filepath)
        child_kit.sha256 = child_hashes.sha256
        child_kit.md5 = child_hashes.md5
        child_kit.sha1 = child_hashes.sha1
        child_kit.tlsh = child_hashes.tlsh

        threshold = settings.browser_dedup_tlsh_threshold

        # --- Ancestor chain dedup (stuck-at-gate detection) ---
        # Walk parent → grandparent → … → root.  If the child's content
        # matches any ancestor, it's stuck at the same protection gate
        # (e.g. still seeing the Cloudflare challenge page).
        dup_of: str | None = None
        dup_reason: str | None = None
        stuck_at_gate = False

        ancestors = _walk_ancestor_chain(db, child_kit, settings.chain_max_depth)
        for ancestor in ancestors:
            matched, detail = _content_matches(
                child_hashes.tlsh, child_hashes.sha256,
                ancestor.tlsh, ancestor.sha256,
                threshold,
            )
            if matched:
                dup_of = str(ancestor.id)
                dup_reason = (
                    f"Content matches ancestor {ancestor.id} at depth "
                    f"{ancestor.chain_depth} ({detail}) — stuck at gate"
                )
                stuck_at_gate = True
                break

        # --- Direct sibling dedup (relay pool exhaustion) ---
        # Compare against children of the same parent only — never across
        # depths or different parent chains.
        if not dup_of:
            siblings = _get_direct_siblings(db, child_kit)
            for sibling in siblings:
                matched, detail = _content_matches(
                    child_hashes.tlsh, child_hashes.sha256,
                    sibling.tlsh, sibling.sha256,
                    threshold,
                )
                if matched:
                    dup_of = str(sibling.id)
                    dup_reason = (
                        f"Sibling duplicate of kit {sibling.id} ({detail})"
                    )
                    break

        # --- Apply dedup result ---
        # Duplicates are marked FAILED with duplicate_of_kit_id set.
        # Files stay on disk — nothing is deleted.
        if dup_of:
            child_kit.status = KitStatus.FAILED
            child_kit.error_message = dup_reason
            child_kit.duplicate_of_kit_id = uuid.UUID(dup_of)
            db.commit()

            logger.info("Kit %s: %s", child_id, dup_reason)

            if stuck_at_gate:
                # Stuck at a protection gate — re-rendering the same
                # parent won't help.  Don't schedule another attempt.
                return {
                    "kit_id": child_id,
                    "parent_kit_id": kit_id,
                    "status": "stuck_at_gate",
                    "duplicate_of": dup_of,
                    "reason": dup_reason,
                }

            # Sibling duplicate — relay pool may still have new domains.
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

        from darla.tasks.analysis import build_post_download_chain

        build_post_download_chain(download_result).apply_async()

        # Re-render to discover more relay variations (reset dupe counter),
        # but only if the browser redirected to a different domain (relay
        # rotation).  If the final URL stays on the lure domain there's no
        # relay pool to enumerate.
        lure_domain = urlparse(parent_kit.source_url).hostname
        final_domain = urlparse(final_url).hostname if final_url else None
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


# ---------------------------------------------------------------------------
# Passive artifact render — EML, SVG, PDF, DOCX screenshots
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.browser.render_artifact",
    bind=True,
    max_retries=0,
    queue="browser",
    soft_time_limit=180,
    time_limit=210,
)
def render_artifact(self, kit_id: str) -> dict:
    """Produce passive visual renders for a kit's underlying file.

    Dispatched in parallel with the analysis chain for any kit whose file
    is an EML, SVG, PDF, or DOCX. Produces ``00_<type>.png`` images under
    ``<download_dir>/_screenshots/`` which the existing screenshot API
    surfaces unchanged.

    Non-fatal: failures are recorded as errors on the AnalysisResult but
    never mark the kit as FAILED.
    """
    settings = get_settings()
    if not getattr(settings, "artifact_render_enabled", True):
        return {"kit_id": kit_id, "rendered": 0, "skipped": "disabled"}

    db = get_sync_db()
    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {"kit_id": kit_id, "rendered": 0, "error": "kit_not_found"}

        if not kit.local_path:
            return {"kit_id": kit_id, "rendered": 0, "skipped": "no_local_path"}

        local = Path(kit.local_path)
        if not local.is_file():
            return {"kit_id": kit_id, "rendered": 0, "error": "file_missing"}

        from darla.analysis.artifact_renderer import (
            classify_artifact, render_artifact as do_render,
        )

        fmt = classify_artifact(local)
        if fmt is None:
            return {"kit_id": kit_id, "rendered": 0, "skipped": "unsupported"}

        # Screenshots live next to any browser-render screenshots under the
        # kit's download directory.  Fall back to the configured root +
        # kit_id when local_path is inside a nested subdir (e.g. a child
        # kit whose local_path points into the parent's _nested_emls dir).
        download_root = Path(settings.kit_download_dir) / kit_id
        # Prefer the parent dir of the file itself when it's already in a
        # per-kit directory; otherwise use the canonical download root.
        candidate = local.parent
        shots_dir = (
            candidate / "_screenshots"
            if (candidate / "_browser_resources").exists()
            else download_root / "_screenshots"
        )

        result = do_render(local, shots_dir, timeout=settings.browser_download_timeout)

        # Record in AnalysisResult so analysts can see what rendered.
        try:
            from darla.models.analysis_result import AnalysisType
            from darla.tasks.analysis import upsert_analysis_result

            upsert_analysis_result(
                db,
                kit_id=kit.id,
                analysis_type=AnalysisType.ARTIFACT_RENDER,
                result_data={
                    "format": result.format,
                    "rendered_files": [Path(p).name for p in result.rendered_files],
                    "stage_labels": result.stage_labels,
                    "errors": result.errors[:10],
                },
                files_processed=len(result.rendered_files),
            )
            db.commit()
        except Exception as rec_err:
            logger.debug(
                "Failed to persist ARTIFACT_RENDER result for %s: %s",
                kit_id, rec_err,
            )
            db.rollback()

        logger.info(
            "Artifact render for kit %s (%s): %d images, %d errors",
            kit_id, result.format, len(result.rendered_files), len(result.errors),
        )
        return {
            "kit_id": kit_id,
            "rendered": len(result.rendered_files),
            "format": result.format,
            "errors": result.errors[:5],
        }

    except Exception as e:
        logger.exception("render_artifact failed for kit %s", kit_id)
        return {"kit_id": kit_id, "rendered": 0, "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Active SVG detonation — JS-enabled render + network interception.
# Runs as a chain step (not fire-and-forget) so terminal URLs flow into the
# chain crawler inside the same analysis pipeline that already processes the
# originating EML submission.
# ---------------------------------------------------------------------------

def _iter_svg_attachments(extract_dir: Path, limit: int) -> list[Path]:
    """Yield SVG attachments under *extract_dir*, tolerating trailing-dot names.

    Attacker attachments sometimes land as ``ATT021.svg..`` where ``.suffix``
    returns ``"."``. We strip trailing dots/spaces from the filename so the
    real extension surfaces.
    """
    svgs: list[Path] = []
    try:
        for path in extract_dir.rglob("*"):
            if not path.is_file():
                continue
            # Skip anything under our own output dirs to avoid infinite loops
            # on re-analysis (resources_saved would grow each run).
            if any(
                part in {"_browser_resources", "_screenshots"}
                for part in path.parts
            ):
                continue
            name = path.name.rstrip(". ")
            if Path(name).suffix.lower() == ".svg":
                svgs.append(path)
                if len(svgs) >= limit:
                    break
    except Exception as exc:  # pragma: no cover — IO failure only
        logger.debug("SVG enumeration failed under %s: %s", extract_dir, exc)
    return svgs


def _resolve_recipient_email(db, kit: Kit) -> str | None:
    """Best-effort recipient-email lookup for pre-seeding ``window.dawa``.

    We check, in order:
      1. The kit's own ``local_path`` if it is an EML.
      2. The parent chain — nested EML children inherit the recipient from
         the outer envelope in real attacks.
    Returns ``None`` when nothing usable is found. Safe to call on kits
    that never had an EML involved; callers tolerate ``None``.
    """
    from darla.analysis.eml_parser import EMLParser

    def _parse(p: Path) -> str | None:
        try:
            if not p.is_file() or p.suffix.lower() != ".eml":
                return None
            parsed = EMLParser().parse(str(p))
            to_hdr = (parsed.headers or {}).get("To")
            if not to_hdr:
                return None
            # Pull the first address out — addresses can be "Name <a@b>" or
            # comma-separated. We want only the bare e-mail.
            import email.utils as _eu
            addrs = _eu.getaddresses([to_hdr])
            for _name, addr in addrs:
                if addr and "@" in addr:
                    return addr.strip()
        except Exception as exc:
            logger.debug("Failed to parse recipient from %s: %s", p, exc)
        return None

    if kit.local_path:
        email_addr = _parse(Path(kit.local_path))
        if email_addr:
            return email_addr

    # Walk up to 3 parents — nested-EML chains shouldn't be deeper than that.
    current = kit
    for _ in range(3):
        if not current.parent_kit_id:
            break
        parent = db.query(Kit).filter(Kit.id == current.parent_kit_id).first()
        if not parent:
            break
        if parent.local_path:
            email_addr = _parse(Path(parent.local_path))
            if email_addr:
                return email_addr
        current = parent
    return None


@celery_app.task(
    name="darla.tasks.browser.execute_svgs_active",
    bind=True,
    max_retries=0,
    queue="browser",
    soft_time_limit=240,
    time_limit=300,
)
def execute_svgs_active(self, prev_result: dict) -> dict:
    """Detonate SVG attachments with JS enabled and capture outbound URLs.

    Placed in the analysis chain between ``fetch_external_js`` and
    ``crawl_chain`` so that terminal URLs discovered by active rendering
    merge with the httpx-fetched set before child-kit spawning. The task
    no-ops cleanly when:

      * the feature is disabled in settings,
      * the kit has no extract_dir (non-archive single files),
      * no SVGs exist under the extract tree,
      * Camoufox is not installed in the worker image.

    Returns ``prev_result`` augmented with ``svg_active_terminal_urls`` so
    the existing ``crawl_chain`` pipeline can route them into child kits.
    """
    kit_id = prev_result.get("kit_id")
    if prev_result.get("status") == "failed" or not kit_id:
        return prev_result

    from darla.config import get_settings
    settings = get_settings()
    if not getattr(settings, "svg_active_exec_enabled", True):
        return {**prev_result, "svg_active_skipped": "disabled"}

    extract_dir = prev_result.get("extract_dir")
    # Single-file EML kits land on local_path instead of an extract_dir; the
    # fetch_external_js step synthesizes an extract_dir for them, so by the
    # time we run here, prev_result.extract_dir is usually populated even
    # for flat submissions. Fall back to local_path's parent if missing.
    if not extract_dir:
        filepath = prev_result.get("filepath")
        if filepath and Path(filepath).is_file():
            extract_dir = str(Path(filepath).parent)
    if not extract_dir:
        return {**prev_result, "svg_active_skipped": "no_extract_dir"}

    extract_path = Path(extract_dir)
    if not extract_path.is_dir():
        return {**prev_result, "svg_active_skipped": "extract_dir_missing"}

    svg_paths = _iter_svg_attachments(
        extract_path, limit=settings.svg_active_exec_max_per_kit,
    )
    if not svg_paths:
        return {**prev_result, "svg_active_skipped": "no_svgs"}

    db = get_sync_db()
    import time as _time
    start = _time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "svg_active_skipped": "kit_not_found"}

        # Only run on kits inside an investigation — otherwise the captured
        # URLs have nowhere to go and we're burning browser budget for
        # nothing. (render_artifact stays live for preview regardless.)
        if not kit.investigation_id:
            return {**prev_result, "svg_active_skipped": "no_investigation"}

        # Depth guard — don't let a chain-spawned child re-detonate SVGs
        # already seen upstream.
        if getattr(kit, "chain_depth", 0) >= settings.chain_max_depth:
            return {**prev_result, "svg_active_skipped": "max_depth"}

        from darla.analysis.browser_svg_runner import (
            derive_dawa_from_email, execute_svg_with_capture,
        )
        from darla.models.analysis_result import AnalysisType
        from darla.tasks.analysis import upsert_analysis_result

        recipient = _resolve_recipient_email(db, kit)
        dawa_value = derive_dawa_from_email(recipient)

        # Output directory — reuse the kit's download dir so screenshots
        # and resources live next to passive-render outputs.
        out_dir = Path(settings.kit_download_dir) / kit_id
        out_dir.mkdir(parents=True, exist_ok=True)

        aggregated_urls: list[str] = []
        aggregated_terminals: list[str] = []
        aggregated_navs: list[str] = []
        per_svg: list[dict] = []
        errors: list[str] = []
        total_resources = 0

        seen_u: set[str] = set()
        seen_t: set[str] = set()

        for svg_path in svg_paths:
            try:
                res = execute_svg_with_capture(
                    svg_path, out_dir,
                    dawa_value=dawa_value,
                    timeout=settings.svg_active_exec_timeout,
                    max_requests=settings.svg_active_exec_max_requests,
                )
            except Exception as exc:
                logger.exception(
                    "Active SVG exec crashed for kit %s (%s)",
                    kit_id, svg_path.name,
                )
                errors.append(f"{svg_path.name}:{exc}")
                continue

            for u in res.urls_discovered:
                if u not in seen_u:
                    seen_u.add(u)
                    aggregated_urls.append(u)
            for u in res.terminal_urls:
                if u not in seen_t:
                    seen_t.add(u)
                    aggregated_terminals.append(u)
            for nav in res.navigations:
                if nav not in aggregated_navs:
                    aggregated_navs.append(nav)

            total_resources += res.resources_saved
            per_svg.append({
                "svg": svg_path.name,
                "status": res.status,
                "urls": len(res.urls_discovered),
                "terminal_urls": len(res.terminal_urls),
                "resources_saved": res.resources_saved,
                "network_events": res.network_events,
                "duration_seconds": res.duration_seconds,
                "screenshots": [Path(s).name for s in res.screenshots],
                "error": res.error,
            })
            if res.error:
                errors.append(f"{svg_path.name}:{res.error}")

        duration = _time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.SVG_ACTIVE_EXEC,
            result_data={
                "svgs_processed": len(svg_paths),
                "urls_discovered": aggregated_urls[:100],
                "terminal_urls": aggregated_terminals[:50],
                "navigations": aggregated_navs[:50],
                "resources_saved": total_resources,
                "recipient_dawa_set": dawa_value is not None,
                "per_svg": per_svg,
                "errors": errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=len(svg_paths),
        )
        db.commit()

        logger.info(
            "SVG active exec for kit %s: %d SVGs → %d urls, %d terminals, "
            "%d resources (dawa_set=%s, dur=%.2fs)",
            kit_id, len(svg_paths), len(aggregated_urls),
            len(aggregated_terminals), total_resources,
            dawa_value is not None, duration,
        )

        # Merge terminal URLs with anything the httpx-driven external-JS
        # fetch already discovered, so crawl_chain's existing reader
        # (``external_js_terminal_urls``) picks up both in one list.
        existing_terminals = list(prev_result.get("external_js_terminal_urls", []))
        merged_terminals = existing_terminals + [
            u for u in aggregated_terminals if u not in existing_terminals
        ]

        return {
            **prev_result,
            "svg_active_svgs_processed": len(svg_paths),
            "svg_active_urls": aggregated_urls,
            "svg_active_terminal_urls": aggregated_terminals,
            # crawl_chain reads this key for chain-crawling; augmenting it
            # means we don't need a separate wiring change to spawn kits.
            "external_js_terminal_urls": merged_terminals,
        }

    except Exception as e:
        logger.exception("execute_svgs_active failed for kit %s", kit_id)
        try:
            from darla.models.analysis_result import AnalysisType
            from darla.tasks.analysis import upsert_analysis_result
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.SVG_ACTIVE_EXEC,
                    result_data={"error": str(e)},
                    duration_seconds=round(_time.time() - start, 3),
                    error=str(e),
                )
                db.commit()
        except Exception:
            pass
        return {**prev_result, "svg_active_error": str(e)}
    finally:
        db.close()
