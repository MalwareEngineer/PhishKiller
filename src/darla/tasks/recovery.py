"""Recovery task — detect and re-queue stuck kits on startup and periodically."""

import logging
from datetime import UTC, datetime, timedelta

from celery.signals import worker_ready
from sqlalchemy import select, text

from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.investigation import Investigation, InvestigationStatus
from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)

STUCK_STATUSES = [KitStatus.DOWNLOADING, KitStatus.ANALYZING, KitStatus.DOWNLOADED]


@celery_app.task(
    name="darla.tasks.recovery.recover_stuck_kits",
    bind=True,
    queue="celery",
    max_retries=0,
)
def recover_stuck_kits(self, timeout_minutes: int = 30) -> dict:
    """Find kits stuck in transient states and re-queue them for processing.

    A kit is "stuck" if it has been in DOWNLOADING, DOWNLOADED, or ANALYZING
    status for longer than ``timeout_minutes`` without progressing.
    """
    from darla.tasks.analysis import build_analysis_chain

    db = get_sync_db()
    try:
        cutoff = datetime.now(UTC) - timedelta(minutes=timeout_minutes)

        # Exclude kits that ``recover_chain_cursors`` is responsible
        # for — those are DOWNLOADED|ANALYZING with a chain_cursor set,
        # and the cursor-based path can resume them in-place without
        # re-downloading or re-triggering browser-render fanout.
        # Without this exclusion the two jobs would race at the 30-min
        # mark and double-dispatch the same kit.
        from sqlalchemy import and_, not_

        stuck_kits = db.scalars(
            select(Kit).where(
                Kit.status.in_(STUCK_STATUSES),
                Kit.updated_at < cutoff,
                not_(
                    and_(
                        Kit.status.in_(
                            [KitStatus.DOWNLOADED, KitStatus.ANALYZING]
                        ),
                        Kit.chain_cursor.is_not(None),
                    )
                ),
            )
        ).all()

        if not stuck_kits:
            logger.info("[recovery] No stuck kits found (cutoff=%s)", cutoff.isoformat())
            return {"recovered": 0}

        recovered = 0
        for kit in stuck_kits:
            old_status = kit.status
            kit.status = KitStatus.PENDING
            kit.error_message = None
            db.flush()

            build_analysis_chain(str(kit.id)).apply_async()
            recovered += 1
            logger.info(
                "[recovery] Re-queued kit %s (%s -> PENDING)",
                kit.id,
                old_status.value,
            )

        # NOTE: We do NOT re-dispatch PENDING kits here. They already have
        # messages in the queue (task_acks_late ensures redelivery on restart).
        # Re-dispatching them would create duplicate messages.

        db.commit()
        logger.info("[recovery] Recovered %d stuck kits", recovered)
        return {"recovered": recovered}

    except Exception:
        db.rollback()
        logger.exception("[recovery] Failed to recover stuck kits")
        raise
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.recovery.full_reset_and_redispatch",
    bind=True,
    queue="celery",
    max_retries=0,
)
def full_reset_and_redispatch(self) -> dict:
    """Purge all queues, clean old analysis data, and re-dispatch all non-failed kits.

    This forces every kit through the current (new) analysis chain, ensuring
    new pipeline steps like YARA scanning and actor correlation run on all kits.
    """
    from kombu import Connection

    from darla.tasks.analysis import build_analysis_chain

    db = get_sync_db()
    try:
        # 1. Purge RabbitMQ queues
        settings = get_settings()
        logger.info("[reset] Purging downloads and analysis queues...")
        with Connection(settings.celery_broker_url) as conn:
            for queue_name in ("downloads", "analysis"):
                try:
                    simple_q = conn.SimpleQueue(queue_name)
                    simple_q.clear()
                    simple_q.close()
                    logger.info("[reset] Purged queue: %s", queue_name)
                except Exception as e:
                    logger.warning("[reset] Could not purge %s: %s", queue_name, e)

        # 2. Bulk delete indicators and analysis_results
        ind_count = db.execute(text("DELETE FROM indicators")).rowcount
        ar_count = db.execute(text("DELETE FROM analysis_results")).rowcount
        db.flush()
        logger.info("[reset] Deleted %d indicators, %d analysis_results", ind_count, ar_count)

        # 3. Reset all non-FAILED kits to PENDING
        non_failed = db.scalars(
            select(Kit).where(Kit.status != KitStatus.FAILED)
        ).all()

        for kit in non_failed:
            kit.status = KitStatus.PENDING
            kit.sha256 = None
            kit.md5 = None
            kit.sha1 = None
            kit.tlsh = None
            kit.error_message = None

        db.commit()
        logger.info("[reset] Reset %d kits to PENDING", len(non_failed))

        # 4. Re-dispatch in batches
        dispatched = 0
        for kit in non_failed:
            build_analysis_chain(str(kit.id)).apply_async()
            dispatched += 1
            if dispatched % 1000 == 0:
                logger.info("[reset] Dispatched %d / %d kits", dispatched, len(non_failed))

        logger.info(
            "[reset] Complete — reset %d kits, dispatched %d chains",
            len(non_failed), dispatched,
        )
        return {
            "reset": len(non_failed),
            "dispatched": dispatched,
            "indicators_deleted": ind_count,
            "results_deleted": ar_count,
        }

    except Exception:
        db.rollback()
        logger.exception("[reset] Failed during full reset")
        raise
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.recovery.recover_stuck_investigations",
    bind=True,
    queue="celery",
    max_retries=0,
)
def recover_stuck_investigations(self, timeout_minutes: int = 60) -> dict:
    """Find investigations stuck in IN_PROGRESS and complete them if all kits are terminal.

    An investigation is "stuck" if it has been IN_PROGRESS for longer than
    ``timeout_minutes`` and every one of its kits is in a terminal state
    (ANALYZED or FAILED).
    """
    from sqlalchemy import func

    db = get_sync_db()
    try:
        cutoff = datetime.now(UTC) - timedelta(minutes=timeout_minutes)

        stuck = db.scalars(
            select(Investigation).where(
                Investigation.status == InvestigationStatus.IN_PROGRESS,
                Investigation.updated_at < cutoff,
            )
        ).all()

        if not stuck:
            logger.info("[recovery] No stuck investigations found (cutoff=%s)", cutoff.isoformat())
            return {"recovered": 0}

        recovered = 0
        for inv in stuck:
            # Count kits still in non-terminal states
            pending_count = db.query(Kit).filter(
                Kit.investigation_id == inv.id,
                Kit.status.notin_([KitStatus.ANALYZED, KitStatus.FAILED]),
            ).count()

            if pending_count > 0:
                logger.debug(
                    "[recovery] Investigation %s still has %d non-terminal kits, skipping",
                    inv.id, pending_count,
                )
                continue

            # All kits are terminal — recompute counters and mark COMPLETED
            actual_count = db.query(Kit).filter(
                Kit.investigation_id == inv.id,
            ).count()
            actual_depth = db.query(func.coalesce(func.max(Kit.chain_depth), 0)).filter(
                Kit.investigation_id == inv.id,
            ).scalar()

            inv.total_kits = actual_count
            inv.total_depth_reached = actual_depth
            inv.status = InvestigationStatus.COMPLETED
            recovered += 1
            logger.info(
                "[recovery] Completed investigation %s (%d kits, depth %d)",
                inv.id, actual_count, actual_depth,
            )

        db.commit()
        logger.info("[recovery] Recovered %d stuck investigations", recovered)
        return {"recovered": recovered}

    except Exception:
        db.rollback()
        logger.exception("[recovery] Failed to recover stuck investigations")
        raise
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.recovery.recover_chain_cursors",
    bind=True,
    queue="celery",
    max_retries=0,
)
def recover_chain_cursors(self, timeout_minutes: int = 10) -> dict:
    """Resume post-download analysis chains stalled at a known cursor.

    A kit qualifies for cursor-based recovery when ALL of:

      * status is ``DOWNLOADED`` (chain not yet completed via
        ``finalize_kit``) or ``ANALYZING`` (chain in progress)
      * ``chain_cursor`` is set (chain started past download — we know
        where to resume)
      * ``updated_at`` is older than ``timeout_minutes`` ago (the chain
        actually stalled rather than being mid-step)

    For each match we build a partial chain starting at
    ``post_download_steps_from_cursor(kit.chain_cursor)`` and dispatch
    it with a synthetic ``prev_result`` reconstructed from the kit's
    persisted state (``local_path``, ``file_size``, ``sha256``).  This
    is much cheaper than the existing ``recover_stuck_kits`` flow,
    which restarts from ``download_kit`` and re-does the entire chain
    — including re-triggering browser-render fanout for OAuth/JS
    loaders that already had their browser children rendered.

    Idempotency note: every chain step is required to be idempotent
    against re-execution (we use ``upsert_analysis_result`` everywhere)
    so resuming AT the cursor (rather than after it) is safe.  Worst
    case the cursor's step runs twice and overwrites its own analysis
    result with identical data.
    """
    from pathlib import Path

    from celery import chain as celery_chain

    from darla.tasks.analysis import (
        _post_download_steps,
        post_download_steps_from_cursor,
    )

    db = get_sync_db()
    try:
        cutoff = datetime.now(UTC) - timedelta(minutes=timeout_minutes)
        stuck = db.scalars(
            select(Kit).where(
                Kit.status.in_([KitStatus.DOWNLOADED, KitStatus.ANALYZING]),
                Kit.updated_at < cutoff,
                Kit.chain_cursor.is_not(None),
            )
        ).all()

        if not stuck:
            logger.info(
                "[recovery] No stalled chains found (cutoff=%s)",
                cutoff.isoformat(),
            )
            return {"recovered": 0}

        recovered = 0
        for kit in stuck:
            steps = post_download_steps_from_cursor(kit.chain_cursor)
            if not steps:
                logger.warning(
                    "[recovery] Kit %s has unknown chain_cursor=%s, "
                    "falling back to recover_stuck_kits semantics",
                    kit.id, kit.chain_cursor,
                )
                continue

            # Reconstruct the chain prev_result dict from persisted state.
            # The downstream steps tolerate missing optional keys
            # (compute_hashes returns hashed=True if already done, etc.).
            extract_dir = (
                str(Path(kit.local_path).parent) if kit.local_path else None
            )
            prev_result = {
                "kit_id": str(kit.id),
                "status": "downloaded",
                "filepath": kit.local_path,
                "file_size": kit.file_size,
                "sha256": kit.sha256,
                "hashed": bool(kit.sha256),
                "extract_dir": extract_dir,
            }
            if kit.parent_kit_id:
                prev_result["parent_kit_id"] = str(kit.parent_kit_id)

            # First step takes the dict via .si() (immutable signature
            # binds the prev_result and ignores any chained input).
            first_step = steps[0].clone(args=(prev_result,), immutable=True)
            celery_chain(first_step, *steps[1:]).apply_async()

            recovered += 1
            logger.info(
                "[recovery] Resumed kit %s from chain_cursor=%s (%d "
                "remaining steps)",
                kit.id, kit.chain_cursor, len(steps),
            )

        db.commit()
        logger.info("[recovery] Resumed %d stalled chains", recovered)
        return {"recovered": recovered}

    except Exception:
        db.rollback()
        logger.exception("[recovery] recover_chain_cursors failed")
        raise
    finally:
        db.close()


@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    """Trigger recovery as soon as the worker comes online."""
    logger.info("[recovery] Worker ready — dispatching stuck-kit recovery (5min cutoff)")
    recover_stuck_kits.delay(timeout_minutes=5)
    recover_stuck_investigations.delay(timeout_minutes=5)
    # Cursor-based chain resume — picks up kits that completed the
    # download step but stalled mid-analysis.  Cheaper than full
    # recover_stuck_kits because it skips work that already finished.
    recover_chain_cursors.delay(timeout_minutes=5)
