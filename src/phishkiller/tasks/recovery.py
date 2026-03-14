"""Recovery task — detect and re-queue stuck kits on startup and periodically."""

import logging
from datetime import datetime, timedelta, timezone

from celery.signals import worker_ready
from sqlalchemy import select, text

from phishkiller.celery_app import celery_app
from phishkiller.config import get_settings
from phishkiller.database import get_sync_db
from phishkiller.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)

STUCK_STATUSES = [KitStatus.DOWNLOADING, KitStatus.ANALYZING, KitStatus.DOWNLOADED]


@celery_app.task(
    name="phishkiller.tasks.recovery.recover_stuck_kits",
    bind=True,
    queue="celery",
    max_retries=0,
)
def recover_stuck_kits(self, timeout_minutes: int = 30) -> dict:
    """Find kits stuck in transient states and re-queue them for processing.

    A kit is "stuck" if it has been in DOWNLOADING, DOWNLOADED, or ANALYZING
    status for longer than ``timeout_minutes`` without progressing.
    """
    from phishkiller.tasks.analysis import build_analysis_chain

    db = get_sync_db()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)

        stuck_kits = db.scalars(
            select(Kit).where(
                Kit.status.in_(STUCK_STATUSES),
                Kit.updated_at < cutoff,
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
    name="phishkiller.tasks.recovery.full_reset_and_redispatch",
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

    from phishkiller.tasks.analysis import build_analysis_chain

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

        logger.info("[reset] Complete — reset %d kits, dispatched %d chains", len(non_failed), dispatched)
        return {"reset": len(non_failed), "dispatched": dispatched, "indicators_deleted": ind_count, "results_deleted": ar_count}

    except Exception:
        db.rollback()
        logger.exception("[reset] Failed during full reset")
        raise
    finally:
        db.close()


@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    """Trigger recovery as soon as the worker comes online."""
    logger.info("[recovery] Worker ready — dispatching stuck-kit recovery (5min cutoff)")
    recover_stuck_kits.delay(timeout_minutes=5)
