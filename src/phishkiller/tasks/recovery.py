"""Recovery task — detect and re-queue stuck kits on startup and periodically."""

import logging
from datetime import datetime, timedelta, timezone

from celery.signals import worker_ready
from sqlalchemy import select

from phishkiller.celery_app import celery_app
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

        # Also re-dispatch PENDING kits that were queued but never picked up
        stale_pending = db.scalars(
            select(Kit).where(
                Kit.status == KitStatus.PENDING,
                Kit.updated_at < cutoff,
            )
        ).all()

        for kit in stale_pending:
            build_analysis_chain(str(kit.id)).apply_async()
            recovered += 1
            logger.info("[recovery] Re-dispatched stale PENDING kit %s", kit.id)

        db.commit()
        logger.info("[recovery] Recovered %d stuck kits", recovered)
        return {"recovered": recovered}

    except Exception:
        db.rollback()
        logger.exception("[recovery] Failed to recover stuck kits")
        raise
    finally:
        db.close()


@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    """Trigger recovery as soon as the worker comes online."""
    logger.info("[recovery] Worker ready — dispatching stuck-kit recovery (5min cutoff)")
    recover_stuck_kits.delay(timeout_minutes=5)
