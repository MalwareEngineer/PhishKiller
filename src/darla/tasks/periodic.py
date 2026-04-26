"""Celery Beat periodic task schedule."""

from celery.schedules import crontab

from darla.celery_app import celery_app

# Periodic task schedule
celery_app.conf.beat_schedule = {
    "recover-chain-cursors-every-5m": {
        # Cheap cursor-based resume: picks up kits stalled mid-analysis
        # and continues from their last completed step.  Runs first /
        # most often because it avoids redoing the download step or
        # re-triggering browser-render fanout.
        "task": "darla.tasks.recovery.recover_chain_cursors",
        "schedule": crontab(minute="*/5"),
        "args": [10],
        "options": {"queue": "celery"},
    },
    "recover-stuck-kits-every-15m": {
        # Heavier recovery: resets kits to PENDING and re-runs the full
        # chain.  Catches kits without a cursor (failed before the
        # post-download chain even started) and stuck DOWNLOADING /
        # ANALYZING kits that the cursor-based path can't help.
        "task": "darla.tasks.recovery.recover_stuck_kits",
        "schedule": crontab(minute="*/15"),
        "args": [30],
        "options": {"queue": "celery"},
    },
    "recover-stuck-investigations-every-30m": {
        "task": "darla.tasks.recovery.recover_stuck_investigations",
        "schedule": crontab(minute="*/30"),
        "args": [60],
        "options": {"queue": "celery"},
    },
    "cleanup-duplicate-kit-artifacts-daily": {
        # Tombstone same-investigation duplicate kits in COMPLETED
        # investigations older than 24h.  Drops the on-disk artifacts
        # (page.html, requests.json, screenshots, sub-resources) but
        # keeps the Kit row + duplicate_of_kit_id pointer + error
        # message so the audit trail of pool-enumeration attempts
        # survives.  Daily cadence matches the 24h grace window:
        # operators get a full day to inspect a freshly-completed
        # investigation before its bulky duplicates are GC'd.
        "task": "darla.tasks.recovery.cleanup_completed_investigation_duplicates",
        "schedule": crontab(minute=15, hour=4),  # daily at 04:15 UTC
        "args": [24],
        "options": {"queue": "celery"},
    },
}
