"""Celery Beat periodic task schedule."""

from celery.schedules import crontab

from phishkiller.celery_app import celery_app

# Periodic task schedule
celery_app.conf.beat_schedule = {
    "recover-stuck-kits-every-15m": {
        "task": "phishkiller.tasks.recovery.recover_stuck_kits",
        "schedule": crontab(minute="*/15"),
        "args": [30],
        "options": {"queue": "celery"},
    },
}
