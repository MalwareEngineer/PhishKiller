"""Celery Beat periodic task schedule."""

from celery.schedules import crontab

from phishkiller.celery_app import celery_app

# Periodic task schedule
celery_app.conf.beat_schedule = {
    "ingest-phishtank-every-3h": {
        "task": "phishkiller.tasks.feeds.ingest_phishtank",
        "schedule": crontab(minute=0, hour="*/3"),
        "options": {"queue": "feeds"},
    },
    "ingest-urlhaus-hourly": {
        "task": "phishkiller.tasks.feeds.ingest_urlhaus",
        "schedule": crontab(minute=15),
        "options": {"queue": "feeds"},
    },
    "ingest-openphish-every-6h": {
        "task": "phishkiller.tasks.feeds.ingest_openphish",
        "schedule": crontab(minute=30, hour="*/6"),
        "options": {"queue": "feeds"},
    },
}
