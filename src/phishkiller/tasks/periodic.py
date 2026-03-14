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
    "ingest-phishstats-every-6h": {
        "task": "phishkiller.tasks.feeds.ingest_phishstats",
        "schedule": crontab(minute=45, hour="*/6"),
        "options": {"queue": "feeds"},
    },
    "ingest-phishing-database-every-12h": {
        "task": "phishkiller.tasks.feeds.ingest_phishing_database",
        "schedule": crontab(minute=0, hour="*/12"),
        "options": {"queue": "feeds"},
    },
    "process-feed-entries-every-2m": {
        "task": "phishkiller.tasks.feeds.process_feed_entries",
        "schedule": crontab(minute="*/2"),
        "args": [2000],
        "options": {"queue": "feeds"},
    },
    "recover-stuck-kits-every-15m": {
        "task": "phishkiller.tasks.recovery.recover_stuck_kits",
        "schedule": crontab(minute="*/15"),
        "args": [30],
        "options": {"queue": "celery"},
    },
}
