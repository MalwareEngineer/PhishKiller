"""Celery application instance and configuration."""

from celery import Celery

from phishkiller.config import get_settings

settings = get_settings()

celery_app = Celery(
    "phishkiller",
    broker=settings.celery_broker_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "phishkiller.tasks.download.*": {"queue": "downloads"},
        "phishkiller.tasks.browser.*": {"queue": "browser"},
        "phishkiller.tasks.analysis.*": {"queue": "analysis"},
        "phishkiller.tasks.chain.*": {"queue": "analysis"},
        "phishkiller.tasks.correlation.*": {"queue": "analysis"},
        "phishkiller.tasks.campaigns.*": {"queue": "analysis"},
    },
)

celery_app.conf.include = [
    "phishkiller.tasks.download",
    "phishkiller.tasks.browser",
    "phishkiller.tasks.analysis",
    "phishkiller.tasks.chain",
    "phishkiller.tasks.correlation",
    "phishkiller.tasks.campaigns",
    "phishkiller.tasks.recovery",
    "phishkiller.tasks.periodic",
]
