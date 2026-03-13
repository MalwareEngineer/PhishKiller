"""Celery application instance and configuration."""

from celery import Celery

from phishkiller.config import get_settings

settings = get_settings()

celery_app = Celery(
    "phishkiller",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "phishkiller.tasks.feeds.*": {"queue": "feeds"},
        "phishkiller.tasks.download.*": {"queue": "downloads"},
        "phishkiller.tasks.analysis.*": {"queue": "analysis"},
        "phishkiller.tasks.certstream_monitor.*": {"queue": "certstream"},
    },
)

celery_app.conf.include = [
    "phishkiller.tasks.feeds",
    "phishkiller.tasks.download",
    "phishkiller.tasks.analysis",
    "phishkiller.tasks.certstream_monitor",
    "phishkiller.tasks.recovery",
    "phishkiller.tasks.periodic",
]
