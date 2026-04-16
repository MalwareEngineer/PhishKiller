"""Celery application instance and configuration."""

from celery import Celery

from darla.config import get_settings

settings = get_settings()

celery_app = Celery(
    "darla",
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
        "darla.tasks.download.*": {"queue": "downloads"},
        "darla.tasks.browser.*": {"queue": "browser"},
        "darla.tasks.analysis.*": {"queue": "analysis"},
        "darla.tasks.chain.*": {"queue": "analysis"},
        "darla.tasks.correlation.*": {"queue": "analysis"},
        "darla.tasks.campaigns.*": {"queue": "analysis"},
    },
)

celery_app.conf.include = [
    "darla.tasks.download",
    "darla.tasks.browser",
    "darla.tasks.analysis",
    "darla.tasks.chain",
    "darla.tasks.correlation",
    "darla.tasks.campaigns",
    "darla.tasks.recovery",
    "darla.tasks.periodic",
]
