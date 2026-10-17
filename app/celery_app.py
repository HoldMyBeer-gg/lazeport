"""
Celery app for background tasks.
Uses Redis as broker and result backend.
Works on EC2 with Redis (self-hosted or ElastiCache).
"""
from celery import Celery
from celery.signals import after_setup_logger, after_setup_task_logger

from app.config import settings
from app.logging_utils import install_log_scrubbing

app = Celery(
    "lazeport",
    broker=settings.celery_broker_url,
    backend=settings.redis_url,
    include=["app.tasks.burp_import", "app.tasks.llm_generation"],
)
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)


@after_setup_logger.connect
@after_setup_task_logger.connect
def _scrub_celery_logs(logger, *args, **kwargs):
    """Celery builds its own handlers; apply the same log scrubbing to them."""
    install_log_scrubbing(logger)
