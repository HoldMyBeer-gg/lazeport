"""
Celery app for background tasks.
Uses Redis as broker and result backend.
Works on EC2 with Redis (self-hosted or ElastiCache).
"""
from celery import Celery
from app.config import settings

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
