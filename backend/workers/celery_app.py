"""
Celery application and task scheduler for ClarityTI.
"""
from celery import Celery
from celery.schedules import crontab
from app.config import settings

celery_app = Celery(
    "clarityti",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "workers.tasks.collection_tasks",
        "workers.tasks.lens_tasks",
        "workers.tasks.kev_tasks",
        "workers.tasks.digest_tasks",
    ],
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
        "workers.tasks.collection_tasks.*":   {"queue": "collection"},
        "workers.tasks.lens_tasks.*":         {"queue": "lens"},
        "workers.tasks.kev_tasks.*":          {"queue": "default"},
        "workers.tasks.digest_tasks.*":       {"queue": "digest"},
    },
    beat_schedule={
        # ── Collection ───────────────────────────────────────────────────
        "crawl-all-sources-30min": {
            "task":     "workers.tasks.collection_tasks.crawl_all_active_sources",
            "schedule": crontab(minute="*/30"),
        },
        # ── KEV Sync ─────────────────────────────────────────────────────
        "sync-kev-daily": {
            "task":     "workers.tasks.kev_tasks.sync_kev_catalog",
            "schedule": crontab(hour=6, minute=0),
        },
        "enrich-epss-daily": {
            "task":     "workers.tasks.kev_tasks.enrich_epss_scores",
            "schedule": crontab(hour=7, minute=0),
        },
        # ── Digest ───────────────────────────────────────────────────────
        "generate-daily-digest": {
            "task":     "workers.tasks.digest_tasks.generate_daily_digest",
            "schedule": crontab(hour=8, minute=0),
        },
    },
)
