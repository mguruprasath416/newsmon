"""
Celery & Celery Beat Application Configuration — Production & Windows-Safe Setup.

Fixes Celery Worker/Beat stability issues on Windows & Linux:
1. Sets worker pool to 'solo' on Windows to prevent prefork process crashes/freezes.
2. Implements connection retry on startup & late task acknowledgements.
3. Provides run_async_task helper to execute motor/httpx coroutines safely without loop crashes.
4. Cleans up stale celerybeat-schedule lock files automatically on startup.
"""
import os
import sys
import asyncio
from pathlib import Path
from celery import Celery
from celery.schedules import crontab
import structlog

from app.config import settings

log = structlog.get_logger()

# Cleanup stale celerybeat lock files on Windows if present
def _cleanup_beat_locks():
    try:
        for fname in ["celerybeat-schedule", "celerybeat-schedule.db", "celerybeat.pid"]:
            p = Path(fname)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
    except Exception as e:
        log.warning("Beat lock cleanup warning", error=str(e))

_cleanup_beat_locks()

# Initialize Celery app instance
celery_app = Celery(
    "clarityti",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

# Configure Windows & Production parameters
is_windows = sys.platform.startswith("win")

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    worker_cancel_long_running_tasks_on_connection_error=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=86400,
)

# Use solo pool on Windows to prevent prefork child process silent crashes
if is_windows:
    celery_app.conf.update(
        worker_pool="solo",
    )

# ── Periodic Task Schedule (Celery Beat) ──────────────────────────────────────
celery_app.conf.beat_schedule = {
    # Crawl active threat intelligence feeds every 15 minutes
    "crawl-threat-feeds-every-15m": {
        "task": "app.tasks.feed_tasks.crawl_all_feeds_task",
        "schedule": crontab(minute="*/15"),
    },
    # Sync CISA Known Exploited Vulnerabilities catalog every 6 hours
    "sync-cisa-kev-every-6h": {
        "task": "app.tasks.feed_tasks.sync_cisa_kev_task",
        "schedule": crontab(minute="0", hour="*/6"),
    },
    # Auto-dispatch Today's News to Microsoft Teams every day at 08:00 AM UTC
    "dispatch-teams-daily-news-8am": {
        "task": "app.tasks.feed_tasks.dispatch_teams_daily_news_task",
        "schedule": crontab(minute="0", hour="8"),
    },
}

# Auto-discover tasks in app.tasks
celery_app.autodiscover_tasks(["app.tasks.feed_tasks"])


def run_async_task(coro_fn, *args, **kwargs):
    """
    Safely executes an async coroutine inside a synchronous Celery task.
    Handles loop lifecycle & Motor/httpx async client connections without crashes.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(coro_fn(*args, **kwargs))
