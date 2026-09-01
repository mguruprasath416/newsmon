"""
Celery Task Definitions for Feed Crawling, CISA KEV Syncing, and Microsoft Teams Dispatch.
"""
import asyncio
from datetime import datetime, timezone, timedelta
import structlog

from app.core.celery_app import celery_app, run_async_task
from app.db.mongodb import MongoDB, get_sources_collection, get_articles_collection
from app.services.collector import CollectorFactory, crawl_source
from app.services.kev_service import KEVSyncService
from app.services.teams_service import TeamsService
from app.config import settings

log = structlog.get_logger()


async def _async_crawl_all_feeds():
    """Async worker function to crawl all registered sources."""
    await MongoDB.connect()
    sources_col = get_sources_collection()

    sources = [s async for s in sources_col.find({"enabled": {"$ne": False}})]
    log.info("Starting background feed crawl...", total_sources=len(sources))

    if not sources:
        return {"status": "success", "new_articles": 0}

    total_new_articles = 0
    sem = asyncio.Semaphore(10)

    async def _crawl_one(src):
        nonlocal total_new_articles
        async with sem:
            try:
                res = await asyncio.wait_for(crawl_source(src), timeout=90.0)
                new_count = res.get("added", 0)
                total_new_articles += new_count
            except asyncio.TimeoutError:
                log.warning("Feed crawl timed out", source=src.get("name"), timeout=90.0)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error(f"Failed crawling source: {src.get('name')}", error=str(e))

    try:
        tasks = [_crawl_one(src) for src in sources]
        await asyncio.gather(*tasks, return_exceptions=False)
    except asyncio.CancelledError:
        log.info("Background feed crawl job cancelled during application shutdown.")
        raise

    log.info("Completed feed crawl job", total_new=total_new_articles)
    # Trigger CyberPulse viral correlation sweep on fresh ingested articles
    try:
        from app.services.cyberpulse_service import CyberPulseService
        cp_result = await CyberPulseService.recalculate_all_viral_events(hours=72)
        log.info("CyberPulse correlation completed after feed crawl", result=cp_result)
    except asyncio.CancelledError:
        log.info("CyberPulse post-crawl correlation stopped during shutdown.")
        raise
    except Exception as cp_err:
        log.error("CyberPulse post-crawl correlation error", error=str(cp_err))

    return {"status": "success", "new_articles": total_new_articles}


async def _async_sync_cisa_kev():
    """Async worker function to sync CISA KEV."""
    await MongoDB.connect()
    result = await KEVSyncService().sync()
    log.info("CISA KEV catalog sync completed", result=result)
    return result


async def _async_run_cyberpulse():
    """Async worker function for CyberPulse viral news correlation and heat mapping."""
    await MongoDB.connect()
    from app.services.cyberpulse_service import CyberPulseService
    result = await CyberPulseService.recalculate_all_viral_events(hours=72)
    log.info("CyberPulse task sweep completed", result=result)
    return result


async def _async_dispatch_teams_daily_news():
    """Async worker function to dispatch today's news to Microsoft Teams regional channels and high priority news."""
    await MongoDB.connect()
    cyber_pulse_url = settings.TEAMS_WEBHOOK_URL_CYBER_PULSE or settings.CYBER_PULSE_WEBHOOK_URL
    channel_webhooks = {
        "cyber-pulse": cyber_pulse_url,
    }

    default_webhook = cyber_pulse_url
    if not any(channel_webhooks.values()):
        log.warning("Skipping daily Teams dispatch — Cyber Pulse webhook not configured")
        return {"status": "skipped", "reason": "no_webhook"}

    articles_col = get_articles_collection()
    since_time = datetime.now(timezone.utc) - timedelta(hours=24)

    # Strictly query only fresh, non-dispatched cybersecurity articles from the last 24h
    cursor = articles_col.find({
        "published_at": {"$gte": since_time},
        "is_duplicate": {"$ne": True},
        "is_cybersecurity_news": True,
        "teams_dispatched": {"$ne": True}
    }).sort("published_at", -1).limit(50)
    articles = [a async for a in cursor]

    if not articles:
        log.info("No new non-dispatched high-severity articles found for Teams today.")
        return {"status": "skipped", "reason": "no_new_articles"}

    result = await TeamsService.send_todays_news(default_webhook, articles, channel_webhooks=channel_webhooks)
    log.info("Teams daily news dispatch completed", result=result)
    return result


# ── Celery Task Definitions ──────────────────────────────────────────────────

@celery_app.task(name="app.tasks.feed_tasks.crawl_all_feeds_task", bind=True, max_retries=3)
def crawl_all_feeds_task(self):
    """Celery task: Crawls all active intelligence sources."""
    try:
        return run_async_task(_async_crawl_all_feeds)
    except Exception as exc:
        log.error("crawl_all_feeds_task failed", error=str(exc))
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.tasks.feed_tasks.sync_cisa_kev_task", bind=True, max_retries=3)
def sync_cisa_kev_task(self):
    """Celery task: Syncs CISA KEV catalog."""
    try:
        return run_async_task(_async_sync_cisa_kev)
    except Exception as exc:
        log.error("sync_cisa_kev_task failed", error=str(exc))
        raise self.retry(exc=exc, countdown=120)


@celery_app.task(name="app.tasks.feed_tasks.run_cyberpulse_task", bind=True, max_retries=2)
def run_cyberpulse_task(self):
    """Celery task: Runs CyberPulse viral news correlation and priority heat alert check."""
    try:
        return run_async_task(_async_run_cyberpulse)
    except Exception as exc:
        log.error("run_cyberpulse_task failed", error=str(exc))
        raise self.retry(exc=exc, countdown=120)


@celery_app.task(name="app.tasks.feed_tasks.dispatch_teams_daily_news_task", bind=True, max_retries=2)
def dispatch_teams_daily_news_task(self):
    """Celery task: Dispatches today's news to Microsoft Teams."""
    try:
        return run_async_task(_async_dispatch_teams_daily_news)
    except Exception as exc:
        log.error("dispatch_teams_daily_news_task failed", error=str(exc))
        raise self.retry(exc=exc, countdown=180)
