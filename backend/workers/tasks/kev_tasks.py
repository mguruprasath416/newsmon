"""KEV Celery tasks."""
import asyncio
from workers.celery_app import celery_app
import structlog

log = structlog.get_logger()


@celery_app.task(name="workers.tasks.kev_tasks.sync_kev_catalog")
def sync_kev_catalog():
    asyncio.run(_sync())


@celery_app.task(name="workers.tasks.kev_tasks.enrich_epss_scores")
def enrich_epss_scores():
    asyncio.run(_enrich())


async def _sync():
    from app.db.mongodb import MongoDB
    await MongoDB.connect()
    from app.services.kev_service import KEVSyncService
    await KEVSyncService().sync()


async def _enrich():
    from app.db.mongodb import MongoDB
    await MongoDB.connect()
    from app.services.kev_service import KEVSyncService
    await KEVSyncService().enrich_epss()
