"""
Collection Celery tasks.
"""
import asyncio
from workers.celery_app import celery_app
import structlog

log = structlog.get_logger()


@celery_app.task(name="workers.tasks.collection_tasks.crawl_all_active_sources", bind=True, max_retries=2)
def crawl_all_active_sources(self):
    """Crawl all active intelligence sources."""
    try:
        asyncio.run(_run_collection())
    except Exception as exc:
        log.error("Collection task failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(name="workers.tasks.collection_tasks.crawl_single_source", bind=True, max_retries=3)
def crawl_single_source(self, source_id: str):
    """Crawl a single source by ID."""
    try:
        asyncio.run(_run_single(source_id))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)


async def _run_collection():
    from app.db.mongodb import MongoDB, get_sources_collection
    await MongoDB.connect()
    col = get_sources_collection()
    sources = []
    async for doc in col.find({"is_active": True}):
        sources.append(doc)

    from app.services.collector import crawl_source
    results = await asyncio.gather(*[crawl_source(src) for src in sources], return_exceptions=True)

    total_added = sum(r.get("added", 0) for r in results if isinstance(r, dict))
    log.info(f"Collection complete: {total_added} new articles from {len(sources)} sources")


async def _run_single(source_id: str):
    from app.db.mongodb import MongoDB, get_sources_collection
    from bson import ObjectId
    await MongoDB.connect()
    col = get_sources_collection()
    source = await col.find_one({"_id": ObjectId(source_id)})
    if source:
        from app.services.collector import crawl_source
        await crawl_source(source)
