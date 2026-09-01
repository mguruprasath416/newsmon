"""Digest generation Celery tasks."""
import asyncio
from workers.celery_app import celery_app
import structlog

log = structlog.get_logger()


@celery_app.task(name="workers.tasks.digest_tasks.generate_daily_digest")
def generate_daily_digest():
    asyncio.run(_generate())


async def _generate():
    from app.db.mongodb import MongoDB
    await MongoDB.connect()
    from app.services.digest_service import DigestGenerationService
    await DigestGenerationService().generate()
