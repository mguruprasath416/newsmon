"""Lens Celery tasks."""
import asyncio
from workers.celery_app import celery_app
import structlog

log = structlog.get_logger()


@celery_app.task(name="workers.tasks.lens_tasks.run_lens_analysis", bind=True, max_retries=1)
def run_lens_analysis(self, job_id: str, input_type: str, input_value: str):
    try:
        asyncio.run(_analyze(job_id, input_type, input_value))
    except Exception as exc:
        log.error("Lens task failed", job_id=job_id, error=str(exc))
        raise self.retry(exc=exc, countdown=30)


async def _analyze(job_id: str, input_type: str, input_value: str):
    from app.db.mongodb import MongoDB
    await MongoDB.connect()
    from app.services.lens_service import LensAnalysisService
    service = LensAnalysisService()
    await service.run_analysis(job_id, input_type, input_value)
