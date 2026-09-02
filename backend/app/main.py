import structlog
import sentry_sdk
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.mongodb import MongoDB
from app.db.elasticsearch import ElasticsearchClient
from app.db.redis_client import RedisClient
from app.api.v1.router import api_router
from app.core.exceptions import newsmon_exception_handler, NewsMonException

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    log.info("ClarityTI starting up...", env=settings.ENVIRONMENT)

    # Connect to databases
    await MongoDB.connect()
    log.info("MongoDB connected")

    try:
        await ElasticsearchClient.connect()
        log.info("Elasticsearch connected")
    except Exception as e:
        log.warning("Elasticsearch unavailable — search features disabled", error=str(e))

    try:
        await RedisClient.connect()
        log.info("Redis connected")
    except Exception as e:
        log.warning("Redis unavailable — caching disabled", error=str(e))

    # Create indexes
    try:
        from app.db.indexes import create_all_indexes
        await create_all_indexes()
        log.info("Database indexes created")
    except Exception as e:
        log.warning("Index creation failed", error=str(e))

    # Seed admin user
    try:
        from app.core.seeder import seed_admin_user
        await seed_admin_user()
    except Exception as e:
        log.warning("Seeder failed", error=str(e))

    # Start APScheduler 24/7 fallback background scheduler
    scheduler = None
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from app.tasks.feed_tasks import _async_crawl_all_feeds, _async_sync_cisa_kev, _async_dispatch_teams_daily_news

        scheduler = AsyncIOScheduler()
        scheduler.add_job(_async_crawl_all_feeds, 'interval', minutes=15, id='crawl_feeds_job', replace_existing=True)
        scheduler.add_job(_async_sync_cisa_kev, 'interval', hours=6, id='sync_kev_job', replace_existing=True)
        scheduler.add_job(_async_dispatch_teams_daily_news, 'cron', hour=8, minute=0, id='dispatch_teams_job', replace_existing=True)
        scheduler.start()
        log.info("APScheduler 24/7 background scheduler started (15m crawl, 6h KEV sync, 8am Teams dispatch)")
    except Exception as e:
        log.warning("APScheduler background scheduler initialization error", error=str(e))

    yield

    # Shutdown
    if scheduler and scheduler.running:
        try:
            scheduler.shutdown(wait=False)
            log.info("APScheduler background scheduler stopped")
        except Exception:
            pass

    await MongoDB.disconnect()
    try:
        await ElasticsearchClient.disconnect()
    except Exception:
        pass
    try:
        await RedisClient.disconnect()
    except Exception:
        pass
    log.info("NewsMon shutdown complete")


def create_app() -> FastAPI:
    if settings.SENTRY_DSN:
        sentry_sdk.init(dsn=settings.SENTRY_DSN, environment=settings.ENVIRONMENT)

    app = FastAPI(
        title="NewsMon API",
        description="Enterprise Cyber Threat Intelligence Platform",
        version=settings.APP_VERSION,
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url="/api/redoc" if not settings.is_production else None,
        openapi_url="/api/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https?://.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception Handlers ────────────────────────────────────────────
    app.add_exception_handler(NewsMonException, newsmon_exception_handler)

    # ── Routers ───────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    # ── Health & Readiness Probes ─────────────────────────────────────
    @app.get("/health", tags=["health"])
    async def health():
        return {
            "status": "healthy",
            "service": "NewsMon CTI API",
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }

    @app.get("/health/detailed", tags=["health"])
    @app.get("/api/v1/health", tags=["health"])
    async def detailed_health():
        # Check MongoDB
        mongo_status = "unavailable"
        try:
            if MongoDB.client:
                await MongoDB.client.admin.command("ping")
                mongo_status = "healthy"
        except Exception as e:
            mongo_status = f"error: {str(e)}"

        # Check Redis
        redis_status = "unavailable"
        try:
            if RedisClient._client:
                pong = await RedisClient._client.ping()
                if pong:
                    redis_status = "healthy"
        except Exception as e:
            redis_status = f"error: {str(e)}"

        # Check Elasticsearch
        es_status = "unavailable"
        try:
            es_c = getattr(ElasticsearchClient, "client", None)
            if es_c:
                info = await es_c.info()
                if info:
                    es_status = "healthy"
        except Exception as e:
            es_status = f"error: {str(e)}"

        overall_status = "healthy" if mongo_status == "healthy" else "degraded"

        return {
            "status": overall_status,
            "service": "NewsMon / ClarityTI Enterprise",
            "version": settings.APP_VERSION,
            "components": {
                "mongodb": mongo_status,
                "redis": redis_status,
                "elasticsearch": es_status,
                "ai_engine": "configured" if bool(settings.GEMINI_API_KEY or settings.NVIDIA_API_KEY) else "unconfigured",
            }
        }

    return app


app = create_app()
