from fastapi import APIRouter, Depends, Query
from app.core.dependencies import require_role, get_current_user
from app.db.mongodb import get_users_collection, get_sources_collection, get_logs_collection
from math import ceil
import structlog

log = structlog.get_logger()
router = APIRouter()


@router.get("/health")
async def system_health(current_user: dict = Depends(require_role("admin"))):
    from app.db.mongodb import MongoDB
    from app.db.elasticsearch import ElasticsearchClient
    from app.db.redis_client import RedisClient

    health = {"status": "healthy", "services": {}}

    try:
        await MongoDB.client.admin.command("ping")
        health["services"]["mongodb"] = "healthy"
    except Exception as e:
        health["services"]["mongodb"] = f"error: {str(e)}"
        health["status"] = "degraded"

    try:
        await ElasticsearchClient.client.ping()
        health["services"]["elasticsearch"] = "healthy"
    except Exception as e:
        health["services"]["elasticsearch"] = f"error: {str(e)}"
        health["status"] = "degraded"

    try:
        await RedisClient.get_client().ping()
        health["services"]["redis"] = "healthy"
    except Exception as e:
        health["services"]["redis"] = f"error: {str(e)}"
        health["status"] = "degraded"

    return health


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(require_role("admin")),
):
    col = get_users_collection()
    total = await col.count_documents({})
    skip = (page - 1) * page_size
    cursor = col.find({}, {"password_hash": 0, "api_key_hash": 0}).skip(skip).limit(page_size)
    users = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        users.append(doc)
    return {"data": users, "meta": {"total": total, "page": page, "page_size": page_size}}


@router.get("/logs")
async def get_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    level: str = Query(None),
    category: str = Query(None),
    current_user: dict = Depends(require_role("admin")),
):
    col = get_logs_collection()
    query = {}
    if level:
        query["level"] = level
    if category:
        query["category"] = category

    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("created_at", -1).skip(skip).limit(page_size)
    logs = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        logs.append(doc)

    return {"data": logs, "meta": {"total": total, "page": page, "page_size": page_size}}
