from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from typing import Optional
from math import ceil
from datetime import datetime, timezone, timedelta
from app.core.dependencies import get_current_user, require_role
from app.db.mongodb import get_kev_collection
import structlog

log = structlog.get_logger()
router = APIRouter()


def serialize_kev(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


@router.get("")
async def list_kev(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    vendor: Optional[str] = Query(None),
    known_ransomware: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    sort_by: str = Query("date_added", pattern="^(date_added|cvss_v3_score|epss_score|due_date)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),

    q: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    col = get_kev_collection()
    query = {}

    if vendor:
        query["vendor"] = {"$regex": vendor, "$options": "i"}
    if known_ransomware is not None:
        query["known_ransomware"] = known_ransomware
    if severity:
        query["cvss_v3_severity"] = severity.upper()
    if date_from or date_to:
        query["date_added"] = {}
        if date_from:
            query["date_added"]["$gte"] = datetime.fromisoformat(date_from)
        if date_to:
            query["date_added"]["$lte"] = datetime.fromisoformat(date_to)
    if q:
        query["$or"] = [
            {"cve_id": {"$regex": q, "$options": "i"}},
            {"vendor": {"$regex": q, "$options": "i"}},
            {"product": {"$regex": q, "$options": "i"}},
            {"vulnerability_name": {"$regex": q, "$options": "i"}},
        ]

    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    sort_direction = -1 if sort_order == "desc" else 1

    cursor = col.find(query).sort(sort_by, sort_direction).skip(skip).limit(page_size)
    entries = [serialize_kev(doc) async for doc in cursor]

    return {
        "data": entries,
        "meta": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": ceil(total / page_size) if total > 0 else 0,
            "has_next": page * page_size < total,
            "has_prev": page > 1,
        }
    }


@router.get("/stats")
async def kev_stats(current_user: dict = Depends(get_current_user)):
    col = get_kev_collection()
    now = datetime.now(timezone.utc)

    stats = {
        "total": await col.count_documents({}),
        "ransomware_associated": await col.count_documents({"known_ransomware": True}),
        "added_last_30_days": await col.count_documents({"date_added": {"$gte": now - timedelta(days=30)}}),
        "added_last_7_days": await col.count_documents({"date_added": {"$gte": now - timedelta(days=7)}}),
        "critical_cvss": await col.count_documents({"cvss_v3_score": {"$gte": 9.0}}),
        "high_epss": await col.count_documents({"epss_score": {"$gte": 0.5}}),
    }

    # Top vendors
    pipeline = [
        {"$group": {"_id": "$vendor", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 15}
    ]
    top_vendors = [{"vendor": d["_id"], "count": d["count"]} async for d in col.aggregate(pipeline)]
    stats["top_vendors"] = top_vendors

    # Monthly additions (last 12 months)
    pipeline = [
        {"$match": {"date_added": {"$gte": now - timedelta(days=365)}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m", "date": "$date_added"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    monthly = [{"month": d["_id"], "count": d["count"]} async for d in col.aggregate(pipeline)]
    stats["monthly_additions"] = monthly

    # CVSS distribution
    pipeline = [
        {"$group": {"_id": "$cvss_v3_severity", "count": {"$sum": 1}}}
    ]
    cvss_dist = {d["_id"]: d["count"] async for d in col.aggregate(pipeline)}
    stats["cvss_severity_distribution"] = cvss_dist

    return stats


@router.get("/recent")
async def recent_kev(
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    col = get_kev_collection()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    cursor = col.find({"date_added": {"$gte": since}}).sort("date_added", -1)
    entries = [serialize_kev(doc) async for doc in cursor]
    return {"data": entries, "total": len(entries), "since_days": days}


@router.get("/{cve_id}")
async def get_kev_entry(
    cve_id: str,
    current_user: dict = Depends(get_current_user),
):
    col = get_kev_collection()
    doc = await col.find_one({"cve_id": cve_id.upper()})
    if not doc:
        raise HTTPException(status_code=404, detail=f"KEV entry not found: {cve_id}")
    return serialize_kev(doc)


@router.post("/sync")
async def trigger_kev_sync(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_role("admin")),
):
    """Manually trigger CISA KEV catalog synchronization."""
    background_tasks.add_task(_sync_kev_task)
    return {"message": "KEV sync triggered", "status": "running"}


async def _sync_kev_task():
    from app.services.kev_service import KEVSyncService
    service = KEVSyncService()
    await service.sync()
