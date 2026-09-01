"""Stub routers for malware, campaigns, and sources endpoints."""
from fastapi import APIRouter, Depends, Query, HTTPException, Path
from typing import Optional
from math import ceil
from bson import ObjectId
from app.core.dependencies import get_current_user, require_permission
from app.db.mongodb import get_malware_collection, get_campaigns_collection, get_sources_collection
import structlog

log = structlog.get_logger()

# ── Malware ───────────────────────────────────────────────────────────────────
malware_router = APIRouter()

@malware_router.get("")
async def list_malware(
    page: int = Query(1, ge=1),
    page_size: int = Query(20),
    type: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    col = get_malware_collection()
    query = {}
    if type:
        query["type"] = type
    if q:
        query["$or"] = [{"name": {"$regex": q, "$options": "i"}}, {"aliases": {"$regex": q, "$options": "i"}}]
    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("article_count", -1).skip(skip).limit(page_size)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "meta": {"total": total, "page": page, "page_size": page_size, "pages": ceil(total/page_size) if total > 0 else 0}}

@malware_router.get("/{malware_id}")
async def get_malware(malware_id: str, current_user: dict = Depends(get_current_user)):
    col = get_malware_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(malware_id)})
    except Exception:
        doc = await col.find_one({"name": {"$regex": malware_id, "$options": "i"}})
    if not doc:
        raise HTTPException(status_code=404, detail="Malware not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


# ── Campaigns ─────────────────────────────────────────────────────────────────
campaigns_router = APIRouter()

@campaigns_router.get("")
async def list_campaigns(
    page: int = Query(1, ge=1),
    page_size: int = Query(20),
    active_status: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    col = get_campaigns_collection()
    query = {}
    if active_status:
        query["active_status"] = active_status
    if q:
        query["$or"] = [{"name": {"$regex": q, "$options": "i"}}, {"description": {"$regex": q, "$options": "i"}}]
    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("start_date", -1).skip(skip).limit(page_size)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "meta": {"total": total, "page": page, "page_size": page_size, "pages": ceil(total/page_size) if total > 0 else 0}}

@campaigns_router.get("/{campaign_id}")
async def get_campaign(campaign_id: str, current_user: dict = Depends(get_current_user)):
    col = get_campaigns_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(campaign_id)})
    except Exception:
        doc = await col.find_one({"name": {"$regex": campaign_id, "$options": "i"}})
    if not doc:
        raise HTTPException(status_code=404, detail="Campaign not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


# ── Sources ───────────────────────────────────────────────────────────────────
sources_router = APIRouter()

@sources_router.get("")
async def list_sources(
    category: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    col = get_sources_collection()
    query = {}
    if category:
        query["category"] = category
    if is_active is not None:
        query["is_active"] = is_active
    cursor = col.find(query).sort("priority", 1)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "total": len(results)}

@sources_router.get("/{source_id}/health")
async def source_health(source_id: str, current_user: dict = Depends(get_current_user)):
    col = get_sources_collection()
    doc = await col.find_one({"_id": ObjectId(source_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Source not found")
    return {
        "source_id": source_id,
        "name": doc.get("name"),
        "health_status": doc.get("health_status", "unknown"),
        "last_crawled_at": doc.get("last_crawled_at"),
        "last_article_at": doc.get("last_article_at"),
        "article_count": doc.get("article_count", 0),
    }


# Create router instances for import in router.py
router_malware = malware_router
router_campaigns = campaigns_router
router_sources = sources_router
