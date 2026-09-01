from fastapi import APIRouter, Depends, Query, HTTPException, Path
from typing import Optional, List
from math import ceil
from bson import ObjectId
from app.core.dependencies import get_current_user
from app.db.mongodb import get_articles_collection, get_sources_collection
from datetime import datetime, timezone
import structlog

log = structlog.get_logger()
router = APIRouter()


def serialize_article(doc: dict, user_id: str = None) -> dict:
    doc["id"] = str(doc.pop("_id"))
    if "source_id" in doc:
        doc["source_id"] = str(doc["source_id"])
    if user_id:
        doc["is_bookmarked"] = user_id in doc.get("bookmarked_by", [])
    doc.pop("content_raw", None)  # Don't return raw HTML in list
    doc.pop("bookmarked_by", None)
    return doc


@router.get("")
async def get_feed(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: Optional[str] = Query(None, description="vendor|news|cert"),
    severity: Optional[str] = Query(None),
    source_slug: Optional[str] = Query(None),
    source_name: Optional[str] = Query(None),
    threat_actor: Optional[str] = Query(None),
    malware: Optional[str] = Query(None),
    cve: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Full-text search"),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    query = {"is_duplicate": False, "is_cybersecurity_news": True}

    if category:
        query["source_category"] = category
    if severity:
        query["severity"] = severity
    if source_name:
        import re
        query["source_name"] = {"$regex": f"^{re.escape(source_name)}$", "$options": "i"}
    if source_slug:
        query["source_slug"] = source_slug
    if threat_actor:
        query["threat_actors"] = threat_actor
    if malware:
        query["malware_families"] = malware
    if cve:
        query["cves"] = cve
    if tag:
        query["tags"] = tag
    if date_from or date_to:
        query["published_at"] = {}
        if date_from:
            query["published_at"]["$gte"] = datetime.fromisoformat(date_from)
        if date_to:
            query["published_at"]["$lte"] = datetime.fromisoformat(date_to)
    if q:
        query["$text"] = {"$search": q}

    total = await col.count_documents(query)
    skip = (page - 1) * page_size

    cursor = col.find(query).sort("published_at", -1).skip(skip).limit(page_size)
    articles = []
    async for doc in cursor:
        articles.append(serialize_article(doc, current_user["id"]))

    return {
        "data": articles,
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
async def get_feed_stats(current_user: dict = Depends(get_current_user)):
    col = get_articles_collection()
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    stats = {
        "total_articles": await col.count_documents({}),
        "articles_today": await col.count_documents({"published_at": {"$gte": today}}),
        "articles_this_week": await col.count_documents({"published_at": {"$gte": now - timedelta(days=7)}}),
        "critical_today": await col.count_documents({"severity": "critical", "published_at": {"$gte": today}}),
        "high_today": await col.count_documents({"severity": "high", "published_at": {"$gte": today}}),
        "pending_enrichment": await col.count_documents({"enrichment_status": "pending"}),
    }

    # Severity breakdown
    pipeline = [
        {"$match": {"published_at": {"$gte": today}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    severity_breakdown = {}
    async for doc in col.aggregate(pipeline):
        severity_breakdown[doc["_id"]] = doc["count"]
    stats["severity_breakdown"] = severity_breakdown

    # Top sources today
    pipeline = [
        {"$match": {"published_at": {"$gte": today}}},
        {"$group": {"_id": "$source_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_sources = []
    async for doc in col.aggregate(pipeline):
        top_sources.append({"source": doc["_id"], "count": doc["count"]})
    stats["top_sources_today"] = top_sources

    return stats


@router.get("/{article_id}")
async def get_article(
    article_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(article_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Article not found")

    if not doc:
        raise HTTPException(status_code=404, detail="Article not found")

    # Increment view count
    await col.update_one({"_id": doc["_id"]}, {"$inc": {"view_count": 1}})
    doc["view_count"] = doc.get("view_count", 0) + 1

    return serialize_article(doc, current_user["id"])


@router.post("/{article_id}/bookmark")
async def bookmark_article(
    article_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    try:
        result = await col.update_one(
            {"_id": ObjectId(article_id)},
            {"$addToSet": {"bookmarked_by": current_user["id"]}}
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Article not found")

    return {"bookmarked": True}


@router.delete("/{article_id}/bookmark")
async def remove_bookmark(
    article_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    await col.update_one(
        {"_id": ObjectId(article_id)},
        {"$pull": {"bookmarked_by": current_user["id"]}}
    )
    return {"bookmarked": False}


@router.post("/{article_id}/notes")
async def add_note(
    article_id: str = Path(...),
    note: str = Query(..., min_length=1, max_length=5000),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    note_doc = {
        "user_id": current_user["id"],
        "note": note,
        "created_at": datetime.now(timezone.utc),
    }
    await col.update_one(
        {"_id": ObjectId(article_id)},
        {"$push": {"analyst_notes": note_doc}}
    )
    return {"note": note_doc}


@router.get("/bookmarks/me")
async def my_bookmarks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    col = get_articles_collection()
    query = {"bookmarked_by": current_user["id"]}
    total = await col.count_documents(query)
    skip = (page - 1) * page_size
    cursor = col.find(query).sort("published_at", -1).skip(skip).limit(page_size)
    articles = [serialize_article(doc, current_user["id"]) async for doc in cursor]
    return {
        "data": articles,
        "meta": {"total": total, "page": page, "page_size": page_size, "pages": ceil(total / page_size) if total > 0 else 0}
    }


@router.post("/{article_id}/enrich")
async def enrich_article(
    article_id: str = Path(..., description="Article MongoDB ObjectId"),
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger on-demand AI enrichment for an existing article.
    Extracts 10 CTI structured fields: claim_status, severity, threat_actor,
    target_country, sector, claimed_records_count, attack_vector,
    company_response, cves, ai_summary.
    """
    from app.services.ai_enrichment import AIEnrichmentService

    col = get_articles_collection()
    try:
        doc = await col.find_one({"_id": ObjectId(article_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid article ID format")

    if not doc:
        raise HTTPException(status_code=404, detail="Article not found")

    title = doc.get("title", "")
    body_text = doc.get("content_clean") or doc.get("summary") or ""

    try:
        enriched = await AIEnrichmentService.enrich_article(title=title, body_text=body_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI enrichment failed: {str(e)}")

    enrich_update = {
        "claim_status": enriched.get("claim_status", "claimed"),
        "severity": enriched.get("severity", doc.get("severity", "medium")),
        "threat_actors": (
            [enriched["threat_actor"]]
            if enriched.get("threat_actor") and enriched["threat_actor"] != "Unattributed"
            else doc.get("threat_actors", ["Unattributed"])
        ),
        "target_country": enriched.get("target_country"),
        "sector": enriched.get("sector"),
        "claimed_records_count": enriched.get("claimed_records_count"),
        "attack_vector": enriched.get("attack_vector"),
        "company_response": enriched.get("company_response"),
        "cves": list(set((doc.get("cves") or []) + (enriched.get("cves") or []))),
        "ai_summary": enriched.get("summary"),
        "enriched_at": datetime.now(timezone.utc),
        "enrichment_status": "enriched",
    }

    await col.update_one({"_id": ObjectId(article_id)}, {"$set": enrich_update})
    log.info("On-demand AI enrichment completed", article_id=article_id, claim_status=enriched.get("claim_status"))

    return {
        "status": "enriched",
        "article_id": article_id,
        "enriched_fields": enrich_update,
    }

