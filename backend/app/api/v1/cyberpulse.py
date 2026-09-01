"""
CyberPulse REST API Endpoints — Viral Cyber News Detection, Heat Mapping & Priority Events.

Endpoints:
  GET  /viral-events                  — List viral events with pagination & filters
  GET  /viral-events/heat-map         — Heat map matrix data
  GET  /viral-events/trending         — Top trending events (>= 5 sources)
  GET  /viral-events/high-priority    — High heat priority events (>= 10 sources)
  GET  /viral-events/{event_id}       — Single event details & explanation
  GET  /viral-events/{event_id}/sources  — List of independent sources
  GET  /viral-events/{event_id}/articles — List of correlated articles
  GET  /viral-events/{event_id}/timeline — Growth history & publication timeline
  POST /viral-events/recalculate      — Trigger background correlation sweep
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from bson import ObjectId
from datetime import datetime, timezone, timedelta
from calendar import monthrange
import structlog

from app.db.mongodb import get_viral_events_collection, get_articles_collection, get_sources_collection
from app.services.cyberpulse_service import CyberPulseService
from app.config import settings

log = structlog.get_logger()
router = APIRouter()


def _build_timeframe_query(
    timeframe: Optional[str] = "24h",
    year: Optional[int] = None,
    month: Optional[int] = None
) -> Dict[str, Any]:
    """Helper to build MongoDB date filter for Daily, Weekly, Monthly, or Custom Month queries."""
    now = datetime.now(timezone.utc)
    if year and month:
        try:
            start = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
            _, last_day = monthrange(year, month)
            end = datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc)
            return {"last_detected_at": {"$gte": start, "$lte": end}}
        except Exception:
            pass

    tf = (timeframe or "24h").lower()
    if tf in ("today", "daily", "24h"):
        cutoff = now - timedelta(hours=24)
        return {"last_detected_at": {"$gte": cutoff}}
    elif tf in ("7d", "week", "weekly"):
        cutoff = now - timedelta(days=7)
        return {"last_detected_at": {"$gte": cutoff}}
    elif tf in ("month", "monthly", "30d"):
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return {"last_detected_at": {"$gte": start}}
    elif tf == "all":
        return {}
    return {"last_detected_at": {"$gte": now - timedelta(hours=24)}}


def _serialize_event(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert MongoDB ObjectId and datetimes to JSON serializable dict."""
    if not doc:
        return {}
    doc["_id"] = str(doc.get("_id", ""))
    return doc


@router.get("")
async def list_viral_events(
    min_sources: int = Query(default=1, description="Minimum unique source count"),
    status: Optional[str] = Query(default=None, description="Status filter: emerging | trending | high_heat"),
    priority: Optional[str] = Query(default=None, description="Priority filter: low | medium | high | critical"),
    timeframe: Optional[str] = Query(default="24h", description="Timeframe: 24h | 7d | month | all"),
    year: Optional[int] = Query(default=None),
    month: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    skip: int = Query(default=0, ge=0),
):
    """List all tracked CyberPulse viral events with pagination and timeframe filters."""
    events_col = get_viral_events_collection()
    query: Dict[str, Any] = {"source_count": {"$gte": min_sources}}

    tf_q = _build_timeframe_query(timeframe, year, month)
    if tf_q:
        query.update(tf_q)

    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority

    total = await events_col.count_documents(query)
    cursor = events_col.find(query).sort([("last_detected_at", -1), ("heat_score", -1)]).skip(skip).limit(limit)
    events = [_serialize_event(doc) async for doc in cursor]

    return {
        "total": total,
        "page": (skip // limit) + 1,
        "limit": limit,
        "timeframe": timeframe,
        "events": events,
    }


@router.get("/heat-map")
async def get_heat_map_data(
    min_sources: int = Query(default=settings.CYBERPULSE_MIN_SOURCES),
    timeframe: Optional[str] = Query(default="24h", description="Timeframe: 24h (Daily) | 7d | month (Monthly) | all"),
    year: Optional[int] = Query(default=None),
    month: Optional[int] = Query(default=None),
    limit: int = Query(default=50),
):
    """
    Get prioritized events for the CyberPulse Heat Map filtered by timeframe (Daily, Weekly, Monthly, or Custom Month).
    Only returns events meeting the minimum unique source threshold.
    """
    events_col = get_viral_events_collection()
    query: Dict[str, Any] = {"source_count": {"$gte": min_sources}}

    tf_q = _build_timeframe_query(timeframe, year, month)
    if tf_q:
        query.update(tf_q)

    cursor = events_col.find(query).sort([("last_detected_at", -1), ("heat_score", -1)]).limit(limit)
    events = [_serialize_event(doc) async for doc in cursor]

    # Category buckets for heat matrix
    severe_events = [e for e in events if e.get("heat_score", 0) >= 80]
    high_events = [e for e in events if 60 <= e.get("heat_score", 0) < 80]
    medium_events = [e for e in events if 40 <= e.get("heat_score", 0) < 60]
    low_events = [e for e in events if e.get("heat_score", 0) < 40]

    return {
        "min_source_threshold": min_sources,
        "high_source_threshold": settings.CYBERPULSE_HIGH_SOURCES,
        "total_active_events": len(events),
        "timeframe": timeframe,
        "heat_matrix": {
            "severe": severe_events,
            "high": high_events,
            "medium": medium_events,
            "low": low_events,
        },
        "events": events,
    }


@router.get("/trending")
async def get_trending_events(
    timeframe: Optional[str] = Query(default="24h"),
    year: Optional[int] = Query(default=None),
    month: Optional[int] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=50),
):
    """Get top trending events with at least MIN_SOURCE_THRESHOLD unique sources filtered by timeframe."""
    events_col = get_viral_events_collection()
    query: Dict[str, Any] = {"source_count": {"$gte": settings.CYBERPULSE_MIN_SOURCES}}

    tf_q = _build_timeframe_query(timeframe, year, month)
    if tf_q:
        query.update(tf_q)

    cursor = events_col.find(query).sort([("last_detected_at", -1), ("heat_score", -1)]).limit(limit)
    events = [_serialize_event(doc) async for doc in cursor]

    return {
        "count": len(events),
        "timeframe": timeframe,
        "trending_events": events,
    }


@router.get("/high-priority")
async def get_high_priority_events(
    timeframe: Optional[str] = Query(default="24h"),
    year: Optional[int] = Query(default=None),
    month: Optional[int] = Query(default=None),
    limit: int = Query(default=15, ge=1, le=50),
):
    """Get viral events crossing the HIGH_SOURCE_THRESHOLD filtered by timeframe."""
    events_col = get_viral_events_collection()
    query: Dict[str, Any] = {"source_count": {"$gte": settings.CYBERPULSE_HIGH_SOURCES}}

    tf_q = _build_timeframe_query(timeframe, year, month)
    if tf_q:
        query.update(tf_q)

    cursor = events_col.find(query).sort([("last_detected_at", -1), ("heat_score", -1)]).limit(limit)
    events = [_serialize_event(doc) async for doc in cursor]

    return {
        "count": len(events),
        "timeframe": timeframe,
        "high_priority_events": events,
    }


@router.get("/{event_id}")
async def get_event_detail(event_id: str):
    """Fetch full detail for a single CyberPulse event including analyst explanation."""
    events_col = get_viral_events_collection()
    query = {"event_id": event_id}
    if ObjectId.is_valid(event_id):
        query = {"$or": [{"event_id": event_id}, {"_id": ObjectId(event_id)}]}
    event = await events_col.find_one(query)
    if not event:
        raise HTTPException(status_code=404, detail="CyberPulse event not found")
    return _serialize_event(event)


@router.get("/{event_id}/sources")
async def get_event_sources(event_id: str):
    """List all independent unique sources covering this CyberPulse event."""
    events_col = get_viral_events_collection()
    query = {"event_id": event_id}
    if ObjectId.is_valid(event_id):
        query = {"$or": [{"event_id": event_id}, {"_id": ObjectId(event_id)}]}
    event = await events_col.find_one(query)
    if not event:
        raise HTTPException(status_code=404, detail="CyberPulse event not found")

    unique_names = event.get("unique_source_names") or []
    return {
        "event_id": event.get("event_id"),
        "source_count": len(unique_names),
        "sources": unique_names,
    }


@router.get("/{event_id}/articles")
async def get_event_articles(event_id: str, limit: int = Query(default=50, ge=1, le=100)):
    """List all correlated articles belonging to this CyberPulse event."""
    events_col = get_viral_events_collection()
    query = {"event_id": event_id}
    if ObjectId.is_valid(event_id):
        query = {"$or": [{"event_id": event_id}, {"_id": ObjectId(event_id)}]}
    event = await events_col.find_one(query)
    if not event:
        raise HTTPException(status_code=404, detail="CyberPulse event not found")

    article_ids = event.get("related_article_ids", [])
    object_ids = [ObjectId(aid) for aid in article_ids if ObjectId.is_valid(aid)]

    articles_col = get_articles_collection()
    cursor = articles_col.find({
        "$or": [
            {"_id": {"$in": object_ids}},
            {"viral_event_id": event.get("event_id")},
        ]
    }).sort("published_at", -1).limit(limit)

    articles = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        articles.append(doc)

    return {
        "event_id": event.get("event_id"),
        "article_count": len(articles),
        "articles": articles,
    }


@router.get("/{event_id}/timeline")
async def get_event_timeline(event_id: str):
    """Fetch the source growth history and publication timeline for an event."""
    events_col = get_viral_events_collection()
    query = {"event_id": event_id}
    if ObjectId.is_valid(event_id):
        query = {"$or": [{"event_id": event_id}, {"_id": ObjectId(event_id)}]}
    event = await events_col.find_one(query)
    if not event:
        raise HTTPException(status_code=404, detail="CyberPulse event not found")

    return {
        "event_id": event.get("event_id"),
        "first_detected_at": event.get("first_detected_at"),
        "last_detected_at": event.get("last_detected_at"),
        "trend": event.get("trend"),
        "growth_history": event.get("source_growth_history", []),
    }


@router.post("/recalculate")
async def trigger_recalculation(hours: int = Query(default=72, ge=6, le=168)):
    """Admin manual trigger: run full CyberPulse correlation sweep over recent articles."""
    result = await CyberPulseService.recalculate_all_viral_events(hours=hours)
    return result
