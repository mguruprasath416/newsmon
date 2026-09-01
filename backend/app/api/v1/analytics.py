from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_user
from app.db.mongodb import get_articles_collection, get_kev_collection, get_threat_actors_collection, get_malware_collection, get_campaigns_collection, get_sources_collection
from datetime import datetime, timezone, timedelta
import structlog

log = structlog.get_logger()
router = APIRouter()


@router.get("/overview")
async def overview(current_user: dict = Depends(get_current_user)):
    """Platform-wide intelligence statistics."""
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_7 = now - timedelta(days=7)
    last_30 = now - timedelta(days=30)

    articles_col = get_articles_collection()
    kev_col = get_kev_collection()
    actors_col = get_threat_actors_collection()
    malware_col = get_malware_collection()
    campaigns_col = get_campaigns_collection()
    sources_col = get_sources_collection()

    return {
        "articles": {
            "total": await articles_col.count_documents({}),
            "today": await articles_col.count_documents({"published_at": {"$gte": today}}),
            "last_7_days": await articles_col.count_documents({"published_at": {"$gte": last_7}}),
            "last_30_days": await articles_col.count_documents({"published_at": {"$gte": last_30}}),
            "critical": await articles_col.count_documents({"severity": "critical", "published_at": {"$gte": last_7}}),
        },
        "kev": {
            "total": await kev_col.count_documents({}),
            "ransomware_associated": await kev_col.count_documents({"known_ransomware": True}),
            "added_last_7_days": await kev_col.count_documents({"date_added": {"$gte": last_7}}),
            "high_epss": await kev_col.count_documents({"epss_score": {"$gte": 0.5}}),
        },
        "threat_actors": {
            "total": await actors_col.count_documents({}),
            "active": await actors_col.count_documents({"active_status": "active"}),
        },
        "malware": {
            "total": await malware_col.count_documents({}),
            "active": await malware_col.count_documents({"active_status": "active"}),
        },
        "campaigns": {
            "total": await campaigns_col.count_documents({}),
            "active": await campaigns_col.count_documents({"active_status": "active"}),
        },
        "sources": {
            "total": await sources_col.count_documents({}),
            "active": await sources_col.count_documents({"is_active": True}),
            "healthy": await sources_col.count_documents({"health_status": "healthy", "is_active": True}),
        },
    }


@router.get("/threats")
async def threat_landscape(current_user: dict = Depends(get_current_user)):
    """Threat landscape statistics for charts."""
    articles_col = get_articles_collection()
    last_30 = datetime.now(timezone.utc) - timedelta(days=30)

    # Top threat actors by article count
    pipeline = [
        {"$match": {"published_at": {"$gte": last_30}, "threat_actors": {"$exists": True, "$ne": []}}},
        {"$unwind": "$threat_actors"},
        {"$group": {"_id": "$threat_actors", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_actors = [{"name": d["_id"], "count": d["count"]} async for d in articles_col.aggregate(pipeline)]

    # Top malware
    pipeline = [
        {"$match": {"published_at": {"$gte": last_30}, "malware_families": {"$exists": True, "$ne": []}}},
        {"$unwind": "$malware_families"},
        {"$group": {"_id": "$malware_families", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_malware = [{"name": d["_id"], "count": d["count"]} async for d in articles_col.aggregate(pipeline)]

    # Articles by severity over time (last 30 days, daily buckets)
    pipeline = [
        {"$match": {"published_at": {"$gte": last_30}}},
        {"$group": {
            "_id": {
                "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$published_at"}},
                "severity": "$severity",
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.date": 1}},
    ]
    severity_timeline_raw = [d async for d in articles_col.aggregate(pipeline)]
    severity_timeline = {}
    for item in severity_timeline_raw:
        date = item["_id"]["date"]
        sev = item["_id"]["severity"]
        if date not in severity_timeline:
            severity_timeline[date] = {}
        severity_timeline[date][sev] = item["count"]

    # Top MITRE tactics
    pipeline = [
        {"$match": {"published_at": {"$gte": last_30}, "mitre_techniques": {"$exists": True, "$ne": []}}},
        {"$unwind": "$mitre_techniques"},
        {"$group": {"_id": "$mitre_techniques.tactic", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    top_tactics = [{"tactic": d["_id"], "count": d["count"]} async for d in articles_col.aggregate(pipeline)]

    return {
        "top_threat_actors": top_actors,
        "top_malware": top_malware,
        "severity_timeline": severity_timeline,
        "top_mitre_tactics": top_tactics,
    }
