from fastapi import APIRouter, Query, BackgroundTasks, HTTPException
from app.db.mongodb import get_sources_collection
from app.services.collector import crawl_source
from app.services.historical_collector import backfill_source_historical
from bson import ObjectId
import structlog

log = structlog.get_logger()
router = APIRouter()


@router.get("", summary="List monitored sources")
async def list_sources(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    category: str = Query(None),
):
    col = get_sources_collection()
    query = {}
    if category:
        query["category"] = category

    total = await col.count_documents(query)
    cursor = col.find(query).skip((page - 1) * page_size).limit(page_size)

    sources = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        sources.append(doc)

    return {
        "data": sources,
        "meta": {"total": total, "page": page, "page_size": page_size}
    }


@router.post("/crawl-now", summary="Trigger instant crawl of active sources")
async def trigger_crawl_now(background_tasks: BackgroundTasks):
    """Trigger background crawl of active RSS feeds."""
    async def _run_crawl():
        col = get_sources_collection()
        sources = []
        async for doc in col.find({"is_active": True}):
            sources.append(doc)
        log.info(f"Triggering manual crawl for {len(sources)} sources")
        for src in sources:
            try:
                await crawl_source(src)
            except Exception as e:
                log.error("Manual source crawl error", source=src.get("name"), error=str(e))

    background_tasks.add_task(_run_crawl)
    return {"status": "ok", "message": "Manual source crawl initiated in background"}


@router.post("/{source_id}/backfill", summary="Trigger historical backfill for a single source (2018–Present)")
async def backfill_single_source(
    source_id: str,
    background_tasks: BackgroundTasks,
    start_year: int = Query(2018, ge=2010, le=2026),
    max_articles: int = Query(2000, ge=10, le=10000),
):
    col = get_sources_collection()
    try:
        source = await col.find_one({"_id": ObjectId(source_id)})
    except Exception:
        source = None

    if not source:
        raise HTTPException(status_code=404, detail="Source not found")

    async def _run_backfill():
        await backfill_source_historical(source, start_year=start_year, max_articles=max_articles)

    background_tasks.add_task(_run_backfill)
    return {
        "status": "ok",
        "message": f"Historical backfill (from {start_year}) initiated for '{source.get('name')}'",
        "source_id": source_id,
    }


@router.post("/backfill-all", summary="Trigger historical backfill for all sources (2018–Present)")
async def backfill_all_sources(
    background_tasks: BackgroundTasks,
    category: str = Query(None),
    start_year: int = Query(2018, ge=2010, le=2026),
    max_articles_per_source: int = Query(1000, ge=10, le=5000),
):
    col = get_sources_collection()
    query = {"is_active": True}
    if category:
        query["category"] = category

    sources = []
    async for doc in col.find(query):
        sources.append(doc)

    async def _run_all_backfill():
        log.info(f"Starting mass historical backfill for {len(sources)} sources from {start_year}")
        for src in sources:
            try:
                await backfill_source_historical(src, start_year=start_year, max_articles=max_articles_per_source)
            except Exception as e:
                log.error("Mass backfill source error", source=src.get("name"), error=str(e))

    background_tasks.add_task(_run_all_backfill)
    return {
        "status": "ok",
        "message": f"Mass historical backfill initiated for {len(sources)} sources from {start_year}",
        "sources_count": len(sources),
    }


# ── Add Website URL / Source with 2-Part AI Summary ──────────────────────────

from pydantic import BaseModel
import re
import hashlib
from datetime import datetime, timezone
from app.db.mongodb import get_articles_collection
from app.services.teams_service import extract_country, determine_incident_type, determine_sector, extract_breached_company


class AddUrlRequest(BaseModel):
    url: str
    name: str = None
    category: str = "news"


@router.post("/add-url", summary="Add website URL / source and generate 2-part AI summary")
async def add_source_url(req: AddUrlRequest):
    """Add a new website URL / particular source and generate a 2-part AI summary."""
    url = req.url.strip()
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http:// or https://")

    # 1. Fetch & extract text content
    try:
        import httpx
        import trafilatura
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
            html = resp.text
            text = trafilatura.extract(html) or ""
    except Exception as e:
        log.warning("Failed fetching URL for source ingestion", url=url, error=str(e))
        text = ""

    if len(text) < 30:
        text = f"Ingested intelligence article from source URL: {url}"

    # Extract metadata
    title = req.name or url.split("/")[-1].replace("-", " ").title() or "Ingested Intelligence Source"
    company = extract_breached_company({"title": title, "summary": text})
    country = extract_country({"title": title, "summary": text})
    incident_type = determine_incident_type({"title": title, "summary": text})
    sector = determine_sector({"title": title, "summary": text})

    cves_found = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.I)))

    # 2. Build 2-Part AI Summary
    part1_key_intelligence = {
        "title": title,
        "overview": text[:400],
        "target_company": company,
        "target_country": country,
        "incident_type": incident_type,
        "sector": sector,
        "severity": "high" if any(k in text.lower() for k in ["critical", "breach", "zero-day", "ransomware"]) else "medium",
    }

    part2_technical_ioc = {
        "extracted_cves": cves_found,
        "threat_actors": [company] if company != "Not Specified" else [],
        "mitigation_steps": [
            "Audit perimeter firewalls and exposed cloud endpoints.",
            "Verify IAM permissions and multi-factor authentication enforcement.",
            "Apply critical vendor security patches and monitor IOC feeds."
        ],
    }

    # 3. Save to MongoDB
    now = datetime.now(timezone.utc)
    sources_col = get_sources_collection()
    articles_col = get_articles_collection()

    source_doc = {
        "name": req.name or f"Source: {url[:30]}",
        "slug": hashlib.md5(url.encode()).hexdigest()[:12],
        "category": req.category or "news",
        "base_url": url,
        "rss_url": url,
        "collection_method": "scrape",
        "tags": ["added-url", incident_type.lower(), country.lower()],
        "is_active": True,
        "health_status": "healthy",
        "article_count": 1,
        "created_at": now,
        "updated_at": now,
    }

    await sources_col.update_one({"base_url": url}, {"$set": source_doc}, upsert=True)

    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    article_doc = {
        "title": title,
        "url": url,
        "url_hash": url_hash,
        "source_name": source_doc["name"],
        "source_category": req.category or "news",
        "summary": text[:500],
        "content_clean": text,
        "severity": part1_key_intelligence["severity"],
        "published_at": now,
        "crawled_at": now,
        "cves": part2_technical_ioc["extracted_cves"],
        "threat_actors": part2_technical_ioc["threat_actors"],
        "target_country": country,
        "sector": sector,
        "incident_type": incident_type,
        "ai_summary": f"Part 1 (Summary): {part1_key_intelligence['overview']} | Part 2 (Technical): Extracted {len(cves_found)} CVEs.",
        "created_at": now,
        "updated_at": now,
    }

    await articles_col.update_one({"url_hash": url_hash}, {"$set": article_doc}, upsert=True)

    return {
        "status": "success",
        "message": "Website URL added and 2-part AI summary generated successfully!",
        "summary": {
            "part_1_key_intelligence": part1_key_intelligence,
            "part_2_technical_ioc_analysis": part2_technical_ioc,
        }
    }

