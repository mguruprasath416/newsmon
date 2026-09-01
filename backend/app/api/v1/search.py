from fastapi import APIRouter, Depends, Query
from typing import Optional
from app.core.dependencies import get_current_user
from app.db.mongodb import get_articles_collection, get_kev_collection, get_threat_actors_collection, get_malware_collection, get_campaigns_collection, get_iocs_collection
from app.db.elasticsearch import ElasticsearchClient, INDICES
import structlog

log = structlog.get_logger()
router = APIRouter()


@router.post("")
async def unified_search(
    query: str = Query(..., min_length=1, max_length=500),
    types: str = Query("articles,kev,threat_actors,malware", description="Comma-separated entity types"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    current_user: dict = Depends(get_current_user),
):
    """Unified search across all intelligence entities."""
    type_list = [t.strip() for t in types.split(",")]
    results = {}

    es_client = ElasticsearchClient.get_client()

    # Elasticsearch search for articles
    if "articles" in type_list:
        try:
            es_query = {
                "from": (page - 1) * page_size,
                "size": page_size,
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["title^3", "summary^2", "content_clean", "threat_actors^2", "malware_families^2", "cves^2", "tags"],
                        "type": "best_fields",
                        "fuzziness": "AUTO",
                    }
                },
                "highlight": {
                    "fields": {
                        "title": {},
                        "summary": {"fragment_size": 200, "number_of_fragments": 1},
                    }
                },
                "_source": ["title", "summary", "published_at", "source_name", "severity", "tags", "threat_actors", "malware_families", "cves", "ioc_count"],
            }
            es_result = await es_client.search(index=INDICES["articles"], body=es_query)
            hits = es_result["hits"]["hits"]
            results["articles"] = {
                "data": [{"id": h["_id"], **h["_source"], "highlight": h.get("highlight", {})} for h in hits],
                "total": es_result["hits"]["total"]["value"]
            }
        except Exception as e:
            log.warning("Elasticsearch search failed, falling back to MongoDB", error=str(e))
            results["articles"] = await _mongo_article_search(query, page, page_size)

    # MongoDB-based searches for other entities
    if "threat_actors" in type_list:
        results["threat_actors"] = await _mongo_entity_search(
            get_threat_actors_collection(), query,
            ["name", "aliases", "description"], page, page_size
        )

    if "malware" in type_list:
        results["malware"] = await _mongo_entity_search(
            get_malware_collection(), query,
            ["name", "aliases", "description", "family"], page, page_size
        )

    if "kev" in type_list:
        col = get_kev_collection()
        kev_query = {
            "$or": [
                {"cve_id": {"$regex": query, "$options": "i"}},
                {"vendor": {"$regex": query, "$options": "i"}},
                {"product": {"$regex": query, "$options": "i"}},
                {"vulnerability_name": {"$regex": query, "$options": "i"}},
            ]
        }
        cursor = col.find(kev_query).limit(page_size)
        kev_results = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            kev_results.append(doc)
        results["kev"] = {"data": kev_results, "total": len(kev_results)}

    if "iocs" in type_list:
        results["iocs"] = await _ioc_search(query, page, page_size)

    return {
        "query": query,
        "results": results,
        "types_searched": type_list,
    }


@router.get("/suggest")
async def autocomplete(
    q: str = Query(..., min_length=2),
    current_user: dict = Depends(get_current_user),
):
    """Autocomplete suggestions from all entity types."""
    suggestions = []

    # Quick MongoDB lookups
    actors_col = get_threat_actors_collection()
    async for doc in actors_col.find({"name": {"$regex": f"^{q}", "$options": "i"}}).limit(5):
        suggestions.append({"type": "threat_actor", "value": doc["name"], "id": str(doc["_id"])})

    malware_col = get_malware_collection()
    async for doc in malware_col.find({"name": {"$regex": f"^{q}", "$options": "i"}}).limit(5):
        suggestions.append({"type": "malware", "value": doc["name"], "id": str(doc["_id"])})

    # CVE-style suggestion
    if q.upper().startswith("CVE"):
        kev_col = get_kev_collection()
        async for doc in kev_col.find({"cve_id": {"$regex": f"^{q}", "$options": "i"}}).limit(5):
            suggestions.append({"type": "cve", "value": doc["cve_id"], "in_kev": True})

    return {"suggestions": suggestions[:15]}


@router.post("/ioc/{ioc_value}")
async def search_ioc(
    ioc_value: str,
    current_user: dict = Depends(get_current_user),
):
    """Search for a specific IOC value across all articles and reports."""
    iocs_col = get_iocs_collection()
    articles_col = get_articles_collection()

    # Clean the IOC value (handle defanged formats)
    clean_value = ioc_value.replace("[.]", ".").replace("hxxp", "http").replace("hxxps", "https")

    # Search IOC DB
    ioc_doc = await iocs_col.find_one({
        "$or": [
            {"value": clean_value},
            {"value_raw": clean_value},
            {"value": ioc_value},
        ]
    })

    # Search articles
    article_query = {"$or": [
        {"iocs.ipv4": clean_value},
        {"iocs.domains": clean_value},
        {"iocs.sha256": clean_value},
        {"iocs.sha1": clean_value},
        {"iocs.md5": clean_value},
        {"iocs.urls": {"$regex": clean_value, "$options": "i"}},
        {"iocs.emails": clean_value},
    ]}

    articles = []
    async for doc in articles_col.find(article_query, {"title": 1, "published_at": 1, "source_name": 1, "severity": 1}).limit(20):
        doc["id"] = str(doc.pop("_id"))
        articles.append(doc)

    if ioc_doc:
        ioc_doc["id"] = str(ioc_doc.pop("_id"))

    return {
        "ioc": ioc_value,
        "normalized": clean_value,
        "ioc_record": ioc_doc,
        "articles": articles,
        "article_count": len(articles),
    }


async def _mongo_article_search(query: str, page: int, page_size: int) -> dict:
    col = get_articles_collection()
    q = {
        "$text": {"$search": query},
        "is_cybersecurity_news": True,
        "is_duplicate": False,
    }
    total = await col.count_documents(q)
    cursor = col.find(q, {"title": 1, "summary": 1, "published_at": 1, "source_name": 1, "severity": 1, "attacks": 1, "targets": 1, "geography": 1}).skip(skip).limit(page_size)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "total": total}


async def _mongo_entity_search(col, query: str, fields: list, page: int, page_size: int) -> dict:
    skip = (page - 1) * page_size
    q = {"$or": [{field: {"$regex": query, "$options": "i"}} for field in fields]}
    total = await col.count_documents(q)
    cursor = col.find(q).skip(skip).limit(page_size)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "total": total}


async def _ioc_search(query: str, page: int, page_size: int) -> dict:
    col = get_iocs_collection()
    skip = (page - 1) * page_size
    q = {"$or": [{"value": {"$regex": query, "$options": "i"}}, {"value_raw": {"$regex": query, "$options": "i"}}]}
    total = await col.count_documents(q)
    cursor = col.find(q).skip(skip).limit(page_size)
    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)
    return {"data": results, "total": total}


# ── NVIDIA NIM RAG Retrieval & Reranking Endpoint ─────────────────────────────

@router.post("/rag")
async def nvidia_rag_search(
    query: str = Query(..., min_length=1, max_length=500),
    top_k: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user),
):
    """NVIDIA NIM RAG retrieval & reranking endpoint (Nemotron 1B Embed + Mistral 4B Reranker)."""
    from app.services.rag_service import NVIDIARAGService
    result = await NVIDIARAGService.hybrid_rag_search(query, top_k=top_k)
    return result
