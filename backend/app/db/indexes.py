from app.db.mongodb import (
    get_sources_collection, get_articles_collection, get_reports_collection,
    get_kev_collection, get_threat_actors_collection, get_malware_collection,
    get_campaigns_collection, get_iocs_collection, get_users_collection,
    get_logs_collection, get_ta_aliases_collection, get_vendor_reports_collection,
    get_ta_relationships_collection, get_ta_references_collection, get_viral_events_collection
)
import structlog

log = structlog.get_logger()


async def create_all_indexes():
    """Create all MongoDB indexes on startup."""
    await _create_sources_indexes()
    await _create_articles_indexes()
    await _create_viral_events_indexes()
    await _create_reports_indexes()
    await _create_kev_indexes()
    await _create_threat_actor_indexes()
    await _create_malware_indexes()
    await _create_campaign_indexes()
    await _create_ioc_indexes()
    await _create_user_indexes()
    await _create_log_indexes()
    await _create_ta_enrichment_indexes()
    log.info("All MongoDB indexes created/verified")


async def _create_viral_events_indexes():
    col = get_viral_events_collection()
    await col.create_index([("event_id", 1)], unique=True, background=True)
    await col.create_index([("source_count", -1), ("heat_score", -1)], background=True)
    await col.create_index([("heat_score", -1), ("last_detected_at", -1)], background=True)
    await col.create_index([("last_detected_at", -1)], background=True)
    await col.create_index([("cves", 1)], background=True)
    await col.create_index([("target_company", 1)], background=True)



async def _create_sources_indexes():
    col = get_sources_collection()
    await col.create_index([("slug", 1)], unique=True, background=True)
    await col.create_index([("category", 1), ("is_active", 1)], background=True)
    await col.create_index([("health_status", 1)], background=True)
    await col.create_index([("last_crawled_at", 1)], background=True)
    await col.create_index([("priority", 1), ("is_active", 1)], background=True)


async def _create_articles_indexes():
    col = get_articles_collection()
    await col.create_index([("url_hash", 1)], unique=True, background=True)
    await col.create_index([("source_id", 1), ("published_at", -1)], background=True)
    await col.create_index([("published_at", -1)], background=True)
    await col.create_index([("severity", 1), ("published_at", -1)], background=True)
    await col.create_index([("threat_actors", 1), ("published_at", -1)], background=True)
    await col.create_index([("threat_actors", 1)], background=True)
    await col.create_index([("malware_families", 1)], background=True)
    await col.create_index([("cves", 1)], background=True)
    await col.create_index([("tags", 1)], background=True)
    await col.create_index([("enrichment_status", 1)], background=True)
    await col.create_index([("source_category", 1), ("published_at", -1)], background=True)
    await col.create_index([("is_duplicate", 1)], background=True)
    await col.create_index(
        [("title", "text"), ("summary", "text"), ("ai_summary", "text")],
        background=True,
    )


async def _create_reports_indexes():
    col = get_reports_collection()
    await col.create_index([("job_id", 1)], unique=True, background=True)
    await col.create_index([("created_by", 1), ("created_at", -1)], background=True)
    await col.create_index([("status", 1)], background=True)
    await col.create_index([("share_token", 1)], sparse=True, background=True)
    await col.create_index([("tags", 1)], background=True)
    await col.create_index([("linked_threat_actors", 1)], background=True)


async def _create_kev_indexes():
    col = get_kev_collection()
    await col.create_index([("cve_id", 1)], unique=True, background=True)
    await col.create_index([("vendor", 1)], background=True)
    await col.create_index([("date_added", -1)], background=True)
    await col.create_index([("due_date", 1)], background=True)
    await col.create_index([("known_ransomware", 1)], background=True)
    await col.create_index([("epss_score", -1)], background=True)
    await col.create_index([("cvss_v3_score", -1)], background=True)


async def _create_threat_actor_indexes():
    col = get_threat_actors_collection()
    await col.create_index([("name", 1)], unique=True, background=True)
    await col.create_index([("canonical_name", 1)], background=True)
    await col.create_index([("article_count", -1)], background=True)
    await col.create_index([("confidence_score", -1)], background=True)
    await col.create_index([("aliases", 1)], background=True)
    await col.create_index([("type", 1)], background=True)
    await col.create_index([("origin_country", 1)], background=True)
    await col.create_index([("active_status", 1)], background=True)
    await col.create_index([("targeted_sectors", 1)], background=True)


async def _create_malware_indexes():
    col = get_malware_collection()
    await col.create_index([("name", 1)], unique=True, background=True)
    await col.create_index([("family", 1)], background=True)
    await col.create_index([("type", 1)], background=True)
    await col.create_index([("active_status", 1)], background=True)
    await col.create_index([("threat_actors", 1)], background=True)


async def _create_campaign_indexes():
    col = get_campaigns_collection()
    await col.create_index([("name", 1)], unique=True, background=True)
    await col.create_index([("threat_actors", 1)], background=True)
    await col.create_index([("start_date", -1)], background=True)
    await col.create_index([("active_status", 1)], background=True)
    await col.create_index([("targeted_sectors", 1)], background=True)


async def _create_ioc_indexes():
    col = get_iocs_collection()
    await col.create_index([("type", 1), ("value", 1)], unique=True, background=True)
    await col.create_index([("type", 1)], background=True)
    await col.create_index([("first_seen", -1)], background=True)
    await col.create_index([("threat_actors", 1)], background=True)
    await col.create_index([("malware_families", 1)], background=True)
    await col.create_index([("is_active", 1)], background=True)


async def _create_user_indexes():
    col = get_users_collection()
    await col.create_index([("email", 1)], unique=True, background=True)
    await col.create_index([("api_key", 1)], sparse=True, background=True)
    await col.create_index([("role", 1)], background=True)


async def _create_log_indexes():
    col = get_logs_collection()
    # TTL index - auto-delete after 90 days
    await col.create_index(
        [("created_at", 1)],
        expireAfterSeconds=7776000,  # 90 days
        background=True,
    )
    await col.create_index([("category", 1), ("created_at", -1)], background=True)
    await col.create_index([("level", 1), ("created_at", -1)], background=True)
    await col.create_index([("source_id", 1)], sparse=True, background=True)
    await col.create_index([("job_id", 1)], sparse=True, background=True)


async def _create_ta_enrichment_indexes():
    """Threat actor enrichment collection indexes."""
    # ── threat_actors (enhanced) ──────────────────────────────────────────────
    ta = get_threat_actors_collection()
    await ta.create_index([("slug", 1)], unique=True, sparse=True, background=True)
    await ta.create_index([("canonical_name", 1)], background=True)
    await ta.create_index([("aliases", 1)], background=True)
    await ta.create_index([("mitre_group_id", 1)], sparse=True, background=True)
    await ta.create_index([("source_ids.mitre", 1)], sparse=True, background=True)
    await ta.create_index([("origin_country", 1)], background=True)
    await ta.create_index([("type", 1)], background=True)
    await ta.create_index([("active_status", 1)], background=True)
    await ta.create_index([("confidence_score", -1)], background=True)
    await ta.create_index([("article_count", -1)], background=True)
    await ta.create_index([("updated_at", -1)], background=True)
    await ta.create_index(
        [("name", "text"), ("aliases", "text"), ("description", "text")],
        name="ta_fulltext",
        background=True,
    )

    # ── ta_aliases ─────────────────────────────────────────────────────────────
    al = get_ta_aliases_collection()
    await al.create_index([("alias_lower", 1)], unique=True, background=True)
    await al.create_index([("actor_id", 1)], background=True)
    await al.create_index([("canonical_name", 1)], background=True)

    # ── ta_vendor_reports ──────────────────────────────────────────────────────
    vr = get_vendor_reports_collection()
    await vr.create_index([("url", 1)], unique=True, background=True)
    await vr.create_index([("actor_ids", 1)], background=True)
    await vr.create_index([("source", 1), ("published_at", -1)], background=True)
    await vr.create_index([("published_at", -1)], background=True)

    # ── ta_relationships ───────────────────────────────────────────────────────
    rel = get_ta_relationships_collection()
    await rel.create_index([("source_id", 1), ("target_id", 1), ("relationship", 1)],
                           unique=True, background=True)
    await rel.create_index([("source_id", 1)], background=True)
    await rel.create_index([("target_id", 1)], background=True)

    # ── ta_references ──────────────────────────────────────────────────────────
    ref = get_ta_references_collection()
    await ref.create_index([("url", 1)], unique=True, background=True)
    await ref.create_index([("actor_id", 1)], background=True)



