from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import settings
import structlog

log = structlog.get_logger()


class MongoDB:
    client: AsyncIOMotorClient = None
    _db: AsyncIOMotorDatabase = None

    @classmethod
    async def connect(cls):
        cls.client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            maxPoolSize=50,
            minPoolSize=5,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=10000,
        )
        cls._db = cls.client[settings.MONGODB_DB_NAME]
        # Verify connection
        await cls.client.admin.command("ping")
        await cls.ensure_indexes()

    @classmethod
    async def ensure_indexes(cls):
        """Create database compound and field indexes."""
        try:
            articles_col = cls.collection("articles")
            # Existing compound indexes
            await articles_col.create_index([("threat_actors", 1), ("published_at", -1)], background=True)
            await articles_col.create_index([("source_category", 1), ("published_at", -1)], background=True)
            await articles_col.create_index([("severity", 1), ("published_at", -1)], background=True)
            # New compound indexes from schema update
            await articles_col.create_index([("claim_status", 1), ("published_at", -1)], background=True)
            await articles_col.create_index([("duplicate_of", 1)], background=True)
            await articles_col.create_index([("viral_event_id", 1)], background=True)
            await articles_col.create_index([("embedding_model", 1), ("crawled_at", -1)], background=True)
            await articles_col.create_index([("target_country", 1)], background=True)

            # CyberPulse Viral News Events indexes
            events_col = cls.collection("viral_news_events")
            await events_col.create_index([("event_id", 1)], unique=True, background=True)
            await events_col.create_index([("heat_score", -1), ("last_detected_at", -1)], background=True)
            await events_col.create_index([("source_count", -1)], background=True)
            await events_col.create_index([("status", 1), ("priority", 1)], background=True)
            await events_col.create_index([("created_at", -1)], background=True)
            # Incidents Collection Indexes
            incidents_col = cls.collection("incidents")
            await incidents_col.create_index([("incident_id", 1)], unique=True, background=True)
            await incidents_col.create_index([("target_organization", 1), ("incident_type", 1)], background=True)
            await incidents_col.create_index([("severity", 1), ("claim_status", 1)], background=True)
            await incidents_col.create_index([("first_reported_at", -1)], background=True)
            await incidents_col.create_index([("teams_dispatched", 1)], background=True)

            # Evidence Collection Indexes
            evidence_col = cls.collection("evidence")
            await evidence_col.create_index([("incident_id", 1)], background=True)
            await evidence_col.create_index([("article_id", 1)], background=True)
            await evidence_col.create_index([("evidence_score", -1)], background=True)

            # Alert Dispatches Audit Collection Indexes
            dispatches_col = cls.collection("alert_dispatches")
            await dispatches_col.create_index([("alert_id", 1)], unique=True, background=True)
            await dispatches_col.create_index([("fingerprint", 1)], background=True)
            await dispatches_col.create_index([("dispatched_at", -1)], background=True)
            await dispatches_col.create_index([("channel", 1), ("status", 1)], background=True)

            log.info("MongoDB compound indexes verified")
        except Exception as e:
            log.warning("MongoDB index creation warning", error=str(e))

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        if cls._db is None:
            raise RuntimeError("MongoDB not connected. Call connect() first.")
        return cls._db

    @classmethod
    async def disconnect(cls):
        if cls.client:
            cls.client.close()
            log.info("MongoDB disconnected")

    @classmethod
    def collection(cls, name: str):
        return cls.get_db()[name]


# ── Collection Accessors ──────────────────────────────────────────────────────
def get_sources_collection():
    return MongoDB.collection("sources")

def get_articles_collection():
    return MongoDB.collection("articles")

def get_incidents_collection():
    return MongoDB.collection("incidents")

def get_evidence_collection():
    return MongoDB.collection("evidence")

def get_alert_dispatches_collection():
    return MongoDB.collection("alert_dispatches")

def get_reports_collection():
    return MongoDB.collection("reports")

def get_cluster_rules_collection():
    return MongoDB.collection("cluster_rules")

def get_kev_collection():
    return MongoDB.collection("cisa_kev")

def get_threat_actors_collection():
    return MongoDB.collection("threat_actors")

def get_malware_collection():
    return MongoDB.collection("malware")

def get_events_collection():
    return MongoDB.collection("viral_news_events")

def get_campaigns_collection():
    return MongoDB.collection("campaigns")

def get_iocs_collection():
    return MongoDB.collection("iocs")

def get_users_collection():
    return MongoDB.collection("users")

def get_digests_collection():
    return MongoDB.collection("digests")

def get_logs_collection():
    return MongoDB.collection("logs")

def get_settings_collection():
    return MongoDB.collection("settings")

def get_viral_events_collection():
    """CyberPulse viral news events collection."""
    return MongoDB.collection("viral_news_events")

# ── Threat Actor Enrichment Collections ───────────────────────────────────────
def get_ta_aliases_collection():
    """Normalised alias index: {alias, canonical_name, actor_id, source, confidence}"""
    return MongoDB.collection("ta_aliases")

def get_vendor_reports_collection():
    """Vendor blog/RSS intelligence reports referencing threat actors."""
    return MongoDB.collection("ta_vendor_reports")

def get_ta_relationships_collection():
    """Directional entity relationships: actor→malware, actor→campaign, actor→actor."""
    return MongoDB.collection("ta_relationships")

def get_ta_references_collection():
    """Canonical URL reference store per threat actor."""
    return MongoDB.collection("ta_references")
