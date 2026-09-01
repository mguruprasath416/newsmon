from elasticsearch import AsyncElasticsearch
from app.config import settings
import structlog

log = structlog.get_logger()

INDICES = {
    "articles": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_articles",
    "reports": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_reports",
    "threat_actors": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_threat_actors",
    "malware": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_malware",
    "campaigns": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_campaigns",
    "iocs": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_iocs",
    "kev": f"{settings.ELASTICSEARCH_INDEX_PREFIX}_kev",
}

ARTICLES_MAPPING = {
    "mappings": {
        "properties": {
            "title": {"type": "text", "analyzer": "english", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
            "summary": {"type": "text", "analyzer": "english"},
            "content_clean": {"type": "text", "analyzer": "english"},
            "ai_summary": {"type": "text", "analyzer": "english"},
            "author": {"type": "keyword"},
            "source_name": {"type": "keyword"},
            "source_category": {"type": "keyword"},
            "source_slug": {"type": "keyword"},
            "url": {"type": "keyword"},
            "published_at": {"type": "date"},
            "crawled_at": {"type": "date"},
            "severity": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "threat_actors": {"type": "keyword"},
            "malware_families": {"type": "keyword"},
            "cves": {"type": "keyword"},
            "ioc_count": {"type": "integer"},
            "tlp_level": {"type": "keyword"},
            "language": {"type": "keyword"},
            "mitre_techniques": {
                "type": "nested",
                "properties": {
                    "technique_id": {"type": "keyword"},
                    "technique_name": {"type": "text"},
                    "tactic": {"type": "keyword"},
                }
            },
        }
    },
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 0,
    }
}

KEV_MAPPING = {
    "mappings": {
        "properties": {
            "cve_id": {"type": "keyword"},
            "vendor": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "product": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "vulnerability_name": {"type": "text", "analyzer": "english"},
            "description": {"type": "text"},
            "date_added": {"type": "date"},
            "due_date": {"type": "date"},
            "cvss_v3_score": {"type": "float"},
            "epss_score": {"type": "float"},
            "epss_percentile": {"type": "float"},
            "known_ransomware": {"type": "boolean"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0}
}


class ElasticsearchClient:
    client: AsyncElasticsearch = None

    @classmethod
    async def connect(cls):
        cls.client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            retry_on_timeout=True,
            max_retries=3,
        )
        info = await cls.client.info()
        log.info("Elasticsearch connected", version=info["version"]["number"])

    @classmethod
    async def disconnect(cls):
        if cls.client:
            await cls.client.close()

    @classmethod
    def get_client(cls) -> AsyncElasticsearch:
        return cls.client

    @classmethod
    async def create_index(cls, index_name: str, mapping: dict):
        exists = await cls.client.indices.exists(index=index_name)
        if not exists:
            await cls.client.indices.create(index=index_name, body=mapping)
            log.info(f"Elasticsearch index created: {index_name}")

    @classmethod
    async def create_all_indexes(cls):
        await cls.create_index(INDICES["articles"], ARTICLES_MAPPING)
        await cls.create_index(INDICES["kev"], KEV_MAPPING)

    @classmethod
    async def index_document(cls, index_key: str, doc_id: str, document: dict):
        await cls.client.index(
            index=INDICES[index_key],
            id=doc_id,
            document=document,
        )

    @classmethod
    async def search(cls, index_key: str, query: dict) -> dict:
        return await cls.client.search(index=INDICES[index_key], body=query)

    @classmethod
    async def multi_search(cls, query: dict) -> dict:
        return await cls.client.search(
            index=",".join(INDICES.values()),
            body=query
        )
