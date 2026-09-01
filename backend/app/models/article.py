from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from bson import ObjectId


class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, str):
            return v
        raise ValueError("Invalid ObjectId")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Article Models ────────────────────────────────────────────────────────────

class MITRETechniqueModel(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    confidence: float = 0.7

class ArticleIOCs(BaseModel):
    ipv4: List[str] = []
    ipv6: List[str] = []
    cidr: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    emails: List[str] = []
    sha256: List[str] = []
    sha1: List[str] = []
    md5: List[str] = []
    filenames: List[str] = []
    registry_keys: List[str] = []
    mutex: List[str] = []
    user_agents: List[str] = []
    cves: List[str] = []

class AnalystNote(BaseModel):
    user_id: str
    note: str
    created_at: datetime = Field(default_factory=utcnow)

class ArticleCreate(BaseModel):
    source_id: str
    source_name: str
    source_category: str
    source_slug: str
    url: str
    url_hash: str
    title: str
    summary: Optional[str] = None
    content_raw: Optional[str] = None
    content_clean: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    language: str = "en"
    tags: List[str] = []

class ArticleDB(BaseModel):
    id: Optional[str] = None
    source_id: str
    source_name: str
    source_category: str
    source_slug: str
    url: str
    url_hash: str
    title: str
    summary: Optional[str] = None
    content_raw: Optional[str] = None
    content_clean: Optional[str] = None
    content_markdown: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    crawled_at: datetime = Field(default_factory=utcnow)
    enriched_at: Optional[datetime] = None
    language: str = "en"
    word_count: int = 0
    severity: str = "informational"
    severity_score: float = 0.0
    tags: List[str] = []
    tlp_level: str = "white"
    threat_actors: List[str] = []
    malware_families: List[str] = []
    campaigns: List[str] = []
    cves: List[str] = []
    mitre_techniques: List[MITRETechniqueModel] = []
    iocs: ArticleIOCs = Field(default_factory=ArticleIOCs)
    ioc_count: int = 0
    enrichment_status: str = "pending"
    ai_summary: Optional[str] = None
    ai_confidence: float = 0.0
    is_duplicate: bool = False
    # New Schema Fields
    claim_status: str = "claimed"  # claimed | confirmed | denied
    claimed_records_count: Optional[int] = None
    attack_vector: Optional[str] = None
    company_response: Optional[str] = None
    target_country: Optional[str] = None
    duplicate_of: Optional[str] = None
    similarity_score: Optional[float] = None
    embedding_vector: Optional[List[float]] = None
    embedding_model: Optional[str] = None
    rerank_score: Optional[float] = None
    ai_summary_model: Optional[str] = None
    ai_summary_generated_at: Optional[datetime] = None

    bookmarked_by: List[str] = []
    analyst_notes: List[AnalystNote] = []
    view_count: int = 0
    report_generated: bool = False
    report_id: Optional[str] = None


class RawArticle(BaseModel):
    url: str
    title: str
    content: str = ""
    summary: str = ""
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}


class EnrichedArticle(RawArticle):
    claim_status: str = "claimed"
    claimed_records_count: Optional[int] = None
    attack_vector: Optional[str] = None
    company_response: Optional[str] = None
    target_country: Optional[str] = None
    duplicate_of: Optional[str] = None
    similarity_score: Optional[float] = None
    embedding_vector: Optional[List[float]] = None
    embedding_model: Optional[str] = None
    rerank_score: Optional[float] = None
    ai_summary_model: Optional[str] = None
    ai_summary_generated_at: Optional[datetime] = None


class ArticleResponse(BaseModel):
    id: str
    source_name: str
    source_category: str
    source_slug: str
    url: str
    title: str
    summary: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    crawled_at: datetime
    language: str = "en"
    severity: str = "informational"
    tags: List[str] = []
    tlp_level: str = "white"
    threat_actors: List[str] = []
    malware_families: List[str] = []
    cves: List[str] = []
    mitre_techniques: List[MITRETechniqueModel] = []
    iocs: ArticleIOCs
    ioc_count: int = 0
    enrichment_status: str
    ai_summary: Optional[str] = None
    claim_status: str = "claimed"
    claimed_records_count: Optional[int] = None
    attack_vector: Optional[str] = None
    company_response: Optional[str] = None
    target_country: Optional[str] = None
    duplicate_of: Optional[str] = None
    similarity_score: Optional[float] = None
    embedding_model: Optional[str] = None
    rerank_score: Optional[float] = None
    view_count: int = 0
    is_bookmarked: bool = False


# ── Source Models ─────────────────────────────────────────────────────────────

class SourceCreate(BaseModel):
    name: str
    slug: str
    category: str  # vendor | news | cert
    subcategory: Optional[str] = None
    base_url: str
    rss_url: Optional[str] = None
    logo_url: Optional[str] = None
    collection_method: str = "rss"
    schedule_cron: str = "*/30 * * * *"
    rate_limit_rpm: int = 10
    priority: int = 2
    tags: List[str] = []
    language: str = "en"
    require_js: bool = False

class SourceDB(SourceCreate):
    id: Optional[str] = None
    is_active: bool = True
    article_count: int = 0
    last_crawled_at: Optional[datetime] = None
    last_article_at: Optional[datetime] = None
    health_status: str = "healthy"  # healthy | degraded | failing
    last_error_reason: Optional[str] = None  # RATE_LIMITED_429 | FORBIDDEN_403 | NOT_FOUND_404 | DNS_CONNECT_TIMEOUT | PARSE_ERROR | SSL_CERT_ERROR
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ── IOC Models ────────────────────────────────────────────────────────────────

class IOCCreate(BaseModel):
    type: str
    value: str
    value_raw: str
    confidence: float = 0.9
    tlp_level: str = "white"
    threat_actors: List[str] = []
    malware_families: List[str] = []
    campaigns: List[str] = []
    tags: List[str] = []
    source_articles: List[str] = []
    source_reports: List[str] = []

class IOCDB(IOCCreate):
    id: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    is_active: bool = True
    false_positive: bool = False
    enrichment: Dict[str, Any] = {}
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ── Pagination ────────────────────────────────────────────────────────────────

class PaginationMeta(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    has_next: bool
    has_prev: bool

class PaginatedResponse(BaseModel):
    data: List[Any]
    meta: PaginationMeta
