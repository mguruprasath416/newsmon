"""
ClarityTI Threat Intelligence Domain Models
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


def utcnow():
    return datetime.now(timezone.utc)


# ── Threat Actor ──────────────────────────────────────────────────────────────

class AliasMeta(BaseModel):
    """A single known alias with provenance."""
    alias: str
    source: str  # mitre | misp | microsoft | crowdstrike | ...
    confidence: float = 1.0
    added_at: datetime = Field(default_factory=utcnow)


class MitreTechnique(BaseModel):
    technique_id: str           # T1566
    technique_name: str
    tactic: str                 # initial-access
    sub_technique_id: Optional[str] = None
    url: Optional[str] = None


class VendorReport(BaseModel):
    """A vendor intelligence report referencing this actor."""
    title: str
    url: str
    source: str                 # microsoft | crowdstrike | talos | ...
    published_at: Optional[datetime] = None
    summary: Optional[str] = None
    threat_actor_names: List[str] = []
    cves: List[str] = []
    iocs: Dict[str, List[str]] = {}
    added_at: datetime = Field(default_factory=utcnow)


class RelationshipRecord(BaseModel):
    """Directional relationship between two entities."""
    source_id: str              # ObjectId of actor/malware/campaign
    source_type: str            # threat_actor | malware | campaign
    target_id: str
    target_type: str
    relationship: str           # uses | attributed_to | part_of | targets
    confidence: float = 0.8
    source: str = "manual"
    created_at: datetime = Field(default_factory=utcnow)


class ThreatActorCreate(BaseModel):
    name: str
    aliases: List[str] = []
    type: str = "unknown"       # apt | ransomware-group | hacktivist | criminal | nation-state | unknown
    origin_country: Optional[str] = None
    motivation: List[str] = []
    sophistication: str = "unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: Optional[str] = None
    mitre_group_id: Optional[str] = None
    targeted_sectors: List[str] = []
    targeted_countries: List[str] = []
    references: List[str] = []
    tlp_level: str = "white"


class ThreatActorDB(ThreatActorCreate):
    """Full threat actor document as stored in MongoDB."""
    id: Optional[str] = None

    # Canonical identity
    canonical_name: Optional[str] = None
    slug: Optional[str] = None

    # Enriched aliases with provenance
    alias_records: List[AliasMeta] = []

    # Activity
    active_status: str = "active"      # active | inactive | disrupted | unknown
    campaigns: List[str] = []
    malware_used: List[str] = []
    tools: List[str] = []
    ttps: List[MitreTechnique] = []
    infrastructure: Dict[str, Any] = {}
    related_actors: List[str] = []
    cves: List[str] = []

    # Targeting
    industries: List[str] = []         # alias for targeted_sectors (normalised field)
    countries: List[str] = []          # alias for targeted_countries (normalised field)

    # Provenance
    sources: List[str] = []            # which sources contributed data
    source_ids: Dict[str, str] = {}    # {mitre: "G0007", misp: "..."}
    vendor_report_ids: List[str] = []

    # Scoring
    article_count: int = 0
    report_count: int = 0
    confidence_score: float = 0.5
    confidence: float = 0.8            # keep legacy field

    # AI-generated summary
    ai_summary: Optional[str] = None
    ai_summary_generated_at: Optional[datetime] = None

    # Timestamps
    last_enriched_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ThreatActorFull(ThreatActorDB):
    """Response model including resolved relations."""
    campaign_docs: List[Dict[str, Any]] = []
    malware_docs: List[Dict[str, Any]] = []
    vendor_reports: List[VendorReport] = []
    relationship_docs: List[RelationshipRecord] = []


# ── Malware ───────────────────────────────────────────────────────────────────

class MalwareCreate(BaseModel):
    name: str
    aliases: List[str] = []
    family: Optional[str] = None
    type: str = "unknown"       # ransomware | trojan | backdoor | rat | loader | stealer | wiper
    description: Optional[str] = None
    capabilities: List[str] = []
    platforms: List[str] = ["Windows"]
    programming_language: Optional[str] = None
    c2_protocols: List[str] = []
    mitre_software_id: Optional[str] = None
    references: List[str] = []


class MalwareDB(MalwareCreate):
    id: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    active_status: str = "active"
    obfuscation_techniques: List[str] = []
    persistence_mechanisms: List[str] = []
    encryption_algorithms: List[str] = []
    ttps: List[str] = []
    iocs: Dict[str, List[str]] = {}
    yara_rules: List[str] = []
    sigma_rules: List[str] = []
    detection_names: Dict[str, str] = {}
    threat_actors: List[str] = []
    campaigns: List[str] = []
    article_count: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ── Campaign ──────────────────────────────────────────────────────────────────

class CampaignTimelineEvent(BaseModel):
    date: Optional[datetime] = None
    event: str
    source: Optional[str] = None


class CampaignCreate(BaseModel):
    name: str
    aliases: List[str] = []
    description: Optional[str] = None
    objective: Optional[str] = None
    targeted_sectors: List[str] = []
    targeted_countries: List[str] = []
    references: List[str] = []


class CampaignDB(CampaignCreate):
    id: Optional[str] = None
    threat_actors: List[str] = []
    malware_used: List[str] = []
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    active_status: str = "active"
    ttps: List[str] = []
    cves_exploited: List[str] = []
    iocs: Dict[str, List[str]] = {}
    timeline: List[CampaignTimelineEvent] = []
    related_campaigns: List[str] = []
    article_count: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# ── CISA KEV ──────────────────────────────────────────────────────────────────

class KEVEntry(BaseModel):
    id: Optional[str] = None
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    description: Optional[str] = None
    date_added: Optional[datetime] = None
    due_date: Optional[datetime] = None
    required_action: Optional[str] = None
    known_ransomware: bool = False
    notes: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[datetime] = None
    references: List[str] = []
    patch_url: Optional[str] = None
    nvd_url: Optional[str] = None
    synced_at: datetime = Field(default_factory=utcnow)
    threat_actors: List[str] = []
    campaigns: List[str] = []


# ── Digest ────────────────────────────────────────────────────────────────────

class DigestHighlight(BaseModel):
    title: str
    summary: str
    severity: str = "high"
    source: Optional[str] = None
    url: Optional[str] = None


class DigestContent(BaseModel):
    headline: str
    todays_highlights: str
    critical_threats: List[DigestHighlight] = []
    top_cves: List[Dict[str, Any]] = []
    top_ransomware: List[Dict[str, Any]] = []
    apt_activity: List[Dict[str, Any]] = []
    major_breaches: List[Dict[str, Any]] = []
    trending_vendors: List[str] = []
    trending_threat_actors: List[str] = []
    trending_malware: List[str] = []
    analyst_note: Optional[str] = None


class DigestDB(BaseModel):
    id: Optional[str] = None
    period_start: datetime
    period_end: datetime
    generated_at: datetime = Field(default_factory=utcnow)
    generation_time_ms: int = 0
    article_count_analyzed: int = 0
    ai_model: str = "gpt-4.1"
    digest: Optional[DigestContent] = None
    article_ids: List[str] = []
    sent_at: Optional[datetime] = None
    sent_to: List[str] = []
