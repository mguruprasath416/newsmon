"""
ClarityTI / NewsMon — Incident, Evidence, and Alert Dispatch Data Models
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceRecord(BaseModel):
    """Stores verified evidence with provenance."""
    evidence_id: Optional[str] = None
    source_name: str
    source_type: str  # official_company | regulator | law_enforcement | cert | security_vendor | reputable_media | threat_actor | social_media | unknown
    claim_text: str
    evidence_type: str  # official_statement | regulatory_filing | technical_forensics | leak_site_post | stolen_data_sample | screenshots | reputable_media_reporting
    evidence_score: int = Field(default=1, ge=0, le=5)
    confidence: Literal["high", "medium", "low"] = "low"
    article_id: Optional[str] = None
    incident_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)


class IncidentDB(BaseModel):
    """First-class CTI Incident Entity Object stored in MongoDB."""
    id: Optional[str] = None
    incident_id: str  # Stable canonical fingerprint ID
    title: str
    incident_type: str  # data_breach | data_theft | ransomware | company_compromise | critical_infrastructure | major_cyberattack | service_disruption | extortion_leak
    target_organization: str
    target_country: Optional[str] = None
    sector: Optional[str] = None
    threat_actor: str = "Unattributed"
    claim_status: Literal["claimed", "confirmed", "denied"] = "claimed"
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    claimed_records_count: Optional[int] = None
    attack_vector: Optional[str] = None
    company_response: Optional[str] = None
    first_reported_at: datetime = Field(default_factory=utcnow)
    last_updated_at: datetime = Field(default_factory=utcnow)
    source_count: int = 1
    article_ids: List[str] = []
    evidence_ids: List[str] = []
    status: Literal["active", "contained", "resolved", "disputed"] = "active"
    status_history: List[Dict[str, Any]] = []
    material_updates: List[Dict[str, Any]] = []
    teams_dispatched: bool = False
    dispatched_channels: List[str] = []


class AlertDispatchDB(BaseModel):
    """Audit trail for every dispatched Microsoft Teams alert card."""
    id: Optional[str] = None
    alert_id: str
    incident_id: str
    article_id: Optional[str] = None
    channel: str  # #high-priority-news | #indian-breaches | #middle-east-companies
    webhook_key: str
    fingerprint: str
    dispatched_at: datetime = Field(default_factory=utcnow)
    status: Literal["sent", "failed", "retrying"] = "sent"
    alert_version: int = 1
    update_type: Optional[str] = None
    reason: Optional[str] = None
    payload_snapshot: Dict[str, Any] = {}
