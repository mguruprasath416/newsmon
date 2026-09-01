from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SourceGrowthPoint(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    source_count: int = 0
    article_count: int = 0
    heat_score: int = 0


class ViralNewsEventDB(BaseModel):
    event_id: str
    title: str
    normalized_title: str
    summary: str
    explanation: str

    # Relationships
    related_article_ids: List[str] = []
    unique_source_ids: List[str] = []
    unique_source_names: List[str] = []
    source_count: int = 0
    article_count: int = 0

    # Heat & Scores (0-100)
    heat_score: int = 0
    coverage_score: float = 0.0
    velocity_score: float = 0.0
    recency_score: float = 0.0
    trend: str = "increasing"  # "increasing" | "stable" | "decreasing"

    # Status & Categorization
    priority: str = "medium"   # "medium" | "high" | "critical"
    status: str = "trending"   # "emerging" | "trending" | "high_heat"
    target_company: Optional[str] = None
    target_country: Optional[str] = None
    incident_type: Optional[str] = None
    cves: List[str] = []
    threat_actors: List[str] = []

    # Timeline
    first_detected_at: datetime = Field(default_factory=utcnow)
    last_detected_at: datetime = Field(default_factory=utcnow)
    source_growth_history: List[Dict[str, Any]] = []

    # Alert State
    alert_triggered: bool = False
    alert_triggered_at: Optional[datetime] = None
    alert_channel: Optional[str] = None

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
