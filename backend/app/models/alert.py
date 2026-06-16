"""
Alert Pydantic Models
======================
Domain models for security alert ingestion, enrichment, triage, and retrieval.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Alert severity classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(str, Enum):
    """Alert lifecycle status."""
    NEW = "new"
    TRIAGING = "triaging"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class AlertSource(str, Enum):
    """Source system that generated the alert."""
    FIREWALL = "firewall"
    IDS = "ids"
    IPS = "ips"
    EDR = "edr"
    SIEM = "siem"
    WAF = "waf"
    CLOUD = "cloud"
    AUTH = "auth"
    NETWORK = "network"
    CUSTOM = "custom"


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────

class MitreMapping(BaseModel):
    """A single MITRE ATT&CK TTP annotation on an alert."""
    tactic: str = Field(..., description="ATT&CK tactic name (e.g., 'Execution')")
    tactic_id: str = Field(..., description="ATT&CK tactic ID (e.g., 'TA0002')")
    technique: str = Field(..., description="Technique name")
    technique_id: str = Field(..., description="Technique ID (e.g., 'T1059')")
    sub_technique: Optional[str] = Field(None, description="Sub-technique name")
    sub_technique_id: Optional[str] = Field(None, description="Sub-technique ID (e.g., 'T1059.001')")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Mapping confidence score")
    mapping_method: str = Field(..., description="rule_based | semantic | llm_inferred")
    rationale: Optional[str] = Field(None, description="Explanation for the mapping")


# ── Enrichment Data ────────────────────────────────────────────────────────────

class EntityInfo(BaseModel):
    """Resolved entity metadata."""
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    is_privileged: bool = False
    asset_criticality: Optional[str] = None  # "critical" | "high" | "medium" | "low"


class IOCInfo(BaseModel):
    """Indicator of Compromise reputation data."""
    value: str
    ioc_type: str  # "ip" | "domain" | "hash" | "url"
    reputation_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    malicious: Optional[bool] = None
    sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class EnrichmentData(BaseModel):
    """Aggregated enrichment data attached to an alert."""
    entity: Optional[EntityInfo] = None
    iocs: List[IOCInfo] = Field(default_factory=list)
    correlated_event_count: int = 0
    baseline_deviation_score: Optional[float] = None
    pre_llm_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    enriched_at: Optional[datetime] = None


# ── AI Triage ─────────────────────────────────────────────────────────────────

class TriageResult(BaseModel):
    """LLM-generated triage assessment for an alert."""
    severity: Severity
    priority_rank: int = Field(..., ge=1, le=5, description="1=highest priority")
    false_positive_probability: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    classification: str = Field(..., description="Short threat classification label")
    summary: str = Field(..., description="Analyst-readable triage narrative")
    recommended_actions: List[str] = Field(default_factory=list)
    analyst_questions: List[str] = Field(default_factory=list)
    triaged_at: datetime = Field(default_factory=datetime.utcnow)
    model_used: str = "llama3"
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[float] = None


# ── Core Alert Models ─────────────────────────────────────────────────────────

class AlertIngest(BaseModel):
    """
    Schema for ingesting a raw alert event via POST /api/v1/alerts/ingest.
    This is the external-facing input model.
    """
    source: AlertSource
    source_alert_id: Optional[str] = Field(None, description="Original alert ID from source system")
    title: str = Field(..., min_length=3, max_length=500)
    description: str = Field(..., min_length=10, max_length=10_000)
    raw_severity: Optional[str] = Field(None, description="Severity as reported by source")
    source_timestamp: Optional[datetime] = Field(None, description="When the source generated the event")
    host: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    raw_event: Optional[Dict[str, Any]] = Field(None, description="Original raw event payload")

    @field_validator("title", "description", mode="before")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class AlertResponse(BaseModel):
    """Complete alert document as returned by the API."""
    id: str = Field(..., description="Elasticsearch document ID")
    source: AlertSource
    source_alert_id: Optional[str] = None
    title: str
    description: str
    status: AlertStatus = AlertStatus.NEW
    severity: Optional[Severity] = None
    source_timestamp: Optional[datetime] = None
    ingested_at: datetime
    host: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    enrichment: Optional[EnrichmentData] = None
    mitre_mappings: List[MitreMapping] = Field(default_factory=list)
    triage: Optional[TriageResult] = None
    incident_id: Optional[str] = None

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    """Paginated alert list response."""
    total: int
    page: int
    page_size: int
    items: List[AlertResponse]


class AlertStatusUpdate(BaseModel):
    """Payload for updating alert status."""
    status: AlertStatus
    comment: Optional[str] = Field(None, max_length=2000)
