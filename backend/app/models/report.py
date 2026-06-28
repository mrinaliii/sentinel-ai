"""
Report Generation Pydantic Models
===================================
Input / output schemas for the incident report generation pipeline.

Models
------
ReportFormat       – Enum: markdown | pdf | both
IOCSummary         – A single IOC row for the report table
TimelineEvent      – A forensic timeline entry
ReportRequest      – Full input to the generator (alert analysis + MITRE + notes)
ReportResult       – Output: report_id, paths, markdown content, metadata
ReportMetadata     – Lightweight status record for the GET /reports/{id} endpoint
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    PDF = "pdf"
    BOTH = "both"


class ReportSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ---------------------------------------------------------------------------
# Sub-models (used within ReportRequest)
# ---------------------------------------------------------------------------


class MitreMatchInput(BaseModel):
    """
    A single MITRE ATT&CK technique match.
    Mirrors ``TechniqueMatch`` from mitre_mapper.py so callers can pass
    ``.model_dump()`` directly.
    """

    technique_id: str = Field(..., description="e.g. 'T1059'")
    technique_name: str
    tactic: str
    tactic_id: str
    sub_technique: Optional[str] = None
    sub_technique_id: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    mapping_method: str
    rationale: Optional[str] = None


class AlertAnalysisInput(BaseModel):
    """
    LLM / heuristic analysis output.
    Mirrors ``AlertAnalysis`` from llm_analyzer.py.
    """

    summary: str
    risk_assessment: str
    investigation_steps: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class IOCSummary(BaseModel):
    """An Indicator of Compromise row for the report IOC table."""

    value: str
    ioc_type: str = Field(..., description="ip | domain | hash | url | email")
    malicious: Optional[bool] = None
    reputation_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """A single entry in the incident forensic timeline."""

    timestamp: datetime
    event_type: str = Field(
        ..., description="alert | action | note | status_change | detection"
    )
    description: str
    actor: Optional[str] = None
    reference_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Primary Input Model
# ---------------------------------------------------------------------------


class ReportRequest(BaseModel):
    """
    Full input payload to ``IncidentReportGenerator.generate_report()``.

    Collects all data needed to produce a professional SOC incident report.
    """

    # ── Incident metadata ────────────────────────────────────────────────
    incident_id: str = Field(..., description="Incident or case reference ID")
    title: str = Field(..., min_length=5, max_length=500)
    severity: ReportSeverity = ReportSeverity.MEDIUM
    status: str = Field(default="Investigating")

    # Who is doing this?
    analyst_name: str = Field(default="SOC Analyst")
    analyst_email: Optional[str] = None
    organization: str = Field(default="Security Operations Center")

    # Timestamps
    detected_at: Optional[datetime] = None
    reported_at: datetime = Field(default_factory=datetime.utcnow)

    # Affected assets
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    source_system: Optional[str] = None

    # ── Core intelligence inputs ──────────────────────────────────────────
    alert_analysis: AlertAnalysisInput = Field(
        ..., description="Output of AlertAnalyzer.analyze()"
    )
    mitre_matches: List[MitreMatchInput] = Field(
        default_factory=list,
        description="Output of MitreMapper.map_alert().matches",
    )

    # ── Analyst inputs ────────────────────────────────────────────────────
    investigation_notes: str = Field(
        default="",
        max_length=50_000,
        description="Free-form investigation notes written by the analyst",
    )
    iocs: List[IOCSummary] = Field(
        default_factory=list, description="Observed indicators of compromise"
    )
    timeline: List[TimelineEvent] = Field(
        default_factory=list, description="Forensic timeline of events"
    )

    # ── Optional context ─────────────────────────────────────────────────
    tags: List[str] = Field(default_factory=list)
    raw_alert_metadata: Optional[Dict[str, Any]] = Field(
        None, description="Raw alert dict for appendix section"
    )
    classification: Optional[str] = Field(
        None, description="Short threat classification, e.g. 'Ransomware / Lateral Movement'"
    )

    # ── Output preferences ───────────────────────────────────────────────
    format: ReportFormat = ReportFormat.BOTH
    include_appendix: bool = True


# ---------------------------------------------------------------------------
# Output Models
# ---------------------------------------------------------------------------


class ReportResult(BaseModel):
    """
    Result returned by ``IncidentReportGenerator.generate_report()``.
    """

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    title: str
    severity: ReportSeverity
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str

    # Content
    markdown_content: str = Field(..., description="Full report in Markdown")
    pdf_path: Optional[str] = Field(
        None, description="Absolute path to generated PDF file on disk"
    )
    markdown_path: Optional[str] = Field(
        None, description="Absolute path to saved .md file"
    )

    # Stats
    word_count: int = 0
    mitre_technique_count: int = 0
    ioc_count: int = 0
    has_pdf: bool = False

    model_config = {"from_attributes": True}


class ReportMetadata(BaseModel):
    """
    Lightweight record returned by GET /reports/{report_id}.
    Does not include the full markdown content to keep responses small.
    """

    report_id: str
    incident_id: str
    title: str
    severity: ReportSeverity
    generated_at: datetime
    generated_by: str
    has_pdf: bool
    pdf_path: Optional[str] = None
    markdown_path: Optional[str] = None
    word_count: int = 0
    mitre_technique_count: int = 0
    ioc_count: int = 0

    model_config = {"from_attributes": True}
