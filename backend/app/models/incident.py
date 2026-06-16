"""
Incident Pydantic Models
=========================
Domain models for incident creation, management, and reporting.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentCreate(BaseModel):
    """Schema for creating a new incident."""
    title: str = Field(..., min_length=5, max_length=500)
    description: str = Field(..., min_length=10, max_length=20_000)
    severity: IncidentSeverity
    alert_ids: List[str] = Field(..., min_length=1, description="Alert IDs to link to incident")
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    """Schema for updating incident fields."""
    title: Optional[str] = Field(None, min_length=5, max_length=500)
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class TimelineEntry(BaseModel):
    """A single event in the incident forensic timeline."""
    timestamp: datetime
    event_type: str  # "alert", "action", "note", "status_change"
    actor: Optional[str] = None  # user_id or "system"
    description: str
    reference_id: Optional[str] = None  # alert_id or action_id


class IncidentResponse(BaseModel):
    """Complete incident document returned by the API."""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    alert_ids: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    created_by: str
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    timeline: List[TimelineEntry] = Field(default_factory=list)
    resolution_notes: Optional[str] = None
    report_id: Optional[str] = None

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    """Paginated incident list."""
    total: int
    page: int
    page_size: int
    items: List[IncidentResponse]
