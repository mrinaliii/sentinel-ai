"""
Common / Shared Pydantic Models
================================
Generic response envelopes, pagination, and health check schemas
used across all API endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


# ── Success response envelope ─────────────────────────────────────────────────

class SuccessResponse(BaseModel, Generic[T]):
    """
    Standard success envelope wrapping any data payload.

    Usage:
        return SuccessResponse[AlertResponse](data=alert, message="Alert retrieved")
    """
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None
    request_id: Optional[str] = None


class PaginationMeta(BaseModel):
    """Pagination metadata included in list responses."""
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool

    @classmethod
    def from_count(cls, total: int, page: int, page_size: int) -> "PaginationMeta":
        total_pages = max(1, -(-total // page_size))  # ceil division
        return cls(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        )


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated list response with metadata."""
    success: bool = True
    items: List[T]
    pagination: PaginationMeta
    request_id: Optional[str] = None


# ── Health check models ────────────────────────────────────────────────────────

class ServiceStatus(str):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class DependencyHealth(BaseModel):
    """Health status of a single external dependency."""
    name: str
    status: str  # "healthy" | "degraded" | "unhealthy"
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    version: Optional[str] = None


class HealthResponse(BaseModel):
    """Overall application health response."""
    status: str  # "healthy" | "degraded" | "unhealthy"
    version: str
    environment: str
    uptime_seconds: float
    dependencies: List[DependencyHealth] = Field(default_factory=list)
    timestamp: str  # ISO8601


# ── Query models ──────────────────────────────────────────────────────────────

class NaturalLanguageQuery(BaseModel):
    """Request to translate a natural language query to ES DSL."""
    query: str = Field(
        ...,
        min_length=5,
        max_length=2000,
        description="Natural language security query",
        examples=["Show PowerShell executions from service accounts in the last 6 hours"],
    )
    time_range_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="Time window to search in hours",
    )
    max_results: int = Field(default=50, ge=1, le=500)


class NLQueryResponse(BaseModel):
    """Result of a natural language SIEM query."""
    query_text: str
    generated_dsl: Dict[str, Any]
    result_count: int
    results: List[Dict[str, Any]]
    explanation: str = Field(..., description="Human-readable explanation of what was searched")


# ── Chat models ───────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    """A single message in the analyst copilot chat."""
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str = Field(..., min_length=1, max_length=32_000)


class ChatRequest(BaseModel):
    """Send a message to the analyst copilot."""
    session_id: Optional[str] = Field(None, description="Existing session ID for continuity")
    message: str = Field(..., min_length=1, max_length=10_000)
    alert_context_id: Optional[str] = Field(None, description="Alert ID to ground the conversation")
    incident_context_id: Optional[str] = Field(None, description="Incident ID for context")


class ChatResponse(BaseModel):
    """Response from the analyst copilot."""
    session_id: str
    message: str
    role: str = "assistant"
    citations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence references cited in the response",
    )
    suggested_queries: List[str] = Field(
        default_factory=list,
        description="Follow-up query suggestions",
    )
    tokens_used: Optional[int] = None
