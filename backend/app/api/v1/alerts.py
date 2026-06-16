"""
Alerts API Router  —  /api/v1/alerts
======================================
Handles alert ingestion, retrieval, triage triggering, and status management.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Query, status
from fastapi.responses import ORJSONResponse

from app.core.logging import get_logger
from app.core.security import AnalystRequired, TokenPayload, ViewerRequired
from app.models.alert import (
    AlertIngest,
    AlertListResponse,
    AlertResponse,
    AlertSource,
    AlertStatus,
    AlertStatusUpdate,
    Severity,
)
from app.models.common import SuccessResponse
from app.services.alert_service import AlertService

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["Alerts"])

# ── Dependency: alert service ─────────────────────────────────────────────────

def get_alert_service() -> AlertService:
    return AlertService()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/ingest",
    response_model=SuccessResponse[AlertResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a new security alert",
    description=(
        "Accepts a raw security event, indexes it in Elasticsearch, and "
        "triggers the async enrichment + triage pipeline in the background."
    ),
)
async def ingest_alert(
    payload: AlertIngest,
    background_tasks: BackgroundTasks,
    token: TokenPayload = AnalystRequired,
    svc: AlertService = Depends(get_alert_service),
) -> SuccessResponse[AlertResponse]:
    logger.info(
        "alert_ingest_requested",
        source=payload.source,
        user_id=token.user_id,
    )
    alert = await svc.create_alert(payload, created_by=token.user_id)
    background_tasks.add_task(svc.run_enrichment_pipeline, alert.id)
    return SuccessResponse(
        data=alert,
        message="Alert ingested. Enrichment pipeline started.",
    )


@router.get(
    "/",
    response_model=SuccessResponse[AlertListResponse],
    summary="List alerts",
    description="Paginated, filterable list of security alerts.",
)
async def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status: Optional[AlertStatus] = Query(default=None),
    severity: Optional[Severity] = Query(default=None),
    source: Optional[AlertSource] = Query(default=None),
    search: Optional[str] = Query(default=None, description="Full-text search term"),
    token: TokenPayload = ViewerRequired,
    svc: AlertService = Depends(get_alert_service),
) -> SuccessResponse[AlertListResponse]:
    result = await svc.list_alerts(
        page=page,
        page_size=page_size,
        status_filter=status,
        severity_filter=severity,
        source_filter=source,
        search=search,
    )
    return SuccessResponse(data=result)


@router.get(
    "/{alert_id}",
    response_model=SuccessResponse[AlertResponse],
    summary="Get alert by ID",
)
async def get_alert(
    alert_id: str = Path(..., description="Elasticsearch document ID"),
    token: TokenPayload = ViewerRequired,
    svc: AlertService = Depends(get_alert_service),
) -> SuccessResponse[AlertResponse]:
    alert = await svc.get_alert(alert_id)
    return SuccessResponse(data=alert)


@router.post(
    "/{alert_id}/triage",
    response_model=SuccessResponse[AlertResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger AI triage for an alert",
    description=(
        "Manually triggers the LangChain triage agent for the specified alert. "
        "Useful for re-triaging after analyst feedback or enrichment updates."
    ),
)
async def trigger_triage(
    alert_id: str = Path(..., description="Alert ID to triage"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    token: TokenPayload = AnalystRequired,
    svc: AlertService = Depends(get_alert_service),
) -> SuccessResponse[AlertResponse]:
    alert = await svc.get_alert(alert_id)
    background_tasks.add_task(svc.run_triage, alert_id, triggered_by=token.user_id)
    logger.info("triage_manually_triggered", alert_id=alert_id, user_id=token.user_id)
    return SuccessResponse(
        data=alert,
        message="Triage pipeline triggered. Results will appear shortly.",
    )


@router.put(
    "/{alert_id}/status",
    response_model=SuccessResponse[AlertResponse],
    summary="Update alert status",
)
async def update_alert_status(
    payload: AlertStatusUpdate,
    alert_id: str = Path(...),
    token: TokenPayload = AnalystRequired,
    svc: AlertService = Depends(get_alert_service),
) -> SuccessResponse[AlertResponse]:
    alert = await svc.update_status(
        alert_id=alert_id,
        new_status=payload.status,
        comment=payload.comment,
        updated_by=token.user_id,
    )
    logger.info(
        "alert_status_updated",
        alert_id=alert_id,
        new_status=payload.status,
        user_id=token.user_id,
    )
    return SuccessResponse(data=alert, message=f"Alert status updated to {payload.status.value}.")


@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an alert",
    description="Permanently removes an alert. Restricted to admin role.",
)
async def delete_alert(
    alert_id: str = Path(...),
    token: TokenPayload = AnalystRequired,
    svc: AlertService = Depends(get_alert_service),
) -> None:
    await svc.delete_alert(alert_id)
    logger.info("alert_deleted", alert_id=alert_id, user_id=token.user_id)
