"""
Incidents API Router  —  /api/v1/incidents
===========================================
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Query, status

from app.core.logging import get_logger
from app.core.security import AnalystRequired, TokenPayload, ViewerRequired
from app.models.common import SuccessResponse
from app.models.incident import (
    IncidentCreate,
    IncidentListResponse,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdate,
)
from app.services.incident_service import IncidentService

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["Incidents"])


def get_incident_service() -> IncidentService:
    return IncidentService()


@router.post(
    "/",
    response_model=SuccessResponse[IncidentResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new incident",
)
async def create_incident(
    payload: IncidentCreate,
    token: TokenPayload = AnalystRequired,
    svc: IncidentService = Depends(get_incident_service),
) -> SuccessResponse[IncidentResponse]:
    incident = await svc.create_incident(payload, created_by=token.user_id)
    logger.info("incident_created", incident_id=incident.id, user_id=token.user_id)
    return SuccessResponse(data=incident, message="Incident created successfully.")


@router.get(
    "/",
    response_model=SuccessResponse[IncidentListResponse],
    summary="List incidents",
)
async def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: Optional[IncidentStatus] = Query(default=None, alias="status"),
    assigned_to: Optional[str] = Query(default=None),
    token: TokenPayload = ViewerRequired,
    svc: IncidentService = Depends(get_incident_service),
) -> SuccessResponse[IncidentListResponse]:
    result = await svc.list_incidents(
        page=page, page_size=page_size,
        status_filter=status_filter, assigned_to=assigned_to,
    )
    return SuccessResponse(data=result)


@router.get(
    "/{incident_id}",
    response_model=SuccessResponse[IncidentResponse],
    summary="Get incident details",
)
async def get_incident(
    incident_id: str = Path(...),
    token: TokenPayload = ViewerRequired,
    svc: IncidentService = Depends(get_incident_service),
) -> SuccessResponse[IncidentResponse]:
    incident = await svc.get_incident(incident_id)
    return SuccessResponse(data=incident)


@router.patch(
    "/{incident_id}",
    response_model=SuccessResponse[IncidentResponse],
    summary="Update incident",
)
async def update_incident(
    payload: IncidentUpdate,
    incident_id: str = Path(...),
    token: TokenPayload = AnalystRequired,
    svc: IncidentService = Depends(get_incident_service),
) -> SuccessResponse[IncidentResponse]:
    incident = await svc.update_incident(
        incident_id=incident_id, update=payload, updated_by=token.user_id
    )
    return SuccessResponse(data=incident, message="Incident updated.")


@router.post(
    "/{incident_id}/report",
    response_model=SuccessResponse[dict],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate AI incident report",
    description="Triggers the LangChain report generation chain for this incident.",
)
async def generate_report(
    incident_id: str = Path(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    token: TokenPayload = AnalystRequired,
    svc: IncidentService = Depends(get_incident_service),
) -> SuccessResponse[dict]:
    background_tasks.add_task(
        svc.generate_report, incident_id=incident_id, requested_by=token.user_id
    )
    logger.info("report_generation_triggered", incident_id=incident_id, user_id=token.user_id)
    return SuccessResponse(
        data={"incident_id": incident_id},
        message="Report generation started. Check /api/v1/reports for progress.",
    )
