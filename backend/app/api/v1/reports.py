"""
Reports API Router  —  /api/v1/reports
========================================
Endpoints for generating, retrieving, and downloading SOC incident reports.

Routes
------
POST   /reports/generate            Generate a new report (sync, returns full result)
GET    /reports/{report_id}         Get report metadata
GET    /reports/{report_id}/markdown  Return raw Markdown content
GET    /reports/{report_id}/download  Stream the PDF as application/pdf
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Path as FPath, Query, status
from fastapi.responses import PlainTextResponse, Response

from app.core.logging import get_logger
from app.core.security import AnalystRequired, TokenPayload, ViewerRequired
from app.models.common import SuccessResponse
from app.models.report import ReportFormat, ReportMetadata, ReportRequest, ReportResult
from app.services.report_generator import IncidentReportGenerator, get_generator

logger = get_logger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])


def _get_generator() -> IncidentReportGenerator:
    """Dependency that returns the module-level report generator singleton."""
    return get_generator()


# ---------------------------------------------------------------------------
# POST /reports/generate
# ---------------------------------------------------------------------------


@router.post(
    "/generate",
    response_model=SuccessResponse[ReportResult],
    status_code=status.HTTP_201_CREATED,
    summary="Generate a SOC incident report",
    description=(
        "Accepts alert analysis output, MITRE ATT&CK mappings, and investigation notes. "
        "Returns a complete report in Markdown and optionally generates a PDF on disk."
    ),
)
async def generate_report(
    payload: ReportRequest,
    token: TokenPayload = AnalystRequired,
    gen: IncidentReportGenerator = _get_generator(),
) -> SuccessResponse[ReportResult]:
    """
    Generate a professional SOC incident report synchronously.

    The result contains the full Markdown content in the response body.
    For PDF, call ``GET /reports/{report_id}/download`` after generation.
    """
    # Override analyst name from authenticated token if not explicitly set
    if payload.analyst_name == "SOC Analyst":
        payload = payload.model_copy(update={"analyst_name": token.user_id})

    result = gen.generate_report(payload)

    logger.info(
        "report_generated",
        report_id=result.report_id,
        incident_id=result.incident_id,
        has_pdf=result.has_pdf,
        words=result.word_count,
        user_id=token.user_id,
    )

    return SuccessResponse(
        data=result,
        message=(
            f"Report generated successfully. "
            f"{'PDF saved. ' if result.has_pdf else ''}"
            f"Word count: {result.word_count}."
        ),
    )


# ---------------------------------------------------------------------------
# GET /reports/{report_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{report_id}",
    response_model=SuccessResponse[ReportMetadata],
    summary="Get report metadata",
    description="Returns lightweight metadata for a previously generated report.",
)
async def get_report_metadata(
    report_id: str = FPath(..., description="UUID of the generated report"),
    token: TokenPayload = ViewerRequired,
    gen: IncidentReportGenerator = _get_generator(),
) -> SuccessResponse[ReportMetadata]:
    metadata = gen.get_report_metadata(report_id)
    if metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return SuccessResponse(data=metadata)


# ---------------------------------------------------------------------------
# GET /reports/{report_id}/markdown
# ---------------------------------------------------------------------------


@router.get(
    "/{report_id}/markdown",
    response_class=PlainTextResponse,
    summary="Download report as Markdown",
    description="Returns the raw Markdown content of a previously generated report.",
)
async def get_report_markdown(
    report_id: str = FPath(..., description="UUID of the generated report"),
    token: TokenPayload = ViewerRequired,
    gen: IncidentReportGenerator = _get_generator(),
) -> PlainTextResponse:
    md = gen.get_markdown(report_id)
    if md is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    filename = f"incident_report_{report_id[:8]}.md"
    return PlainTextResponse(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ---------------------------------------------------------------------------
# GET /reports/{report_id}/download
# ---------------------------------------------------------------------------


@router.get(
    "/{report_id}/download",
    summary="Download report as PDF",
    description=(
        "Streams the PDF version of a generated report. "
        "Returns 404 if PDF was not generated (e.g. format=markdown was requested)."
    ),
)
async def download_report_pdf(
    report_id: str = FPath(..., description="UUID of the generated report"),
    token: TokenPayload = ViewerRequired,
    gen: IncidentReportGenerator = _get_generator(),
) -> Response:
    pdf_bytes = gen.get_pdf_bytes(report_id)
    if pdf_bytes is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"PDF for report '{report_id}' not found. "
                "Ensure the report was generated with format='pdf' or format='both'."
            ),
        )
    filename = f"incident_report_{report_id[:8]}.pdf"
    logger.info(
        "report_pdf_downloaded",
        report_id=report_id,
        size_bytes=len(pdf_bytes),
        user_id=token.user_id,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
