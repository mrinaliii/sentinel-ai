"""
Custom Exception Classes & Handlers
=====================================
Defines domain-specific exceptions and registers FastAPI exception handlers
that serialize errors into a consistent JSON envelope.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import ORJSONResponse

from app.core.logging import get_logger

logger = get_logger(__name__)


# ── Base exception ─────────────────────────────────────────────────────────────

class SentinelBaseException(Exception):
    """
    Base class for all Sentinel-AI application exceptions.

    Attributes:
        status_code: HTTP status code to return.
        error_code:  Machine-readable error code (e.g. "ALERT_NOT_FOUND").
        message:     Human-readable error message.
        details:     Optional extra context for debugging.
    """

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An unexpected error occurred.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


# ── Domain exceptions ─────────────────────────────────────────────────────────

class NotFoundError(SentinelBaseException):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "NOT_FOUND"

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"{resource} '{identifier}' not found.",
            details={"resource": resource, "identifier": identifier},
        )


class ValidationError(SentinelBaseException):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "VALIDATION_ERROR"


class AuthenticationError(SentinelBaseException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "AUTHENTICATION_FAILED"


class AuthorizationError(SentinelBaseException):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "AUTHORIZATION_FAILED"


class ElasticsearchError(SentinelBaseException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "ELASTICSEARCH_ERROR"

    def __init__(self, operation: str, cause: str) -> None:
        super().__init__(
            message=f"Elasticsearch operation '{operation}' failed.",
            details={"operation": operation, "cause": cause},
        )


class LLMError(SentinelBaseException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "LLM_ERROR"

    def __init__(self, model: str, cause: str) -> None:
        super().__init__(
            message=f"LLM model '{model}' returned an error.",
            details={"model": model, "cause": cause},
        )


class IngestionError(SentinelBaseException):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "INGESTION_ERROR"


class RateLimitError(SentinelBaseException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    error_code = "RATE_LIMIT_EXCEEDED"

    def __init__(self, retry_after: int = 60) -> None:
        super().__init__(
            message="Rate limit exceeded. Please slow down.",
            details={"retry_after_seconds": retry_after},
        )


# ── Error response serializer ─────────────────────────────────────────────────

def _error_envelope(
    status_code: int,
    error_code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> ORJSONResponse:
    """Build a consistent JSON error envelope."""
    return ORJSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {
                "code": error_code,
                "message": message,
                "details": details or {},
            },
            "request_id": request_id,
        },
    )


# ── Handler registration ──────────────────────────────────────────────────────

def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers on the FastAPI app."""

    @app.exception_handler(SentinelBaseException)
    async def sentinel_exception_handler(
        request: Request, exc: SentinelBaseException
    ) -> ORJSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.error(
            "application_error",
            error_code=exc.error_code,
            message=exc.message,
            status_code=exc.status_code,
            path=request.url.path,
            request_id=request_id,
        )
        return _error_envelope(
            exc.status_code, exc.error_code, exc.message, exc.details, request_id
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> ORJSONResponse:
        request_id = getattr(request.state, "request_id", None)
        errors = [
            {
                "field": " → ".join(str(loc) for loc in e["loc"]),
                "message": e["msg"],
                "type": e["type"],
            }
            for e in exc.errors()
        ]
        logger.warning(
            "request_validation_failed",
            errors=errors,
            path=request.url.path,
            request_id=request_id,
        )
        return _error_envelope(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Request validation failed.",
            {"errors": errors},
            request_id,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> ORJSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "unhandled_exception",
            exc_type=type(exc).__name__,
            path=request.url.path,
            request_id=request_id,
        )
        return _error_envelope(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An unexpected internal error occurred.",
            request_id=request_id,
        )
