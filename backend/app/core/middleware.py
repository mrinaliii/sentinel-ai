"""
Logging Middleware
==================
Starlette/FastAPI middleware that:
  - Assigns a unique X-Request-ID to every request
  - Logs structured request/response metadata
  - Records request duration in milliseconds
  - Propagates request_id into structlog context for downstream log correlation
"""

from __future__ import annotations

import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.logging import get_logger, request_id_ctx

logger = get_logger(__name__)

# Paths that generate very high log volume and should be filtered at INFO level
_LOW_PRIORITY_PATHS = frozenset({"/health", "/metrics", "/favicon.ico"})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured request/response logging middleware.

    Injects X-Request-ID header into every response and logs:
    - method, path, query string, client IP
    - response status code and latency
    - user agent (truncated to 200 chars)
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Generate or inherit correlation ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Store in context var so all downstream loggers can access it
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id

        start = time.perf_counter()
        status_code = 500

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            request_id_ctx.reset(token)

            log_fn = logger.info
            if request.url.path in _LOW_PRIORITY_PATHS:
                log_fn = logger.debug

            log_fn(
                "http_request",
                method=request.method,
                path=request.url.path,
                query=str(request.url.query) or None,
                status_code=status_code,
                duration_ms=duration_ms,
                client_ip=_get_client_ip(request),
                user_agent=(request.headers.get("user-agent", "")[:200] or None),
                request_id=request_id,
            )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = str(duration_ms)
        return response


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For behind a proxy."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
