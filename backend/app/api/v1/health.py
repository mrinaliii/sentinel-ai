"""
Health Check Router
====================
Provides /health endpoint for load balancer, Docker, and Kubernetes probes.
Checks liveness of all critical dependencies.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import ORJSONResponse

from app.core.config import settings
from app.core.logging import get_logger
from app.models.common import DependencyHealth, HealthResponse

logger = get_logger(__name__)
router = APIRouter(tags=["Health"])

# Module-level start time for uptime calculation
_START_TIME = time.time()


async def _check_elasticsearch() -> DependencyHealth:
    """Ping Elasticsearch and return health status."""
    import asyncio
    try:
        from elasticsearch import AsyncElasticsearch

        es = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            basic_auth=(settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
            verify_certs=settings.ELASTICSEARCH_VERIFY_CERTS,
            request_timeout=5,
        )
        t0 = time.perf_counter()
        info = await asyncio.wait_for(es.ping(), timeout=5.0)
        latency = round((time.perf_counter() - t0) * 1000, 2)
        await es.close()

        return DependencyHealth(
            name="elasticsearch",
            status="healthy" if info else "unhealthy",
            latency_ms=latency,
        )
    except Exception as exc:
        logger.warning("health_check_es_failed", error=str(exc))
        return DependencyHealth(
            name="elasticsearch",
            status="unhealthy",
            message=str(exc),
        )


async def _check_ollama() -> DependencyHealth:
    """Ping Ollama API and return health status."""
    import asyncio
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5.0) as client:
            t0 = time.perf_counter()
            resp = await asyncio.wait_for(
                client.get(f"{settings.OLLAMA_BASE_URL}/api/tags"),
                timeout=5.0,
            )
            latency = round((time.perf_counter() - t0) * 1000, 2)

        models = [m["name"] for m in resp.json().get("models", [])]
        target_present = any(settings.OLLAMA_MODEL in m for m in models)

        return DependencyHealth(
            name="ollama",
            status="healthy" if resp.status_code == 200 else "degraded",
            latency_ms=latency,
            message=f"Model '{settings.OLLAMA_MODEL}' {'available' if target_present else 'NOT FOUND'}",
            version=settings.OLLAMA_MODEL,
        )
    except Exception as exc:
        logger.warning("health_check_ollama_failed", error=str(exc))
        return DependencyHealth(
            name="ollama",
            status="unhealthy",
            message=str(exc),
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application health check",
    description=(
        "Returns the health status of the application and all critical dependencies. "
        "Status is 'healthy' if all dependencies are up, 'degraded' if some are down, "
        "'unhealthy' if critical dependencies are unavailable."
    ),
    responses={
        200: {"description": "System is healthy or degraded"},
        503: {"description": "System is unhealthy"},
    },
)
async def health_check() -> ORJSONResponse:
    """Comprehensive health check with dependency probing."""
    import asyncio

    deps = await asyncio.gather(
        _check_elasticsearch(),
        _check_ollama(),
        return_exceptions=False,
    )

    all_healthy = all(d.status == "healthy" for d in deps)
    any_unhealthy = any(d.status == "unhealthy" for d in deps)

    if any_unhealthy:
        overall = "unhealthy"
    elif not all_healthy:
        overall = "degraded"
    else:
        overall = "healthy"

    uptime = round(time.time() - _START_TIME, 2)

    body = HealthResponse(
        status=overall,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT.value,
        uptime_seconds=uptime,
        dependencies=list(deps),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    http_status = 200 if overall != "unhealthy" else 503
    return ORJSONResponse(content=body.model_dump(), status_code=http_status)


@router.get(
    "/health/live",
    summary="Liveness probe",
    description="Lightweight liveness probe — returns 200 if the process is alive.",
    response_model=dict,
)
async def liveness() -> dict:
    """Kubernetes liveness probe — always returns 200 if process is running."""
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get(
    "/health/ready",
    summary="Readiness probe",
    description="Readiness probe — returns 200 only when all dependencies are healthy.",
    response_model=dict,
)
async def readiness() -> ORJSONResponse:
    """Kubernetes readiness probe — checks Elasticsearch connectivity."""
    es_health = await _check_elasticsearch()
    ready = es_health.status == "healthy"
    return ORJSONResponse(
        status_code=200 if ready else 503,
        content={
            "ready": ready,
            "elasticsearch": es_health.status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
