"""
Sentinel-AI  —  FastAPI Application Entrypoint
================================================
Bootstraps the FastAPI application with:
  - Lifespan context manager (startup/shutdown hooks)
  - CORS middleware
  - Request logging middleware
  - Exception handlers
  - API v1 router mounted at /api/v1
  - ORJSON for fast JSON serialization
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import ORJSONResponse

from app.api.v1 import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestLoggingMiddleware

# Initialise structured logging before anything else
configure_logging()
logger = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler.

    Startup:
      - Log boot summary
      - Verify Elasticsearch connectivity
      - Load MITRE ATT&CK local cache
      - Warm Ollama model (optional keep-alive ping)

    Shutdown:
      - Close Elasticsearch client connections
      - Flush any pending audit log entries
    """
    # ── STARTUP ───────────────────────────────────────────────────────────────
    logger.info(
        "sentinel_ai_starting",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT.value,
        ollama_model=settings.OLLAMA_MODEL,
        elasticsearch_url=settings.ELASTICSEARCH_URL,
    )

    # TODO: Initialize and store Elasticsearch client on app.state
    # app.state.es = AsyncElasticsearch(...)

    # TODO: Load MITRE ATT&CK cache
    # await mitre_service.load_cache()

    # TODO: Warm Ollama model
    # await ollama_service.warmup()

    logger.info("sentinel_ai_ready", docs_url=settings.DOCS_URL)
    yield

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────
    logger.info("sentinel_ai_shutting_down")

    # TODO: Close ES client
    # if hasattr(app.state, "es"):
    #     await app.state.es.close()

    logger.info("sentinel_ai_stopped")


# ── Application Factory ────────────────────────────────────────────────────────

def create_application() -> FastAPI:
    """
    Application factory — creates and fully configures the FastAPI instance.

    Separating construction from instantiation makes the app testable:
    tests can call create_application() with test settings injected.
    """
    app = FastAPI(
        title=settings.APP_NAME,
        description=settings.APP_DESCRIPTION,
        version=settings.APP_VERSION,
        docs_url=settings.DOCS_URL if settings.docs_enabled else None,
        redoc_url=settings.REDOC_URL if settings.docs_enabled else None,
        openapi_url=settings.OPENAPI_URL if settings.docs_enabled else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
        contact={
            "name": "Sentinel-AI Security Engineering",
            "email": "security-eng@example.com",
        },
        license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
        openapi_tags=[
            {"name": "Health", "description": "Liveness, readiness, and dependency health probes"},
            {"name": "Alerts", "description": "Alert ingestion, triage, and management"},
            {"name": "Incidents", "description": "Incident creation and investigation"},
            {"name": "Analyst Copilot", "description": "LangChain-powered AI chat assistant"},
        ],
    )

    # ── Middleware (order matters — outermost = last applied to request) ───────

    # GZip compression for responses > 1KB
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
    )

    # Request logging + correlation ID injection (innermost — applied first)
    app.add_middleware(RequestLoggingMiddleware)

    # ── Exception Handlers ────────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # ── Root endpoint ─────────────────────────────────────────────────────────
    @app.get("/", include_in_schema=False, response_class=ORJSONResponse)
    async def root() -> dict:
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": settings.DOCS_URL,
            "health": f"{settings.API_V1_PREFIX}/health",
        }

    return app


# ── Module-level app instance (used by Uvicorn) ───────────────────────────────
app = create_application()


# ── Dev server entrypoint ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        workers=settings.WORKERS,
        log_level=settings.LOG_LEVEL.value.lower(),
        access_log=False,  # Handled by our RequestLoggingMiddleware
    )
