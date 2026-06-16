"""
Structured Logging Configuration
==================================
Provides JSON-structured logging via structlog with request correlation IDs,
performance timing, and security-relevant field sanitization.
"""

from __future__ import annotations

import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, WrappedLogger

from app.core.config import LogLevel, settings

# ── Context variable for per-request correlation ID ───────────────────────────
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")

# ── Fields that must NEVER appear in logs ─────────────────────────────────────
_SENSITIVE_FIELDS = frozenset({
    "password", "secret", "token", "api_key", "authorization",
    "cookie", "x-api-key", "credit_card", "ssn",
})


def _sanitize_event(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """
    Structlog processor: redact sensitive fields before emission.
    Recursively checks all dict values for known sensitive keys.
    """
    def _redact(obj: Any, depth: int = 0) -> Any:
        if depth > 5:
            return obj
        if isinstance(obj, dict):
            return {
                k: "[REDACTED]" if k.lower() in _SENSITIVE_FIELDS else _redact(v, depth + 1)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [_redact(i, depth + 1) for i in obj]
        return obj

    return _redact(event_dict)


def _add_request_id(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Structlog processor: inject current request correlation ID."""
    rid = request_id_ctx.get("")
    if rid:
        event_dict["request_id"] = rid
    return event_dict


def _add_service_context(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Structlog processor: inject static service metadata."""
    event_dict.setdefault("service", settings.APP_NAME)
    event_dict.setdefault("version", settings.APP_VERSION)
    event_dict.setdefault("environment", settings.ENVIRONMENT.value)
    return event_dict


def configure_logging() -> None:
    """
    Initialize structlog with the correct renderer for the environment.

    - Production / JSON format  → JSONRenderer (machine-parseable)
    - Development / console     → ConsoleRenderer (human-readable, colorized)
    """
    log_level = logging.getLevelName(settings.LOG_LEVEL.value)

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _add_service_context,
        _add_request_id,
        _sanitize_event,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.LOG_FORMAT == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Quieten noisy third-party loggers
    for noisy in ("uvicorn.access", "elasticsearch", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str = __name__) -> structlog.stdlib.BoundLogger:
    """Factory function — returns a bound structlog logger."""
    return structlog.get_logger(name)
