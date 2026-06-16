"""
Core Package
=============
Exports all core utilities for convenient imports throughout the application.
"""

from app.core.config import Settings, get_settings, settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ElasticsearchError,
    IngestionError,
    LLMError,
    NotFoundError,
    RateLimitError,
    SentinelBaseException,
    ValidationError,
    register_exception_handlers,
)
from app.core.logging import configure_logging, get_logger, request_id_ctx
from app.core.middleware import RequestLoggingMiddleware
from app.core.security import (
    AdminRequired,
    AnalystRequired,
    UserRole,
    ViewerRequired,
    create_access_token,
    decode_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)

__all__ = [
    # Config
    "Settings",
    "get_settings",
    "settings",
    # Logging
    "configure_logging",
    "get_logger",
    "request_id_ctx",
    # Middleware
    "RequestLoggingMiddleware",
    # Exceptions
    "SentinelBaseException",
    "NotFoundError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "ElasticsearchError",
    "LLMError",
    "IngestionError",
    "RateLimitError",
    "register_exception_handlers",
    # Security
    "UserRole",
    "create_access_token",
    "decode_token",
    "get_current_user",
    "hash_password",
    "verify_password",
    "require_role",
    "AdminRequired",
    "AnalystRequired",
    "ViewerRequired",
]
