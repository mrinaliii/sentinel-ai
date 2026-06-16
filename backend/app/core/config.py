"""
Sentinel-AI Configuration Management
=====================================
Uses Pydantic BaseSettings for type-safe, environment-driven configuration.
All settings can be overridden via environment variables or a .env file.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import List, Optional

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Runtime environment identifiers."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    """Allowed log level values."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """
    Central application settings.

    All fields map directly to environment variables.
    Nested sections are separated by double-underscore (__) in env vars.
    Example: ELASTICSEARCH__URL maps to settings.elasticsearch.url
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "Sentinel-AI"
    APP_DESCRIPTION: str = "AI-Powered SOC Analyst Assistant"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = False

    # ── Server ───────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    RELOAD: bool = False

    # ── API ──────────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    DOCS_URL: Optional[str] = "/docs"
    REDOC_URL: Optional[str] = "/redoc"
    OPENAPI_URL: Optional[str] = "/openapi.json"

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]

    # ── Security & Auth ───────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="CHANGE-ME-IN-PRODUCTION-use-256-bit-random-key",
        description="JWT signing secret — override in production",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: LogLevel = LogLevel.INFO
    LOG_FORMAT: str = "json"  # "json" | "console"
    LOG_REQUEST_BODY: bool = False  # Enable only in development
    LOG_RESPONSE_BODY: bool = False

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_USERNAME: str = "elastic"
    ELASTICSEARCH_PASSWORD: str = "changeme"
    ELASTICSEARCH_CA_CERT: Optional[str] = None
    ELASTICSEARCH_VERIFY_CERTS: bool = False
    ELASTICSEARCH_TIMEOUT: int = 30

    # Index names
    ES_INDEX_EVENTS: str = "sentinel-events"
    ES_INDEX_ALERTS: str = "sentinel-alerts"
    ES_INDEX_INCIDENTS: str = "sentinel-incidents"
    ES_INDEX_AUDIT: str = "sentinel-audit"

    # ── Ollama / LLM ─────────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"
    OLLAMA_TEMPERATURE: float = 0.1
    OLLAMA_MAX_TOKENS: int = 2048
    OLLAMA_CONTEXT_WINDOW: int = 8192
    OLLAMA_TIMEOUT: int = 120
    OLLAMA_KEEP_ALIVE: str = "5m"

    # ── Vector Store ─────────────────────────────────────────────────────────
    VECTOR_STORE_TYPE: str = "faiss"  # "faiss" | "chroma"
    VECTOR_STORE_PATH: str = "./data/vectorstore"
    EMBEDDING_MODEL: str = "nomic-embed-text"

    # ── Redis (Cache & Celery broker) ─────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TTL_IOC: int = 14400       # 4 hours
    REDIS_TTL_ENTITY: int = 3600     # 1 hour
    REDIS_TTL_MITRE: int = 86400     # 24 hours

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    MITRE_LOCAL_CACHE_PATH: str = "./data/mitre-attack.json"
    MITRE_STIX_URL: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    MITRE_AUTO_UPDATE: bool = True
    MITRE_UPDATE_INTERVAL_HOURS: int = 24

    # ── Alert Enrichment ──────────────────────────────────────────────────────
    ENRICHMENT_WINDOW_SECONDS: int = 300   # ±5 min correlation window
    ENRICHMENT_MAX_EVENTS: int = 50         # Max events pulled per alert

    # ── Threat Intelligence ───────────────────────────────────────────────────
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ── Computed Properties ───────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == Environment.DEVELOPMENT

    @property
    def docs_enabled(self) -> bool:
        """Disable Swagger/ReDoc in production."""
        return not self.is_production

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | List[str]) -> List[str]:
        """Allow comma-separated string or list for CORS_ORIGINS env var."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        """Warn if using default secret key outside development."""
        if v == "CHANGE-ME-IN-PRODUCTION-use-256-bit-random-key":
            import warnings
            warnings.warn(
                "Using default SECRET_KEY. This is insecure in production!",
                stacklevel=2,
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached application settings singleton.

    Using @lru_cache ensures settings are parsed only once,
    regardless of how many times get_settings() is called.
    """
    return Settings()


# Module-level alias for convenience
settings: Settings = get_settings()
