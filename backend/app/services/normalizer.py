"""
Log Normalization Engine
========================
Transforms raw alert payloads from Splunk, Elasticsearch, and Wazuh into a
common ``NormalizedAlert`` schema.

Architecture
------------
- ``NormalizedAlert``    – validated Pydantic output schema (the contract).
- ``BaseParser``         – abstract interface that every source adapter implements.
- ``SplunkParser``       – maps Splunk notable-event fields → ``NormalizedAlert``.
- ``ElasticsearchParser``– maps ES _source docs     → ``NormalizedAlert``.
- ``WazuhParser``        – maps Wazuh alert dicts    → ``NormalizedAlert``.
- ``NormalizerRegistry`` – discovers parsers by ``source`` tag (open/closed).
- ``LogNormalizer``      – public façade; delegates to the right parser.

Adding a new source
-------------------
1. Subclass ``BaseParser`` and implement ``_parse()``.
2. Set the class attribute ``source_name`` to your source identifier string.
3. Call ``registry.register(YourParser)``  *or*  let the default registry
   auto-discover it via ``@NormalizerRegistry.auto_register``.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, Optional, Type

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.exceptions import SentinelBaseException
from app.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class NormalizationError(SentinelBaseException):
    """Raised when a raw log payload cannot be normalized."""

    error_code = "NORMALIZATION_ERROR"

    def __init__(self, source: str, reason: str, raw: Optional[Any] = None) -> None:
        super().__init__(
            message=f"Normalization failed for source '{source}': {reason}",
            details={"source": source, "reason": reason, "raw_preview": str(raw)[:300]},
        )


class UnknownSourceError(SentinelBaseException):
    """Raised when no parser is registered for the requested source."""

    error_code = "UNKNOWN_SOURCE"

    def __init__(self, source: str) -> None:
        super().__init__(
            message=f"No parser registered for source '{source}'.",
            details={"source": source},
        )


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

# Canonical severity levels in descending order.
_SEVERITY_MAP: Dict[str, str] = {
    # critical aliases
    "critical": "critical",
    "crit": "critical",
    "15": "critical",
    "14": "critical",
    "13": "critical",
    # high aliases
    "high": "high",
    "12": "high",
    "11": "high",
    "10": "high",
    "9": "high",
    "error": "high",
    "err": "high",
    # medium aliases
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "8": "medium",
    "7": "medium",
    "6": "medium",
    # low aliases
    "low": "low",
    "5": "low",
    "4": "low",
    "notice": "low",
    "3": "low",
    # informational aliases
    "informational": "informational",
    "info": "informational",
    "2": "informational",
    "1": "informational",
    "0": "informational",
    "debug": "informational",
}


def _normalize_severity(raw: Optional[str]) -> str:
    """Map any source-specific severity label to a canonical level."""
    if raw is None:
        return "medium"
    return _SEVERITY_MAP.get(str(raw).lower().strip(), "medium")


def _parse_timestamp(raw: Optional[Any]) -> str:
    """
    Coerce *raw* to an ISO-8601 UTC timestamp string.

    Accepts:
    - ``datetime`` objects
    - UNIX epoch integers / floats (seconds)
    - ISO-8601 strings (with or without timezone)
    - Splunk ``_time`` strings (``YYYY-MM-DDTHH:MM:SS.ffffff+00:00``)
    """
    if raw is None:
        return datetime.now(timezone.utc).isoformat()

    if isinstance(raw, datetime):
        dt = raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    if isinstance(raw, (int, float)):
        # Wazuh sometimes returns milliseconds – detect by magnitude
        epoch = raw / 1000.0 if raw > 1e10 else float(raw)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

    if isinstance(raw, str):
        raw = raw.strip()
        # Try fromisoformat first (Python 3.7+)
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass
        # Try common Splunk / syslog formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

    # Fall back to now
    logger.warning("normalizer_timestamp_parse_failed", raw=str(raw)[:80])
    return datetime.now(timezone.utc).isoformat()


class NormalizedAlert(BaseModel):
    """
    Canonical alert representation produced by the normalization engine.

    All fields use ``str`` so downstream systems can store them without
    type negotiation.  ``severity`` is validated to a known canonical level.
    """

    timestamp: str = Field(..., description="ISO-8601 UTC timestamp of the alert")
    source: str = Field(..., description="Originating system (splunk | elasticsearch | wazuh)")
    severity: str = Field(..., description="Canonical severity: critical|high|medium|low|informational")
    alert_name: str = Field(..., description="Human-readable alert / rule title")
    host: str = Field(default="unknown", description="Affected host name or IP")
    user: str = Field(default="unknown", description="Associated user account")
    raw_log: str = Field(..., description="Original log payload serialised as JSON string")

    # ── validators ──────────────────────────────────────────────────────────

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        canonical = _SEVERITY_MAP.get(v.lower().strip())
        if canonical is None:
            raise ValueError(
                f"Invalid severity '{v}'. Must be one of: "
                "critical, high, medium, low, informational"
            )
        return canonical

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {v!r}") from exc
        return v

    @field_validator("source")
    @classmethod
    def _validate_source(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source must not be blank")
        return v.strip().lower()

    @field_validator("alert_name")
    @classmethod
    def _validate_alert_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("alert_name must not be blank")
        return v.strip()

    @model_validator(mode="after")
    def _validate_raw_log_is_json(self) -> "NormalizedAlert":
        try:
            json.loads(self.raw_log)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"raw_log must be a valid JSON string: {exc}") from exc
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Return the alert as a plain ``dict`` (matches the required output schema)."""
        return self.model_dump()


# ---------------------------------------------------------------------------
# Base parser (Strategy interface)
# ---------------------------------------------------------------------------


class BaseParser(ABC):
    """
    Abstract base class for all source-specific alert parsers.

    Subclasses must:
    - Set ``source_name`` (class attribute) to a unique string identifier.
    - Implement ``_parse(raw)`` returning a ``NormalizedAlert``.
    """

    source_name: ClassVar[str]

    def parse(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """
        Public entry point.  Validates ``raw`` type, delegates to ``_parse``,
        and wraps any unexpected errors into ``NormalizationError``.
        """
        if not isinstance(raw, dict):
            raise NormalizationError(
                source=self.source_name,
                reason=f"Expected dict payload, got {type(raw).__name__}",
                raw=raw,
            )
        try:
            return self._parse(raw)
        except NormalizationError:
            raise
        except Exception as exc:
            raise NormalizationError(
                source=self.source_name,
                reason=str(exc),
                raw=raw,
            ) from exc

    @abstractmethod
    def _parse(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Transform *raw* into a ``NormalizedAlert``.  Must not catch exceptions."""

    @staticmethod
    def _to_raw_log(raw: Dict[str, Any]) -> str:
        """Serialise the raw dict to a compact JSON string (for ``raw_log`` field)."""
        return json.dumps(raw, default=str)

    @staticmethod
    def _first(*candidates: Optional[str]) -> str:
        """Return the first non-empty, non-None candidate, or ``'unknown'``."""
        for c in candidates:
            if c and str(c).strip():
                return str(c).strip()
        return "unknown"


# ---------------------------------------------------------------------------
# Splunk parser
# ---------------------------------------------------------------------------

# Splunk ES notable event field reference:
# https://docs.splunk.com/Documentation/ES/latest/User/Notableeventfields
_SPLUNK_SEVERITY_MAP: Dict[str, str] = {
    "informational": "informational",
    "unknown": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SplunkParser(BaseParser):
    """
    Parser for Splunk Enterprise Security notable events.

    Expected top-level fields (any subset is acceptable):
    - ``_time``         : event timestamp
    - ``rule_name``     : alert / correlation search name
    - ``urgency``       : Splunk urgency string
    - ``src``, ``dest`` : source / destination host
    - ``user``          : associated user
    """

    source_name = "splunk"

    def _parse(self, raw: Dict[str, Any]) -> NormalizedAlert:
        timestamp = _parse_timestamp(
            raw.get("_time") or raw.get("timestamp") or raw.get("time")
        )
        alert_name = self._first(
            raw.get("rule_name"),
            raw.get("search_name"),
            raw.get("event_id"),
            "Splunk Alert",
        )
        raw_urgency = raw.get("urgency") or raw.get("severity") or raw.get("priority")
        severity = _normalize_severity(
            _SPLUNK_SEVERITY_MAP.get(str(raw_urgency).lower(), raw_urgency)
            if raw_urgency
            else None
        )
        host = self._first(raw.get("dest"), raw.get("src"), raw.get("host"))
        user = self._first(raw.get("user"), raw.get("src_user"), raw.get("dest_user"))

        return NormalizedAlert(
            timestamp=timestamp,
            source=self.source_name,
            severity=severity,
            alert_name=alert_name,
            host=host,
            user=user,
            raw_log=self._to_raw_log(raw),
        )


# ---------------------------------------------------------------------------
# Elasticsearch / Kibana SIEM alert parser
# ---------------------------------------------------------------------------

# Kibana/ECS severity field value convention
_ES_SEVERITY_MAP: Dict[str, str] = {
    "0": "informational",
    "1": "low",
    "2": "low",
    "3": "medium",
    "4": "medium",
    "5": "medium",
    "6": "high",
    "7": "high",
    "8": "critical",
    "9": "critical",
    "10": "critical",
}


class ElasticsearchParser(BaseParser):
    """
    Parser for Elasticsearch / OpenSearch / Kibana SIEM alert documents.

    Supports both ECS-normalised documents and raw connector output:
    - ECS: ``@timestamp``, ``signal.*``, ``kibana.alert.*``, ``host.name``, ``user.name``
    - Generic: ``timestamp``, ``severity``, ``message``, ``host``, ``user``
    """

    source_name = "elasticsearch"

    def _parse(self, raw: Dict[str, Any]) -> NormalizedAlert:
        # ── timestamp ──
        timestamp = _parse_timestamp(
            raw.get("@timestamp")
            or raw.get("timestamp")
            or raw.get("event", {}).get("created")
        )

        # ── alert name ──
        alert_name = self._first(
            raw.get("signal", {}).get("rule", {}).get("name"),
            raw.get("kibana.alert.rule.name"),
            raw.get("rule", {}).get("name"),
            raw.get("message"),
            raw.get("alert_name"),
            "Elasticsearch Alert",
        )

        # ── severity ──
        # kibana.alert.severity is a numeric string 0-100
        raw_sev = (
            raw.get("kibana.alert.severity")
            or raw.get("signal", {}).get("rule", {}).get("severity")
            or raw.get("severity")
            or raw.get("event", {}).get("severity")
        )
        # Handle ECS numeric severity (0-100 mapped via deciles)
        if isinstance(raw_sev, (int, float)):
            decile = str(min(int(raw_sev) // 10, 10))
            severity = _ES_SEVERITY_MAP.get(decile, "medium")
        else:
            severity = _normalize_severity(str(raw_sev) if raw_sev is not None else None)

        # ── host ──
        host = self._first(
            raw.get("host", {}).get("name") if isinstance(raw.get("host"), dict) else raw.get("host"),
            raw.get("destination", {}).get("ip"),
            raw.get("source", {}).get("ip"),
        )

        # ── user ──
        user = self._first(
            raw.get("user", {}).get("name") if isinstance(raw.get("user"), dict) else raw.get("user"),
            raw.get("signal", {}).get("original_event", {}).get("user", {}).get("name"),
        )

        return NormalizedAlert(
            timestamp=timestamp,
            source=self.source_name,
            severity=severity,
            alert_name=alert_name,
            host=host,
            user=user,
            raw_log=self._to_raw_log(raw),
        )


# ---------------------------------------------------------------------------
# Wazuh parser
# ---------------------------------------------------------------------------

# Wazuh rule levels are 0–15 (integers).
# Reference: https://documentation.wazuh.com/current/user-manual/ruleset/rules/severity.html
_WAZUH_LEVEL_SEVERITY: Dict[str, str] = {
    **{str(i): "informational" for i in range(0, 4)},   # 0-3
    **{str(i): "low" for i in range(4, 8)},              # 4-7
    **{str(i): "medium" for i in range(8, 12)},          # 8-11
    **{str(i): "high" for i in range(12, 14)},           # 12-13
    **{str(i): "critical" for i in range(14, 16)},       # 14-15
}


class WazuhParser(BaseParser):
    """
    Parser for Wazuh alert dicts returned by ``WazuhConnector.query_alerts()``.

    Field mapping:
    - ``timestamp`` / ``@timestamp``      → timestamp
    - ``rule.description``                → alert_name
    - ``rule.level``                      → severity (integer 0-15)
    - ``agent.name`` / ``agent.ip``       → host
    - ``data.srcuser`` / ``data.dstuser`` → user
    """

    source_name = "wazuh"

    def _parse(self, raw: Dict[str, Any]) -> NormalizedAlert:
        # ── timestamp ──
        timestamp = _parse_timestamp(
            raw.get("timestamp") or raw.get("@timestamp")
        )

        # ── alert name from rule ──
        rule = raw.get("rule", {})
        alert_name = self._first(
            rule.get("description"),
            rule.get("id"),
            "Wazuh Alert",
        )

        # ── severity from rule level ──
        level = rule.get("level")
        if level is not None:
            severity = _WAZUH_LEVEL_SEVERITY.get(str(level), "medium")
        else:
            # Fallback: check rule.level.name (some API versions)
            severity = _normalize_severity(rule.get("level_name") or rule.get("groups", [None])[0])

        # ── host ──
        agent = raw.get("agent", {})
        host = self._first(
            agent.get("name"),
            agent.get("ip"),
            raw.get("manager", {}).get("name"),
        )

        # ── user ──
        data = raw.get("data", {})
        user = self._first(
            data.get("srcuser"),
            data.get("dstuser"),
            data.get("win", {}).get("eventdata", {}).get("subjectUserName"),
            raw.get("syscheck", {}).get("uname_after"),
        )

        return NormalizedAlert(
            timestamp=timestamp,
            source=self.source_name,
            severity=severity,
            alert_name=alert_name,
            host=host,
            user=user,
            raw_log=self._to_raw_log(raw),
        )


# ---------------------------------------------------------------------------
# Registry (extensible parser catalogue)
# ---------------------------------------------------------------------------


class NormalizerRegistry:
    """
    Maps ``source_name`` strings to ``BaseParser`` classes.

    Usage::

        registry = NormalizerRegistry()
        registry.register(SplunkParser)

        # Or use as a class decorator:
        @registry.auto_register
        class MyCustomParser(BaseParser):
            source_name = "my_tool"
            ...
    """

    def __init__(self) -> None:
        self._parsers: Dict[str, Type[BaseParser]] = {}

    def register(self, parser_cls: Type[BaseParser]) -> None:
        """Register a parser class.  Overwrites any existing entry."""
        if not hasattr(parser_cls, "source_name") or not parser_cls.source_name:
            raise TypeError(
                f"Parser {parser_cls.__name__} must define a non-empty 'source_name'."
            )
        self._parsers[parser_cls.source_name.lower()] = parser_cls
        logger.debug("normalizer_parser_registered", source=parser_cls.source_name)

    def auto_register(self, parser_cls: Type[BaseParser]) -> Type[BaseParser]:
        """Class decorator that registers and returns the class unchanged."""
        self.register(parser_cls)
        return parser_cls

    def get(self, source: str) -> BaseParser:
        """
        Return an instantiated parser for *source*.

        Raises:
            UnknownSourceError: if no parser is registered for *source*.
        """
        parser_cls = self._parsers.get(source.lower())
        if parser_cls is None:
            raise UnknownSourceError(source=source)
        return parser_cls()

    @property
    def registered_sources(self) -> list[str]:
        """Sorted list of registered source names."""
        return sorted(self._parsers.keys())


# ---------------------------------------------------------------------------
# Default registry – populated with built-in parsers
# ---------------------------------------------------------------------------

default_registry = NormalizerRegistry()
default_registry.register(SplunkParser)
default_registry.register(ElasticsearchParser)
default_registry.register(WazuhParser)


# ---------------------------------------------------------------------------
# Public façade
# ---------------------------------------------------------------------------


class LogNormalizer:
    """
    Public façade for the normalization engine.

    Usage::

        normalizer = LogNormalizer()

        alert = normalizer.normalize("wazuh", wazuh_raw_dict)
        print(alert.to_dict())

        # Batch variant (skips / logs individual failures)
        alerts = normalizer.normalize_batch("splunk", [event1, event2, ...])
    """

    def __init__(self, registry: Optional[NormalizerRegistry] = None) -> None:
        self._registry = registry or default_registry

    def normalize(self, source: str, raw: Dict[str, Any]) -> NormalizedAlert:
        """
        Normalize a single raw alert dict from *source*.

        Args:
            source: Source system identifier (``"splunk"``, ``"elasticsearch"``, ``"wazuh"``).
            raw:    Raw alert payload as a Python dict.

        Returns:
            A validated ``NormalizedAlert`` instance.

        Raises:
            UnknownSourceError:  No parser registered for *source*.
            NormalizationError:  Parsing or validation failed.
        """
        parser = self._registry.get(source)
        normalized = parser.parse(raw)
        logger.info(
            "normalizer_alert_normalized",
            source=source,
            alert_name=normalized.alert_name,
            severity=normalized.severity,
        )
        return normalized

    def normalize_batch(
        self,
        source: str,
        raws: list[Dict[str, Any]],
        *,
        skip_errors: bool = True,
    ) -> list[NormalizedAlert]:
        """
        Normalize a batch of raw alert dicts from *source*.

        Args:
            source:      Source system identifier.
            raws:        List of raw alert payloads.
            skip_errors: If ``True`` (default), log and skip individual failures.
                         If ``False``, re-raise on the first error.

        Returns:
            List of successfully normalized ``NormalizedAlert`` instances.
        """
        results: list[NormalizedAlert] = []
        for idx, raw in enumerate(raws):
            try:
                results.append(self.normalize(source, raw))
            except (NormalizationError, UnknownSourceError) as exc:
                if skip_errors:
                    logger.warning(
                        "normalizer_batch_item_failed",
                        source=source,
                        index=idx,
                        reason=exc.message,
                    )
                else:
                    raise
        logger.info(
            "normalizer_batch_complete",
            source=source,
            total=len(raws),
            success=len(results),
            failed=len(raws) - len(results),
        )
        return results

    @property
    def supported_sources(self) -> list[str]:
        """List of source names supported by the current registry."""
        return self._registry.registered_sources
