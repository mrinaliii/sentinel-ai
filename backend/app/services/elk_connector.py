"""
Elasticsearch Connector
========================
Async service class for querying alerts and events from an Elasticsearch /
OpenSearch cluster via the official ``elasticsearch-py`` async client.

Authentication methods:
  - Username / password (HTTP Basic)
  - API Key (id + value pair)
  - Bearer token

Capabilities:
  - query_alerts()      : DSL search with scroll/search-after pagination
  - get_alert_by_id()   : single document fetch by _id
  - run_dsl_query()     : execute arbitrary DSL query dict
  - scroll_all()        : async generator for large result sets
  - test_connection()   : cluster health check
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from elasticsearch import AsyncElasticsearch, NotFoundError as ESNotFoundError
from elasticsearch.exceptions import (
    AuthenticationException,
    ConnectionError as ESConnectionError,
    TransportError,
)

from app.core.exceptions import SentinelBaseException
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class ElasticsearchConnectorError(SentinelBaseException):
    """Raised for all Elasticsearch connector failures."""

    error_code = "ELASTICSEARCH_CONNECTOR_ERROR"

    def __init__(self, operation: str, cause: str) -> None:
        super().__init__(
            message=f"Elasticsearch operation '{operation}' failed: {cause}",
            details={"operation": operation, "cause": cause},
        )


class ElasticsearchAuthError(ElasticsearchConnectorError):
    """Raised when authentication with Elasticsearch fails."""

    error_code = "ELASTICSEARCH_AUTH_ERROR"

    def __init__(self, cause: str) -> None:
        super().__init__(operation="authenticate", cause=cause)


# ---------------------------------------------------------------------------
# Authentication config
# ---------------------------------------------------------------------------


@dataclass
class ESBasicAuth:
    """Username / password credentials."""
    username: str
    password: str


@dataclass
class ESApiKeyAuth:
    """API Key credentials (id + value)."""
    api_key_id: str
    api_key_value: str


@dataclass
class ESBearerAuth:
    """Bearer / service-account token."""
    token: str


ESAuthConfig = ESBasicAuth | ESApiKeyAuth | ESBearerAuth


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class ElasticsearchConfig:
    """All configuration needed to connect to an Elasticsearch cluster."""

    hosts: List[str] = field(default_factory=lambda: ["http://localhost:9200"])
    auth: Optional[ESAuthConfig] = None
    ca_certs: Optional[str] = None          # path to CA bundle for TLS verification
    verify_certs: bool = True
    timeout: int = 30
    max_retries: int = 3
    retry_on_timeout: bool = True

    # Index to query for alerts
    alerts_index: str = "sentinel-alerts"

    # Default time window
    default_window_hours: int = 24

    # Pagination
    default_page_size: int = 100
    max_page_size: int = 1_000

    # scroll API keep-alive (used by scroll_all generator)
    scroll_ttl: str = "2m"


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class ElasticsearchConnector:
    """
    Async Elasticsearch connector.

    Usage (context manager)::

        cfg = ElasticsearchConfig(
            hosts=["https://es.corp.local:9200"],
            auth=ESApiKeyAuth(api_key_id="abc", api_key_value="xyz"),
        )
        async with ElasticsearchConnector(cfg) as conn:
            alerts = await conn.query_alerts(severity="HIGH", hours=48)

    Usage (manual lifecycle)::

        conn = ElasticsearchConnector(cfg)
        await conn.connect()
        try:
            ...
        finally:
            await conn.close()
    """

    def __init__(self, config: ElasticsearchConfig) -> None:
        self.config = config
        self._client: Optional[AsyncElasticsearch] = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def __aenter__(self) -> "ElasticsearchConnector":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """Build and verify the Elasticsearch async client."""
        kwargs: Dict[str, Any] = {
            "hosts": self.config.hosts,
            "timeout": self.config.timeout,
            "retry_on_timeout": self.config.retry_on_timeout,
            "max_retries": self.config.max_retries,
            "verify_certs": self.config.verify_certs,
        }
        if self.config.ca_certs:
            kwargs["ca_certs"] = self.config.ca_certs

        auth = self.config.auth
        if isinstance(auth, ESBasicAuth):
            kwargs["basic_auth"] = (auth.username, auth.password)
        elif isinstance(auth, ESApiKeyAuth):
            kwargs["api_key"] = (auth.api_key_id, auth.api_key_value)
        elif isinstance(auth, ESBearerAuth):
            kwargs["bearer_auth"] = auth.token

        self._client = AsyncElasticsearch(**kwargs)
        # Eagerly test connectivity
        try:
            info = await self._client.info()
            logger.info(
                "elasticsearch_connected",
                version=info["version"]["number"],
                cluster=info.get("cluster_name"),
            )
        except AuthenticationException as exc:
            await self._client.close()
            raise ElasticsearchAuthError(cause=str(exc)) from exc
        except Exception as exc:
            await self._client.close()
            raise ElasticsearchConnectorError(operation="connect", cause=str(exc)) from exc

    async def close(self) -> None:
        """Close the underlying async transport."""
        if self._client:
            await self._client.close()
            self._client = None
        logger.info("elasticsearch_disconnected")

    # ── internal helpers ──────────────────────────────────────────────────

    def _assert_connected(self) -> AsyncElasticsearch:
        if self._client is None:
            raise ElasticsearchConnectorError(
                operation="request", cause="Client not connected. Call connect() first."
            )
        return self._client

    def _time_range_filter(
        self,
        hours: Optional[int],
        start: Optional[datetime],
        end: Optional[datetime],
        timestamp_field: str = "@timestamp",
    ) -> Dict[str, Any]:
        """Build an Elasticsearch ``range`` filter dict."""
        now = datetime.now(timezone.utc)
        gte: str
        lte: str = now.isoformat()

        if start is not None:
            gte = start.isoformat()
            if end is not None:
                lte = end.isoformat()
        else:
            window = hours if hours is not None else self.config.default_window_hours
            gte = (now - timedelta(hours=window)).isoformat()

        return {"range": {timestamp_field: {"gte": gte, "lte": lte}}}

    async def _search(
        self,
        index: str,
        query: Dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Optional[List[Dict[str, Any]]] = None,
        search_after: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Low-level DSL search with error translation."""
        client = self._assert_connected()
        body: Dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort
        if from_ and search_after is None:
            body["from"] = from_
        if search_after:
            body["search_after"] = search_after

        try:
            resp = await client.search(index=index, body=body)
            return resp.body if hasattr(resp, "body") else dict(resp)
        except AuthenticationException as exc:
            raise ElasticsearchAuthError(cause=str(exc)) from exc
        except (ESConnectionError, TransportError) as exc:
            raise ElasticsearchConnectorError(operation="search", cause=str(exc)) from exc

    # ── public API ─────────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        """Return True if the cluster is reachable and auth is valid."""
        try:
            client = self._assert_connected()
            health = await client.cluster.health()
            body = health.body if hasattr(health, "body") else dict(health)
            logger.info("elasticsearch_cluster_health", status=body.get("status"))
            return True
        except (ElasticsearchConnectorError, Exception):
            return False

    async def run_dsl_query(
        self,
        query: Dict[str, Any],
        *,
        index: Optional[str] = None,
        size: int = 100,
        from_: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Execute an arbitrary Elasticsearch DSL query.

        Args:
            query:   Full Elasticsearch ``query`` dict (e.g. ``{"bool": {...}}``).
            index:   Target index pattern; defaults to ``config.alerts_index``.
            size:    Page size (number of hits to return).
            from_:   Offset for simple pagination (use ``scroll_all`` for large sets).

        Returns:
            Tuple of (list of ``_source`` dicts, total hit count).
        """
        target = index or self.config.alerts_index
        resp = await self._search(target, query, size=size, from_=from_)
        hits = resp.get("hits", {})
        total: int = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        sources = [h.get("_source", {}) | {"_id": h["_id"]} for h in hits.get("hits", [])]
        return sources, total

    async def query_alerts(
        self,
        *,
        index: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        hours: Optional[int] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        page: int = 0,
        timestamp_field: str = "@timestamp",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Query Elasticsearch for security alerts with common filter options.

        Args:
            index:           Target index (defaults to ``config.alerts_index``).
            severity:        Filter by ``severity`` field value (e.g. ``"HIGH"``).
            status:          Filter by ``status`` field value (e.g. ``"open"``).
            source_ip:       Filter by source IP.
            dest_ip:         Filter by destination IP.
            hours:           Look-back window in hours (mutually exclusive with ``start``/``end``).
            start:           Explicit window start (UTC).
            end:             Explicit window end (UTC, defaults to now).
            limit:           Page size — number of results to return.
            page:            Zero-based page number (simple ``from`` pagination).
            timestamp_field: Name of the date field used for the time range filter.

        Returns:
            Tuple of (alerts list, total matching count).
        """
        target = index or self.config.alerts_index
        size = min(limit, self.config.max_page_size)

        must: List[Dict[str, Any]] = [
            self._time_range_filter(hours, start, end, timestamp_field)
        ]
        if severity:
            must.append({"term": {"severity": severity.upper()}})
        if status:
            must.append({"term": {"status": status.lower()}})
        if source_ip:
            must.append({"term": {"source.ip": source_ip}})
        if dest_ip:
            must.append({"term": {"destination.ip": dest_ip}})

        query = {"bool": {"must": must}}
        sources, total = await self.run_dsl_query(
            query, index=target, size=size, from_=page * size
        )
        logger.info(
            "elasticsearch_alerts_queried",
            index=target,
            total_hits=total,
            returned=len(sources),
            page=page,
        )
        return sources, total

    async def get_alert_by_id(
        self,
        alert_id: str,
        index: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a single alert document by Elasticsearch ``_id``.

        Returns:
            Document source dict, or ``None`` if not found.
        """
        client = self._assert_connected()
        target = index or self.config.alerts_index
        try:
            resp = await client.get(index=target, id=alert_id)
            body = resp.body if hasattr(resp, "body") else dict(resp)
            return body.get("_source", {}) | {"_id": body["_id"]}
        except ESNotFoundError:
            logger.warning("elasticsearch_alert_not_found", id=alert_id, index=target)
            return None
        except (ESConnectionError, TransportError) as exc:
            raise ElasticsearchConnectorError(operation="get", cause=str(exc)) from exc

    async def scroll_all(
        self,
        query: Dict[str, Any],
        *,
        index: Optional[str] = None,
        page_size: Optional[int] = None,
        timestamp_field: str = "@timestamp",
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator that yields all matching documents using search-after
        pagination (pit-less, low overhead alternative to scroll API).

        Args:
            query:           Elasticsearch DSL query dict.
            index:           Target index.
            page_size:       Hits per internal fetch.
            timestamp_field: Field used for deterministic sort.

        Yields:
            Individual ``_source`` dicts (with ``_id`` injected).
        """
        client = self._assert_connected()
        target = index or self.config.alerts_index
        size = min(page_size or self.config.default_page_size, self.config.max_page_size)
        sort = [{timestamp_field: "asc"}, {"_id": "asc"}]

        search_after: Optional[List[Any]] = None
        while True:
            body: Dict[str, Any] = {"query": query, "size": size, "sort": sort}
            if search_after:
                body["search_after"] = search_after
            try:
                resp = await client.search(index=target, body=body)
                raw = resp.body if hasattr(resp, "body") else dict(resp)
            except (ESConnectionError, TransportError) as exc:
                raise ElasticsearchConnectorError(operation="scroll_all", cause=str(exc)) from exc

            hits: List[Dict[str, Any]] = raw.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                yield h.get("_source", {}) | {"_id": h["_id"]}
            search_after = hits[-1]["sort"]
            if len(hits) < size:
                break
