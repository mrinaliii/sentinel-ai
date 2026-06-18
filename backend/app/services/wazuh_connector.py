"""
Wazuh Connector
================
Async service class for querying alerts and agents from a Wazuh manager
via the Wazuh REST API v4.

Authentication:
  - Username / password → JWT token acquired on connect (auto-refreshed)
  - Pre-supplied JWT    → pass as ``token`` in WazuhConfig

Capabilities:
  - query_alerts()      : query Wazuh alerts index with filters + pagination
  - get_alert_by_id()   : fetch a single alert from the Wazuh alerts index
  - list_agents()       : paginated agent inventory
  - get_agent()         : fetch a single agent by ID
  - test_connection()   : API-level health check
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx

from app.core.exceptions import SentinelBaseException
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class WazuhConnectorError(SentinelBaseException):
    """Raised for all Wazuh connector failures."""

    error_code = "WAZUH_CONNECTOR_ERROR"

    def __init__(self, operation: str, cause: str) -> None:
        super().__init__(
            message=f"Wazuh operation '{operation}' failed: {cause}",
            details={"operation": operation, "cause": cause},
        )


class WazuhAuthError(WazuhConnectorError):
    """Raised when JWT authentication with Wazuh fails."""

    error_code = "WAZUH_AUTH_ERROR"

    def __init__(self, cause: str) -> None:
        super().__init__(operation="authenticate", cause=cause)


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class WazuhConfig:
    """All configuration needed to connect to a Wazuh manager."""

    host: str
    port: int = 55000
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None              # pre-issued JWT; bypasses login
    verify_ssl: bool = True
    ca_cert: Optional[str] = None           # path to CA cert for TLS verification
    timeout: int = 30
    max_retries: int = 3

    # Default time window for alert queries
    default_window_hours: int = 24

    # Pagination
    default_page_size: int = 100
    max_page_size: int = 500                # Wazuh API cap per request

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def __post_init__(self) -> None:
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "WazuhConfig requires either a 'token' or both 'username' and 'password'."
            )


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class WazuhConnector:
    """
    Async Wazuh connector.

    Wazuh REST API reference: https://documentation.wazuh.com/current/user-manual/api/reference.html

    Usage (context manager)::

        cfg = WazuhConfig(host="wazuh.corp.local", username="wazuh-wui", password="secret")
        async with WazuhConnector(cfg) as conn:
            alerts, total = await conn.query_alerts(severity="high", hours=48)

    Usage (manual lifecycle)::

        conn = WazuhConnector(cfg)
        await conn.connect()
        try:
            ...
        finally:
            await conn.close()
    """

    _AUTH_ENDPOINT = "/security/user/authenticate"
    _ALERTS_ENDPOINT = "/alerts"
    _AGENTS_ENDPOINT = "/agents"

    def __init__(self, config: WazuhConfig) -> None:
        self.config = config
        self._jwt: Optional[str] = config.token
        self._client: Optional[httpx.AsyncClient] = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def __aenter__(self) -> "WazuhConnector":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """Build the HTTP client and acquire a JWT token if needed."""
        ssl_context: Any = True
        if self.config.ca_cert:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.load_verify_locations(self.config.ca_cert)
            ssl_context = ctx
        elif not self.config.verify_ssl:
            ssl_context = False

        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            verify=ssl_context,
            timeout=self.config.timeout,
        )
        if not self._jwt:
            await self._authenticate()
        logger.info("wazuh_connected", host=self.config.host)

    async def close(self) -> None:
        """Gracefully close the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("wazuh_disconnected", host=self.config.host)

    # ── auth ──────────────────────────────────────────────────────────────

    async def _authenticate(self) -> None:
        """POST credentials to Wazuh auth endpoint and store the JWT."""
        assert self._client is not None
        try:
            resp = await self._client.post(
                self._AUTH_ENDPOINT,
                auth=(self.config.username or "", self.config.password or ""),
            )
            if resp.status_code == 401:
                raise WazuhAuthError(cause="Invalid credentials (HTTP 401)")
            resp.raise_for_status()
            data = resp.json()
            self._jwt = data["data"]["token"]
            logger.info("wazuh_authenticated", username=self.config.username)
        except WazuhAuthError:
            raise
        except Exception as exc:
            raise WazuhAuthError(cause=str(exc)) from exc

    @property
    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._jwt}"}

    # ── internal helpers ──────────────────────────────────────────────────

    async def _get(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        attempt: int = 1,
    ) -> Dict[str, Any]:
        """Perform a GET request with automatic JWT refresh on 401."""
        assert self._client is not None, "Call connect() first."
        try:
            resp = await self._client.get(
                endpoint,
                params=params,
                headers=self._auth_headers,
            )
            if resp.status_code == 401 and attempt == 1 and not self.config.token:
                logger.warning("wazuh_token_expired_reauthenticating")
                await self._authenticate()
                return await self._get(endpoint, params=params, attempt=2)
            if resp.status_code == 404:
                return {"data": {"affected_items": [], "total_affected_items": 0}}
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise WazuhConnectorError(
                operation=f"GET {endpoint}",
                cause=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            ) from exc
        except httpx.RequestError as exc:
            if attempt < self.config.max_retries:
                wait = 2 ** attempt
                logger.warning("wazuh_request_retrying", attempt=attempt, wait=wait)
                await asyncio.sleep(wait)
                return await self._get(endpoint, params=params, attempt=attempt + 1)
            raise WazuhConnectorError(
                operation=f"GET {endpoint}", cause=str(exc)
            ) from exc

    def _build_time_params(
        self,
        hours: Optional[int],
        start: Optional[datetime],
        end: Optional[datetime],
        timestamp_field: str = "timestamp",
    ) -> Dict[str, str]:
        """Return Wazuh API q-parameter fragment and date range strings."""
        now = datetime.now(timezone.utc)
        if start is not None:
            gte = start.isoformat().replace("+00:00", "Z")
            lte = (end or now).isoformat().replace("+00:00", "Z")
        else:
            window = hours if hours is not None else self.config.default_window_hours
            gte = (now - timedelta(hours=window)).isoformat().replace("+00:00", "Z")
            lte = now.isoformat().replace("+00:00", "Z")
        return {"older_than": gte, "q": f"{timestamp_field}<={lte};{timestamp_field}>={gte}"}

    # ── public API ─────────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        """Return True if the Wazuh manager API is reachable and auth is valid."""
        try:
            result = await self._get("/")
            return "data" in result
        except WazuhConnectorError:
            return False

    async def query_alerts(
        self,
        *,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        hours: Optional[int] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        page: int = 0,
        sort_field: str = "timestamp",
        sort_order: str = "desc",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Query Wazuh alerts with optional filters and pagination.

        Args:
            severity:    Filter by rule level name (e.g. ``"critical"``, ``"high"``).
            agent_id:    Filter by Wazuh agent ID (zero-padded, e.g. ``"001"``).
            rule_id:     Filter by rule ID.
            hours:       Look-back window in hours. Mutually exclusive with ``start``/``end``.
            start:       Explicit UTC start of the time window.
            end:         Explicit UTC end of the time window (defaults to now).
            limit:       Page size.
            page:        Zero-based page number.
            sort_field:  Field to sort results by.
            sort_order:  ``"asc"`` or ``"desc"``.

        Returns:
            Tuple of (alerts list, total matching count).
        """
        size = min(limit, self.config.max_page_size)
        offset = page * size

        params: Dict[str, Any] = {
            "limit": size,
            "offset": offset,
            "sort": f"{'-' if sort_order == 'desc' else '+'}{sort_field}",
            "pretty": False,
        }

        # Wazuh API uses a ``q`` query-string language for filters
        q_parts: List[str] = []
        if severity:
            q_parts.append(f"rule.level.name={severity}")
        if agent_id:
            q_parts.append(f"agent.id={agent_id}")
        if rule_id:
            q_parts.append(f"rule.id={rule_id}")

        time_params = self._build_time_params(hours, start, end)
        if q_parts:
            # Combine existing q from time_params with extra filters
            combined_q = ";".join(q_parts)
            existing_q = time_params.pop("q", "")
            time_params["q"] = f"{existing_q};{combined_q}" if existing_q else combined_q
        params.update(time_params)

        resp = await self._get(self._ALERTS_ENDPOINT, params=params)
        data = resp.get("data", {})
        alerts: List[Dict[str, Any]] = data.get("affected_items", [])
        total: int = data.get("total_affected_items", 0)

        logger.info(
            "wazuh_alerts_queried",
            total=total,
            returned=len(alerts),
            page=page,
            hours=hours,
        )
        return alerts, total

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a single Wazuh alert by its ``_id``.

        Returns:
            Alert dict, or ``None`` if not found.
        """
        resp = await self._get(f"{self._ALERTS_ENDPOINT}/{alert_id}")
        data = resp.get("data", {})
        items: List[Dict[str, Any]] = data.get("affected_items", [])
        if not items:
            logger.warning("wazuh_alert_not_found", id=alert_id)
            return None
        return items[0]

    async def list_agents(
        self,
        *,
        status: Optional[str] = None,
        group: Optional[str] = None,
        limit: int = 100,
        page: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List Wazuh agents with optional status / group filters.

        Args:
            status: Agent status filter (``"active"``, ``"disconnected"``, ``"never_connected"``).
            group:  Agent group name filter.
            limit:  Page size.
            page:   Zero-based page number.

        Returns:
            Tuple of (agent list, total agent count).
        """
        size = min(limit, self.config.max_page_size)
        params: Dict[str, Any] = {
            "limit": size,
            "offset": page * size,
            "pretty": False,
        }
        if status:
            params["status"] = status
        if group:
            params["group"] = group

        resp = await self._get(self._AGENTS_ENDPOINT, params=params)
        data = resp.get("data", {})
        agents: List[Dict[str, Any]] = data.get("affected_items", [])
        total: int = data.get("total_affected_items", 0)
        logger.info("wazuh_agents_listed", total=total, returned=len(agents))
        return agents, total

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a single Wazuh agent by ID (zero-padded string, e.g. ``"001"``).

        Returns:
            Agent dict, or ``None`` if not found.
        """
        resp = await self._get(f"{self._AGENTS_ENDPOINT}/{agent_id}")
        data = resp.get("data", {})
        items: List[Dict[str, Any]] = data.get("affected_items", [])
        if not items:
            logger.warning("wazuh_agent_not_found", id=agent_id)
            return None
        return items[0]

    async def iter_alerts(
        self,
        *,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        hours: Optional[int] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        page_size: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator that yields all matching alerts page by page.

        Example::

            async for alert in conn.iter_alerts(hours=72, severity="high"):
                process(alert)
        """
        page_size = min(page_size or self.config.default_page_size, self.config.max_page_size)
        page = 0
        while True:
            batch, total = await self.query_alerts(
                severity=severity,
                agent_id=agent_id,
                rule_id=rule_id,
                hours=hours,
                start=start,
                end=end,
                limit=page_size,
                page=page,
            )
            if not batch:
                break
            for alert in batch:
                yield alert
            page += 1
            if page * page_size >= total:
                break
