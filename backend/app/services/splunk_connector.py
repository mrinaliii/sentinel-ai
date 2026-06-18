"""
Splunk Connector
=================
Async service class for querying alerts and events from a Splunk instance
via the Splunk REST API (Search API v2).

Authentication methods:
  - Username / password  → session token acquired on connect
  - Pre-issued auth token → supplied directly in constructor

Capabilities:
  - run_search()        : execute a synchronous/blocking SPL search job
  - query_alerts()      : page through notable events (ES notable index)
  - get_alert_by_id()   : fetch a single notable event by event ID
  - test_connection()   : lightweight health/auth check
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from app.core.exceptions import SentinelBaseException
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class SplunkConnectorError(SentinelBaseException):
    """Raised for all Splunk connector failures."""

    error_code = "SPLUNK_CONNECTOR_ERROR"

    def __init__(self, operation: str, cause: str) -> None:
        super().__init__(
            message=f"Splunk operation '{operation}' failed: {cause}",
            details={"operation": operation, "cause": cause},
        )


class SplunkAuthError(SplunkConnectorError):
    """Raised when Splunk authentication fails."""

    error_code = "SPLUNK_AUTH_ERROR"

    def __init__(self, cause: str) -> None:
        super().__init__(operation="authenticate", cause=cause)


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class SplunkConfig:
    """All configuration needed to connect to a Splunk instance."""

    host: str
    port: int = 8089
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None                # pre-issued auth token
    verify_ssl: bool = True
    timeout: int = 30                          # per-request timeout (seconds)
    max_retries: int = 3
    # Default search window if no explicit window is supplied
    default_earliest: str = "-24h"
    default_latest: str = "now"
    # Pagination
    default_page_size: int = 100
    max_page_size: int = 1000

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def __post_init__(self) -> None:
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "SplunkConfig requires either a 'token' or both 'username' and 'password'."
            )


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class SplunkConnector:
    """
    Async Splunk connector.

    Usage::

        cfg = SplunkConfig(host="splunk.corp.local", username="admin", password="secret")
        async with SplunkConnector(cfg) as conn:
            alerts = await conn.query_alerts(limit=200)
    """

    _SEARCH_ENDPOINT = "/services/search/v2/jobs"
    _LOGIN_ENDPOINT = "/services/auth/login"
    _FIELD_SUMMARY = "/services/search/v2/jobs/{sid}/results"

    def __init__(self, config: SplunkConfig) -> None:
        self.config = config
        self._session_token: Optional[str] = config.token
        self._client: Optional[httpx.AsyncClient] = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def __aenter__(self) -> "SplunkConnector":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """Initialise the HTTP client and authenticate if needed."""
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not self._session_token:
            await self._authenticate()
        logger.info("splunk_connected", host=self.config.host)

    async def close(self) -> None:
        """Gracefully close the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("splunk_disconnected", host=self.config.host)

    # ── auth ──────────────────────────────────────────────────────────────

    async def _authenticate(self) -> None:
        """Exchange credentials for a Splunk session token."""
        assert self._client is not None, "Call connect() first."
        try:
            resp = await self._client.post(
                self._LOGIN_ENDPOINT,
                data={
                    "username": self.config.username,
                    "password": self.config.password,
                    "output_mode": "json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._session_token = data["sessionKey"]
            logger.info("splunk_authenticated", username=self.config.username)
        except httpx.HTTPStatusError as exc:
            raise SplunkAuthError(cause=str(exc)) from exc
        except Exception as exc:
            raise SplunkAuthError(cause=str(exc)) from exc

    @property
    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Splunk {self._session_token}"}

    # ── internal helpers ──────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        attempt: int = 1,
    ) -> Dict[str, Any]:
        """Perform a request with retry logic."""
        assert self._client is not None, "Call connect() first."
        try:
            resp = await self._client.request(
                method,
                endpoint,
                params={**(params or {}), "output_mode": "json"},
                data=data,
                headers=self._auth_headers,
            )
            if resp.status_code == 401 and attempt == 1 and not self.config.token:
                # Token may have expired; re-authenticate once
                logger.warning("splunk_token_expired_reauthenticating")
                await self._authenticate()
                return await self._request(method, endpoint, params=params, data=data, attempt=2)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise SplunkConnectorError(
                operation=f"{method} {endpoint}",
                cause=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            ) from exc
        except httpx.RequestError as exc:
            if attempt < self.config.max_retries:
                wait = 2 ** attempt
                logger.warning("splunk_request_retrying", attempt=attempt, wait=wait)
                await asyncio.sleep(wait)
                return await self._request(method, endpoint, params=params, data=data, attempt=attempt + 1)
            raise SplunkConnectorError(
                operation=f"{method} {endpoint}", cause=str(exc)
            ) from exc

    async def _run_search_job(
        self,
        spl: str,
        earliest: str,
        latest: str,
        max_count: int,
    ) -> str:
        """Create a Splunk search job and return its SID."""
        body = {
            "search": spl if spl.startswith("search") else f"search {spl}",
            "earliest_time": earliest,
            "latest_time": latest,
            "max_count": str(max_count),
            "exec_mode": "blocking",   # wait until complete
        }
        result = await self._request("POST", self._SEARCH_ENDPOINT, data=body)
        sid: str = result["sid"]
        logger.debug("splunk_job_created", sid=sid)
        return sid

    async def _fetch_results(
        self,
        sid: str,
        offset: int = 0,
        count: int = 100,
    ) -> Dict[str, Any]:
        """Retrieve a page of results for the given SID."""
        endpoint = self._FIELD_SUMMARY.format(sid=sid)
        return await self._request(
            "GET",
            endpoint,
            params={"offset": offset, "count": count},
        )

    # ── public API ─────────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        """Return True if the connector can authenticate and hit the API."""
        try:
            await self._request("GET", "/services/server/info")
            return True
        except SplunkConnectorError:
            return False

    async def run_search(
        self,
        spl: str,
        *,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Execute an arbitrary SPL search and return all results.

        Args:
            spl:       SPL query string (with or without leading ``search``).
            earliest:  Splunk time modifier for the start of the window (e.g. ``-24h``).
            latest:    Splunk time modifier for the end of the window (e.g. ``now``).
            limit:     Maximum number of results to return.

        Returns:
            List of result dicts.
        """
        earliest = earliest or self.config.default_earliest
        latest = latest or self.config.default_latest
        count = min(limit, self.config.max_page_size)

        sid = await self._run_search_job(spl, earliest, latest, count)
        data = await self._fetch_results(sid, offset=0, count=count)
        results: List[Dict[str, Any]] = data.get("results", [])
        logger.info("splunk_search_complete", sid=sid, returned=len(results))
        return results

    async def query_alerts(
        self,
        *,
        index: str = "notable",
        severity_filter: Optional[str] = None,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        limit: int = 100,
        page_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Splunk Enterprise Security notable events (alerts).

        Args:
            index:           Splunk index to search (default ``notable``).
            severity_filter: Optional urgency level filter (e.g. ``critical``, ``high``).
            earliest:        Window start; defaults to ``config.default_earliest``.
            latest:          Window end; defaults to ``config.default_latest``.
            limit:           Total maximum number of alerts to return.
            page_size:       Results fetched per page (defaults to ``config.default_page_size``).

        Returns:
            Flat list of alert dicts.
        """
        earliest = earliest or self.config.default_earliest
        latest = latest or self.config.default_latest
        page_size = min(page_size or self.config.default_page_size, self.config.max_page_size)

        spl_parts = [f"index={index}"]
        if severity_filter:
            spl_parts.append(f'urgency="{severity_filter}"')
        spl = " ".join(spl_parts) + " | table _time event_id rule_name urgency src dest user"

        sid = await self._run_search_job(spl, earliest, latest, limit)

        alerts: List[Dict[str, Any]] = []
        offset = 0
        while len(alerts) < limit:
            fetch_count = min(page_size, limit - len(alerts))
            page = await self._fetch_results(sid, offset=offset, count=fetch_count)
            batch: List[Dict[str, Any]] = page.get("results", [])
            if not batch:
                break
            alerts.extend(batch)
            offset += len(batch)
            if len(batch) < fetch_count:
                break  # no more results

        logger.info(
            "splunk_alerts_queried",
            index=index,
            earliest=earliest,
            latest=latest,
            total=len(alerts),
        )
        return alerts

    async def get_alert_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single notable event by its event_id.

        Returns:
            Alert dict, or ``None`` if not found.
        """
        results = await self.run_search(
            f'index=notable event_id="{event_id}"',
            limit=1,
        )
        return results[0] if results else None

    async def iter_alerts(
        self,
        *,
        index: str = "notable",
        severity_filter: Optional[str] = None,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        page_size: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator that yields alerts one page at a time.

        Useful for streaming large result sets without loading everything in
        memory at once::

            async for alert in conn.iter_alerts(earliest="-7d"):
                process(alert)
        """
        earliest = earliest or self.config.default_earliest
        latest = latest or self.config.default_latest
        page_size = min(page_size or self.config.default_page_size, self.config.max_page_size)

        spl_parts = [f"index={index}"]
        if severity_filter:
            spl_parts.append(f'urgency="{severity_filter}"')
        spl = " ".join(spl_parts) + " | table _time event_id rule_name urgency src dest user"

        # Use a large max so we can paginate freely
        sid = await self._run_search_job(spl, earliest, latest, max_count=self.config.max_page_size)

        offset = 0
        while True:
            page = await self._fetch_results(sid, offset=offset, count=page_size)
            batch: List[Dict[str, Any]] = page.get("results", [])
            if not batch:
                break
            for item in batch:
                yield item
            offset += len(batch)
            if len(batch) < page_size:
                break
