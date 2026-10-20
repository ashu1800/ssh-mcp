"""Client for the credential service (``GET /api/mcp/credentials``).

The service returns the server list plus one encrypted blob per server. Only a
short in-memory TTL cache is kept: the service sends ``Cache-Control: no-store``
and a blob carries the same authority as the token, so nothing is written to
disk.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx2

from ssh_mcp.config import Settings
from ssh_mcp.crypto.blob_decryptor import decrypt_blob
from ssh_mcp.errors import ToolFailure
from ssh_mcp.models import CredentialPayload, ServerSummary

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = {500, 502, 503, 504}
# How long a failed fetch is shared before another attempt is allowed.
_FAILURE_TTL = 10.0


@dataclass
class _CacheEntry:
    fetched_at: float
    servers: list[dict[str, Any]]


class CredentialServiceError(ToolFailure):
    """The credential service could not be reached or refused the token."""

    def __init__(self, error: str, hint: str, *, stage: str = "credentials", retryable: bool = False, **details):
        super().__init__(error, stage=stage, hint=hint, retryable=retryable, **details)


class CredentialClient:
    """Fetches and decrypts server credentials, with a short in-memory cache."""

    def __init__(self, settings: Settings, transport: httpx2.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._cache: _CacheEntry | None = None
        self._lock = asyncio.Lock()
        self._last_failure: CredentialServiceError | None = None
        self._last_failure_at = 0.0
        self._client = httpx2.AsyncClient(
            timeout=httpx2.Timeout(settings.credentials_timeout),
            transport=transport,
            follow_redirects=False,
            # The service rejects a browser-style Origin header; httpx2 does not
            # add one, but be explicit so nothing in the stack introduces it.
            headers={"Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- public API -----------------------------------------------------------

    async def list_servers(self, *, refresh: bool = False) -> list[ServerSummary]:
        entry = await self._fetch(refresh=refresh)
        summaries: list[ServerSummary] = []
        for item in entry.servers:
            summaries.append(
                ServerSummary(
                    server_id=str(item.get("server_id")),
                    alias=str(item.get("alias") or f"服务器 #{item.get('server_id')}"),
                    encrypted_blob_ref=str(item.get("encrypted_blob_ref") or ""),
                    auth_type=item.get("auth_type"),
                    group_name=item.get("group_name"),
                )
            )
        return summaries

    async def get_credential(self, server_id: str, *, refresh: bool = False) -> CredentialPayload:
        """Return the decrypted payload for ``server_id``.

        Refreshes the list once when the server is absent from a cached response
        (a server added or re-keyed since the last fetch), then fails with
        ``server_not_found``.
        """
        started = time.monotonic()
        entry = await self._fetch(refresh=refresh)
        blob = self._find_blob(entry, server_id)
        # Only re-download when the answer came from a cache that predates this
        # call; a cache that was cold or expired was fetched just now.
        if blob is None and not refresh and entry.fetched_at < started:
            entry = await self._fetch(refresh=True)
            blob = self._find_blob(entry, server_id)
        if blob is None:
            raise CredentialServiceError(
                "server_not_found",
                f"服务器列表中不存在 server_id={server_id}，请先调用 list_servers 确认可用服务器。",
                retryable=True,
                server_id=server_id,
            )
        # ``DecryptFailed`` is already a ``ToolFailure``; let it through as-is.
        return decrypt_blob(self._settings.mcp_key, blob)

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _find_blob(entry: _CacheEntry, server_id: str) -> dict[str, Any] | None:
        for item in entry.servers:
            if str(item.get("server_id")) == str(server_id):
                blob = item.get("blob")
                if isinstance(blob, dict):
                    return blob
                return None
        return None

    def _cache_valid(self, entry: _CacheEntry | None) -> bool:
        if entry is None:
            return False
        ttl = self._settings.credentials_cache_ttl
        if ttl <= 0:
            return False
        return (time.monotonic() - entry.fetched_at) < ttl

    async def _fetch(self, *, refresh: bool) -> _CacheEntry:
        if not refresh and self._cache_valid(self._cache):
            return self._cache  # type: ignore[return-value]
        async with self._lock:
            # Another caller may have refreshed while we waited for the lock.
            if not refresh and self._cache_valid(self._cache):
                return self._cache  # type: ignore[return-value]
            if not refresh and self._last_failure is not None and (time.monotonic() - self._last_failure_at) < _FAILURE_TTL:
                # Waiters that piled up behind a failing fetch must not each run
                # their own retry/backoff sequence; share the failure briefly.
                raise self._last_failure
            try:
                entry = await self._request_with_retry()
            except CredentialServiceError as exc:
                if exc.retryable:
                    self._last_failure = exc
                    self._last_failure_at = time.monotonic()
                raise
            self._cache = entry
            self._last_failure = None
            return entry

    async def _request_with_retry(self) -> _CacheEntry:
        attempts = self._settings.credentials_max_retries + 1
        delay = 0.5
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return await self._request_once()
            except _Retryable as exc:
                last_error = exc.cause
                if attempt == attempts - 1:
                    break
                logger.info(
                    "credential service unavailable (attempt %d/%d): %s; retrying in %.1fs",
                    attempt + 1,
                    attempts,
                    exc.brief,
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 8.0)
        raise CredentialServiceError(
            "credentials_unavailable",
            "无法从服务器管理服务获取凭据，请检查网络连通性后重试。",
            retryable=True,
            detail=str(last_error) if last_error else None,
        )

    async def _request_once(self) -> _CacheEntry:
        url = self._settings.credentials_url
        try:
            response = await self._client.get(
                url, headers={"Authorization": f"Bearer {self._settings.mcp_key}"}
            )
        except httpx2.HTTPError as exc:
            raise _Retryable(str(exc), exc) from None

        status = response.status_code
        if status == 401:
            # The service answers 401 with plain text, not JSON.
            raise CredentialServiceError(
                "mcp_key_invalid",
                "MCP 密钥无效、已禁用或已过期，请在服务器管理端重新签发并更新 MCP_KEY。",
                retryable=False,
                status=status,
            )
        if status == 403:
            raise CredentialServiceError(
                "mcp_key_forbidden",
                "MCP 密钥缺少 servers:credential 权限，请用 scopes=[] 重新签发密钥。",
                retryable=False,
                status=status,
            )
        if status in _RETRYABLE_STATUS:
            raise _Retryable(f"HTTP {status}", None)
        if status != 200:
            raise CredentialServiceError(
                "credentials_unavailable",
                f"服务器管理服务返回了意外状态码 {status}，请稍后重试。",
                retryable=True,
                status=status,
            )

        try:
            body = response.json()
        except ValueError:
            raise CredentialServiceError(
                "credentials_invalid",
                "服务器管理服务返回了无法解析的响应，请稍后重试。",
                retryable=True,
            ) from None

        if not isinstance(body, dict) or body.get("code") != 200:
            message = body.get("message") if isinstance(body, dict) else None
            raise CredentialServiceError(
                "credentials_invalid",
                f"服务器管理服务返回错误：{message or '未知错误'}",
                retryable=True,
            )

        data = body.get("data") or {}
        servers = data.get("servers")
        if not isinstance(servers, list):
            servers = []
        return _CacheEntry(
            fetched_at=time.monotonic(),
            servers=[item for item in servers if isinstance(item, dict)],
        )


class _Retryable(Exception):
    def __init__(self, brief: str, cause: Exception | None) -> None:
        super().__init__(brief)
        self.brief = brief
        self.cause = cause
