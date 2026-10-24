"""In-process SSH connection pool.

One connection per ``(host, port, username)``, shared by every tool call. A
per-key lock makes concurrent ``connect`` calls collapse onto a single
connection instead of opening one each. Idle entries are closed by a background
reaper.

Calls address a pool entry through an opaque ``connection_handle``; the handle
survives for the life of the entry and is replaced when the entry is rebuilt.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import asyncssh

from ssh_mcp.config import Settings
from ssh_mcp.errors import ConnectionMissing, ToolFailure
from ssh_mcp.models import CredentialPayload

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.ssh.connector import ConnectFailure, ConnectResult, Connector

logger = logging.getLogger(__name__)


@dataclass
class PoolEntry:
    key: tuple[str, int, str]
    handle: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    conn: asyncssh.SSHClientConnection | None = None
    sftp: asyncssh.SFTPClient | None = None
    sftp_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    server_id: str | None = None
    auth_method: str = "password"
    compression: str = "zlib"
    warning: str | None = None
    in_flight: int = 0
    last_used: float = field(default_factory=time.monotonic)
    # Set when the socket is gone but the handle is kept alive so a caller
    # holding it can reconnect instead of seeing "connection_not_found".
    closed_at: float | None = None

    @property
    def host(self) -> str:
        return self.key[0]

    @property
    def port(self) -> int:
        return self.key[1]

    @property
    def username(self) -> str:
        return self.key[2]

    def is_alive(self) -> bool:
        return self.conn is not None and not self.conn.is_closed()

    def touch(self) -> None:
        self.last_used = time.monotonic()


@dataclass
class Acquired:
    """A borrowed pool entry; release it through :func:`borrow`."""

    entry: PoolEntry
    conn: asyncssh.SSHClientConnection
    _pool: "ConnectionPool"

    async def sftp_client(self) -> asyncssh.SFTPClient:
        return await self._pool.sftp_for(self.entry)


class ConnectionPool:
    """Pool of live SSH connections keyed by (host, port, username)."""

    def __init__(
        self,
        settings: Settings,
        connector: Connector,
        credentials: "CredentialClient | None" = None,
    ) -> None:
        self._settings = settings
        self._connector = connector
        # Used only to refetch a credential when a dead connection is rebuilt;
        # without it a lost socket means a lost handle.
        self._credentials = credentials
        # Limits simultaneous SSH handshakes; see max_concurrent_connects.
        self._connect_gate = asyncio.Semaphore(settings.max_concurrent_connects)
        self._entries: dict[tuple[str, int, str], PoolEntry] = {}
        self._by_handle: dict[str, tuple[str, int, str]] = {}
        self._map_lock = asyncio.Lock()
        self._counters: dict[str, int] = {}
        self._error_counts: dict[str, int] = {}
        self._reaper: asyncio.Task | None = None
        self._closed = False
        # Handle the client most recently used, so tools can omit it. Only
        # meaningful for a single-user transport (stdio); on the stateless HTTP
        # transport one process serves many callers, and letting an omitted
        # handle resolve to whoever connected last would cross sessions.
        self._default_handle: str | None = None

    # -- lifecycle ------------------------------------------------------------

    def start_reaper(self) -> None:
        """Start the idle-reaper task.

        Safe to call from synchronous setup: when no event loop is running yet
        the task is started lazily by the first :meth:`connect`.
        """
        if self._reaper is not None or self._closed:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._reaper = loop.create_task(self._reap_loop(), name="ssh-mcp-pool-reaper")

    async def aclose(self) -> None:
        self._closed = True
        reaper = self._reaper
        self._reaper = None
        if reaper is not None:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(reaper, timeout=1.0)
        entries = list(self._entries.values())
        self._entries.clear()
        self._by_handle.clear()
        for entry in entries:
            # Close each channel without letting one stuck connection block the
            # rest; ``asyncio.wait_for`` bounds a peer that never finishes the
            # SSH disconnect handshake.
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._close_entry(entry), timeout=3.0)

    async def _close_entry(self, entry: PoolEntry) -> None:
        sftp, entry.sftp = entry.sftp, None
        conn, entry.conn = entry.conn, None
        if sftp is not None:
            with contextlib.suppress(Exception):
                sftp.exit()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(sftp.wait_closed(), timeout=2)
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.wait_closed(), timeout=2)

    async def _reap_loop(self) -> None:
        interval = self._settings.pool_reaper_interval
        while True:
            try:
                await asyncio.sleep(interval)
                await self.reap_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the reaper must never die
                logger.exception("connection pool reaper failed")

    async def reap_once(self) -> list[tuple[str, int, str]]:
        """Close idle connections, keeping their handles usable.

        The socket is released but the entry (and therefore the handle the
        client is holding) stays behind: an idle timeout means "stop using
        resources", not "invalidate every handle the model was given". The
        next call through that handle reconnects transparently.

        Entries are dropped entirely once they have been idle-and-closed for
        ``pool_handle_ttl`` seconds, so handles cannot accumulate forever.
        """
        if self._settings.pool_idle_timeout <= 0:
            return []
        now = time.monotonic()
        closed: list[tuple[str, int, str]] = []
        async with self._map_lock:
            candidates = [
                entry
                for entry in self._entries.values()
                if entry.is_alive()
                and entry.in_flight == 0
                and (now - entry.last_used) >= self._settings.pool_idle_timeout
            ]
        for entry in candidates:
            async with entry.lock:
                if entry.in_flight != 0 or (time.monotonic() - entry.last_used) < self._settings.pool_idle_timeout:
                    continue
                await self._close_entry(entry)
                entry.closed_at = time.monotonic()
                closed.append(entry.key)
                logger.info(
                    "closed idle SSH connection to %s@%s:%s (handle stays valid)",
                    entry.username,
                    entry.host,
                    entry.port,
                )
        await self._expire_old_handles(now)
        return closed

    async def _expire_old_handles(self, now: float) -> int:
        """Drop handles that have been closed for longer than ``pool_handle_ttl``."""
        ttl = self._settings.pool_handle_ttl
        if ttl <= 0:
            return 0
        expired = 0
        async with self._map_lock:
            for key in list(self._entries):
                entry = self._entries[key]
                if entry.closed_at is None or entry.in_flight != 0:
                    continue
                if (now - entry.closed_at) < ttl:
                    continue
                self._entries.pop(key, None)
                self._by_handle.pop(entry.handle, None)
                if self._default_handle == entry.handle:
                    self._default_handle = None
                expired += 1
        if expired:
            logger.info("expired %d stale connection handle(s)", expired)
        return expired

    # -- public API -----------------------------------------------------------

    async def connect(
        self,
        payload: CredentialPayload,
        *,
        server_id: str | None = None,
        force_new: bool = False,
        timeout: float | None = None,
    ) -> PoolEntry:
        """Return a live entry for ``payload``, building it when needed."""
        key = payload.key
        if self._closed:
            raise ToolFailure("server_shutting_down", stage="pool", hint="服务正在关闭，请稍后重试。", retryable=True)
        self.start_reaper()
        entry = await self._get_or_create_entry(key)
        async with entry.lock:
            entry.server_id = server_id or str(payload.server_id)
            if entry.is_alive() and not force_new:
                self.record("connections_reused")
                entry.touch()
                self._default_handle = entry.handle
                return entry

            if entry.is_alive() and force_new:
                await self._close_entry(entry)

            # Gate the handshake itself, not the whole entry lock: a host that
            # accepts TCP and then stalls would otherwise leave one socket per
            # attempt, and a retrying client turns that into hundreds of
            # half-open sessions on the server.
            async with self._connect_gate:
                try:
                    result: ConnectResult = await self._connector.connect(payload, timeout=timeout)
                except ConnectFailure:
                    self.record("connect_failures")
                    raise
                except Exception as exc:  # noqa: BLE001
                    self.record("connect_failures")
                    raise ToolFailure(
                        "connect_failed",
                        stage="connect",
                        hint=f"建立连接时发生意外错误（{type(exc).__name__}），请重试。",
                        retryable=True,
                        host=payload.host,
                        port=payload.port,
                    ) from None

            self.record("connections_established")
            self.record(f"auth_{result.auth_method}")
            entry.conn = result.conn
            entry.auth_method = result.auth_method
            entry.compression = result.compression
            entry.warning = result.warning
            entry.sftp = None
            entry.closed_at = None
            # The handle is deliberately *not* rotated. A client that was given
            # this handle keeps it across reconnects; rotating it turned every
            # transient disconnect into "connection_not_found" for code that
            # was still holding the old value.
            entry.touch()
            async with self._map_lock:
                self._by_handle[entry.handle] = key
            self._default_handle = entry.handle
            return entry

    async def acquire(self, handle: str | None) -> Acquired:
        """Borrow the entry behind ``handle`` for the duration of one tool call.

        ``None`` means "the connection this client used last". That is only
        unambiguous on a single-user transport; the HTTP transport passes an
        explicit handle on every call.

        A handle whose socket has gone away is reconnected rather than
        rejected: idle reaping, a network blip and a server restart all look
        the same to the caller, and none of them should invalidate the handle
        the model is holding.
        """
        if handle is None:
            handle = self._default_handle
            if handle is None:
                raise ConnectionMissing(None)
        key = self._by_handle.get(handle)
        if key is None:
            raise ConnectionMissing(handle)
        entry = self._entries.get(key)
        if entry is None or entry.handle != handle:
            if self._default_handle == handle:
                self._default_handle = None
            raise ConnectionMissing(handle)

        if not entry.is_alive():
            await self._reconnect(entry)

        entry.in_flight += 1
        entry.touch()
        self._default_handle = handle
        assert entry.conn is not None
        return Acquired(entry=entry, conn=entry.conn, _pool=self)

    async def _reconnect(self, entry: PoolEntry) -> None:
        """Rebuild a dead entry in place, keeping its handle.

        The credential may have rotated since the connection was made, so it is
        fetched again (subject to the credential client's own short TTL cache)
        rather than reusing whatever the entry was built from.
        """
        if self._credentials is None or entry.server_id is None:
            raise ConnectionMissing(entry.handle)
        async with entry.lock:
            if entry.is_alive():
                return  # another caller won the race
            try:
                payload = await self._credentials.get_credential(str(entry.server_id))
            except ToolFailure:
                raise
            except Exception as exc:  # noqa: BLE001
                raise ToolFailure(
                    "connection_lost",
                    stage="reconnect",
                    hint=f"连接已断开，重新获取凭据失败（{type(exc).__name__}）。请调用 connect 重试。",
                    retryable=True,
                    connection_handle=entry.handle,
                ) from None
            try:
                # Same gate as ``connect``: a reconnect is a handshake too, and
                # a link flapping on many handles must not bypass the ceiling.
                async with self._connect_gate:
                    result = await self._connector.connect(payload)
            except ConnectFailure as exc:
                raise ToolFailure(
                    exc.error,
                    stage=exc.stage,
                    hint=f"连接已断开，自动重连失败：{exc.hint}",
                    retryable=exc.retryable,
                    connection_handle=entry.handle,
                    **{k: v for k, v in exc.details.items() if k not in {"stage"}},
                ) from None
            self.record("connections_reestablished")
            entry.conn = result.conn
            entry.auth_method = result.auth_method
            entry.compression = result.compression
            entry.warning = result.warning
            entry.sftp = None
            entry.closed_at = None
            entry.touch()
            logger.info("reconnected to %s@%s:%s", entry.username, entry.host, entry.port)

    def set_default(self, handle: str) -> None:
        """Remember ``handle`` as the implicit target for later calls."""
        if self._by_handle.get(handle) is not None:
            self._default_handle = handle

    def release(self, entry: PoolEntry) -> None:
        entry.in_flight = max(0, entry.in_flight - 1)
        entry.touch()

    async def sftp_for(self, entry: PoolEntry, *, force_new: bool = False) -> asyncssh.SFTPClient:
        """Return the entry's shared SFTP channel, opening it on first use.

        ``force_new`` drops the cached channel first. A channel outlives
        nothing: once its transport is gone it stays gone, so a transfer that
        wants to retry after a dropped connection must ask for a fresh one
        rather than the cached handle.
        """
        if force_new:
            old, entry.sftp = entry.sftp, None
            if old is not None:
                with contextlib.suppress(Exception):
                    old.exit()
        if entry.sftp is not None:
            return entry.sftp
        async with entry.sftp_lock:
            if entry.sftp is not None:
                return entry.sftp
            conn = entry.conn
            if conn is None or conn.is_closed():
                # Rebuild the transport in place; the handle survives, so a
                # retrying transfer does not have to reconnect by hand.
                await self._reconnect(entry)
                conn = entry.conn
            if conn is None or conn.is_closed():
                raise ConnectionMissing(entry.handle)
            entry.sftp = await conn.start_sftp_client()
            return entry.sftp

    async def disconnect(self, handle: str) -> tuple[str, int, str]:
        """Close the entry behind ``handle`` and forget it."""
        key = self._by_handle.get(handle)
        if key is None:
            raise ConnectionMissing(handle)
        entry = self._entries.get(key)
        # A rebuilt entry has a new handle; the old one is stale and must not
        # be able to tear down the connection that replaced it.
        if entry is None or entry.handle != handle:
            self._by_handle.pop(handle, None)
            raise ConnectionMissing(handle)
        async with entry.lock:
            async with self._map_lock:
                self._entries.pop(entry.key, None)
                self._by_handle.pop(entry.handle, None)
                if self._default_handle == entry.handle:
                    self._default_handle = None
            await self._close_entry(entry)
        return key

    def stats(self) -> dict:
        entries = []
        for entry in self._entries.values():
            entries.append(
                {
                    "handle": entry.handle,
                    "host": entry.host,
                    "port": entry.port,
                    "username": entry.username,
                    "server_id": entry.server_id,
                    "auth_method": entry.auth_method,
                    "alive": entry.is_alive(),
                    "in_flight": entry.in_flight,
                    "idle_seconds": round(time.monotonic() - entry.last_used, 1),
                }
            )
        return {
            "entries": entries,
            "count": len(entries),
            "max_entries": self._settings.pool_max_entries,
            "default_handle": self._default_handle,
            "counters": dict(self._counters),
            "errors": dict(self._error_counts),
        }

    def record(self, name: str, amount: int = 1) -> None:
        """Bump a lifetime counter, for the observability tool."""
        self._counters[name] = self._counters.get(name, 0) + amount

    def note_failure(self, error: str) -> None:
        self._error_counts[error] = self._error_counts.get(error, 0) + 1

    # -- internals ------------------------------------------------------------

    async def _get_or_create_entry(self, key: tuple[str, int, str]) -> PoolEntry:
        async with self._map_lock:
            entry = self._entries.get(key)
            if entry is not None:
                return entry
            # Cap the number of live connections. Rather than refusing at the
            # limit, evict the least recently used *idle* entry: a pool that has
            # grown to its ceiling is almost always holding connections nobody
            # is using any more.
            if len(self._entries) >= self._settings.pool_max_entries:
                victim = self._pick_eviction_victim()
                if victim is not None:
                    self._entries.pop(victim.key, None)
                    self._by_handle.pop(victim.handle, None)
                    asyncio.create_task(self._close_entry(victim), name="ssh-mcp-pool-evict")
                    logger.info(
                        "pool at capacity (%d); evicted idle connection to %s@%s:%s",
                        self._settings.pool_max_entries,
                        victim.username,
                        victim.host,
                        victim.port,
                    )
            entry = PoolEntry(key=key, handle=secrets.token_urlsafe(18))
            self._entries[key] = entry
            self._by_handle[entry.handle] = key
            return entry

    def _pick_eviction_victim(self) -> PoolEntry | None:
        """Least-recently-used entry that no tool call is currently using."""
        idle = [entry for entry in self._entries.values() if entry.in_flight == 0]
        if not idle:
            return None
        return min(idle, key=lambda entry: entry.last_used)


@contextlib.asynccontextmanager
async def borrow(pool: ConnectionPool, handle: str | None) -> AsyncIterator[Acquired]:
    acquired = await pool.acquire(handle)
    try:
        yield acquired
    finally:
        pool.release(acquired.entry)
