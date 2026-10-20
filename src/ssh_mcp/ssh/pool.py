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

import asyncssh

from ssh_mcp.config import Settings
from ssh_mcp.errors import ConnectionMissing, ToolFailure
from ssh_mcp.models import CredentialPayload
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

    def __init__(self, settings: Settings, connector: Connector) -> None:
        self._settings = settings
        self._connector = connector
        self._entries: dict[tuple[str, int, str], PoolEntry] = {}
        self._by_handle: dict[str, tuple[str, int, str]] = {}
        self._map_lock = asyncio.Lock()
        self._reaper: asyncio.Task | None = None
        self._closed = False

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
        """Close idle entries; returns the keys that were closed."""
        if self._settings.pool_idle_timeout <= 0:
            return []
        now = time.monotonic()
        closed: list[tuple[str, int, str]] = []
        async with self._map_lock:
            candidates = [
                entry
                for entry in self._entries.values()
                if entry.in_flight == 0 and (now - entry.last_used) >= self._settings.pool_idle_timeout
            ]
        for entry in candidates:
            async with entry.lock:
                if entry.in_flight != 0 or (time.monotonic() - entry.last_used) < self._settings.pool_idle_timeout:
                    continue
                async with self._map_lock:
                    self._entries.pop(entry.key, None)
                    self._by_handle.pop(entry.handle, None)
                await self._close_entry(entry)
                closed.append(entry.key)
                logger.info("closed idle SSH connection to %s@%s:%s", entry.username, entry.host, entry.port)
        return closed

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
                entry.touch()
                return entry

            if entry.is_alive() and force_new:
                await self._close_entry(entry)

            try:
                result: ConnectResult = await self._connector.connect(payload, timeout=timeout)
            except ConnectFailure:
                raise
            except Exception as exc:  # noqa: BLE001
                raise ToolFailure(
                    "connect_failed",
                    stage="connect",
                    hint=f"建立连接时发生意外错误（{type(exc).__name__}），请重试。",
                    retryable=True,
                    host=payload.host,
                    port=payload.port,
                ) from None

            entry.conn = result.conn
            entry.auth_method = result.auth_method
            entry.compression = result.compression
            entry.warning = result.warning
            entry.sftp = None
            previous_handle = entry.handle
            entry.handle = secrets.token_urlsafe(18)
            entry.touch()
            async with self._map_lock:
                # Retire the old handle: it must not resolve to the rebuilt
                # connection, or a stale handle could disconnect a live entry.
                if previous_handle != entry.handle:
                    self._by_handle.pop(previous_handle, None)
                self._by_handle[entry.handle] = key
            return entry

    async def acquire(self, handle: str) -> Acquired:
        """Borrow the entry behind ``handle`` for the duration of one tool call."""
        key = self._by_handle.get(handle)
        if key is None:
            raise ConnectionMissing(handle)
        entry = self._entries.get(key)
        if entry is None or entry.handle != handle or not entry.is_alive():
            raise ConnectionMissing(handle)
        entry.in_flight += 1
        entry.touch()
        assert entry.conn is not None
        return Acquired(entry=entry, conn=entry.conn, _pool=self)

    def release(self, entry: PoolEntry) -> None:
        entry.in_flight = max(0, entry.in_flight - 1)
        entry.touch()

    async def sftp_for(self, entry: PoolEntry) -> asyncssh.SFTPClient:
        """Return the entry's shared SFTP channel, opening it on first use."""
        if entry.sftp is not None:
            return entry.sftp
        async with entry.sftp_lock:
            if entry.sftp is not None:
                return entry.sftp
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
        return {"entries": entries, "count": len(entries)}

    # -- internals ------------------------------------------------------------

    async def _get_or_create_entry(self, key: tuple[str, int, str]) -> PoolEntry:
        async with self._map_lock:
            entry = self._entries.get(key)
            if entry is not None:
                return entry
            entry = PoolEntry(key=key, handle=secrets.token_urlsafe(18))
            self._entries[key] = entry
            self._by_handle[entry.handle] = key
            return entry


@contextlib.asynccontextmanager
async def borrow(pool: ConnectionPool, handle: str) -> AsyncIterator[Acquired]:
    acquired = await pool.acquire(handle)
    try:
        yield acquired
    finally:
        pool.release(acquired.entry)
