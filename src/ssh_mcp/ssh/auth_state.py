"""Per-target authentication state.

State is keyed by ``(host, port, username)`` and deliberately contains no secret
material -- only which phase a target is in, when a key was rejected, and where
the local key file lives (the file itself holds the private key).

    UNKNOWN          no local key, or the key was marked invalid
    KEY_READY        a local key exists and last authenticated successfully
    PASSWORD_FALLBACK  the key was rejected; password auth is in use
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from ssh_mcp.ssh.keys import key_id_for

logger = logging.getLogger(__name__)


class AuthState(StrEnum):
    UNKNOWN = "UNKNOWN"
    KEY_READY = "KEY_READY"
    PASSWORD_FALLBACK = "PASSWORD_FALLBACK"


@dataclass
class AuthRecord:
    state: AuthState = AuthState.UNKNOWN
    invalid_at: float | None = None
    last_auth_method: str | None = None
    updated_at: float = 0.0


class AuthStateStore:
    """Loads and persists :class:`AuthRecord` entries as JSON."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._records: dict[str, AuthRecord] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("auth state file unreadable (%s); starting fresh", exc)
            return
        if not isinstance(raw, dict):
            return
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            try:
                self._records[key] = AuthRecord(
                    state=AuthState(value.get("state", "UNKNOWN")),
                    invalid_at=value.get("invalid_at"),
                    last_auth_method=value.get("last_auth_method"),
                    updated_at=float(value.get("updated_at") or 0.0),
                )
            except ValueError:
                logger.warning("ignoring malformed auth state entry for %s", key)

    def get(self, host: str, port: int, username: str) -> AuthRecord:
        self._ensure_loaded()
        return self._records.get(key_id_for(host, port, username), AuthRecord())

    async def set_state(
        self,
        host: str,
        port: int,
        username: str,
        state: AuthState,
        *,
        auth_method: str | None = None,
        mark_invalid: bool = False,
    ) -> None:
        self._ensure_loaded()
        key = key_id_for(host, port, username)
        now = time.time()
        record = self._records.get(key, AuthRecord())
        previous = record.state
        record.state = state
        record.updated_at = now
        if auth_method:
            record.last_auth_method = auth_method
        if mark_invalid:
            record.invalid_at = now
        self._records[key] = record
        if previous != state:
            logger.info("auth state for %s@%s:%s: %s -> %s", username, host, port, previous, state)
        await self._persist()

    async def mark_key_invalid(self, host: str, port: int, username: str) -> None:
        """Public-key auth was refused: keep the key for audit, stop using it."""
        await self.set_state(
            host, port, username, AuthState.PASSWORD_FALLBACK, auth_method="password", mark_invalid=True
        )

    async def _persist(self) -> None:
        async with self._lock:
            payload = {
                key: {
                    "state": record.state.value,
                    "invalid_at": record.invalid_at,
                    "last_auth_method": record.last_auth_method,
                    "updated_at": record.updated_at,
                }
                for key, record in self._records.items()
            }
            await asyncio.to_thread(self._write, payload)

    def _write(self, payload: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:  # pragma: no cover
            pass
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover
            pass
        os.replace(tmp, self._path)

    def snapshot(self) -> dict[str, dict]:
        self._ensure_loaded()
        return {key: asdict(record) for key, record in self._records.items()}
