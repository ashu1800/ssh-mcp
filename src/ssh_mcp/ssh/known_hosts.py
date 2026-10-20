"""Host key verification and TOFU.

Two rules, both enforced here:

* A host with no entry is recorded on first successful use (trust on first use).
* A host with an entry must present a key from that entry. A different key is a
  hard failure -- the pin is never silently replaced.

The file is OpenSSH ``known_hosts`` format, so it can be inspected with regular
tooling, and it lives under the MCP state directory instead of ``~/.ssh``.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import asyncssh

logger = logging.getLogger(__name__)


def host_pattern(host: str, port: int) -> str:
    """Return the known_hosts host field for a target (port only when non-default)."""
    return host if port == 22 else f"[{host}]:{port}"


class KnownHostsStore:
    """Reads, matches, and appends host key pins."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> asyncssh.SSHKnownHosts:
        if not self._path.is_file():
            return asyncssh.SSHKnownHosts()
        try:
            return asyncssh.read_known_hosts(str(self._path))
        except (ValueError, OSError) as exc:
            # A corrupt pin file must not silently degrade to "trust everything".
            raise HostKeyStoreError(f"known_hosts 文件无法解析（{self._path}）：{exc}") from exc

    def lookup(self, host: str, addr: str | None, port: int) -> list[asyncssh.SSHKey]:
        """Return pinned keys for ``host``/``port`` (empty when unknown)."""
        store = self.load()
        keys = self._match(store, host, addr, port)
        if not keys and addr and addr != host:
            keys = self._match(store, host, None, port)
        return keys

    def pinned_store(self, host: str, addr: str | None, port: int) -> asyncssh.SSHKnownHosts | None:
        """Return a snapshot containing only ``host``'s entries, or ``None`` when unpinned.

        AsyncSSH accepts a :class:`~asyncssh.SSHKnownHosts` object as
        ``known_hosts``; it runs every key in it through the trust check, so the
        snapshot must hold exactly this host's lines and nothing else.
        """
        store = self.load()
        if not self._match(store, host, addr, port):
            return None
        pattern = host_pattern(host, port)
        lines: list[str] = []
        for line in self._path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split(None, 1)
            if not fields:
                continue
            if pattern in fields[0].split(","):
                lines.append(stripped)
        if not lines:
            return None
        return asyncssh.import_known_hosts("\n".join(lines) + "\n")

    @staticmethod
    def _match(store: asyncssh.SSHKnownHosts, host: str, addr: str | None, port: int):
        result = store.match(host, addr or "", port if port != 22 else None)
        return list(result[0])

    async def trust(self, host: str, port: int, key: asyncssh.SSHKey) -> None:
        """Append ``key`` for ``host:port`` unless an identical pin already exists."""
        async with self._lock:
            pattern = host_pattern(host, port)
            existing = self.lookup(host, None, port)
            if any(pin == key for pin in existing):
                return
            if existing:
                # Another key type was already pinned for this host. Record the
                # new type alongside it (the server may offer several types);
                # a *changed* key of an already-pinned type never reaches here
                # because matching would have failed the connection.
                logger.info("adding an additional host key type for %s", pattern)
            line = f"{pattern} {_public_key_text(key)}"
            await asyncio.to_thread(self._append_line, line)
            logger.info("pinned host key for %s (%s)", pattern, key.get_fingerprint("sha256"))

    def _append_line(self, line: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:  # pragma: no cover
            pass
        existing = ""
        if self._path.is_file():
            existing = self._path.read_text(encoding="utf-8", errors="replace")
        if existing and not existing.endswith("\n"):
            existing += "\n"
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(existing + line + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover
            pass
        os.replace(tmp, self._path)


class HostKeyStoreError(RuntimeError):
    """The pin file could not be read or written."""


def _public_key_text(key: asyncssh.SSHKey) -> str:
    exported = key.export_public_key("openssh")
    if isinstance(exported, bytes):
        exported = exported.decode("ascii")
    return exported.strip()
