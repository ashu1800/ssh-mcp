"""Local Ed25519 key management.

The private key never leaves this machine: only the public half is appended to
the remote ``~/.ssh/authorized_keys``. Files are created with restrictive
permissions where the platform honours them.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

import asyncssh

logger = logging.getLogger(__name__)


def key_id_for(host: str, port: int, username: str) -> str:
    """Stable filename-safe identifier for a connection target."""
    raw = f"{host}\x00{port}\x00{username}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, 0o700)


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - Windows may refuse; ACLs govern there
        logger.debug("could not set mode %o on %s", mode, path)


class KeyStore:
    """Loads or creates the per-server Ed25519 key pair used for key auth."""

    def __init__(self, keys_dir: Path) -> None:
        self._dir = keys_dir

    @property
    def directory(self) -> Path:
        return self._dir

    def path_for(self, host: str, port: int, username: str) -> Path:
        return self._dir / f"{key_id_for(host, port, username)}.key"

    def load(self, host: str, port: int, username: str) -> asyncssh.SSHKey | None:
        path = self.path_for(host, port, username)
        if not path.is_file():
            return None
        try:
            return asyncssh.read_private_key(str(path))
        except (asyncssh.KeyImportError, OSError) as exc:
            logger.warning("stored key for %s:%s is unreadable (%s); ignoring it", host, port, type(exc).__name__)
            return None

    def create(self, host: str, port: int, username: str, comment: str) -> asyncssh.SSHKey:
        ensure_private_dir(self._dir)
        key = asyncssh.generate_private_key("ssh-ed25519", comment=comment.encode("utf-8"))
        path = self.path_for(host, port, username)
        tmp = path.with_suffix(".key.tmp")
        # Write to a temporary file first so a crash cannot leave a truncated key.
        with tmp.open("wb") as handle:
            handle.write(key.export_private_key("openssh"))
        _chmod(tmp, 0o600)
        os.replace(tmp, path)
        _chmod(path, 0o600)
        logger.info("generated Ed25519 key for %s@%s:%s", username, host, port)
        return key

    def delete(self, host: str, port: int, username: str) -> None:
        path = self.path_for(host, port, username)
        try:
            path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            logger.warning("could not delete local key %s", path)


def public_key_line(key: asyncssh.SSHKey) -> str:
    """Return the OpenSSH one-line public key (``ssh-ed25519 AAAA... comment``)."""
    exported = key.export_public_key("openssh")
    if isinstance(exported, bytes):
        exported = exported.decode("ascii")
    return exported.strip()
