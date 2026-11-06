"""Local connection history: which server was used, and when.

The payoff is cross-restart continuity: ``connect`` with no argument reopens
the most recent server, and ``list_servers`` annotates rows with ``last_used``
so the AI can pick "the one from yesterday" without asking. The file is tiny
and rewritten on every successful connect; there is no prune step because its
size is bounded by the number of servers the credential service issues.

Writing is best-effort on purpose. This is bookkeeping, not shared state: a
sync client, indexer or antivirus holding ``history.json`` open for a moment
must never turn a working connection into a failed one.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

from ssh_mcp.fsutil import replace_with_retry

logger = logging.getLogger(__name__)


def _load(path: Path) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def record_connect(path: Path, server_id: str, alias: str | None) -> None:
    """Note a successful connect; never raises because of a filesystem hiccup."""
    entries = _load(path)
    entries[str(server_id)] = {"alias": alias, "last_used": time.time()}
    payload = json.dumps(entries, ensure_ascii=False, sort_keys=True)
    # A per-write suffix keeps two concurrent connects from sharing one temp
    # file and renaming each other's half-written content into place.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(payload, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        replace_with_retry(
            tmp, path, fallback=lambda: path.write_text(payload, encoding="utf-8")
        )
    except OSError as exc:  # noqa: BLE001 - bookkeeping must not fail a connect
        logger.warning("could not record connection history (%s); continuing", type(exc).__name__)
        with contextlib.suppress(OSError):
            tmp.unlink()


def last_used(path: Path, server_id: str) -> float | None:
    """Epoch seconds of the last successful connect, or None."""
    entry = _load(path).get(str(server_id))
    value = entry.get("last_used") if isinstance(entry, dict) else None
    return float(value) if value else None


def most_recent(path: Path) -> dict[str, Any] | None:
    """The newest entry as ``{server_id, alias, last_used}``, or None."""
    entries = _load(path)
    if not entries:
        return None
    server_id, entry = max(entries.items(), key=lambda kv: float(kv[1].get("last_used") or 0.0))
    return {
        "server_id": server_id,
        "alias": entry.get("alias"),
        "last_used": float(entry.get("last_used") or 0.0),
    }
