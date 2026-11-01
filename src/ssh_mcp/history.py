"""Local connection history: which server was used, and when.

The payoff is cross-restart continuity: ``connect`` with no argument reopens
the most recent server, and ``list_servers`` annotates rows with ``last_used``
so the AI can pick "the one from yesterday" without asking. The file is tiny
and rewritten on every successful connect; there is no prune step because its
size is bounded by the number of servers the credential service issues.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _load(path: Path) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def record_connect(path: Path, server_id: str, alias: str | None) -> None:
    """Note a successful connect; atomic write so a crash cannot truncate it."""
    entries = _load(path)
    entries[str(server_id)] = {"alias": alias, "last_used": time.time()}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(entries, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:  # pragma: no cover - Windows ACLs govern there
        pass
    os.replace(tmp, path)


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
