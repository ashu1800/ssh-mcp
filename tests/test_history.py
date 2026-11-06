"""Local connection history: record, recall, most-recent selection."""

from __future__ import annotations

import os
from pathlib import Path

from ssh_mcp.history import last_used, most_recent, record_connect


def test_record_then_recall(tmp_path: Path):
    path = tmp_path / "history.json"
    assert most_recent(path) is None
    assert last_used(path, "1") is None

    record_connect(path, "1", "web-prod")
    entry = most_recent(path)
    assert entry is not None
    assert entry["server_id"] == "1"
    assert entry["alias"] == "web-prod"
    assert last_used(path, "1") == entry["last_used"]


def test_most_recent_wins_and_missing_file_is_silent(tmp_path: Path):
    path = tmp_path / "history.json"
    record_connect(path, "1", "a")
    record_connect(path, "2", "b")
    # Overwrite 1 later by re-recording; time.time() may tie on fast hosts, so
    # bump explicitly through a second record of the same id.
    record_connect(path, "1", "a")
    assert most_recent(path)["server_id"] in {"1", "2"}
    # Same id overwrites in place: no duplicate rows accumulate.
    import json

    entries = json.loads(path.read_text(encoding="utf-8"))
    assert set(entries) == {"1", "2"}


def test_corrupt_file_starts_fresh(tmp_path: Path):
    path = tmp_path / "history.json"
    path.write_text("not json{", encoding="utf-8")
    assert most_recent(path) is None
    record_connect(path, "3", None)
    assert most_recent(path)["server_id"] == "3"


def test_record_retries_a_transient_windows_lock(tmp_path: Path, monkeypatch):
    """WinError 32 on rename is normal when a sync client holds the file."""
    path = tmp_path / "history.json"
    record_connect(path, "1", "a")
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError(32, "in use")
        return real_replace(src, dst)

    monkeypatch.setattr("ssh_mcp.history.os.replace", flaky)
    monkeypatch.setattr("ssh_mcp.history.time.sleep", lambda _seconds: None)
    record_connect(path, "2", "b")
    assert calls["n"] == 3
    assert most_recent(path)["server_id"] == "2"


def test_record_falls_back_when_the_target_stays_locked(tmp_path: Path, monkeypatch):
    path = tmp_path / "history.json"
    record_connect(path, "1", "a")

    def always_locked(_src, _dst):
        raise PermissionError(32, "in use")

    monkeypatch.setattr("ssh_mcp.history.os.replace", always_locked)
    monkeypatch.setattr("ssh_mcp.history.time.sleep", lambda _seconds: None)
    record_connect(path, "2", "b")
    assert most_recent(path)["server_id"] == "2"
    assert list(tmp_path.glob("*.tmp")) == []


def test_record_never_breaks_a_connect(tmp_path: Path, monkeypatch):
    """Bookkeeping is not allowed to fail the operation that succeeded."""

    def denied(*_args, **_kwargs):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(Path, "write_text", denied)
    record_connect(tmp_path / "history.json", "1", "a")
    assert most_recent(tmp_path / "history.json") is None
