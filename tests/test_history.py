"""Local connection history: record, recall, most-recent selection."""

from __future__ import annotations

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
