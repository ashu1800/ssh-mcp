"""Atomic replace: retries the Windows sharing violation, then falls back."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ssh_mcp.fsutil import replace_with_retry, remove_quietly


def _lock_times(monkeypatch, times: int) -> dict[str, int]:
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] <= times:
            raise PermissionError(32, "in use")
        return real_replace(src, dst)

    monkeypatch.setattr("ssh_mcp.fsutil.os.replace", flaky)
    monkeypatch.setattr("ssh_mcp.fsutil.time.sleep", lambda _seconds: None)
    return calls


def test_replaces_after_a_transient_lock(tmp_path: Path, monkeypatch):
    tmp, target = tmp_path / "a.tmp", tmp_path / "a.json"
    tmp.write_text("new", encoding="utf-8")
    calls = _lock_times(monkeypatch, 2)
    replace_with_retry(tmp, target)
    assert calls["n"] == 3
    assert target.read_text(encoding="utf-8") == "new"
    assert not tmp.exists()


def test_reraises_when_the_lock_never_clears(tmp_path: Path, monkeypatch):
    tmp, target = tmp_path / "a.tmp", tmp_path / "a.json"
    tmp.write_text("new", encoding="utf-8")
    _lock_times(monkeypatch, 99)
    with pytest.raises(PermissionError):
        replace_with_retry(tmp, target)
    # The caller still owns the temp file and can decide what to do with it.
    assert tmp.exists()


def test_fallback_writes_in_place_and_drops_the_temp(tmp_path: Path, monkeypatch):
    tmp, target = tmp_path / "a.tmp", tmp_path / "a.json"
    tmp.write_text("new", encoding="utf-8")
    _lock_times(monkeypatch, 99)
    replace_with_retry(
        tmp, target, fallback=lambda: target.write_text("new", encoding="utf-8")
    )
    assert target.read_text(encoding="utf-8") == "new"
    assert not tmp.exists()


def test_remove_quietly_ignores_a_missing_file(tmp_path: Path):
    remove_quietly(tmp_path / "never-created")
