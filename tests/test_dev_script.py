"""The dev workflow script's safety checks.

These matter because the failure it guards against is silent: a test run that
passes against an installed copy of the package looks exactly like a healthy
run. Each test pins one of the checks that makes it loud instead.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "dev.py"


@pytest.fixture(scope="module")
def dev():
    spec = importlib.util.spec_from_file_location("ssh_mcp_dev", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_src_paths_are_recognised(dev):
    assert dev.is_from_src(str(dev.SRC / "ssh_mcp" / "__init__.py"))


def test_site_packages_paths_are_rejected(dev, tmp_path):
    """The whole point: an installed copy must not count as "from src"."""
    assert not dev.is_from_src(str(tmp_path / "site-packages" / "ssh_mcp" / "__init__.py"))


def test_missing_path_is_not_from_src(dev):
    assert not dev.is_from_src(None)
    assert not dev.is_from_src("")


def test_stale_dirs_finds_pip_leftovers(dev, tmp_path, monkeypatch):
    site = tmp_path / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (site / "~sh_mcp").mkdir()
    (site / "~sh_mcp-0.1.0.dist-info").mkdir()
    (site / "asyncssh").mkdir()
    monkeypatch.setattr(dev, "VENV", tmp_path)
    monkeypatch.setattr(dev, "IS_WINDOWS", True)

    found = [p.name for p in dev.stale_dirs()]
    assert found == ["~sh_mcp", "~sh_mcp-0.1.0.dist-info"]


def test_write_pth_points_at_src(dev, tmp_path, monkeypatch):
    monkeypatch.setattr(dev, "VENV", tmp_path)
    monkeypatch.setattr(dev, "IS_WINDOWS", True)
    dev.write_pth()
    pth = tmp_path / "Lib" / "site-packages" / dev.PTH_NAME
    assert pth.is_file()
    assert pth.read_text(encoding="utf-8").strip() == str(dev.SRC.resolve())


def test_write_pth_is_idempotent(dev, tmp_path, monkeypatch):
    monkeypatch.setattr(dev, "VENV", tmp_path)
    monkeypatch.setattr(dev, "IS_WINDOWS", True)
    dev.write_pth()
    pth = tmp_path / "Lib" / "site-packages" / dev.PTH_NAME
    before = pth.stat().st_mtime_ns
    dev.write_pth()
    assert pth.stat().st_mtime_ns == before


def test_python_probe_does_not_inject_src_by_default(dev, monkeypatch):
    """A probe that injects src/ would report a healthy import no matter what.

    ``doctor`` and ``test`` rely on the probe seeing the *real* environment, so
    the helper must only prepend src/ when explicitly asked.
    """
    captured: dict[str, str] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
        captured["env"] = kwargs.get("env", {})
        return _Result()

    monkeypatch.setattr(dev.subprocess, "run", fake_run)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    dev.run(["python", "-c", "pass"], capture=True, quiet=True, inherit_src=False)
    assert "PYTHONPATH" not in captured["env"]

    dev.run(["python", "-c", "pass"], capture=True, quiet=True, inherit_src=True)
    assert str(dev.SRC) in captured["env"]["PYTHONPATH"]
