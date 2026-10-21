"""Local path policy: unrestricted by default, confined only when configured."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssh_mcp.config import ConfigError, Settings, load_settings
from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.transfer import resolve_local_target

TOKEN = "mcp_testtoken_0123456789abcdefghij"


def _settings(**kwargs) -> Settings:
    return Settings(mcp_key=TOKEN, **kwargs)


def test_local_paths_are_unrestricted_by_default():
    settings = _settings()
    assert settings.allowed_local_roots == []
    assert settings.local_paths_restricted is False


def test_unrestricted_settings_accept_any_path(tmp_path: Path):
    settings = _settings()
    outside = tmp_path / "somewhere" / "build" / "rdp-backend-linux-amd64"
    assert settings.resolve_local_path(str(outside)) == outside.resolve(strict=False)


def test_configuring_a_root_turns_the_restriction_on(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    settings = _settings(allowed_local_roots=[allowed])
    assert settings.local_paths_restricted is True
    assert settings.resolve_local_path(str(allowed / "f.bin")) == (allowed / "f.bin").resolve(strict=False)


def test_a_configured_root_rejects_paths_outside_it(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    settings = _settings(allowed_local_roots=[allowed])
    with pytest.raises(Exception) as excinfo:
        settings.resolve_local_path(str(tmp_path / "elsewhere" / "f.bin"))
    assert "不在允许的本地根目录内" in str(excinfo.value)


def test_resolve_local_target_reports_allowed_roots_when_restricted(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    settings = _settings(allowed_local_roots=[allowed])
    with pytest.raises(ToolFailure) as excinfo:
        resolve_local_target(settings, str(tmp_path / "outside.bin"))
    assert excinfo.value.error == "path_not_allowed"
    assert excinfo.value.details["allowed_roots"] == [str(allowed)]


def test_resolve_local_target_allows_anything_when_unrestricted(tmp_path: Path):
    settings = _settings()
    target = resolve_local_target(settings, str(tmp_path / "build" / "artifact"))
    assert target == (tmp_path / "build" / "artifact").resolve(strict=False)


def test_empty_values_are_still_rejected():
    """Dropping the sandbox must not drop the basic argument checks."""
    settings = _settings()
    for bad in ("", "   "):
        with pytest.raises(Exception):
            settings.resolve_local_path(bad)
    with pytest.raises(Exception):
        settings.resolve_local_path("a\x00b")


# -- environment / TOML -------------------------------------------------------


def test_no_env_or_toml_means_unrestricted(tmp_path: Path):
    settings = load_settings({"MCP_KEY": TOKEN, "SSH_MCP_STATE_DIR": str(tmp_path)})
    assert settings.allowed_local_roots == []
    assert settings.local_paths_restricted is False


def test_env_sets_the_roots(tmp_path: Path):
    roots = f"{tmp_path / 'a'}{';' if __import__('os').name == 'nt' else ':'}{tmp_path / 'b'}"
    settings = load_settings(
        {"MCP_KEY": TOKEN, "SSH_MCP_STATE_DIR": str(tmp_path), "SSH_MCP_ALLOWED_LOCAL_ROOTS": roots}
    )
    assert [p.name for p in settings.allowed_local_roots] == ["a", "b"]
    assert settings.local_paths_restricted is True


def test_toml_list_sets_the_roots(tmp_path: Path):
    config = tmp_path / "config.toml"
    # TOML treats backslashes as escapes; forward slashes work on every platform.
    toml_path = (tmp_path / "only").as_posix()
    config.write_text(f'allowed_local_roots = ["{toml_path}"]\n', encoding="utf-8")
    settings = load_settings({"MCP_KEY": TOKEN, "SSH_MCP_STATE_DIR": str(tmp_path), "SSH_MCP_CONFIG": str(config)})
    assert settings.local_paths_restricted is True
    assert settings.allowed_local_roots[0].name == "only"


# -- write-only allowlist -----------------------------------------------------


def test_write_roots_confine_writes_but_not_reads(tmp_path: Path):
    safe = tmp_path / "safe"
    safe.mkdir()
    settings = _settings(write_local_roots=[safe])

    # Writing anywhere else is refused...
    with pytest.raises(Exception) as excinfo:
        settings.resolve_local_path(str(tmp_path / "elsewhere" / "f.bin"), write=True)
    assert "允许写入" in str(excinfo.value)
    # ...but reading there is still allowed, which is the whole point.
    assert settings.resolve_local_path(str(tmp_path / "elsewhere" / "f.bin")) == (
        tmp_path / "elsewhere" / "f.bin"
    ).resolve(strict=False)
    # And writing inside the safe root works.
    assert settings.resolve_local_path(str(safe / "f.bin"), write=True) == (safe / "f.bin").resolve(strict=False)


def test_write_roots_do_not_unlock_the_read_allowlist(tmp_path: Path):
    """Both lists apply: a write root outside the read roots is still a read failure."""
    readable = tmp_path / "readable"
    writable = tmp_path / "writable"
    readable.mkdir()
    writable.mkdir()
    settings = _settings(allowed_local_roots=[readable], write_local_roots=[writable])

    # Inside the write root, so the write check passes...
    assert settings.resolve_local_path(str(writable / "f"), write=True) == (writable / "f").resolve(strict=False)
    # ...but a plain read of it is outside the read roots.
    with pytest.raises(Exception):
        settings.resolve_local_path(str(writable / "f"))


def test_env_sets_write_roots(tmp_path: Path):
    settings = load_settings(
        {
            "MCP_KEY": TOKEN,
            "SSH_MCP_STATE_DIR": str(tmp_path),
            "SSH_MCP_WRITE_LOCAL_ROOTS": str(tmp_path / "downloads"),
        }
    )
    assert settings.local_writes_restricted is True
    assert settings.local_paths_restricted is False
