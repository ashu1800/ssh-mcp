"""install.py key reuse: updates must find the key already in client configs."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("install_script", Path(__file__).resolve().parent.parent / "scripts" / "install.py")
install = importlib.util.module_from_spec(_SPEC)
sys.modules["install_script"] = install  # dataclass resolution inside install.py needs it registered
_SPEC.loader.exec_module(install)

KEY = "mcp_0123456789abcdef0123456789abcdef"


def test_extract_from_json_configs(tmp_path: Path):
    entry = {"command": "ssh-mcp", "args": [], "env": {"MCP_KEY": KEY}}
    for shape in (
        {"mcpServers": {"ssh": entry}},
        {"servers": {"ssh": {"type": "stdio", **entry}}},
        {"mcp": {"servers": {"ssh": {"type": "stdio", **entry}}}},
    ):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(shape), encoding="utf-8")
        assert install._extract_mcp_key(path) == KEY


def test_extract_from_dsh_profile_yaml(tmp_path: Path):
    path = tmp_path / "cordis.patch.yml"
    path.write_text(
        "\n".join(
            [
                "- insert:",
                "    - id: panel-mcp-ssh",
                "      config:",
                "        env:",
                "          MCP_KEY: " + KEY,
                "          SSH_MCP_STATE_DIR: 'C:\\Users\\me\\.ssh-mcp'",
                "        cwd: ''",
            ]
        ),
        encoding="utf-8",
    )
    assert install._extract_mcp_key(path) == KEY


def test_no_key_is_not_fabricated(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": {"other": {"env": {"MCP_KEY": "not-an-mcp-token"}}}}), encoding="utf-8")
    assert install._extract_mcp_key(path) is None
    assert install._extract_mcp_key(tmp_path / "missing.json") is None


def test_extract_from_single_quoted_yaml(tmp_path: Path):
    # ``\S+`` used to capture the quotes too, and the installer then wrote
    # ``'mcp_x'`` (quotes included) into env.MCP_KEY of every client.
    path = tmp_path / "cordis.patch.yml"
    path.write_text("        env:\n          MCP_KEY: 'mcp_single_quoted_token'\n", encoding="utf-8")
    assert install._extract_mcp_key(path) == "mcp_single_quoted_token"


def test_a_sibling_entrys_key_is_not_reused(tmp_path: Path):
    """``.claude.json`` holds one entry per server; only ours may win."""
    foreign = {"command": "panel-mcp-ssh", "args": [], "env": {"MCP_KEY": "mcp_foreign_token"}}
    ours = {"command": "ssh-mcp", "args": ["--transport", "stdio"], "env": {"MCP_KEY": KEY}}
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"mcpServers": {"panel-mcp-ssh": foreign, "ssh": ours}}), encoding="utf-8"
    )
    assert install._extract_mcp_key(path) == KEY


def test_our_config_key_identifies_the_entry(tmp_path: Path):
    # An entry stored under our server name counts even when the command line
    # says nothing about ssh (wrappers, absolute interpreter paths).
    entry = {"command": "/opt/venv/bin/python3", "args": [], "env": {"MCP_KEY": KEY}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": {"ssh": entry}}), encoding="utf-8")
    assert install._extract_mcp_key(path) == KEY


def test_corrupt_config_does_not_abort_the_install(tmp_path: Path):
    # ``_load_json`` exits the script; a broken Cursor/Pi config must not stop
    # an install that never touches that client.
    path = tmp_path / "mcp.json"
    path.write_text("{not json", encoding="utf-8")
    assert install._extract_mcp_key(path) is None


def test_conflicting_keys_reuse_one_and_never_leak(tmp_path: Path, monkeypatch, capsys):
    """Different installs disagreeing on the key must warn, not print secrets."""
    other = "mcp_ffffffffffffffffffffffffffffffff"
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    for path, key in ((first, KEY), (second, other)):
        path.write_text(
            json.dumps({"mcpServers": {"ssh": {"command": "ssh-mcp", "env": {"MCP_KEY": key}}}}),
            encoding="utf-8",
        )
    monkeypatch.setattr(install, "_home", lambda: tmp_path / "home")
    monkeypatch.setattr(
        install,
        "_client_specs",
        lambda: [
            install.ClientSpec("A", first, "mcp-json"),
            install.ClientSpec("B", second, "mcp-json"),
        ],
    )

    found = install._existing_mcp_key()

    assert found is not None and found[0] == KEY
    err = capsys.readouterr().err
    assert "disagree" in err
    assert KEY not in err and other not in err
