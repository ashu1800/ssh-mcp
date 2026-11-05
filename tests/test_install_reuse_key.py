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
