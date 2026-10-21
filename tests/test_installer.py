"""The installer's client-config writers.

Only the DSH writer is covered here: it edits a file that belongs to another
application and holds that application's own settings, so a rewrite that drops
a line is a real regression rather than a cosmetic one.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

INSTALL_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install.py"

ENTRY = {
    "command": r"C:\Users\me\AppData\Roaming\Python\Scripts\ssh-mcp.exe",
    "args": ["--transport", "stdio"],
    "env": {"MCP_KEY": "mcp_test_token_000000000000000000", "SSH_MCP_ALLOWED_LOCAL_ROOTS": "~/ssh-mcp-files"},
}


@pytest.fixture(scope="module")
def installer():
    spec = importlib.util.spec_from_file_location("ssh_mcp_installer", INSTALL_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


DESKTOP_PATCH = """\
# Your patch layer for this dsh profile.
- id: llm-pi-ai
  name: "@deepseek-ai/dsh-llm-pi-ai"
  config:
    providers:
      llm-deepseek:
        apiKeyEnv: LLM_DEEPSEEK_API_KEY
        models:
          - id: deepseek-v4.1-flash
            name: DeepSeek V4.1 Flash
# >>> dsh-skill-mcp-panel:mcp:begin
- insert:
    - id: panel-mcp-dart
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: dart
        transport: stdio
        command: C:\\flutter\\bin\\dart.bat
        args:
          - mcp-server --enable
    - id: panel-mcp-SSH
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: SSH
        transport: streamable-http
        url: http://10.0.0.1:9000/mcp
        headers:
          Authorization: Bearer mcp_other_real_credential
# <<< dsh-skill-mcp-panel:mcp:end
- id: ui-theme
  name: "@deepseek-ai/dsh-client-ui-theme"
  config:
    preference: light
"""

WEB_PATCH = """\
# dsh profile root -- an empty entry list. Edit cordis.patch.yml, not cordis.yml.
[]
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_dsh_writer_preserves_every_foreign_line(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", DESKTOP_PATCH)
    assert installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    after = target.read_text(encoding="utf-8")

    # The other plugin's server and its credential must survive untouched.
    assert "    - id: panel-mcp-dart\n" in after
    assert "          Authorization: Bearer mcp_other_real_credential\n" in after
    # Everything outside the managed block is byte-identical.
    before_outside = DESKTOP_PATCH[: DESKTOP_PATCH.index(installer.DSH_BLOCK_BEGIN)]
    after_outside = after[: after.index(installer.DSH_BLOCK_BEGIN)]
    assert after_outside == before_outside
    assert after.endswith("- id: ui-theme\n  name: \"@deepseek-ai/dsh-client-ui-theme\"\n  config:\n    preference: light\n")


def test_dsh_writer_appends_the_row_inside_the_insert_list(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", DESKTOP_PATCH)
    installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    after = target.read_text(encoding="utf-8")

    ssh_row = "    - id: panel-mcp-ssh\n"
    assert ssh_row in after
    # Indented under `- insert:`, so the loader sees it as a server row rather
    # than a stray top-level entry.
    assert after.index(ssh_row) > after.index("- insert:")
    assert "        command: C:\\Users\\me\\AppData\\Roaming\\Python\\Scripts\\ssh-mcp.exe\n" in after
    assert "          - --transport\n" in after


def test_dsh_writer_is_idempotent(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", DESKTOP_PATCH)
    installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    once = target.read_text(encoding="utf-8")
    assert installer._wire_dsh_profile(target, ENTRY, dry_run=False) is False
    assert target.read_text(encoding="utf-8") == once


def test_dsh_writer_replaces_a_stale_row_in_place(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", DESKTOP_PATCH)
    installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    moved = {**ENTRY, "command": r"D:\other\.venv\Scripts\ssh-mcp.exe"}
    installer._wire_dsh_profile(target, moved, dry_run=False)
    after = target.read_text(encoding="utf-8")

    assert after.count("    - id: panel-mcp-ssh\n") == 1
    assert r"D:\other\.venv\Scripts\ssh-mcp.exe" in after
    assert "    - id: panel-mcp-dart\n" in after


def test_dsh_writer_replaces_the_empty_array_template(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", WEB_PATCH)
    installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    after = target.read_text(encoding="utf-8")

    # `[] - insert:` would not parse, so the template must be gone.
    assert "\n[]" not in after
    assert after.startswith("# dsh profile root")
    assert "- insert:\n    - id: panel-mcp-ssh\n" in after


def test_dsh_writer_creates_the_block_when_absent(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", "- id: ui-theme\n  name: \"@deepseek-ai/dsh-client-ui-theme\"\n")
    installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    after = target.read_text(encoding="utf-8")

    assert after.startswith("- id: ui-theme\n")
    assert installer.DSH_BLOCK_BEGIN in after
    assert after.rstrip().endswith(installer.DSH_BLOCK_END)


def test_dsh_writer_rejects_half_a_marker_pair(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", "- id: x\n# >>> dsh-skill-mcp-panel:mcp:begin\n- insert: []\n")
    with pytest.raises(SystemExit):
        installer._wire_dsh_profile(target, ENTRY, dry_run=False)
    assert target.read_text(encoding="utf-8").endswith("- insert: []\n")


def test_dsh_writer_leaves_the_file_alone_on_dry_run(installer, tmp_path):
    target = _write(tmp_path / "cordis.patch.yml", DESKTOP_PATCH)
    assert installer._wire_dsh_profile(target, ENTRY, dry_run=True) is True
    assert target.read_text(encoding="utf-8") == DESKTOP_PATCH


def test_dsh_writer_quotes_values_yaml_would_misread(installer):
    assert installer._yaml_scalar(r"C:\x\python.exe") == r"C:\x\python.exe"
    assert installer._yaml_scalar("~/ssh-mcp-files") == "~/ssh-mcp-files"
    assert installer._yaml_scalar("a # b") == '"a # b"'
    assert installer._yaml_scalar("key: value") == '"key: value"'
    assert installer._yaml_scalar("null") == '"null"'
    assert installer._yaml_scalar("-x") == "-x"
    assert installer._yaml_scalar("- x") == '"- x"'
