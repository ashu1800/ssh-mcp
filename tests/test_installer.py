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


# -- pip recovery from a locked launcher --------------------------------------
#
# A client that started ``ssh-mcp.exe`` keeps Windows from replacing it, and pip
# aborts mid-install. The installer must end with an importable package rather
# than leave the environment without one.

import subprocess as _subprocess  # noqa: E402


class _FakePip:
    """Records the pip invocations the installer makes and replays outcomes."""

    def __init__(self, installer, monkeypatch, results: list[tuple[int, str]]):
        self.calls: list[list[str]] = []
        self._results = list(results)
        monkeypatch.setattr(installer.subprocess, "run", self)

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if "uninstall" in cmd:
            # The uninstall always dies on the locked launcher; that is fine,
            # because it has already moved the old package directory aside.
            return _subprocess.CompletedProcess(cmd, 2, "", "PermissionError: [WinError 32]")
        code, text = self._results.pop(0) if self._results else (0, "")
        return _subprocess.CompletedProcess(cmd, code, text if code else text, text if code else "")


def test_pip_retries_after_uninstalling_when_the_launcher_is_locked(installer, monkeypatch, tmp_path):
    lock = (
        "ERROR: Could not install packages due to an OSError: [WinError 32] "
        "The process cannot access the file because it is being used by another process: "
        "'c:\\x\\.venv\\scripts\\ssh-mcp.exe'"
    )
    fake = _FakePip(installer, monkeypatch, results=[(1, lock), (0, "")])
    monkeypatch.setattr(installer, "_package_is_installed", lambda scripts_dir: True)
    monkeypatch.setattr(installer, "_clean_invalid_dists", lambda scripts_dir: None)

    outcome = installer._pip_install(["python", "-m", "pip", "install"], "req", scripts_dir=tmp_path / "Scripts")

    assert outcome == "script_locked"
    assert any("uninstall" in call for call in fake.calls), "the old package must be removed before retrying"
    assert sum(1 for call in fake.calls if "install" in call) == 2


def test_pip_failure_unrelated_to_a_lock_is_reported_as_is(installer, monkeypatch, tmp_path):
    fake = _FakePip(installer, monkeypatch, results=[(1, "ERROR: No matching distribution found for ssh-mcp")])
    with pytest.raises(SystemExit) as excinfo:
        installer._pip_install(["python", "-m", "pip", "install"], "req", scripts_dir=tmp_path / "Scripts")
    assert "No matching distribution" in str(excinfo.value)
    assert not any("uninstall" in call for call in fake.calls)


def test_pip_gives_up_with_client_hint_when_the_package_is_still_missing(installer, monkeypatch, tmp_path):
    lock = "WinError 32: the process cannot access the file 'ssh-mcp.exe'"
    monkeypatch.setattr(installer, "_package_is_installed", lambda scripts_dir: False)
    monkeypatch.setattr(installer, "_running_ssh_mcp", lambda: ['"ssh-mcp.exe","1"'])
    _FakePip(installer, monkeypatch, results=[(1, lock), (1, lock)])

    with pytest.raises(SystemExit) as excinfo:
        installer._pip_install(["python", "-m", "pip", "install"], "req", scripts_dir=tmp_path / "Scripts")
    assert "running right now" in str(excinfo.value)


def test_install_package_uses_the_interpreter_when_the_launcher_is_locked(installer, monkeypatch, tmp_path):
    """The stale launcher must not end up in the client config."""
    venv = tmp_path / "venv"
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "python.exe").write_bytes(b"")
    (scripts / "ssh-mcp.exe").write_bytes(b"MZ stale")
    monkeypatch.setattr(installer.os, "name", "nt")
    monkeypatch.setattr(installer, "_pip_install", lambda *a, **k: "script_locked")

    args = installer.parse_args(["--mcp-key", "mcp_x", "--venv", str(venv)])
    command, _ = installer.install_package(args, tmp_path)

    assert command == str(scripts / "python.exe")
    assert not command.endswith("ssh-mcp.exe")
    assert installer.launch_argv(command) == [command, "-m", "ssh_mcp", "--transport", "stdio"]
