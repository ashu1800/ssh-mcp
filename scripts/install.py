"""One-shot installer for ssh-mcp: install the package and wire it into MCP clients.

Typical use on this machine:

    python scripts/install.py --mcp-key mcp_xxx

On another machine (private repo), build a wheel first and point at it:

    python scripts/install.py --from-wheel dist/ssh_mcp-0.1.0-py3-none-any.whl --mcp-key mcp_xxx

What it does, in order:

1. Installs ssh-mcp into a virtualenv (default ``<repo>/.venv``) or into the
   running interpreter's environment, verifying ``ssh-mcp --help`` afterwards.
2. Writes the server entry into every client config it can find:
   Claude Code (``claude mcp add`` if the CLI exists, else ``~/.claude.json``),
   Claude Desktop, Cursor, and VS Code / 通义灵码 style ``mcp.json`` files.
3. Rewrites existing files atomically and keeps a ``.bak`` copy first.

The MCP key is never printed. Use ``--dry-run`` to see which files would change.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SERVER_NAME = "ssh"
DEFAULT_ROOTS = "~/ssh-mcp-files"
PACKAGE_URL = "git+https://github.com/ashu1800/ssh-mcp.git"


@dataclass
class ClientTarget:
    """One configuration file that can hold ``mcpServers``."""

    label: str
    path: Path
    kind: str  # "claude-json" | "mcp-json" | "vscode-json" | "cli" | "dsh-profile"
    exists: bool = False
    changed: bool = False
    note: str = ""


@dataclass
class InstallResult:
    command: str = ""
    command_source: str = ""
    clients: list[ClientTarget] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# -- installation -------------------------------------------------------------


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


# An MCP client starts ``ssh-mcp.exe`` and keeps it running, and Windows will not
# let pip replace a running launcher: the rename to ``.deleteme`` fails with
# WinError 32. What matters is that the importable package still gets installed,
# because ``python -m ssh_mcp`` runs it without going through the launcher.
_IN_USE_MARKERS = (
    "winerror 32",
    "winerror 5",
    "另一个程序正在使用此文件",
    "being used by another process",
    "process cannot access the file",
)


def _pip_install(pip_args: list[str], requirement: str, *, scripts_dir: Path | None) -> str:
    """Run pip and return ``"ok"``, ``"script_locked"`` or raise.

    ``script_locked`` means the package was installed but the launcher could not
    be replaced because a client is running it. That is a warning, not a
    failure: the caller switches to ``python -m ssh_mcp`` for that environment.
    """
    proc = subprocess.run([*pip_args, requirement], capture_output=True, text=True)
    output = f"{proc.stdout or ''}{proc.stderr or ''}"
    if proc.returncode == 0:
        _clean_invalid_dists(scripts_dir)
        return "ok"
    if not any(marker in output.lower() for marker in _IN_USE_MARKERS):
        raise SystemExit(output.strip() or f"pip failed with exit status {proc.returncode}")

    # A locked launcher aborts pip *after* it has already renamed the old
    # package directory aside (``ssh_mcp`` -> ``~sh_mcp``), which leaves the
    # environment with no importable package at all -- the worst outcome, since
    # the command that was working before now fails. An uninstall gets the
    # rename done and fails on the same launcher, so a plain reinstall after it
    # succeeds; the launcher is the only thing that stays stale.
    _pip_uninstall(pip_args, scripts_dir)
    retry = subprocess.run([*pip_args, requirement], capture_output=True, text=True)
    if retry.returncode == 0:
        _clean_invalid_dists(scripts_dir)
        print("  ssh-mcp.exe is running, so its launcher could not be replaced.")
        print("  The package itself was updated; clients will use python -m ssh_mcp.")
        return "script_locked"

    if _package_is_installed(scripts_dir):
        _clean_invalid_dists(scripts_dir)
        print("  ssh-mcp.exe is running, so its launcher could not be replaced.")
        print("  The package itself was updated; clients will use python -m ssh_mcp.")
        return "script_locked"

    raise SystemExit(f"{retry.stdout or ''}{retry.stderr or ''}".strip() + "\n\n" + _close_clients_hint())


def _pip_uninstall(pip_args: list[str], scripts_dir: Path | None) -> None:
    """Remove the installed package, tolerating a locked console script.

    pip renames the package directory before it touches ``Scripts/``, so a
    failure there still leaves the old package out of the way -- which is
    exactly what the following install needs.
    """
    python = str(scripts_dir.parent / ("Scripts/python.exe" if os.name == "nt" else "bin/python")) if scripts_dir else sys.executable
    subprocess.run([python, "-m", "pip", "uninstall", "-y", "ssh-mcp"], capture_output=True, text=True)


def _package_is_installed(scripts_dir: Path | None) -> bool:
    """Whether ``ssh_mcp`` can be imported by the environment pip targeted."""
    if scripts_dir is None:
        return True
    python = scripts_dir.parent / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    python = python if python.is_file() else Path(sys.executable)
    proc = subprocess.run([str(python), "-c", "import ssh_mcp"], capture_output=True, text=True)
    return proc.returncode == 0


def _clean_invalid_dists(scripts_dir: Path | None) -> None:
    """Remove the ``~name`` directories pip leaves after a failed uninstall.

    They make every later pip run print ``Ignoring invalid distribution``. The
    new package directory is written before the old one is renamed away, so
    these hold nothing the environment still imports.
    """
    if scripts_dir is None:
        return
    site_packages = scripts_dir.parent / ("Lib/site-packages" if os.name == "nt" else "lib/python3/site-packages")
    if not site_packages.is_dir():
        return
    for entry in site_packages.iterdir():
        if entry.name.startswith("~") and (entry.is_dir() or entry.name.endswith(".dist-info")):
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)


def _running_ssh_mcp() -> list[str]:
    """Whether a client currently has ssh-mcp running."""
    if os.name != "nt":
        return []
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq ssh-mcp.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in proc.stdout.splitlines() if line.lower().startswith('"ssh-mcp.exe"')]


def _close_clients_hint() -> str:
    """What to tell the user when even the package could not be replaced."""
    if _running_ssh_mcp():
        return (
            "ssh-mcp is running right now. Quit the MCP client that started it (Claude Code, DSH, "
            "Cursor, ...) -- or stop the server from its MCP settings -- and run this again."
        )
    return (
        "A process is holding ssh-mcp's files. Quit every MCP client that has this server enabled "
        "and run this again."
    )


def install_package(args: argparse.Namespace, repo: Path) -> tuple[str, str]:
    """Install ssh-mcp and return (command, source)."""
    if args.skip_install:
        if args.from_wheel:
            raise SystemExit("--skip-install cannot be combined with --from-wheel")
        if args.update:
            raise SystemExit("--update installs the package; it cannot be combined with --skip-install")
        existing = shutil.which("ssh-mcp") or _console_script_via_pip([sys.executable, "-m", "pip"])
        if existing:
            return existing, "existing ssh-mcp installation"
        if args.venv:
            python = _venv_python(Path(args.venv).expanduser())
            if python.is_file():
                return str(python), f"existing virtualenv at {python.parent.parent}"
        raise SystemExit("--skip-install was given but no ssh-mcp command was found")

    if args.venv:
        venv = Path(args.venv).expanduser()
        if not venv.is_dir():
            print(f"creating virtualenv {venv}")
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        python = _venv_python(venv)
        if not python.is_file():
            raise SystemExit(f"virtualenv at {venv} has no python executable")
        target = str(python)
        pip_cmd = [target, "-m", "pip", "install"]
    else:
        target = sys.executable
        pip_cmd = [target, "-m", "pip", "install"]

    if args.from_wheel:
        wheel = Path(args.from_wheel).expanduser()
        if not wheel.is_file():
            raise SystemExit(f"wheel not found: {wheel}")
        requirement = str(wheel)
    elif args.package:
        # Installed without a checkout: the script ran from a downloaded copy,
        # so the source tree next to it is not this project.
        requirement = args.package
    else:
        requirement = str(repo)
    pip_args = [*pip_cmd, "--quiet"]
    if args.update:
        # The version number does not change between commits, so pip treats an
        # existing install as satisfied and skips it. --force-reinstall makes
        # ``--update`` mean "take the current content of the requirement".
        pip_args += ["--force-reinstall", "--no-deps"]
    print(f"{'updating' if args.update else 'installing'} {requirement} ...")
    scripts_dir = Path(args.venv).expanduser() / ("Scripts" if os.name == "nt" else "bin") if args.venv else None
    outcome = _pip_install(pip_args, requirement, scripts_dir=scripts_dir)

    # Prefer the console script: it pins the interpreter that actually has the
    # package, whereas a bare ``python`` may resolve to a different one later.
    # When the launcher is locked by a running client it is stale, so point the
    # config at the interpreter instead -- that always runs the fresh code.
    if args.venv:
        script = Path(args.venv).expanduser() / ("Scripts/ssh-mcp.exe" if os.name == "nt" else "bin/ssh-mcp")
        command = str(script) if script.is_file() and outcome != "script_locked" else target
    elif outcome == "script_locked":
        command = target
    else:
        # ``pip install --user`` puts the script outside the interpreter's own
        # bin dir, so ask pip where it landed before falling back to PATH.
        command = shutil.which("ssh-mcp") or _console_script_via_pip(pip_cmd[:2] + ["-m", "pip"]) or target
    return command, f"installed from {requirement}"


def _console_script_via_pip(pip_prefix: list[str]) -> str | None:
    """Ask pip where ``ssh-mcp`` was installed, if it knows."""
    try:
        proc = subprocess.run(
            [*pip_prefix, "show", "--files", "ssh-mcp"], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    location: Path | None = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Location:"):
            location = Path(stripped.split(":", 1)[1].strip())
            continue
        if not stripped.endswith(("ssh-mcp", "ssh-mcp.exe", "ssh-mcp-script.py")):
            continue
        # pip reports paths relative to the install location (``..\Scripts\...``).
        candidate = Path(stripped)
        for base in ([location] if location else []) + [None]:
            resolved = candidate if base is None else (base / candidate)
            if resolved.is_file():
                return str(resolved.resolve())
    return None


def verify_install(command: str) -> None:
    """Run ``--help`` through the exact prefix the client will launch."""
    argv = launch_argv(command)
    cmd = argv[:-2] + ["--help"]  # drop the transport flags
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise SystemExit(f"installed command failed to start:\n{proc.stderr.strip()[:2000]}")


# -- client discovery ---------------------------------------------------------


def _home() -> Path:
    return Path.home()


def desktop_config_paths() -> dict[str, Path]:
    """Claude Desktop config files, standard build first, then the 3p build."""
    home = _home()
    local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData/Local")
    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA") or home / "AppData/Roaming")
        return {
            "Claude Desktop": appdata / "Claude/claude_desktop_config.json",
            "Claude Desktop (3p)": local / "Claude-3p/claude_desktop_config.json",
        }
    if sys.platform == "darwin":
        return {"Claude Desktop": home / "Library/Application Support/Claude/claude_desktop_config.json"}
    return {"Claude Desktop": home / ".config/Claude/claude_desktop_config.json"}


def _binary_or_dir(binary: str, marker: Path) -> bool:
    """Whether a client is installed, by executable or by its data directory."""
    return shutil.which(binary) is not None or (marker.is_dir() and bool(list(marker.iterdir())))


def _desktop_installed(config: Path) -> bool:
    """Whether the Claude Desktop build owning ``config`` is actually present.

    A config file (or its directory) can exist without the app: the standard
    and 3p builds use different locations, and only one of them is installed.
    """
    if config.is_file():
        return True
    install_dir = config.parent
    if not install_dir.is_dir():
        return False
    # The 3p build keeps its app data next to the config; the standard build
    # only creates this directory once the app has run.
    return (install_dir / "claude-code").exists() or bool(list(install_dir.iterdir()))


@dataclass(frozen=True)
class ClientSpec:
    """One MCP client and where it keeps its server list.

    ``format`` selects the writer: ``mcp-json`` (``mcpServers`` map),
    ``vscode-json`` (``servers`` map with a ``type`` field), ``dsh-profile``
    (the managed block in a DSH profile's ``cordis.patch.yml``) or
    ``claude-json`` (fallback when the Claude Code CLI is absent).
    """

    label: str
    file: Path
    format: str
    # Extra paths that prove the app is installed when the config is absent.
    markers: tuple[Path, ...] = ()
    # Executable names that prove the app is installed.
    binaries: tuple[str, ...] = ()
    # Whether a missing config may be created (vs. only updated when present).
    create: bool = True


def _client_specs() -> list[ClientSpec]:
    home = _home()
    local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData/Local")
    appdata = Path(os.environ.get("APPDATA") or home / "AppData/Roaming")
    mac = sys.platform == "darwin"
    app_support = home / "Library/Application Support"

    specs: list[ClientSpec] = [
        ClientSpec("Claude Code", home / ".claude.json", "claude-json", binaries=("claude",)),
    ]

    # Claude Desktop: the standard build and the 3p deployment keep separate
    # configs, and only the installed one is authoritative.
    desktop = (
        appdata / "Claude/claude_desktop_config.json"
        if os.name == "nt"
        else (app_support / "Claude/claude_desktop_config.json" if mac else home / ".config/Claude/claude_desktop_config.json")
    )
    specs.append(ClientSpec("Claude Desktop", desktop, "mcp-json"))
    if os.name == "nt":
        specs.append(ClientSpec("Claude Desktop (3p)", local / "Claude-3p/claude_desktop_config.json", "mcp-json"))

    specs.append(
        ClientSpec("Cursor", home / ".cursor/mcp.json", "mcp-json", markers=(home / ".cursor",), binaries=("cursor",))
    )

    vscode = (
        appdata / "Code/User/mcp.json"
        if os.name == "nt"
        else (app_support / "Code/User/mcp.json" if mac else home / ".config/Code/User/mcp.json")
    )
    specs.append(ClientSpec("VS Code / 通义灵码", vscode, "vscode-json"))

    # Windsurf keeps a single JSON config beside its data directory.
    windsurf = home / ".codeium/windsurf/mcp_config.json"
    specs.append(
        ClientSpec(
            "Windsurf",
            windsurf,
            "mcp-json",
            markers=(home / ".codeium/windsurf", home / ".windsurf"),
            binaries=("windsurf",),
        )
    )

    # Trae: per-user MCP config next to the app data.
    trae = (
        appdata / "Trae/User/mcp.json"
        if os.name == "nt"
        else (app_support / "Trae/User/mcp.json" if mac else home / ".config/Trae/User/mcp.json")
    )
    specs.append(ClientSpec("Trae", trae, "mcp-json", markers=(trae.parent.parent,), binaries=("trae",)))

    # Qoder: same VS Code-derived layout.
    qoder = (
        appdata / "Qoder/User/mcp.json"
        if os.name == "nt"
        else (app_support / "Qoder/User/mcp.json" if mac else home / ".config/Qoder/User/mcp.json")
    )
    specs.append(ClientSpec("Qoder", qoder, "mcp-json", markers=(qoder.parent.parent,), binaries=("qoder",)))

    # WorkBuddy.
    workbuddy = home / ".workbuddy/mcp.json"
    specs.append(
        ClientSpec(
            "WorkBuddy",
            workbuddy,
            "mcp-json",
            markers=(home / ".workbuddy",),
            binaries=("workbuddy",),
        )
    )

    # DSH ships as two editions with independent profile roots -- the desktop
    # app and the web server -- and each reads its MCP servers from
    # ``profiles/<name>/cordis.patch.yml``. ``~/.dsh/skill-mcp-manager/
    # registry.json`` is a cache the panel derives from those rows, so writing
    # it alone changes nothing the loader reads.
    for edition in ("desktop", "web"):
        profile = home / f".dsh/profiles/{edition}"
        specs.append(
            ClientSpec(
                f"DSH ({edition})",
                profile / "cordis.patch.yml",
                "dsh-profile",
                # A profile root without package.json is not a profile DSH knows.
                markers=(profile,) if (profile / "package.json").is_file() else (),
                binaries=("dsh",),
            )
        )

    return specs


def discover_clients() -> list[ClientTarget]:
    candidates: list[ClientTarget] = []
    for spec in _client_specs():
        installed = (
            spec.file.is_file()
            or any(marker.is_dir() and any(marker.iterdir()) for marker in spec.markers)
            or any(shutil.which(binary) for binary in spec.binaries)
        )
        target = ClientTarget(spec.label, spec.file, spec.format)
        if not installed:
            target.note = "client not installed"
        candidates.append(target)
    for candidate in candidates:
        candidate.exists = candidate.path.is_file()
    return candidates


# -- config writing -----------------------------------------------------------


def launch_argv(command: str) -> list[str]:
    """The argv that actually starts the stdio server for ``command``.

    A bare interpreter needs ``-m ssh_mcp``; a console script does not. Getting
    this wrong produces an entry that looks configured but exits immediately
    with "Unknown option: --transport".
    """
    base = [command]
    if Path(command).name.lower().startswith("python"):
        base += ["-m", "ssh_mcp"]
    return base + ["--transport", "stdio"]


def build_entry(command: str, args: argparse.Namespace) -> dict[str, Any]:
    env = {
        "MCP_KEY": args.mcp_key,
        "SSH_MCP_ALLOWED_LOCAL_ROOTS": args.allowed_roots,
    }
    if args.state_dir:
        env["SSH_MCP_STATE_DIR"] = args.state_dir
    argv = launch_argv(command)
    return {"command": argv[0], "args": argv[1:], "env": env}


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot parse {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path} does not contain a JSON object")
    return data


def _write_json(path: Path, data: dict[str, Any], *, dry_run: bool) -> bool:
    """Write atomically after backing up; returns whether a change was needed."""
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    if dry_run:
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        backup = path.with_name(path.name + ".bak")
        shutil.copy2(path, backup)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return True


def wire_file(target: ClientTarget, entry: dict[str, Any], *, dry_run: bool) -> None:
    if target.kind == "dsh-profile":
        target.changed = _wire_dsh_profile(target.path, entry, dry_run=dry_run)
        return

    data = _load_json(target.path)
    if target.kind == "vscode-json":
        # VS Code's schema keys servers under "servers" and requires a type.
        servers = data.setdefault("servers", {})
        servers[SERVER_NAME] = {"type": "stdio", **entry}
    else:
        servers = data.setdefault("mcpServers", {})
        servers[SERVER_NAME] = entry
    target.changed = _write_json(target.path, data, dry_run=dry_run)


def _wire_dsh_profile(path: Path, entry: dict[str, Any], *, dry_run: bool) -> bool:
    """Write the ssh server into a DSH profile's ``cordis.patch.yml``.

    The file is a top-level YAML array of loader patch entries. The MCP panel
    owns one block between ``# >>> dsh-skill-mcp-panel:mcp:begin`` and
    ``# <<< ...:end`` and rewrites everything inside it on the next save, so
    that block is the only place a row can live and survive a panel edit.
    Outside those two comment lines nothing is touched: the same file also
    holds model providers and other plugins' settings.

    No YAML library is available to this script (it has to run from a bare
    Python), so the row is emitted as text and every other line is copied
    through unchanged. The shape mirrors what the panel itself writes, so its
    "MCP" page lists the server and can edit it afterwards.
    """
    raw = path.read_text(encoding="utf-8") if path.is_file() else ""
    updated = _replace_dsh_mcp_block(raw, _render_dsh_row(entry))
    if updated == raw:
        return False
    if dry_run:
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(updated, encoding="utf-8")
    os.replace(tmp, path)
    return True


DSH_BLOCK_BEGIN = "# >>> dsh-skill-mcp-panel:mcp:begin"
DSH_BLOCK_END = "# <<< dsh-skill-mcp-panel:mcp:end"
# The panel names managed rows ``panel-mcp-<serverName>``; matching that keeps
# the entry editable from its UI instead of showing up as a foreign row.
DSH_ROW_ID = "panel-mcp-ssh"
DSH_PLUGIN_NAME = "@deepseek-ai/dsh-mcp-client"


def _yaml_scalar(value: str) -> str:
    """Render ``value`` as a YAML scalar, quoting only when it is required.

    Windows paths (``C:\\Users\\me\\python.exe``) are the common case and are
    valid plain scalars; anything YAML would misread -- a leading ``@`` or
    ``-``, an inner ``: ``/`` #``, braces, a leading quote -- is double-quoted
    with JSON escaping, which is also valid YAML.
    """
    reserved_initials = "?&*!|>%@`\"'"
    if value and value.strip() == value:
        risky = value[0] in reserved_initials or (value[0] == "-" and (len(value) == 1 or value[1] == " "))
        risky = risky or bool(re.search(r": | #|[\{\}\[\],\n\r\t]", value))
        if not risky and value.lower() not in {"null", "true", "false", "yes", "no", "on", "off", "~"}:
            return value
    return json.dumps(value, ensure_ascii=False)


def _render_dsh_row(entry: dict[str, Any]) -> list[str]:
    """The managed ``- id: panel-mcp-ssh`` row, indented under ``insert:``."""
    args = [str(arg) for arg in entry["args"]]
    lines = [
        f"    - id: {DSH_ROW_ID}",
        f"      name: \"{DSH_PLUGIN_NAME}\"",
        "      config:",
        "        serverName: ssh",
        "        toolCallTimeoutMs: 60000",
        "        failOnStartupError: false",
        "        reconnect:",
        "          enabled: true",
        "          initialDelayMs: 500",
        "          maxDelayMs: 30000",
        "          maxAttempts: 10",
        "        transport: stdio",
        "        command: " + _yaml_scalar(entry["command"]),
    ]
    if args:
        lines.append("        args:")
        lines += ["          - " + _yaml_scalar(arg) for arg in args]
    else:
        lines.append("        args: []")
    lines.append("        env:")
    lines += [f"          {key}: {_yaml_scalar(value)}" for key, value in entry["env"].items()]
    lines.append("        cwd: ''")
    return lines


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def _starts_item(line: str) -> bool:
    return line.lstrip().startswith("- ")


def _find_row_span(lines: list[str], row_id: str) -> tuple[int, int] | None:
    """Span of the ``- id: <row_id>`` item in ``lines``, comments included.

    The end is the next item at the same or a shallower indent, which covers
    both places a row can sit: directly in the patch array (indent 0) and
    inside an ``insert:`` list (indent 4).
    """
    marker = f"- id: {row_id}"
    for index, line in enumerate(lines):
        if not _starts_item(line) or line.strip() != marker:
            continue
        indent = _indent_of(line)
        start = index
        # Fold a comment directly above the row back into the replaced span so
        # re-running does not stack stale notes.
        while start > 0 and lines[start - 1].strip().startswith("#") and _indent_of(lines[start - 1]) >= indent:
            start -= 1
        end = index + 1
        while end < len(lines):
            probe = lines[end]
            if probe.strip():
                if _indent_of(probe) <= indent and _starts_item(probe):
                    break
                if _indent_of(probe) < indent and not probe.strip().startswith("- "):
                    # Dedented scalar/comment: the item ended.
                    break
            end += 1
        return start, end
    return None


def _find_insert_span(lines: list[str]) -> tuple[int, int] | None:
    """Span of a top-level ``- insert:`` list, so rows can be appended to it."""
    for index, line in enumerate(lines):
        if line.strip() != "- insert:":
            continue
        indent = _indent_of(line)
        end = index + 1
        while end < len(lines):
            probe = lines[end]
            if probe.strip() and _indent_of(probe) <= indent and _starts_item(probe):
                break
            end += 1
        return index, end
    return None


def _replace_dsh_mcp_block(raw: str, row: list[str]) -> str:
    """Return ``raw`` with the managed MCP block holding ``row``.

    Existing content inside the block is preserved line for line: other
    servers the panel manages keep their exact text, and only the ssh item is
    replaced. A file without a block gets one appended; the ``[]`` template the
    web profile ships with is replaced outright, since ``[] - insert:`` is not
    valid YAML.
    """
    block = [DSH_BLOCK_BEGIN, "- insert:", *row, DSH_BLOCK_END]
    begin = raw.find(DSH_BLOCK_BEGIN)
    end = raw.find(DSH_BLOCK_END)

    if begin >= 0 and end > begin:
        line_start = raw.rfind("\n", 0, begin) + 1
        after_end = raw.find("\n", end)
        line_end = len(raw) if after_end < 0 else after_end + 1
        body = raw[begin + len(DSH_BLOCK_BEGIN) : end].splitlines()
        # Blank lines right after the marker are layout, not content; dropping
        # them keeps a second run from stacking another one each time.
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        span = _find_row_span(body, DSH_ROW_ID)
        if span is not None:
            body = body[: span[0]] + row + body[span[1] :]
        else:
            insert = _find_insert_span(body)
            if insert is not None:
                body = body[: insert[1]] + row + body[insert[1] :]
            else:
                body = [*body, "- insert:", *row]
        return raw[:line_start] + "\n".join([DSH_BLOCK_BEGIN, *body, DSH_BLOCK_END]) + "\n" + raw[line_end:]

    if begin >= 0 or end >= 0:
        raise SystemExit(
            "cordis.patch.yml has an incomplete dsh-skill-mcp-panel block: "
            "the begin/end comment markers must both be present"
        )

    if _is_empty_yaml_array(raw):
        index = raw.rfind("[]")
        return raw[:index] + "\n".join(block) + "\n" + raw[index + 2 :]

    separator = "" if not raw else ("\n" if raw.endswith("\n") else "\n\n")
    return raw + separator + "\n".join(block) + "\n"


def _is_empty_yaml_array(raw: str) -> bool:
    """Whether ``raw`` is only comments plus the flow-style empty array ``[]``."""
    meaningful = [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    return meaningful == ["[]"]


def _matches(label: str, wanted: set[str]) -> bool:
    lowered = label.lower()
    return any(word in lowered for word in wanted if word not in {"all"})


def wire_claude_code(
    entry: dict[str, Any], args: argparse.Namespace, result: InstallResult, *, dry_run: bool
) -> None:
    """Prefer the official CLI; fall back to editing ~/.claude.json."""
    claude = shutil.which("claude")
    claude_json = _home() / ".claude.json"
    if claude:
        if dry_run:
            result.clients.append(
                ClientTarget(
                    "Claude Code (claude mcp add)",
                    claude_json,
                    "cli",
                    exists=True,
                    changed=True,
                    note="would run: claude mcp remove/add ssh",
                )
            )
            return
        # Remove first: ``claude mcp add`` refuses to overwrite an existing name.
        subprocess.run([claude, "mcp", "remove", SERVER_NAME], capture_output=True, text=True)
        command = entry["command"]
        cmd = [claude, "mcp", "add", "-s", args.scope, SERVER_NAME]
        for key, value in entry["env"].items():
            cmd.extend(["-e", f"{key}={value}"])
        cmd.extend(["--", command, *entry["args"]])
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            result.clients.append(
                ClientTarget("Claude Code (claude mcp add)", claude_json, "cli", exists=True, changed=True)
            )
            return
        result.warnings.append(
            f"claude mcp add failed (rc={proc.returncode}); editing ~/.claude.json instead: "
            f"{proc.stderr.strip()[:200]}"
        )

    target = ClientTarget("Claude Code (~/.claude.json)", claude_json, "claude-json", exists=claude_json.is_file())
    wire_file(target, entry, dry_run=dry_run)
    result.clients.append(target)


# -- main ---------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install ssh-mcp and register it with local MCP clients.",
    )
    parser.add_argument("--mcp-key", required=True, help="MCP key issued by the server management service")
    parser.add_argument(
        "--venv",
        default=None,
        help=(
            "virtualenv to install into; default is <repo>/.venv when run from a checkout and "
            "the current interpreter otherwise. Pass an empty string to force the current interpreter"
        ),
    )
    parser.add_argument(
        "--package",
        help="pip requirement to install instead of the local checkout (e.g. git+https://github.com/ashu1800/ssh-mcp.git)",
    )
    parser.add_argument("--from-wheel", help="install this wheel instead of the local source tree")
    parser.add_argument("--allowed-roots", default=DEFAULT_ROOTS, help="directories the AI may read/write locally")
    parser.add_argument("--state-dir", help="override SSH_MCP_STATE_DIR")
    parser.add_argument("--scope", default="user", choices=("local", "user", "project"), help="Claude Code scope")
    parser.add_argument(
        "--clients",
        default="all",
        help=(
            "comma-separated substrings matched against client labels, e.g. claude,cursor,vscode,"
            "windsurf,trae,qoder,workbuddy,dsh (default: all)"
        ),
    )
    parser.add_argument("--skip-install", action="store_true", help="only write client configs")
    parser.add_argument(
        "--update",
        action="store_true",
        help="reinstall an existing installation (needed because the version does not change between commits)",
    )
    parser.add_argument("--dry-run", action="store_true", help="report actions without changing anything")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.mcp_key.startswith("mcp_"):
        raise SystemExit("--mcp-key does not look like an MCP token (expected a 'mcp_' prefix)")

    repo = Path(__file__).resolve().parent.parent
    checkout = (repo / "pyproject.toml").is_file()
    if args.venv is None:
        # A downloaded copy of this script sits next to no project; installing
        # into a venv there would be pointless, so use the running interpreter.
        args.venv = str(repo / ".venv") if checkout else ""
    if not checkout and not (args.package or args.from_wheel or args.skip_install):
        # Public repo: a downloaded copy of this script can install straight
        # from GitHub without the user having to know the URL flag.
        args.package = PACKAGE_URL
    wanted = {part.strip().lower() for part in args.clients.split(",") if part.strip()}

    result = InstallResult()
    if not args.skip_install:
        command, source = install_package(args, repo)
    else:
        command, source = install_package(args, repo)
    result.command, result.command_source = command, source
    if not args.dry_run:
        verify_install(command)
    entry = build_entry(command, args)

    if "all" in wanted or "claude" in wanted:
        wire_claude_code(entry, args, result, dry_run=args.dry_run)

    for target in discover_clients():
        if target.kind == "claude-json":
            continue  # handled above, possibly through the CLI
        if "all" not in wanted and not _matches(target.label, wanted):
            continue
        if target.note == "client not installed":
            result.clients.append(target)
            continue
        if not target.exists:
            target.note = "created"
        wire_file(target, entry, dry_run=args.dry_run)
        result.clients.append(target)

    # -- report ---------------------------------------------------------------
    print()
    print(f"command : {result.command}  ({result.command_source})")
    print(f"mcp key : {args.mcp_key[:6]}***{args.mcp_key[-4:]}  (set in client config, not written to logs)")
    print()
    for client in result.clients:
        if client.changed:
            state = "created" if client.note == "created" else "updated"
        else:
            state = client.note or ("unchanged" if client.exists else "not installed")
        print(f"  {client.label:34} {state:14} {client.path}")
    for warning in result.warnings:
        print(f"  warning: {warning}")
    if args.dry_run:
        print("\ndry run: nothing was written")
    print("\nRestart the client (or its MCP connection) to pick up the new server.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
