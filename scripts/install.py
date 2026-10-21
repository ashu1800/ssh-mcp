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
    kind: str  # "claude-json" | "mcp-json" | "vscode-json"
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
    subprocess.run([*pip_args, requirement], check=True)

    # Prefer the console script: it pins the interpreter that actually has the
    # package, whereas a bare ``python`` may resolve to a different one later.
    if args.venv:
        script = Path(args.venv).expanduser() / ("Scripts/ssh-mcp.exe" if os.name == "nt" else "bin/ssh-mcp")
        command = str(script) if script.is_file() else target
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
    ``vscode-json`` (``servers`` map with a ``type`` field), ``dsh-registry``
    (``~/.dsh`` skill registry) or ``claude-json`` (fallback when the Claude
    Code CLI is absent).
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

    # DSH: a registry of entries rather than an mcpServers map. Its own file
    # also stores credentials, so it is only ever updated, never created here.
    specs.append(
        ClientSpec(
            "DSH",
            home / ".dsh/skill-mcp-manager/registry.json",
            "dsh-registry",
            markers=(home / ".dsh",),
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
    if target.kind == "dsh-registry":
        target.changed = _wire_dsh(target.path, entry, dry_run=dry_run)
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


def _wire_dsh(path: Path, entry: dict[str, Any], *, dry_run: bool) -> bool:
    """Write into DSH's skill registry (``entries`` list, not a name map).

    The registry also holds credentials and tool snapshots for other servers,
    so every existing entry is preserved byte-for-byte; only the ssh entry is
    replaced or appended.
    """
    data = _load_json(path)
    entries = data.get("entries")
    if not isinstance(entries, list):
        entries = []
    data["entries"] = entries
    data.setdefault("version", 1)
    record = {
        "id": SERVER_NAME,
        "name": SERVER_NAME,
        "tier": "on-demand",
        "transport": "stdio",
        "command": entry["command"],
        "args": list(entry["args"]),
        "env": dict(entry["env"]),
        "cwd": None,
        "url": None,
        "headers": {},
        "notes": "installed by ssh-mcp installer",
        "managed": True,
    }
    for index, existing in enumerate(entries):
        if isinstance(existing, dict) and existing.get("id") == SERVER_NAME:
            # Keep the client's own bookkeeping fields (timestamps, tool cache).
            merged = {**existing, **record}
            merged.pop("tools", None)
            entries[index] = merged
            break
    else:
        entries.append(record)
    return _write_json(path, data, dry_run=dry_run)


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
        help="comma-separated subset of: claude,cursor,vscode,desktop,all (default: all)",
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
