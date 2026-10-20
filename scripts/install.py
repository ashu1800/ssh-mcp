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
        existing = shutil.which("ssh-mcp")
        if existing:
            return existing, "existing ssh-mcp on PATH"
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
    else:
        requirement = str(repo)
    print(f"installing {requirement} ...")
    subprocess.run([*pip_cmd, "--quiet", requirement], check=True)

    # Under a virtualenv, prefer the console script; otherwise ``python -m ssh_mcp``.
    if args.venv:
        script = Path(args.venv).expanduser() / ("Scripts/ssh-mcp.exe" if os.name == "nt" else "bin/ssh-mcp")
        command = str(script) if script.is_file() else target
    else:
        command = shutil.which("ssh-mcp") or target
    return command, f"installed from {requirement}"


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


def discover_clients() -> list[ClientTarget]:
    home = _home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData/Roaming")
    candidates: list[ClientTarget] = []

    claude_json = home / ".claude.json"
    candidates.append(ClientTarget("Claude Code (~/.claude.json)", claude_json, "claude-json"))

    # Claude Desktop. Two layouts exist on Windows: the standard build keeps
    # its config in %APPDATA%\Claude, while the 3p (third-party) deployment
    # keeps it in %LOCALAPPDATA%\Claude-3p. Writing only the standard path
    # leaves the app that is actually installed reading a file nobody wrote.
    for label, desktop in desktop_config_paths().items():
        target = ClientTarget(label, desktop, "mcp-json")
        target.note = "" if _desktop_installed(desktop) else "client not installed"
        candidates.append(target)

    cursor = home / ".cursor/mcp.json"
    cursor_target = ClientTarget("Cursor", cursor, "mcp-json")
    if not cursor.is_file() and not _binary_or_dir("cursor", home / ".cursor"):
        cursor_target.note = "client not installed"
    candidates.append(cursor_target)

    # VS Code user-level MCP config (also picked up by 通义灵码's MCP view).
    if os.name == "nt":
        vscode = appdata / "Code/User/mcp.json"
    elif sys.platform == "darwin":
        vscode = home / "Library/Application Support/Code/User/mcp.json"
    else:
        vscode = home / ".config/Code/User/mcp.json"
    vscode_target = ClientTarget("VS Code / 通义灵码", vscode, "vscode-json")
    if not vscode.is_file() and not _binary_or_dir("code", vscode.parent):
        vscode_target.note = "client not installed"
    candidates.append(vscode_target)

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
    data = _load_json(target.path)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers
    servers[SERVER_NAME] = entry
    if target.kind == "vscode-json":
        # VS Code's schema keys servers under "servers" rather than "mcpServers".
        data.setdefault("servers", {}).setdefault(SERVER_NAME, {"type": "stdio", **entry})
        data["mcpServers"].pop(SERVER_NAME, None)
        if not data["mcpServers"]:
            data.pop("mcpServers")
    target.changed = _write_json(target.path, data, dry_run=dry_run)


def _matches(label: str, wanted: set[str]) -> bool:
    lowered = label.lower()
    return any(word in lowered for word in wanted if word not in {"claude", "all"})


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
        default=str(Path(__file__).resolve().parent.parent / ".venv"),
        help="virtualenv to install into (default: <repo>/.venv); pass an empty string to use the current interpreter",
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
    parser.add_argument("--dry-run", action="store_true", help="report actions without changing anything")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.mcp_key.startswith("mcp_"):
        raise SystemExit("--mcp-key does not look like an MCP token (expected a 'mcp_' prefix)")

    repo = Path(__file__).resolve().parent.parent
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
