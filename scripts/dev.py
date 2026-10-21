#!/usr/bin/env python3
"""The one supported dev workflow for this repo.

The failure this exists to prevent
-----------------------------------
``pip install -e .`` rebuilds ``Scripts/ssh-mcp.exe``, and Windows refuses to
replace it while an MCP client has the server running. pip then aborts *after*
renaming the installed package directory aside, which leaves the environment
with no importable ``ssh_mcp`` at all. Separately, a plain (non-editable)
install stays in ``site-packages`` and silently shadows ``src/``, so the test
suite passes against old code.

So nothing here trusts that an install "succeeded": every command ends by
asserting which file ``import ssh_mcp`` actually resolved to.

Usage::

    python scripts/dev.py setup      # first time: venv + deps + editable install
    python scripts/dev.py doctor     # diagnose: which code is live, what is stale
    python scripts/dev.py test       # run the suite against src/
    python scripts/dev.py serve      # start the stdio server from src/

``make dev`` / ``make test`` / ``make doctor`` wrap the same commands.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
VENV = REPO / ".venv"
IS_WINDOWS = os.name == "nt"

# A .pth file makes the venv import from src/ without installing the project at
# all. Editable installs still generate a console script, which is the thing
# that cannot be replaced while a client is running it.
PTH_NAME = "_ssh_mcp_dev.pth"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def venv_scripts() -> Path:
    return VENV / ("Scripts" if IS_WINDOWS else "bin")


def say(message: str) -> None:
    print(message, flush=True)


def _display(path: Path) -> str:
    """Path as shown to the user: relative when under the repo, absolute otherwise.

    A venv can live outside the repo (``--venv`` elsewhere), so ``relative_to``
    must not be assumed to succeed.
    """
    try:
        return str(path.resolve().relative_to(REPO.resolve()))
    except ValueError:
        return str(path)


# -- process helpers ----------------------------------------------------------


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    quiet: bool = False,
    inherit_src: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command, echoing it unless ``quiet``.

    ``inherit_src`` prepends ``src/`` to ``PYTHONPATH``. Probes that ask "which
    code is live?" must pass ``False``: injecting src/ would make every answer
    look healthy and hide exactly the shadowing this script exists to catch.
    """
    if not quiet:
        say(f"$ {' '.join(cmd)}")
    env = dict(os.environ)
    if inherit_src:
        # src/ must win over any installed copy, including for child processes.
        env["PYTHONPATH"] = str(SRC) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run(cmd, cwd=REPO, env=env, capture_output=capture, text=True)
    if check and proc.returncode != 0:
        if capture:
            sys.stderr.write(proc.stdout or "")
            sys.stderr.write(proc.stderr or "")
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def python(
    *args: str,
    check: bool = True,
    capture: bool = False,
    quiet: bool = False,
    inherit_src: bool = True,
) -> subprocess.CompletedProcess:
    return run(
        [str(venv_python()), *args],
        check=check,
        capture=capture,
        quiet=quiet,
        inherit_src=inherit_src,
    )


# -- environment checks -------------------------------------------------------


def resolve_import() -> tuple[str | None, str]:
    """Return (resolved path of ssh_mcp/__init__.py, human-readable note)."""
    proc = python(
        "-c",
        "import ssh_mcp, pathlib; print(pathlib.Path(ssh_mcp.__file__).resolve())",
        check=False,
        capture=True,
        quiet=True,
        inherit_src=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        return None, detail[-1] if detail else "import failed"
    return (proc.stdout or "").strip(), ""


def is_from_src(path: str | None) -> bool:
    if not path:
        return False
    try:
        Path(path).resolve().relative_to(SRC.resolve())
        return True
    except ValueError:
        return False


def site_packages() -> Path:
    """Where pip installs into this venv."""
    return VENV / ("Lib/site-packages" if IS_WINDOWS else "lib/python3/site-packages")


def stale_dirs() -> list[Path]:
    """The ``~name`` directories pip leaves behind after a failed uninstall."""
    site = site_packages()
    if not site.is_dir():
        return []
    return sorted(p for p in site.iterdir() if p.name.startswith("~"))


def running_servers() -> list[str]:
    """PIDs of ssh-mcp processes, which hold the console script open."""
    if not IS_WINDOWS:
        proc = subprocess.run(["pgrep", "-f", "ssh_mcp"], capture_output=True, text=True)
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    proc = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq ssh-mcp.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
    )
    return [
        line.split(",")[1].strip('"')
        for line in proc.stdout.splitlines()
        if line.lower().startswith('"ssh-mcp.exe"') and len(line.split(",")) > 1
    ]


def ensure_venv() -> None:
    if venv_python().is_file():
        return
    say(f"creating virtualenv at {VENV}")
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)


def write_pth() -> None:
    """Point the venv at ``src/`` without installing the project.

    This is what makes the dev loop immune to the locked-launcher problem: no
    console script is generated, so nothing needs replacing.
    """
    site = site_packages()
    site.mkdir(parents=True, exist_ok=True)
    target = site / PTH_NAME
    desired = str(SRC.resolve()) + "\n"
    if target.is_file() and target.read_text(encoding="utf-8") == desired:
        return
    target.write_text(desired, encoding="utf-8")
    say(f"wrote {_display(target)} -> {SRC}")


def drop_installed_copy() -> None:
    """Remove any installed ssh-mcp so it cannot shadow src/.

    A real install in ``site-packages`` is found before any ``.pth`` entry, so
    leaving one in place is exactly how the suite ends up testing stale code.
    """
    proc = python("-m", "pip", "show", "ssh-mcp", check=False, capture=True, quiet=True)
    if proc.returncode != 0:
        return
    say("removing the installed ssh-mcp distribution so src/ is authoritative")
    # A running client may hold Scripts/ssh-mcp.exe; pip fails there but has
    # already moved the package directory aside, which is what matters.
    python("-m", "pip", "uninstall", "-y", "ssh-mcp", check=False, capture=True, quiet=True)
    # pip leaves the package directory itself in place when it dies on the
    # launcher, and a real directory in site-packages still shadows the .pth
    # entry. Removing it directly is what actually restores src/ priority.
    site = site_packages()
    for name in ("ssh_mcp", "ssh_mcp-0.1.0.dist-info"):
        target = site / name
        if target.is_dir():
            say(f"removing {_display(target)}")
            shutil.rmtree(target, ignore_errors=True)


def clean_stale_dirs() -> None:
    for entry in stale_dirs():
        say(f"removing leftover {entry.name}")
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            entry.unlink(missing_ok=True)


# -- commands -----------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    ensure_venv()
    say(f"installing dependencies into {VENV}")
    python("-m", "pip", "install", "--quiet", "--upgrade", "pip")
    python("-m", "pip", "install", "--quiet", "-e", ".[dev]", check=False)
    # That may have aborted on a locked console script. The package may also
    # now be half-removed, so put the environment back into a known state.
    drop_installed_copy()
    clean_stale_dirs()
    write_pth()
    return cmd_doctor(args)


def cmd_install(args: argparse.Namespace) -> int:
    """Refresh dependencies; src/ is already live through the .pth file."""
    ensure_venv()
    python("-m", "pip", "install", "--quiet", "-e", ".[dev]", check=False)
    drop_installed_copy()
    clean_stale_dirs()
    write_pth()
    return cmd_doctor(args)


def cmd_doctor(args: argparse.Namespace) -> int:
    problems: list[str] = []
    say(f"repo     : {REPO}")
    say(f"venv     : {VENV}")

    if not venv_python().is_file():
        problems.append("no virtualenv; run `python scripts/dev.py setup`")
        _report(problems)
        return 1

    path, note = resolve_import()
    if path is None:
        say(f"import   : FAILED ({note})")
        problems.append("ssh_mcp is not importable; run `python scripts/dev.py setup`")
    elif is_from_src(path):
        say(f"import   : {path}  (src/ ✓)")
    else:
        say(f"import   : {path}  (NOT src/ ✗)")
        problems.append(
            "ssh_mcp resolves outside src/, so tests and the server run stale code; "
            "run `python scripts/dev.py install`"
        )

    leftovers = stale_dirs()
    if leftovers:
        say(f"stale    : {', '.join(p.name for p in leftovers)}")
        problems.append("pip left renamed directories behind; run `python scripts/dev.py install`")
    else:
        say("stale    : none")

    pth = site_packages() / PTH_NAME
    say(f"src path : {'set' if pth.is_file() else 'MISSING'}")
    if not pth.is_file():
        problems.append(f"{PTH_NAME} is missing; run `python scripts/dev.py install`")

    for module in ("pytest", "pytest_asyncio", "asyncssh", "mcp", "httpx2", "pydantic"):
        proc = python("-c", f"import {module}", check=False, capture=True, quiet=True, inherit_src=False)
        if proc.returncode != 0:
            problems.append(f"dependency {module} is not importable; run `python scripts/dev.py setup`")

    holders = running_servers()
    if holders:
        say(f"running  : {len(holders)} ssh-mcp process(es) — blocks replacing Scripts/ssh-mcp.exe")
    else:
        say("running  : none")

    _report(problems)
    return 0 if not problems else 1


def _report(problems: list[str]) -> None:
    if not problems:
        say("\nenvironment OK")
        return
    say("")
    for problem in problems:
        say(f"  ! {problem}")


def cmd_test(args: argparse.Namespace) -> int:
    ensure_venv()
    write_pth()
    path, _ = resolve_import()
    if not is_from_src(path):
        say("refusing to run: ssh_mcp does not resolve to src/, so the results would be meaningless")
        say("hint: python scripts/dev.py install")
        return 1
    extra = args.pytest_args or []
    proc = run([str(venv_python()), "-m", "pytest", *extra], check=False)
    return proc.returncode


def cmd_serve(args: argparse.Namespace) -> int:
    ensure_venv()
    write_pth()
    path, _ = resolve_import()
    if not is_from_src(path):
        say("refusing to serve from outside src/: python scripts/dev.py install")
        return 1
    say(f"serving {path}")
    return run([str(venv_python()), "-m", "ssh_mcp", "--transport", args.transport], check=False).returncode


def cmd_clean(args: argparse.Namespace) -> int:
    for pattern in ("build", "dist", "*.egg-info"):
        for path in REPO.glob(pattern):
            say(f"removing {_display(path)}")
            shutil.rmtree(path, ignore_errors=True)
    for cache in REPO.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    for cache in (REPO / ".pytest_cache", REPO / ".mypy_cache", REPO / ".ruff_cache"):
        shutil.rmtree(cache, ignore_errors=True)
    clean_stale_dirs()
    say("clean")
    return 0


# -- entry point --------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dev.py",
        description="Repo-local dev workflow: setup, doctor, test, serve, clean.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, help_text in [
        ("setup", cmd_setup, "create the venv, install dependencies, point it at src/"),
        ("install", cmd_install, "refresh dependencies and re-point the venv at src/"),
        ("doctor", cmd_doctor, "report which code is live and what is stale"),
        ("clean", cmd_clean, "remove build artefacts, caches and pip leftovers"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=handler)

    test = sub.add_parser("test", help="run the suite against src/")
    test.set_defaults(pytest_args=[])
    test.set_defaults(func=cmd_test)

    serve = sub.add_parser("serve", help="run the MCP server from src/")
    serve.add_argument("--transport", default="stdio", choices=("stdio", "streamable-http"))
    serve.set_defaults(func=cmd_serve)

    argv = list(sys.argv[1:] if argv is None else argv)
    # Split off pytest arguments before argparse sees them: ``test`` forwards
    # everything after the subcommand verbatim, so flags like ``-q`` and
    # ``-k expr`` reach pytest instead of being rejected here.
    pytest_args: list[str] = []
    if "test" in argv:
        index = argv.index("test")
        argv, pytest_args = argv[: index + 1], argv[index + 1 :]
        if pytest_args[:1] == ["--"]:
            pytest_args = pytest_args[1:]

    args = parser.parse_args(argv)
    if getattr(args, "func", None) is cmd_test:
        args.pytest_args = pytest_args
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
