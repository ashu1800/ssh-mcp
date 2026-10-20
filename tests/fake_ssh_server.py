"""Local AsyncSSH server used by the test suite.

Implements just enough of an SSH server to exercise the real client code:

* password and public-key authentication (``authorized_keys`` is a real file,
  so the connect flow can append to it and a later connection can use it)
* a session that executes commands via the host shell (or a tiny built-in
  emulation when the platform has no POSIX shell)
* the stock SFTP server, rooted at a temporary directory
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sys
from functools import partial
from pathlib import Path

import asyncssh

PASSWORDS = {"testuser": "test-password"}


class FakeSSHServer(asyncssh.SSHServer):
    def __init__(self, home: Path, handle: "FakeSSHServerHandle | None" = None) -> None:
        self._home = home
        self._handle = handle
        self._conn: asyncssh.SSHServerConnection | None = None
        self.auth_method_used: str | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        if self._handle is not None:
            self._handle.track(conn)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if PASSWORDS.get(username) == password:
            self.auth_method_used = "password"
            return True
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        allowed = read_authorized_keys(self._home)
        if any(candidate == key for candidate in allowed):
            self.auth_method_used = "publickey"
            return True
        return False

    def session_requested(self) -> "asyncssh.SSHServerSession":
        return FakeSession(self._home)


async def _process_factory(process: asyncssh.SSHServerProcess, home: Path) -> None:
    """Serve one exec request.

    Configured alongside ``sftp_factory``: when either is set AsyncSSH routes
    every session through ``SSHServerStreamSession``/``SSHServerProcess`` and
    never calls ``session_requested``, so command execution has to live here.

    On POSIX the command runs in the host shell (``cwd`` = the fake home). On
    Windows there is no POSIX shell, so a tiny built-in interpreter covers the
    handful of commands the tests use (echo, cat, touch, sleep, head, exit,
    ``&&``/``;`` chaining, stderr redirect).
    """
    command = process.command or ""
    if not command.strip():
        process.exit(1)
        return
    if sys.platform == "win32":
        await _run_builtin(process, command, home)
        return
    env = {**os.environ, "HOME": str(home)}
    try:
        child = await asyncio.create_subprocess_shell(
            command,
            cwd=str(home),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            # New process group so a TERM to the shell reaches the whole tree.
            start_new_session=True,
        )
    except OSError as exc:
        process.stderr.write(f"fake server error: {exc}\n".encode())
        process.exit(1)
        return
    try:
        await _pump(child.stdout, process.stdout)
        await _pump(child.stderr, process.stderr)
        code = await child.wait()
        process.exit(code)
    except (BrokenPipeError, ConnectionResetError):
        if child.returncode is None:
            child.kill()
    finally:
        if child.returncode is None:
            child.kill()


async def _run_builtin(process: asyncssh.SSHServerProcess, command: str, home: Path) -> None:
    """Minimal Windows stand-in for a POSIX shell."""
    code = 0
    for segment in command.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        to_stderr = False
        if ">&2" in segment:
            segment = segment.replace(">&2", "").strip()
            to_stderr = True
        stream = process.stderr if to_stderr else process.stdout
        parts = segment.split()
        program, args = parts[0], parts[1:]

        if program == "echo":
            line = " ".join(args)
            if line.endswith("&& exit"):
                line = line[: -len("&& exit")]
            stream.write((line + "\n").encode())
            await stream.drain()
        elif program == "cat":
            for name in args:
                path = home / name
                if path.is_file():
                    stream.write(path.read_bytes())
                    await stream.drain()
        elif program == "touch":
            for name in args:
                (home / name).parent.mkdir(parents=True, exist_ok=True)
                (home / name).write_bytes(b"")
        elif program == "sleep":
            try:
                await asyncio.sleep(float(args[0]) if args else 0)
            except asyncio.CancelledError:
                process.exit(130)
                return
        elif program == "head":
            # ``head -c N file`` only.
            if len(args) >= 3 and args[0] == "-c":
                path = home / args[2]
                if path.is_file():
                    stream.write(path.read_bytes()[: int(args[1])])
                    await stream.drain()
        elif program == "exit":
            code = int(args[0]) if args else 0
            break
        else:
            process.stderr.write(f"fake server: unsupported command {program!r}\n".encode())
            code = 127
            break
    process.exit(code)


async def _pump(source: asyncio.StreamReader | None, sink) -> None:
    if source is None:
        return
    while True:
        chunk = await source.read(65536)
        if not chunk:
            break
        sink.write(chunk)
        await sink.drain()


def read_authorized_keys(home: Path) -> list[asyncssh.SSHKey]:
    path = home / ".ssh" / "authorized_keys"
    if not path.is_file():
        return []
    keys = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            keys.append(asyncssh.import_public_key(line))
        except (asyncssh.KeyImportError, ValueError):
            continue
    return keys


class FakeSession(asyncssh.SSHServerSession):
    """Runs the requested command with the host shell, rooted at ``home``."""

    def __init__(self, home: Path) -> None:
        self._home = home
        self._chan = None
        self._process: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task | None = None

    def connection_made(self, chan) -> None:
        self._chan = chan

    def shell_requested(self) -> bool:
        return False

    def exec_requested(self, command: str) -> bool:
        assert self._chan is not None
        self._task = asyncio.ensure_future(self._run(command))
        return True

    def data_received(self, data, datatype) -> None:
        assert self._chan is not None
        self._chan.write_stderr(b"this fake server does not accept stdin\n")

    def eof_received(self) -> bool:
        return False

    def connection_lost(self, exc) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
        if self._process is not None and self._process.returncode is None:
            self._process.kill()

    def break_received(self, msec: int) -> bool:
        return False

    async def _run(self, command: str) -> None:
        assert self._chan is not None
        try:
            if sys.platform == "win32":
                self._chan.write_stderr(b"fake server: shell execution is disabled on this platform\n")
                self._chan.exit(127)
                return
            self._process = await asyncio.create_subprocess_shell(
                command,
                cwd=str(self._home),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "HOME": str(self._home)},
            )
            assert self._process.stdout is not None
            assert self._process.stderr is not None
            await asyncio.gather(
                self._pump(self._process.stdout, stdout=True),
                self._pump(self._process.stderr, stdout=False),
            )
            code = await self._process.wait()
            self._chan.exit(code)
        except Exception as exc:  # noqa: BLE001
            self._chan.write_stderr(f"fake server error: {type(exc).__name__}\n".encode())
            self._chan.exit(1)
        finally:
            self._chan.write_eof()

    async def _pump(self, stream: asyncio.StreamReader, *, stdout: bool) -> None:
        assert self._chan is not None
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            if stdout:
                self._chan.write(chunk)
            else:
                self._chan.write_stderr(chunk)


class FakeSSHServerHandle:
    def __init__(self, acceptor: asyncssh.SSHAcceptor, home: Path, port: int, loop: asyncio.AbstractEventLoop) -> None:
        self._acceptor = acceptor
        self.home = home
        self.port = port
        self._loop = loop
        self._connections: set[asyncssh.SSHServerConnection] = set()

    def track(self, conn: asyncssh.SSHServerConnection) -> None:
        self._connections.add(conn)

    async def close(self) -> None:
        # Stop accepting first, then tear down live connections, then wait for
        # the listener. Waiting on the acceptor while connections are still up
        # hangs on Windows.
        self._acceptor.close()
        for conn in list(self._connections):
            with contextlib.suppress(Exception):
                conn.close()
        for conn in list(self._connections):
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.wait_closed(), timeout=2)
        self._connections.clear()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._acceptor.wait_closed(), timeout=2)


_PENDING: set[asyncio.Future] = set()


async def start_server(tmp_path: Path, *, host_keys: list[asyncssh.SSHKey] | None = None) -> FakeSSHServerHandle:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / ".ssh").mkdir(exist_ok=True)
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    keys = host_keys or [server_key]
    handles: list[FakeSSHServerHandle] = []

    def factory() -> FakeSSHServer:
        server = FakeSSHServer(home)
        if handles:
            server._handle = handles[0]
        return server

    acceptor = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=factory,
        server_host_keys=keys,
        sftp_factory=lambda chan: _ChrootSFTPServer(chan, home),
        process_factory=partial(_process_factory, home=home),
        encoding=None,
        config=None,
    )
    port = acceptor.get_port()
    handle = FakeSSHServerHandle(acceptor, home, port, asyncio.get_running_loop())
    handles.append(handle)
    return handle


class _ChrootSFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan, home: Path) -> None:
        super().__init__(chan, chroot=str(home))


def install_public_key(home: Path, key: asyncssh.SSHKey) -> None:
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    path = ssh_dir / "authorized_keys"
    exported = key.export_public_key("openssh")
    if isinstance(exported, bytes):
        exported = exported.decode("ascii")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(exported.strip() + "\n")


def remove_authorized_keys(home: Path) -> None:
    path = home / ".ssh" / "authorized_keys"
    if path.exists():
        path.unlink()


def reset_home(home: Path) -> None:
    for child in home.iterdir():
        if child.name == ".ssh":
            remove_authorized_keys(home)
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)
