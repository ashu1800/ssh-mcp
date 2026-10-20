"""Non-interactive remote command execution."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shlex
from dataclasses import dataclass

import asyncssh

from ssh_mcp.config import Settings
from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.pool import ConnectionPool

logger = logging.getLogger(__name__)

# Programs that never make sense without a terminal: they take over the screen
# or wait for keystrokes and would hang an exec channel.
_ALWAYS_INTERACTIVE = frozenset(
    {
        "vi", "vim", "nvim", "nano", "emacs", "less", "more", "most", "htop", "atop",
        "btop", "iftop", "watch", "man", "screen", "tmux", "mc", "nmtui", "alsamixer",
    }
)
# Programs that are interactive only when started without anything to run: with
# a script/query/host argument they terminate on their own. Treating them as
# interactive outright rejects routine commands such as
# ``python3 manage.py migrate`` or ``mysql -e 'select 1'``.
_REPL_WITHOUT_ARGS = frozenset(
    {
        "python", "python3", "node", "irb", "mysql", "psql", "redis-cli", "ssh", "telnet",
        "ftp", "sftp", "bash", "sh", "zsh", "fish", "tcsh", "csh", "pwsh", "powershell",
    }
)
# Commands that stream forever only under a specific flag.
_FOLLOW_FLAGS = frozenset({"-f", "-F", "--follow", "--follow=yes"})


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int | None
    exit_signal: str | None
    truncated: bool
    total_stdout_bytes: int
    total_stderr_bytes: int
    duration_seconds: float
    terminated: bool = False
    timed_out: bool = False

    def to_dict(self) -> dict:
        payload = {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "exit_signal": self.exit_signal,
            "truncated": self.truncated,
            "stdout_total_bytes": self.total_stdout_bytes,
            "stderr_total_bytes": self.total_stderr_bytes,
            "duration_seconds": round(self.duration_seconds, 3),
        }
        if self.terminated:
            payload["terminated"] = True
        if self.timed_out:
            payload["timed_out"] = True
        return payload


def _interactive_reason(command: str) -> str | None:
    """Return the offending program when ``command`` obviously needs a TTY."""
    stripped = command.strip()
    if not stripped:
        return None
    for segment in stripped.split(";"):
        for pipeline_part in segment.split("|"):
            part = pipeline_part.strip()
            if not part:
                continue
            try:
                tokens = shlex.split(part)
            except ValueError:
                tokens = part.split()
            tokens = _strip_wrappers(tokens)
            if not tokens:
                continue
            program = tokens[0].rsplit("/", 1)[-1]
            rest = tokens[1:]
            if program in _ALWAYS_INTERACTIVE:
                return program
            if program == "top" and not any(token in {"-b", "-H", "-n"} for token in rest):
                # ``top -b -n1`` is the documented batch alternative.
                return program
            if program in {"tail", "journalctl"} and _FOLLOW_FLAGS.intersection(rest):
                return f"{program} {' '.join(sorted(_FOLLOW_FLAGS.intersection(rest)))}"
            if program in _REPL_WITHOUT_ARGS and not _has_program_argument(program, rest):
                return program
    return None


def _has_program_argument(program: str, rest: list[str]) -> bool:
    """Whether ``rest`` gives the REPL something to run instead of a prompt.

    Every one of these programs falls back to reading commands from stdin when
    it gets nothing to execute, and the exec channel's stdin stays open -- so
    "no argument" means "hangs until the timeout".
    """
    # An input redirect hands the program a file instead of our open channel.
    if "<" in rest:
        return True
    positional = [token for token in rest if not token.startswith("-")]
    flags = {token for token in rest if token.startswith("-")}
    if program in {"python", "python3", "node", "irb"}:
        return bool(positional) or bool(flags & {"-c", "-m", "-e", "-p", "--eval", "--print"})
    if program in {"bash", "sh", "zsh", "fish", "tcsh", "csh"}:
        return bool(positional) or bool(flags & {"-c", "-i"})
    if program in {"pwsh", "powershell"}:
        return bool(flags & {"-Command", "-File", "-c", "-EncodedCommand"})
    if program in {"mysql", "psql", "redis-cli"}:
        # The database name / query is positional only for redis-cli; for
        # mysql/psql the query comes through a flag.
        return bool(flags & {"-e", "-c", "-f", "--execute", "--command", "--file"}) or (
            program == "redis-cli" and bool(positional)
        )
    if program in {"ssh", "telnet"}:
        # ``ssh host`` alone opens a shell; ``ssh host uptime`` runs and exits.
        return len(positional) >= 2
    # ftp/sftp read commands from stdin unless given a batch file.
    return bool(flags & {"-b", "--batch-file"})


# Wrappers that run another program; the program after them is the real subject.
_WRAPPERS_WITH_ARG = {"sudo", "doas", "env", "nice", "ionice", "timeout", "time", "nohup", "exec", "command"}
_WRAPPERS_WITHOUT_ARG = {"stdbuf", "unbuffer", "script"}


def _strip_wrappers(tokens: list[str]) -> list[str]:
    """Drop privilege/scheduling prefixes so ``sudo htop`` is recognised."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        program = token.rsplit("/", 1)[-1]
        if program not in _WRAPPERS_WITH_ARG and program not in _WRAPPERS_WITHOUT_ARG:
            break
        index += 1
        if program in _WRAPPERS_WITHOUT_ARG:
            continue
        # Skip the wrapper's own options and, for env/timeout, its argument.
        if program in {"timeout", "env"} and index < len(tokens):
            index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
        if program == "sudo":
            # ``sudo -u user cmd``: -u already consumed its value via the
            # generic option loop only when written as ``-uuser``; handle the
            # common two-token form.
            if index >= 2 and tokens[index - 1] == "-u" and index < len(tokens):
                index += 1
    return tokens[index:]


class CommandRunner:
    """Runs commands on a pooled connection with bounded output and hard timeouts."""

    def __init__(self, settings: Settings, pool: ConnectionPool) -> None:
        self._settings = settings
        self._pool = pool

    async def run(
        self,
        handle: str,
        command: str,
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        allow_interactive: bool = False,
    ) -> CommandResult:
        if not command or not command.strip():
            raise ToolFailure("invalid_argument", stage="validate", hint="command 不能为空。", retryable=False)
        if "\x00" in command:
            raise ToolFailure(
                "invalid_argument", stage="validate", hint="command 不能包含 NUL 字符。", retryable=False
            )
        if not allow_interactive:
            offender = _interactive_reason(command)
            if offender is not None:
                raise ToolFailure(
                    "interactive_command_rejected",
                    stage="validate",
                    hint=(
                        f"检测到交互式命令 `{offender}`，非交互式通道执行会挂起。"
                        "请改用非交互形式（如 `top -b -n1`、`tail -n 100`），或显式传 allow_interactive=true。"
                    ),
                    retryable=False,
                    command=offender,
                )

        timeout = timeout_seconds if timeout_seconds is not None else self._settings.command_timeout_default
        if timeout <= 0:
            raise ToolFailure("invalid_argument", stage="validate", hint="timeout_seconds 必须大于 0。", retryable=False)
        timeout = min(timeout, self._settings.command_timeout_max)
        cap = max_output_bytes or self._settings.command_max_output_bytes
        if cap < 1024:
            raise ToolFailure("invalid_argument", stage="validate", hint="max_output_bytes 至少为 1024。", retryable=False)

        acquired = await self._pool.acquire(handle)
        try:
            return await self._execute(acquired.conn, command, timeout=timeout, cap=cap)
        except ToolFailure:
            raise
        except (asyncssh.ChannelOpenError, asyncssh.ConnectionLost, ConnectionError, OSError) as exc:
            # The connection died between acquire() and the exec request, or
            # mid-command: report it as a structured, retryable failure instead
            # of letting asyncssh's exception escape the tool boundary.
            logger.warning("command failed because the SSH connection went away: %s", type(exc).__name__)
            raise ToolFailure(
                "connection_lost",
                stage="execute",
                hint="SSH 连接已断开，命令可能未执行或已中断；请重新 connect 后重试。",
                retryable=True,
                connection_handle=handle,
                detail=type(exc).__name__,
            ) from None
        finally:
            self._pool.release(acquired.entry)

    async def _execute(
        self,
        conn: asyncssh.SSHClientConnection,
        command: str,
        *,
        timeout: float,
        cap: int,
    ) -> CommandResult:
        loop = asyncio.get_running_loop()
        started = loop.time()
        process = await conn.create_process(command, encoding=None)

        stdout_buf = bytearray()
        stderr_buf = bytearray()
        counters = {"stdout": 0, "stderr": 0}

        async def drain(stream, buffer: bytearray, name: str) -> None:
            while True:
                try:
                    chunk = await stream.read(65536)
                except asyncssh.ChannelOpenError:
                    break
                if not chunk:
                    break
                counters[name] += len(chunk)
                room = cap - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])

        timed_out = False
        terminated = False
        cancelled = False
        try:
            async with asyncio.timeout(timeout):
                async with asyncio.TaskGroup() as tg:
                    tg.create_task(drain(process.stdout, stdout_buf, "stdout"))
                    tg.create_task(drain(process.stderr, stderr_buf, "stderr"))
                await process.wait()
        except TimeoutError:
            timed_out = True
            terminated = await self._terminate(process)
            logger.warning("command timed out after %.1fs; remote process terminated=%s", timeout, terminated)
        except asyncio.CancelledError:
            # Client cancelled (stdio EOF or HTTP disconnect): kill the remote
            # process, then let the cancellation propagate.
            cancelled = True
            with contextlib.suppress(Exception):
                await asyncio.shield(self._terminate(process))
            raise
        finally:
            if timed_out or cancelled:
                with contextlib.suppress(Exception):
                    await asyncio.shield(process.wait_closed())

        duration = loop.time() - started
        exit_status = getattr(process, "exit_status", None)
        exit_signal = None
        signal_info = getattr(process, "exit_signal", None)
        if signal_info:
            exit_signal = signal_info[0] if isinstance(signal_info, tuple) else str(signal_info)

        truncated = counters["stdout"] > len(stdout_buf) or counters["stderr"] > len(stderr_buf)
        stdout_text = stdout_buf.decode("utf-8", "replace")
        stderr_text = stderr_buf.decode("utf-8", "replace")
        if counters["stdout"] > len(stdout_buf):
            stdout_text += f"\n[truncated, total {counters['stdout']} bytes]"
        if counters["stderr"] > len(stderr_buf):
            stderr_text += f"\n[truncated, total {counters['stderr']} bytes]"

        result = CommandResult(
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_status,
            exit_signal=exit_signal,
            truncated=truncated,
            total_stdout_bytes=counters["stdout"],
            total_stderr_bytes=counters["stderr"],
            duration_seconds=duration,
            terminated=terminated,
            timed_out=timed_out,
        )
        return result

    async def _terminate(self, process: asyncssh.SSHClientProcess) -> bool:
        """Terminate the remote process, escalating TERM -> KILL -> channel close."""
        for action in (process.terminate, process.kill):
            with contextlib.suppress(Exception):
                action()
            try:
                async with asyncio.timeout(3):
                    await process.wait()
                return True
            except TimeoutError:
                continue
            except Exception:  # noqa: BLE001
                break
        with contextlib.suppress(Exception):
            process.close()
            async with asyncio.timeout(3):
                await process.wait_closed()
            return True
        return False
