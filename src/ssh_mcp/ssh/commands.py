"""Non-interactive remote command execution."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import shlex
from dataclasses import dataclass

import asyncssh

from ssh_mcp.config import Settings
from ssh_mcp.errors import ToolFailure, validate_remote_path
from ssh_mcp.ssh.pool import ConnectionPool, borrow

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


def _short_flags(args: list[str]) -> set[str]:
    """Letters in clustered short options, so ``-bn1`` reads as ``{b, n}``.

    ``top -bn1`` is the batch form people actually type; matching only the
    literal ``-b`` rejected it while accepting ``top -H`` (which is interactive
    and would hang). Both directions were wrong.
    """
    letters: set[str] = set()
    for token in args:
        if not token.startswith("-") or token.startswith("--") or token == "-":
            continue
        for char in token[1:]:
            if not char.isalpha():
                break
            letters.add(char)
    return letters


def _is_batch_top(args: list[str]) -> bool:
    """Whether ``top`` is asked for a single batch snapshot."""
    if "--batch" in args or "b" in _short_flags(args):
        return True
    return False


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


def _split_shell(command: str) -> list[tuple[list[str], bool, str]]:
    """Split a shell command line into the commands it actually runs.

    Quoting has to be honoured: ``grep -E 'a|mysql'`` searches for that
    pattern, it does not pipe into ``mysql``. ``shlex`` in POSIX mode keeps
    quoted text together, and ``punctuation_chars`` exposes the unquoted
    operators so they can act as separators.

    Returns ``(tokens, fed_by_pipe)`` per command, in order.
    ``fed_by_pipe`` is true when the previous command's stdout is this
    command's stdin, which a couple of REPLs treat as a script to run instead
    of opening a prompt. Redirections are dropped.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        # Unbalanced quotes: fall back to plain whitespace splitting rather
        # than guessing; a false negative here is safer than a false positive.
        return [(command.split(), False)]

    commands: list[tuple[list[str], bool]] = []
    current: list[str] = []
    fed_by_pipe = False
    skip_next = False
    for token in tokens:
        if skip_next:
            # The target of a redirection, e.g. the path in ``2>/dev/null``.
            skip_next = False
            continue
        if token and set(token) <= set(";&|()"):
            if current:
                commands.append((current, fed_by_pipe))
            current = []
            # ``||`` and ``;;`` still separate commands; only ``|`` feeds stdin.
            fed_by_pipe = token == "|"
            continue
        if token and set(token) <= set("<>"):
            skip_next = True
            continue
        if token.startswith(">") or token.startswith("<") or token.endswith(">"):
            # ``2>`` / ``>/dev/null`` / ``2>&1`` arrive glued to the fd or path.
            continue
        current.append(token)
    if current:
        commands.append((current, fed_by_pipe))
    return commands


def _interactive_offense(command: str) -> tuple[str, str] | None:
    """Return ``(program, segment)`` for the first part that needs a TTY.

    ``segment`` is the offending command as it appeared, which matters for a
    compound line: reporting the whole line left the caller guessing which
    half to rewrite.
    """
    stripped = command.strip()
    if not stripped:
        return None
    for tokens, fed_by_pipe in _split_shell(stripped):
        original = list(tokens)
        tokens = _strip_wrappers(tokens)
        if not tokens:
            continue
        program = tokens[0].rsplit("/", 1)[-1]
        rest = tokens[1:]
        if program in _ALWAYS_INTERACTIVE:
            return program, " ".join(original)
        if program == "top" and not _is_batch_top(rest):
            # ``top -b -n1`` / ``top -bn1`` are the documented batch forms;
            # ``-H`` or ``-n`` alone still open an interactive display.
            return program, " ".join(original)
        if program in {"tail", "journalctl"} and _FOLLOW_FLAGS.intersection(rest):
            flag = sorted(_FOLLOW_FLAGS.intersection(rest))[0]
            return f"{program} {flag}", " ".join(original)
        if program in _REPL_WITHOUT_ARGS and not _reads_stdin(program, rest, fed_by_pipe):
            return program, " ".join(original)
    return None


def _interactive_reason(command: str) -> str | None:
    """Return the offending program when ``command`` obviously needs a TTY."""
    offense = _interactive_offense(command)
    return offense[0] if offense else None


def _reads_stdin(program: str, rest: list[str], fed_by_pipe: bool) -> bool:
    """Whether ``rest`` gives the REPL something to run instead of a prompt.

    Every one of these programs falls back to reading commands from stdin when
    it gets nothing to execute, and the exec channel's stdin stays open -- so
    "no argument" means "hangs until the timeout". Being on the right side of a
    pipe counts as "has input" only for the programs that actually parse their
    stdin as commands; for the rest the pipe just feeds data and they still
    open a prompt.
    """
    # An input redirect hands the program a file instead of our open channel.
    if "<" in rest:
        return True
    positional = [token for token in rest if not token.startswith("-")]
    flags = {token for token in rest if token.startswith("-")}
    if program in {"python", "python3", "node", "irb"}:
        return bool(positional) or bool(flags & {"-c", "-m", "-e", "-p", "--eval", "--print"})
    if program in {"bash", "sh", "zsh", "fish", "tcsh", "csh"}:
        return bool(positional) or bool(flags & {"-c", "-i"}) or fed_by_pipe
    if program in {"pwsh", "powershell"}:
        return bool(flags & {"-Command", "-File", "-c", "-EncodedCommand"})
    if program in {"mysql", "psql", "redis-cli"}:
        # The database name / query is positional only for redis-cli; for
        # mysql/psql the query comes through a flag. Piped stdin is only a
        # command source for psql and redis-cli.
        if program == "redis-cli" and (positional or fed_by_pipe):
            return True
        if program == "psql" and fed_by_pipe:
            return True
        return bool(flags & {"-e", "-c", "-f", "--execute", "--command", "--file"})
    if program in {"ssh", "telnet"}:
        # ``ssh host`` alone opens a shell; ``ssh host uptime`` runs and exits.
        return len(positional) >= 2
    # ftp/sftp read commands from stdin unless given a batch file.
    return bool(flags & {"-b", "--batch-file"}) or fed_by_pipe


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


def _interactive_hint(offender: str, segment: str) -> str:
    """Explain the refusal with the fix for this specific program."""
    tail = (
        "改法：把查询交给参数（`mysql -e 'select 1'`、`psql -c 'select 1'`），"
        "或从 stdin 喂输入（`echo 'select 1' | redis-cli`）；"
        "只有在确实需要 TTY 时才传 allow_interactive=true。"
    )
    if offender.startswith("top"):
        return (
            f"命令里的 `{offender}` 会打开交互式界面，在非交互通道上会一直挂起到超时。"
            f"改法：加批处理参数 `top -b -n1`（连写 `top -bn1` 也可以），或用 list_processes。{tail}"
        )
    if offender.startswith("tail"):
        return (
            f"命令里的 `{offender}` 会持续跟随文件，永不结束。"
            f"改法：用 `tail -n 100`（不要 -f），或用 tail_log。{tail}"
        )
    if offender.startswith("journalctl"):
        return (
            f"命令里的 `{offender}` 会持续跟随日志。"
            f"改法：用 `journalctl --no-pager -n 100`（不要 -f），或用 tail_log。{tail}"
        )
    return (
        f"命令里的 `{offender}` 会等待终端输入（片段：`{segment}`），"
        f"在非交互通道上会一直挂起到超时。{tail}"
    )


class CommandRunner:
    """Runs commands on a pooled connection with bounded output and hard timeouts."""

    def __init__(self, settings: Settings, pool: ConnectionPool) -> None:
        self._settings = settings
        self._pool = pool

    async def run(
        self,
        handle: str | None,
        command: str,
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        allow_interactive: bool = False,
    ) -> CommandResult:
        validate_remote_path(command, "command")
        if not allow_interactive:
            offense = _interactive_offense(command)
            if offense is not None:
                offender, segment = offense
                raise ToolFailure(
                    "interactive_command_rejected",
                    stage="validate",
                    hint=_interactive_hint(offender, segment),
                    retryable=False,
                    command=offender,
                    segment=segment,
                )

        timeout = timeout_seconds if timeout_seconds is not None else self._settings.command_timeout_default
        if timeout <= 0:
            raise ToolFailure("invalid_argument", stage="validate", hint="timeout_seconds 必须大于 0。", retryable=False)
        timeout = min(timeout, self._settings.command_timeout_max)
        cap = max_output_bytes or self._settings.command_max_output_bytes
        if cap < 1024:
            raise ToolFailure("invalid_argument", stage="validate", hint="max_output_bytes 至少为 1024。", retryable=False)

        try:
            async with borrow(self._pool, handle) as acquired:
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
        # ``setsid`` runs the command as the leader of its own session, so the
        # whole tree it spawns can be killed as one process group. SSH
        # ``signal`` requests only reach the shell, which leaves grandchildren
        # such as ``sleep`` running after a timeout.
        #
        # Not every server has it (busybox images, Windows OpenSSH): the probe
        # runs once per connection and falls back to executing the command
        # directly, where only the channel-level controls are available.
        marker: str | None = None
        remote_command = command
        if await self._supports_setsid(conn):
            marker = f"/tmp/.ssh-mcp-{secrets.token_hex(8)}.pgid"
            remote_command = f"setsid sh -c {shlex.quote(command)} & echo $! > {marker}; wait $!"
        process = await conn.create_process(remote_command, encoding=None)

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
            terminated = await self._terminate(process, conn, marker)
            logger.warning("command timed out after %.1fs; remote process terminated=%s", timeout, terminated)
        except asyncio.CancelledError:
            # Client cancelled (stdio EOF or HTTP disconnect): kill the remote
            # process, then let the cancellation propagate.
            cancelled = True
            with contextlib.suppress(Exception):
                await asyncio.shield(self._terminate(process, conn, marker))
            raise
        finally:
            if timed_out or cancelled:
                # ``_terminate`` closes the channel when the peer does not
                # cooperate, so this only drains an already-closed channel.
                # It stays bounded: a server that never acknowledges must not
                # turn a 2-second timeout into a multi-minute hang.
                with contextlib.suppress(Exception):
                    await asyncio.shield(asyncio.wait_for(process.wait_closed(), timeout=2))

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

    async def _supports_setsid(self, conn: asyncssh.SSHClientConnection) -> bool:
        """Whether the remote can isolate a command in its own session."""
        cached = getattr(conn, "_ssh_mcp_setsid", None)
        if cached is not None:
            return cached
        try:
            result = await asyncio.wait_for(
                conn.run("command -v setsid >/dev/null 2>&1 && echo yes", check=False), timeout=10
            )
            supported = "yes" in str(result.stdout)
        except (asyncssh.Error, OSError, TimeoutError):
            supported = False
        with contextlib.suppress(Exception):
            conn._ssh_mcp_setsid = supported
        return supported

    async def _terminate(
        self,
        process: asyncssh.SSHClientProcess,
        conn: asyncssh.SSHClientConnection,
        marker: str | None,
    ) -> bool:
        """Stop the remote command and everything it spawned.

        Signals alone are not enough: an SSH ``signal`` request reaches the
        remote shell, not the process tree underneath it. The command runs as a
        ``setsid`` session leader, so its group id is the session leader's pid,
        which the wrapper wrote to ``marker``. Killing that group takes the
        grandchildren with it. Returns whether the whole tree is gone.
        """
        pgid = await self._read_pgid(conn, marker) if marker else None
        if marker is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.run(f"rm -f {marker}", check=False), timeout=5)
        if pgid is not None:
            # Negative pid = the whole process group.
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.run(f"kill -TERM -{pgid}", check=False), timeout=5)
            with contextlib.suppress(Exception):
                async with asyncio.timeout(1.5):
                    await process.wait()
        # TERM to a group can be ignored; KILL cannot.
        if pgid is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    conn.run(f"kill -KILL -{pgid} 2>/dev/null; rm -f {marker}", check=False), timeout=5
                )
        else:
            # No marker (the command died before the wrapper ran): fall back to
            # the channel-level controls.
            for action in (process.terminate, process.kill):
                with contextlib.suppress(Exception):
                    action()
                try:
                    async with asyncio.timeout(1.5):
                        await process.wait()
                    break
                except TimeoutError:
                    continue
                except Exception:  # noqa: BLE001
                    break
        process.close()
        if await self._group_alive(conn, pgid):
            return False
        return True

    @staticmethod
    async def _read_pgid(conn: asyncssh.SSHClientConnection, marker: str) -> int | None:
        """Read the group id the wrapper recorded, or ``None``."""
        try:
            result = await asyncio.wait_for(conn.run(f"cat {marker} 2>/dev/null", check=False), timeout=5)
        except (asyncssh.Error, OSError, TimeoutError):
            return None
        try:
            return int(str(result.stdout).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    async def _group_alive(conn: asyncssh.SSHClientConnection, pgid: int | None) -> bool:
        if pgid is None:
            return False
        try:
            result = await asyncio.wait_for(conn.run(f"kill -0 -{pgid} 2>/dev/null && echo alive", check=False), timeout=5)
        except (asyncssh.Error, OSError, TimeoutError):
            return False
        return "alive" in str(result.stdout)

    # -- background commands ---------------------------------------------------

    async def start_background(
        self,
        handle: str | None,
        command: str,
    ) -> dict:
        """Launch ``command`` detached; its output lands in files, not a channel.

        The whole trick is one line of shell: ``setsid`` detaches the process,
        output redirections capture the streams, and the wrapper's pid written
        to the marker file doubles as the job id. Nothing is kept in this
        process, so the job survives disconnects, restarts of this MCP server,
        and needs no reaper of its own.
        """
        validate_remote_path(command, "command")
        offense = _interactive_offense(command)
        if offense is not None:
            offender, segment = offense
            raise ToolFailure(
                "interactive_command_rejected",
                stage="validate",
                hint=(
                    f"命令里的 `{offender}` 会等待终端输入；后台运行同样需要批处理写法。"
                    f"片段：`{segment}`。"
                ),
                retryable=False,
                command=offender,
                segment=segment,
            )
        try:
            async with borrow(self._pool, handle) as acquired:
                conn = acquired.conn
                if not await self._supports_setsid(conn):
                    raise ToolFailure(
                        "background_unsupported",
                        stage="execute",
                        hint="远端没有 setsid，无法安全地脱离会话运行后台命令；请改用 nohup 手工执行。",
                        retryable=False,
                    )
                job_id = f"bg-{secrets.token_hex(6)}"
                out = f"/tmp/.ssh-mcp-{job_id}.out"
                err = f"/tmp/.ssh-mcp-{job_id}.err"
                marker = f"/tmp/.ssh-mcp-{job_id}.pid"
                wrapped = (
                    f"setsid sh -c {shlex.quote(command)} >{shlex.quote(out)} 2>{shlex.quote(err)}"
                    f" & echo $! > {shlex.quote(marker)}"
                )
                result = await asyncio.wait_for(conn.run(wrapped, check=False), timeout=15)
                if result.exit_status != 0:
                    raise ToolFailure(
                        "background_start_failed",
                        stage="execute",
                        hint=f"后台命令启动失败：{str(result.stderr)[:300]}",
                        retryable=True,
                    )
                return {
                    "job_id": job_id,
                    "status": "running",
                    "output_files": {"stdout": out, "stderr": err},
                    "hint": "用 get_background_command 查询进度；结束后它会取回输出并清理临时文件。",
                }
        except ToolFailure:
            raise
        except (asyncssh.Error, ConnectionError, OSError, TimeoutError) as exc:
            raise ToolFailure(
                "background_start_failed",
                stage="execute",
                hint=f"后台命令启动失败（{type(exc).__name__}），请重试。",
                retryable=True,
            ) from None

    async def get_background(
        self,
        handle: str | None,
        job_id: str,
        *,
        max_output_bytes: int | None = None,
        cleanup: bool = False,
    ) -> dict:
        """Report one background job's status and tail its output files.

        ``cleanup`` removes the marker/output files once the AI has what it
        needs; finishing without it keeps the files for a later call.
        """
        if not job_id.replace("-", "").isalnum() or job_id.count("-") != 1 or not job_id.startswith("bg-"):
            # The id becomes part of a shell path below; only our own shape passes.
            raise ToolFailure(
                "invalid_argument", stage="validate", hint=f"job_id 形如 bg-0a1b2c3d4e5f，收到 {job_id!r}。", retryable=False
            )
        cap = max_output_bytes or self._settings.command_max_output_bytes
        out = f"/tmp/.ssh-mcp-{job_id}.out"
        err = f"/tmp/.ssh-mcp-{job_id}.err"
        marker = f"/tmp/.ssh-mcp-{job_id}.pid"
        try:
            async with borrow(self._pool, handle) as acquired:
                conn = acquired.conn
                probe = (
                    f"pid=$(cat {shlex.quote(marker)} 2>/dev/null); "
                    f"if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then echo RUNNING; "
                    f"else echo DONE; fi; "
                    f"echo \"exit=$(cat {shlex.quote(marker)}.code 2>/dev/null || echo '')\"; "
                    f"echo \"out_bytes=$(stat -c %s {shlex.quote(out)} 2>/dev/null || echo 0)\"; "
                    f"echo \"err_bytes=$(stat -c %s {shlex.quote(err)} 2>/dev/null || echo 0)\""
                )
                result = await asyncio.wait_for(conn.run(probe, check=False), timeout=15)
                lines = str(result.stdout).splitlines()
                running = "RUNNING" in (lines[0] if lines else "")
                exit_code: int | None = None
                out_bytes = err_bytes = 0
                for line in lines:
                    if line.startswith("exit="):
                        try:
                            exit_code = int(line[5:])
                        except ValueError:
                            exit_code = None
                    elif line.startswith("out_bytes="):
                        out_bytes = int(line[10:] or 0)
                    elif line.startswith("err_bytes="):
                        err_bytes = int(line[11:] or 0)
                payload: dict = {
                    "job_id": job_id,
                    "status": "running" if running else "finished",
                    "stdout_bytes": out_bytes,
                    "stderr_bytes": err_bytes,
                }
                if not running:
                    payload["exit_code"] = exit_code
                tail_budget = max(1024, min(cap, self._settings.command_max_output_bytes))
                stdout_tail = await self._read_remote_tail(conn, out, tail_budget)
                stderr_tail = await self._read_remote_tail(conn, err, max(1024, tail_budget // 4))
                payload["stdout_tail"] = stdout_tail
                payload["stderr_tail"] = stderr_tail
                if running:
                    payload["hint"] = "仍在运行；稍后再次调用查看进度。结束后可再调一次取完整输出。"
                else:
                    payload["hint"] = "已结束。stdout_tail/stderr_tail 是文件末尾内容；确认不再需要后传 cleanup=true 删除临时文件。"
                if cleanup and not running:
                    await asyncio.wait_for(
                        conn.run(f"rm -f {shlex.quote(out)} {shlex.quote(err)} {shlex.quote(marker)} {marker}.code", check=False),
                        timeout=10,
                    )
                    payload["cleaned"] = True
                return payload
        except ToolFailure:
            raise
        except (asyncssh.Error, ConnectionError, OSError, TimeoutError) as exc:
            raise ToolFailure(
                "connection_lost",
                stage="execute",
                hint=f"查询后台命令失败（{type(exc).__name__}）；后台进程不受影响，请重试。",
                retryable=True,
            ) from None

    @staticmethod
    async def _read_remote_tail(conn: asyncssh.SSHClientConnection, path: str, cap: int) -> str:
        """Last ``cap`` bytes of a remote file, as text; empty when absent."""
        result = await asyncio.wait_for(
            conn.run(f"tail -c {int(cap)} {shlex.quote(path)} 2>/dev/null", check=False), timeout=15
        )
        data = result.stdout
        if isinstance(data, bytes):
            return data.decode("utf-8", "replace")
        return str(data)
