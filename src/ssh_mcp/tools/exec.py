"""Remote command execution tool."""

from __future__ import annotations

import logging
from typing import Annotated

from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.commands import CommandRunner
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)


class ExecTools:
    """Registers ``execute_command``."""

    def __init__(self, app, runner: CommandRunner) -> None:
        self._runner = runner

        @app.tool(
            name="start_background_command",
            title="后台启动长命令",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def start_background_command(
            command: Annotated[str, Field(description="要后台执行的非交互式 shell 命令，例如 apt install -y pkg 或大型迁移脚本。")],
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """把长命令脱离会话放到远端后台运行，立即返回 job_id，不受 execute_command 的超时限制。
            stdout/stderr 落在远端 /tmp 下的文件里；命令继续跑，即使连接断开或本进程重启也不受影响。
            返回 {job_id, status: "running", output_files}。
            Use when 命令预计超过 ~1 分钟（包安装、备份、迁移、构建）；启动后用 get_background_command 轮询。
            """
            try:
                return tool_ok(await self._runner.start_background(connection_handle, command))
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="get_background_command",
            title="查询后台命令状态与输出",
            annotations={"readOnlyHint": True, "openWorldHint": True},
        )
        async def get_background_command(
            job_id: Annotated[str, Field(description="start_background_command 返回的 job_id，形如 bg-0a1b2c3d4e5f。")],
            max_output_bytes: Annotated[
                int | None,
                Field(description="stdout 尾部最多保留的字节数，默认 256 KiB。"),
            ] = None,
            cleanup: Annotated[
                bool,
                Field(description="为 true 且命令已结束时删除远端 /tmp 下的输出与 pid 文件。确认不再需要输出后再传。"),
            ] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """查询后台命令：running/finished、退出码（已结束时）、stdout/stderr 的尾部内容。
            返回 {job_id, status, exit_code?, stdout_bytes, stderr_bytes, stdout_tail, stderr_tail, hint}。
            Use when start_background_command 之后轮询进度；status=finished 后读取输出，确认后传 cleanup=true 清理。
            """
            try:
                return tool_ok(
                    await self._runner.get_background(
                        connection_handle, job_id, max_output_bytes=max_output_bytes, cleanup=cleanup
                    )
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="execute_command",
            title="在远端服务器执行命令",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def execute_command(
            command: Annotated[str, Field(description="要执行的非交互式 shell 命令，例如 `uname -a` 或 `df -h`。")],
            timeout_seconds: Annotated[
                float | None,
                Field(description="命令执行超时秒数，默认 30，超过服务端上限会被截断；超时会主动终止远端进程。"),
            ] = None,
            max_output_bytes: Annotated[
                int | None,
                Field(description="stdout/stderr 各自保留的最大字节数，超出部分丢弃并在结果中标注总字节数。"),
            ] = None,
            allow_interactive: Annotated[
                bool,
                Field(
                    description=(
                        "仅在确实需要 TTY 时才设为 true（会一直挂到超时，通常没用）。"
                        "绝大多数情况请改用上面括号里的批处理写法，不要打开这个开关。"
                    )
                ),
            ] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """在已连接的服务器上执行一条非交互式命令，返回 stdout、stderr、退出码与截断标记。
            返回 {stdout, stderr, exit_code, exit_signal, truncated, stdout_total_bytes, duration_seconds}；
            超时返回 timed_out=true 与已收集的输出，并保证远端进程已被终止。
            Use when 需要查看系统状态、运行脚本、查询服务日志等一次性命令。

            这个通道没有终端，任何等待键盘输入的程序都会挂起到超时，所以下面几类必须写成批处理形式：
            - 持续刷新的：`top` → `top -b -n1`；`watch` → 用 `while sleep` 循环或直接查一次
            - 分页的：`less`/`more`/`man` → `cat`、`--no-pager`、`head -n 100`
            - 跟随文件的：`tail -f`/`journalctl -f` → `tail -n 100`、`journalctl --no-pager -n 100`
            - 交互式编辑器：`vi`/`vim`/`nano` → 用 `sed -i` 或重定向写文件
            - 数据库/shell 客户端：把语句交给参数，`mysql -e 'select 1'`、`psql -c 'select 1'`、
              `redis-cli ping`；不要只写 `mysql`、`psql`、`redis-cli`、`python3`、`bash` 之类的光杆命令

            引号内的内容不会被当成命令：`grep -E 'mysql|redis'` 是安全的搜索，不会被误判。
            """
            try:
                result = await self._runner.run(
                    connection_handle,
                    command,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    allow_interactive=allow_interactive,
                )
            except ToolFailure as exc:
                return tool_err(exc)
            payload = result.to_dict()
            if result.timed_out:
                failure = ToolFailure(
                    "command_timeout",
                    stage="execute",
                    hint=(
                        f"命令在 {timeout_seconds or '默认'} 秒内未结束，已终止远端进程；"
                        "可缩小操作范围、改用非交互参数或调大 timeout_seconds。"
                    ),
                    retryable=True,
                    terminated=result.terminated,
                )
                payload.update(failure.to_dict())
                from ssh_mcp.tools.helpers import tool_err_dict

                return tool_err_dict(payload)
            return tool_ok(payload)
