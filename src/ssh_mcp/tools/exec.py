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
            name="execute_command",
            title="在远端服务器执行命令",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def execute_command(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
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
                Field(description="为 true 时允许执行 top/vim 等交互式命令（通常不可用，建议改用非交互形式）。"),
            ] = False,
        ) -> CallToolResult:
            """在已连接的服务器上执行一条非交互式命令，返回 stdout、stderr、退出码与截断标记。
            返回 {stdout, stderr, exit_code, exit_signal, truncated, stdout_total_bytes, duration_seconds}；
            超时返回 timed_out=true 与已收集的输出，并保证远端进程已被终止。
            Use when 需要查看系统状态、运行脚本、查询服务日志等一次性命令；交互式程序请使用批处理参数（如 top -b -n1）。
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
