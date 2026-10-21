"""Server discovery, resolution, connection lifecycle tools."""

from __future__ import annotations

import logging
from typing import Annotated

from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.errors import ConfirmationRequired, ToolFailure
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)


class ServerTools:
    """Registers ``list_servers`` / ``resolve_server`` / ``connect`` / ``disconnect``."""

    def __init__(self, app, credentials: CredentialClient, pool: ConnectionPool) -> None:
        self._credentials = credentials
        self._pool = pool

        @app.tool(
            name="list_servers",
            title="列出可连接的服务器",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def list_servers(
            refresh: Annotated[
                bool,
                Field(description="为 true 时绕过短时缓存，立即向服务器管理服务重新拉取列表。默认 false。"),
            ] = False,
        ) -> CallToolResult:
            """列出当前 MCP 密钥可访问的 SSH 服务器，返回 server_id、别名和加密凭据引用，不包含任何明文连接信息。
            返回 {servers: [{server_id, alias, encrypted_blob_ref, auth_type, group_name}], total, cached}。
            Use when 用户提到某台机器但你还不知道 server_id，或需要确认可操作范围时先调用本工具。
            """
            try:
                servers = await self._credentials.list_servers(refresh=refresh)
            except ToolFailure as exc:
                return tool_err(exc)
            rows = [s.model_dump(exclude_none=True) for s in servers]
            return tool_ok({"servers": rows, "total": len(rows)})

        @app.tool(
            name="resolve_server",
            title="解析服务器的连接摘要",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def resolve_server(
            server_id: Annotated[str, Field(description="服务器 ID，来自 list_servers 返回的 server_id。")],
        ) -> CallToolResult:
            """解密指定服务器的连接信息并返回脱敏摘要（host、port、username、认证类型），供真正建连前确认目标。
            不返回密码、私钥或密文。解密失败会返回结构化的 decrypt_failed 错误。
            Use when 需要向用户确认“接下来要连的是哪台机器”时，或 connect 之前核对目标是否与用户所说一致时。
            """
            try:
                payload = await self._credentials.get_credential(str(server_id))
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok(payload.redacted_summary())

        @app.tool(
            name="connect",
            title="建立或复用 SSH 连接",
            annotations={
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,  # reuses the live connection
                "openWorldHint": True,
            },
        )
        async def connect(
            server_id: Annotated[str, Field(description="服务器 ID，来自 list_servers 返回的 server_id。")],
            timeout_seconds: Annotated[
                float | None,
                Field(description="TCP 连接与 SSH 握手的超时秒数，默认取服务配置（约 10 秒）。"),
            ] = None,
        ) -> CallToolResult:
            """对指定服务器建立（或复用）SSH 连接，返回 connection_handle 供后续命令执行与 SFTP 工具使用。
            返回 {connection_handle, status, auth_method, host, port, username, compression}；首次密码登录时会生成
            本地 Ed25519 密钥并把公钥写入远端 authorized_keys，若写入了会附带说明。
            Use when 需要在该服务器上执行命令或传输文件之前；同一服务器重复调用会复用同一条连接。
            """
            try:
                payload = await self._credentials.get_credential(str(server_id))
            except ToolFailure as exc:
                return tool_err(exc)

            try:
                entry = await self._pool.connect(
                    payload, server_id=str(server_id), timeout=timeout_seconds
                )
            except ToolFailure as exc:
                return tool_err(exc)
            result = {
                "connection_handle": entry.handle,
                "status": "connected",
                "auth_method": entry.auth_method,
                "host": payload.host,
                "port": payload.port,
                "username": payload.username,
                "server_id": str(server_id),
                "compression": entry.compression,
            }
            if entry.warning:
                result["warning"] = entry.warning
            return tool_ok(result)

        @app.tool(
            name="disconnect",
            title="断开指定 SSH 连接",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def disconnect(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            confirm: Annotated[
                bool,
                Field(description="必须为 true 才会执行。断开后该句柄立即失效，进行中的操作会被终止。"),
            ] = False,
        ) -> CallToolResult:
            """强制关闭一条已建立的 SSH 连接并从连接池移除，返回被断开的 host/port/username。
            进行中的命令与传输会被中断（传输的 .part 文件会保留，可续传）。
            Use when 需要立即释放连接、切换目标，或连接处于异常状态需要重建时。这是破坏性操作，必须先向用户确认。
            """
            if not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "disconnect",
                        "断开后该连接上正在执行的命令或传输会被立即中断",
                        connection_handle=connection_handle,
                    )
                )
            try:
                host, port, username = await self._pool.disconnect(connection_handle)
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok({"status": "disconnected", "host": host, "port": port, "username": username})

        @app.tool(
            name="get_connection_stats",
            title="查看连接池与运行统计",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        )
        async def get_connection_stats() -> CallToolResult:
            """查看当前连接池状态（每条连接的存活、空闲时长、是否在用）与本进程的累计计数。
            返回 {entries: [...], count, max_entries, default_handle, counters, errors}。
            Use when 排查连接泄漏、确认是否复用了连接，或了解有多少条连接正开着。
            """
            return tool_ok(self._pool.stats())
