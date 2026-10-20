"""MCP server assembly: one tool implementation for both transports.

The same :class:`~mcp.server.MCPServer` instance backs stdio and Streamable HTTP.
The HTTP transport runs stateless (each POST is self-contained, no session id);
connections are routed by the explicit ``connection_handle`` tool argument.
"""

from __future__ import annotations

import contextlib
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server import MCPServer

from ssh_mcp.config import Settings
from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.commands import CommandRunner
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.ssh.transfer import SftpTransferEngine
from ssh_mcp.tools.exec import ExecTools
from ssh_mcp.tools.files import FileTools
from ssh_mcp.tools.servers import ServerTools
from ssh_mcp.tools.transfer_tools import TransferTools

logger = logging.getLogger(__name__)


@dataclass
class AppState:
    """Resources that live for the whole server process."""

    settings: Settings
    credentials: CredentialClient
    pool: ConnectionPool


def build_state(settings: Settings) -> AppState:
    state = AppState(settings=settings, credentials=CredentialClient(settings), pool=_build_pool(settings))
    return state


def _build_pool(settings: Settings) -> ConnectionPool:
    known_hosts = KnownHostsStore(settings.known_hosts_path)  # type: ignore[arg-type]
    auth_state = AuthStateStore(settings.auth_state_path)  # type: ignore[arg-type]
    key_store = KeyStore(settings.keys_dir)  # type: ignore[arg-type]
    connector = Connector(settings, known_hosts, auth_state, key_store)
    return ConnectionPool(settings, connector)


def create_server(settings: Settings, *, state: AppState | None = None) -> MCPServer:
    """Build the MCP server with every tool registered.

    ``state`` may be supplied by tests; otherwise it is created from ``settings``
    when the app starts (see :func:`run`).
    """
    app_state_box: dict[str, AppState | None] = {"state": state}

    @asynccontextmanager
    async def lifespan(_app: MCPServer):
        current = app_state_box["state"] or build_state(settings)
        app_state_box["state"] = current
        current.pool.start_reaper()
        logger.info(
            "ssh-mcp ready (credentials=%s, pool_idle=%.0fs, roots=%s)",
            settings.credentials_url,
            settings.pool_idle_timeout,
            ", ".join(str(p) for p in settings.allowed_local_roots),
        )
        try:
            yield current
        finally:
            await current.pool.aclose()
            await current.credentials.aclose()
            logger.info("ssh-mcp stopped")

    app = MCPServer(
        name="ssh-mcp",
        title="SSH / SFTP",
        version="0.1.0",
        instructions=(
            "通过服务器管理服务下发的加密凭据，对远端主机执行非交互式 SSH 命令并进行 SFTP 文件传输。"
            "典型流程：list_servers 找到 server_id → resolve_server 确认目标 → connect 拿到 connection_handle → "
            "execute_command / upload_file / download_file。破坏性操作（删除、覆盖、改权限）必须先在参数里传 confirm=true，"
            "并向用户说明后果。"
        ),
        log_level=settings.log_level,  # type: ignore[arg-type]
        lifespan=lifespan,
    )

    creds = state.credentials if state else CredentialClient(settings)
    conn_pool = state.pool if state else _build_pool(settings)
    if state is None:
        conn_pool.start_reaper()
    runner = CommandRunner(settings, conn_pool)
    engine = SftpTransferEngine(settings)

    ServerTools(app, creds, conn_pool)
    ExecTools(app, runner)
    TransferTools(app, conn_pool, engine, settings)
    FileTools(app, conn_pool, settings)

    app._ssh_mcp_bundle = (creds, conn_pool)  # type: ignore[attr-defined]
    return app


async def shutdown_server(app: MCPServer) -> None:
    """Release resources that :func:`create_server` created eagerly."""
    bundle = getattr(app, "_ssh_mcp_bundle", None)
    if not bundle:
        return
    _creds, pool = bundle
    with contextlib.suppress(Exception):
        await pool.aclose()
