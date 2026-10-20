"""Entry point: ``python -m ssh_mcp [--transport stdio|http]``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys

from ssh_mcp.config import ConfigError, load_settings
from ssh_mcp.logging_setup import configure_logging
from ssh_mcp.server import create_server, shutdown_server

logger = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="ssh-mcp", description="SSH/SFTP MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio (default) or streamable-http",
    )
    parser.add_argument("--host", default=None, help="HTTP bind address (default SSH_MCP_HTTP_HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="HTTP port (default SSH_MCP_HTTP_PORT or 8765)")
    parser.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR/CRITICAL")
    return parser.parse_args(argv)


async def _run_stdio(settings) -> None:
    server = create_server(settings)
    try:
        await server.run_stdio_async()
    finally:
        await shutdown_server(server)


async def _run_http(settings) -> None:
    from ssh_mcp.http_app import run_http

    server = create_server(settings)
    try:
        await run_http(server, settings)
    finally:
        await shutdown_server(server)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"ssh-mcp: configuration error: {exc}", file=sys.stderr)
        return 2

    if args.log_level:
        settings.log_level = args.log_level.upper()
    if args.host:
        settings.http_host = args.host
    if args.port:
        settings.http_port = args.port

    configure_logging(settings.log_level, extra_secrets=[settings.mcp_key, settings.http_bearer_token or ""])

    if args.transport == "http" and not settings.http_is_loopback and not settings.http_bearer_token:
        print(
            "ssh-mcp: refusing to bind a non-loopback address without SSH_MCP_HTTP_TOKEN",
            file=sys.stderr,
        )
        return 2

    try:
        if args.transport == "stdio":
            asyncio.run(_run_stdio(settings))
        else:
            asyncio.run(_run_http(settings))
    except KeyboardInterrupt:  # pragma: no cover
        pass
    except Exception:  # noqa: BLE001
        logger.exception("ssh-mcp terminated with an error")
        return 1
    finally:
        with contextlib.suppress(Exception):
            logging.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
