"""Streamable HTTP transport with origin checking and a static bearer token.

Two independent authentication layers:

* inbound  (AI client -> MCP)  -- static ``SSH_MCP_HTTP_TOKEN``
* outbound (MCP -> credential service) -- ``MCP_KEY``

The transport is stateless: every POST carries its own MCP protocol version and
client capabilities in ``_meta``; there is no ``Mcp-Session-Id`` and no
cross-request state in the protocol layer.
"""

from __future__ import annotations

import hmac
import logging

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ssh_mcp.config import Settings

logger = logging.getLogger(__name__)

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <token>`` on every request."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._token = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        raw = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, credential = raw.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(credential.strip().encode("utf-8"), self._token):
            response = JSONResponse(
                {"error": "unauthorized", "hint": "缺少或无效的 Authorization Bearer 令牌。"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="ssh-mcp"'},
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


class OriginGuardMiddleware:
    """Reject requests whose ``Origin`` is not explicitly allowed (DNS rebinding defence).

    A request with no ``Origin`` header is a non-browser client and is let
    through; the bearer token covers authentication in that case.
    """

    def __init__(self, app: ASGIApp, allowed_origins: list[str]) -> None:
        self._app = app
        self._allowed = {origin.rstrip("/") for origin in allowed_origins}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        origin = headers.get(b"origin")
        if origin is not None:
            value = origin.decode("latin-1").rstrip("/")
            if value not in self._allowed:
                logger.warning("rejected request with disallowed Origin %s", value)
                await PlainTextResponse("Invalid Origin header", status_code=403)(scope, receive, send)
                return
        await self._app(scope, receive, send)


def _default_allowed_origins(settings: Settings) -> list[str]:
    if settings.http_allowed_origins:
        return settings.http_allowed_origins
    port = settings.http_port
    origins = []
    for host in ("127.0.0.1", "localhost", "[::1]"):
        origins.append(f"http://{host}:{port}")
        origins.append(f"https://{host}:{port}")
    return origins


def build_http_app(server: MCPServer, settings: Settings) -> ASGIApp:
    """Return the ASGI app for the Streamable HTTP transport."""
    allowed_origins = _default_allowed_origins(settings)
    if settings.http_is_loopback:
        allowed_hosts = [f"{host}:*" for host in _LOOPBACK_HOSTS]
    else:
        allowed_hosts = [f"{settings.http_host}:*"]

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    mcp_app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=True,
        transport_security=security,
        host=settings.http_host,
    )

    # The SDK app is kept as-is and wrapped: rebuilding a Starlette instance
    # from its routes would silently drop any middleware the SDK installs
    # (auth context, body limits) now or in a future release.
    app: ASGIApp = mcp_app
    if settings.http_bearer_token:
        app = BearerAuthMiddleware(app, token=settings.http_bearer_token)
    app = OriginGuardMiddleware(app, allowed_origins=allowed_origins)
    return app


async def run_http(server: MCPServer, settings: Settings) -> None:
    """Serve the MCP endpoint over streamable HTTP until cancelled."""
    app = build_http_app(server, settings)
    config = uvicorn.Config(
        app,
        host=settings.http_host,
        port=settings.http_port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )
    uvicorn_server = uvicorn.Server(config)
    logger.info(
        "listening on http://%s:%d/mcp (stateless=%s, auth=%s)",
        settings.http_host,
        settings.http_port,
        True,
        "bearer" if settings.http_bearer_token else "none",
    )
    await uvicorn_server.serve()
