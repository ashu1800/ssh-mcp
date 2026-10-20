"""Streamable HTTP transport: statelessness, origin guard, inbound auth."""

from __future__ import annotations

import json

import httpx2
import pytest
from starlette.testclient import TestClient

from ssh_mcp.config import ConfigError, load_settings
from ssh_mcp.http_app import _default_allowed_origins, build_http_app
from ssh_mcp.server import AppState, create_server
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from ssh_mcp.ssh.pool import ConnectionPool
from tests.conftest import TOKEN

PROTOCOL_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2026-07-28",
    # 2026-07-28 requires routing headers that mirror the body's method.
    "Mcp-Method": "tools/list",
}


def _make_state(settings, fake_service):
    credentials = _credentials(settings, fake_service)
    connector = Connector(
        settings,
        KnownHostsStore(settings.known_hosts_path),
        AuthStateStore(settings.auth_state_path),
        KeyStore(settings.keys_dir),
    )
    pool = ConnectionPool(settings, connector)
    return AppState(settings=settings, credentials=credentials, pool=pool)


def _credentials(settings, fake_service):
    from ssh_mcp.credentials.client import CredentialClient

    return CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))


def _client(settings, fake_service, monkeypatch) -> TestClient:
    state = _make_state(settings, fake_service)
    app = create_server(settings, state=state)
    starlette_app = build_http_app(app, settings)
    # The transport security guard validates the Host header; give the test
    # client a loopback base URL so requests look like local ones.
    return TestClient(starlette_app, base_url=f"http://127.0.0.1:{settings.http_port}")


def _tools_list_body(request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "tests", "version": "0"},
            }
        },
    }


@pytest.fixture
def http_settings(settings):
    settings.http_port = 8765
    settings.http_bearer_token = None
    settings.http_allowed_origins = []
    return settings


def test_no_session_header_and_stateless(http_settings, fake_service):
    with _client(http_settings, fake_service, None) as client:
        response = client.post("/mcp", json=_tools_list_body(1), headers=PROTOCOL_HEADERS)
        assert response.status_code == 200
        assert "mcp-session-id" not in {k.lower() for k in response.headers}

        second = client.post("/mcp", json=_tools_list_body(2), headers=PROTOCOL_HEADERS)
        assert second.status_code == 200
        assert "mcp-session-id" not in {k.lower() for k in second.headers}

        body = _decode(second)
        names = {tool["name"] for tool in body["result"]["tools"]}
        assert "execute_command" in names
        assert "upload_file" in names


def test_tools_are_deterministically_ordered(http_settings, fake_service):
    with _client(http_settings, fake_service, None) as client:
        first = _decode(client.post("/mcp", json=_tools_list_body(1), headers=PROTOCOL_HEADERS))
        second = _decode(client.post("/mcp", json=_tools_list_body(2), headers=PROTOCOL_HEADERS))
        assert [t["name"] for t in first["result"]["tools"]] == [t["name"] for t in second["result"]["tools"]]


def test_bad_origin_is_rejected(http_settings, fake_service):
    with _client(http_settings, fake_service, None) as client:
        response = client.post(
            "/mcp",
            json=_tools_list_body(1),
            headers={**PROTOCOL_HEADERS, "Origin": "https://evil.example"},
        )
        assert response.status_code == 403


def test_allowed_origin_passes(http_settings, fake_service):
    http_settings.http_allowed_origins = ["http://localhost:8765"]
    with _client(http_settings, fake_service, None) as client:
        response = client.post(
            "/mcp",
            json=_tools_list_body(1),
            headers={**PROTOCOL_HEADERS, "Origin": "http://localhost:8765"},
        )
        assert response.status_code == 200


def test_bearer_token_required_when_configured(http_settings, fake_service):
    http_settings.http_bearer_token = "s3cret-token-value"
    with _client(http_settings, fake_service, None) as client:
        missing = client.post("/mcp", json=_tools_list_body(1), headers=PROTOCOL_HEADERS)
        assert missing.status_code == 401
        assert "www-authenticate" in {k.lower() for k in missing.headers}

        wrong = client.post(
            "/mcp", json=_tools_list_body(1), headers={**PROTOCOL_HEADERS, "Authorization": "Bearer nope"}
        )
        assert wrong.status_code == 401

        good = client.post(
            "/mcp",
            json=_tools_list_body(1),
            headers={**PROTOCOL_HEADERS, "Authorization": "Bearer s3cret-token-value"},
        )
        assert good.status_code == 200


def test_default_origins_cover_loopback(http_settings):
    origins = _default_allowed_origins(http_settings)
    assert f"http://127.0.0.1:{http_settings.http_port}" in origins
    assert f"http://localhost:{http_settings.http_port}" in origins


def test_public_bind_without_token_refuses_to_start():
    with pytest.raises(ConfigError):
        load_settings({"MCP_KEY": TOKEN, "SSH_MCP_HTTP_HOST": "0.0.0.0"})
    settings = load_settings(
        {"MCP_KEY": TOKEN, "SSH_MCP_HTTP_HOST": "0.0.0.0", "SSH_MCP_HTTP_TOKEN": "t" * 40}
    )
    assert settings.http_is_loopback is False


def _decode(response) -> dict:
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        for line in response.text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[6:])
        raise AssertionError(f"no SSE data frame in {response.text!r}")
    return response.json()
