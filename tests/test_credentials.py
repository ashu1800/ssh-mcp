"""Credential service client: retry policy, status mapping, caching."""

from __future__ import annotations

import httpx2
import pytest

from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.errors import ToolFailure
from tests.conftest import TOKEN


@pytest.mark.asyncio
async def test_lists_servers_without_credentials(credential_client):
    servers = await credential_client.list_servers()
    assert len(servers) == 1
    assert servers[0].server_id == "1"
    assert servers[0].alias == "fake-1"
    dumped = servers[0].model_dump()
    assert "blob" not in dumped
    assert "password" not in dumped
    assert "host" not in dumped


@pytest.mark.asyncio
async def test_resolves_credential(credential_client, ssh_server):
    payload = await credential_client.get_credential("1")
    assert payload.host == "127.0.0.1"
    assert payload.port == ssh_server.port
    assert payload.password == "test-password"


@pytest.mark.asyncio
async def test_unknown_server_returns_structured_error(credential_client):
    with pytest.raises(ToolFailure) as excinfo:
        await credential_client.get_credential("999")
    assert excinfo.value.error == "server_not_found"
    assert excinfo.value.retryable is True


@pytest.mark.asyncio
async def test_short_ttl_cache_avoids_duplicate_fetches(settings, fake_service):
    transport = httpx2.MockTransport(fake_service.handler)
    client = CredentialClient(settings, transport=transport)
    await client.list_servers()
    await client.list_servers()
    assert fake_service.requests == 1
    await client.list_servers(refresh=True)
    assert fake_service.requests == 2


@pytest.mark.asyncio
async def test_zero_ttl_disables_cache(settings, fake_service):
    settings.credentials_cache_ttl = 0
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    await client.list_servers()
    await client.list_servers()
    assert fake_service.requests == 2


@pytest.mark.asyncio
async def test_401_is_not_retried_and_does_not_parse_json(settings, fake_service):
    fake_service.status_override = 401
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.list_servers()
    assert excinfo.value.error == "mcp_key_invalid"
    assert excinfo.value.retryable is False
    assert fake_service.requests == 1


@pytest.mark.asyncio
async def test_403_reports_missing_scope(settings, fake_service):
    fake_service.status_override = 403
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.list_servers()
    assert excinfo.value.error == "mcp_key_forbidden"
    assert "servers:credential" in excinfo.value.hint
    assert fake_service.requests == 1


@pytest.mark.asyncio
async def test_5xx_is_retried_with_backoff(settings, fake_service, monkeypatch):
    settings.credentials_max_retries = 2
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("ssh_mcp.credentials.client.asyncio.sleep", fake_sleep)
    fake_service.fail_next = 2
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    servers = await client.list_servers()
    assert len(servers) == 1
    assert fake_service.requests == 3
    assert sleeps == [0.5, 1.0]


@pytest.mark.asyncio
async def test_exhausted_retries_report_unavailable(settings, fake_service, monkeypatch):
    settings.credentials_max_retries = 1

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("ssh_mcp.credentials.client.asyncio.sleep", fake_sleep)
    fake_service.fail_next = 5
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.list_servers()
    assert excinfo.value.error == "credentials_unavailable"
    assert excinfo.value.retryable is True
    assert fake_service.requests == 2


@pytest.mark.asyncio
async def test_network_error_is_retried(settings, monkeypatch):
    settings.credentials_max_retries = 1
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        raise httpx2.ConnectError("boom")

    async def fake_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("ssh_mcp.credentials.client.asyncio.sleep", fake_sleep)
    client = CredentialClient(settings, transport=httpx2.MockTransport(handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.list_servers()
    assert excinfo.value.error == "credentials_unavailable"
    assert attempts["n"] == 2


@pytest.mark.asyncio
async def test_wrong_token_never_reaches_decrypt(settings, credential_client, fake_service):
    fake_service._token = "mcp_another_token_0123456789abc"
    with pytest.raises(ToolFailure) as excinfo:
        await credential_client.get_credential("1")
    assert excinfo.value.error == "mcp_key_invalid"


def test_settings_requires_mcp_key():
    from ssh_mcp.config import ConfigError, load_settings

    with pytest.raises(ConfigError):
        load_settings({})
    with pytest.raises(ConfigError):
        load_settings({"MCP_KEY": "not-an-mcp-token"})


def test_settings_refuse_public_bind_without_token():
    from ssh_mcp.config import ConfigError, load_settings

    with pytest.raises(ConfigError):
        load_settings({"MCP_KEY": TOKEN, "SSH_MCP_HTTP_HOST": "0.0.0.0"})
    settings = load_settings({"MCP_KEY": TOKEN, "SSH_MCP_HTTP_HOST": "0.0.0.0", "SSH_MCP_HTTP_TOKEN": "t" * 32})
    assert settings.http_host == "0.0.0.0"
