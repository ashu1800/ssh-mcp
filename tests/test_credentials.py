"""Credential service client: retry policy, status mapping, caching."""

from __future__ import annotations

import httpx2
import pytest

from ssh_mcp.credentials.client import CredentialClient, _CacheEntry, parse_target
from ssh_mcp.errors import ToolFailure
from tests.conftest import PASSWORD, TOKEN, USERNAME, build_credential_blob, make_credential_item


@pytest.mark.asyncio
async def test_lists_servers_exposes_addressing_not_credentials(credential_client, ssh_server):
    """v2 contract: host/port plaintext for IP addressing; no blob, no secrets."""
    servers = await credential_client.list_servers()
    assert len(servers) == 1
    assert servers[0].server_id == "1"
    assert servers[0].alias == "fake-1"
    assert servers[0].host == "127.0.0.1"
    assert servers[0].port == ssh_server.port
    dumped = servers[0].model_dump()
    assert "blob" not in dumped
    assert "password" not in dumped


@pytest.mark.asyncio
async def test_resolves_credential(credential_client, ssh_server):
    payload = await credential_client.get_credential("1")
    assert payload.host == "127.0.0.1"
    assert payload.port == ssh_server.port
    assert payload.password == "test-password"


@pytest.mark.asyncio
async def test_unknown_server_returns_structured_error(credential_client, ssh_server):
    with pytest.raises(ToolFailure) as excinfo:
        await credential_client.get_credential("999")
    assert excinfo.value.error == "server_not_found"
    assert excinfo.value.retryable is True
    assert excinfo.value.details["candidates"] == [
        {
            "server_id": "1",
            "alias": "fake-1",
            "host": "127.0.0.1",
            "port": ssh_server.port,
            "group_name": "tests",
        }
    ]


@pytest.mark.asyncio
async def test_connect_by_bare_ip_resolves_directly(credential_client, ssh_server):
    payload = await credential_client.get_credential("127.0.0.1")
    assert payload.host == "127.0.0.1"
    assert payload.port == ssh_server.port


@pytest.mark.asyncio
async def test_connect_by_ip_port_resolves(credential_client, ssh_server):
    payload = await credential_client.get_credential(f"127.0.0.1:{ssh_server.port}")
    assert payload.server_id == 1


@pytest.mark.asyncio
async def test_ip_with_wrong_port_is_not_found(credential_client):
    with pytest.raises(ToolFailure) as excinfo:
        await credential_client.get_credential("127.0.0.1:1")
    assert excinfo.value.error == "server_not_found"


@pytest.mark.asyncio
async def test_same_ip_two_ports_returns_ambiguous_ports(settings, fake_service, ssh_server):
    """User scenario: one IP, two SSH ports; bare IP must offer the ports."""
    other_port = ssh_server.port + 1
    fake_service._servers.append(
        make_credential_item(
            settings.mcp_key,
            server_id=2,
            alias="fake-2",
            host="127.0.0.1",
            port=other_port,
            username=USERNAME,
            password=PASSWORD,
        )
    )
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.get_credential("127.0.0.1")
    failure = excinfo.value
    assert failure.error == "ambiguous_ports"
    assert failure.next_actions == ["ask_user_then_retry_connect_with_port"]
    assert sorted(c["port"] for c in failure.details["candidates"]) == sorted([ssh_server.port, other_port])
    # Picking a port resolves the right server immediately.
    payload = await client.get_credential(f"127.0.0.1:{other_port}")
    assert payload.server_id == 2


@pytest.mark.asyncio
async def test_exact_alias_resolves_without_listing(credential_client, ssh_server):
    payload = await credential_client.get_credential("fake-1")
    assert payload.host == "127.0.0.1"
    assert payload.port == ssh_server.port


@pytest.mark.asyncio
async def test_unique_substring_resolves(credential_client, ssh_server):
    payload = await credential_client.get_credential("fake")
    assert payload.port == ssh_server.port


@pytest.mark.asyncio
async def test_ambiguous_match_lists_candidates(credential_client):
    """Base fixture has one server, so substring 'fake' resolves fine here;
    the real ambiguity case is covered by test_ambiguous_alias_offers_candidates."""
    payload = await credential_client.get_credential("fake")
    assert payload.host == "127.0.0.1"


@pytest.mark.asyncio
async def test_ambiguous_alias_offers_candidates(settings, fake_service, ssh_server):
    # Deliberately an old-contract item (no plaintext host/port): host matching
    # must silently no-op and the alias substring path must behave as before.
    fake_service._servers.append(
        {
            "server_id": 2,
            "alias": "fake-2",
            "encrypted_blob_ref": "cred-2-v1",
            "auth_type": "password",
            "group_name": "tests",
            "blob": build_credential_blob(
                settings.mcp_key,
                {
                    "version": 1,
                    "server_id": 2,
                    "alias": "fake-2",
                    "host": "127.0.0.1",
                    "port": ssh_server.port,
                    "username": USERNAME,
                    "auth": {"type": "password"},
                    "password": PASSWORD,
                },
            ),
        }
    )
    client = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    with pytest.raises(ToolFailure) as excinfo:
        await client.get_credential("fake")
    assert excinfo.value.error == "server_ambiguous"
    assert len(excinfo.value.details["candidates"]) == 2
    # The exact id still wins over the substring.
    payload = await client.get_credential("2")
    assert payload.alias == "fake-2"


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


def test_parse_target_shapes():
    assert parse_target("10.0.0.7") == ("10.0.0.7", None)
    assert parse_target("10.0.0.7:2222") == ("10.0.0.7", 2222)
    assert parse_target(" 10.0.0.7:22 ") == ("10.0.0.7", 22)
    assert parse_target("[::1]:22") == ("::1", 22)
    assert parse_target("::1") == ("::1", None)
    assert parse_target("db.internal") == ("db.internal", None)
    assert parse_target("10.0.0.7:99999") is None  # port out of range
    assert parse_target("服务器 #12") is None  # not address-shaped
    assert parse_target("") is None


def test_parse_target_unwraps_a_bare_bracketed_ipv6():
    # The brackets are a reference syntax, not part of the address.
    assert parse_target("[::1]") == ("::1", None)
    assert parse_target("[2001:DB8::1]") == ("2001:db8::1", None)
    assert parse_target("[ssh://host]") is None


def test_resolve_matches_equivalent_ipv6_spellings():
    blob = {"version": 1}
    entry = _CacheEntry(
        fetched_at=0.0,
        servers=[{"server_id": 7, "alias": "v6", "host": "::1", "port": 22, "blob": blob}],
    )
    for reference in ("[::1]", "::1", "[::1]:22", "[0:0:0:0:0:0:0:1]", "[0:0:0:0:0:0:0:1]:22"):
        found, state, _hits = CredentialClient._resolve(entry, reference)
        assert (found, state) == (blob, "ok"), reference


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
