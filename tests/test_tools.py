"""Tool layer end-to-end: the exact results an MCP client would receive."""

from __future__ import annotations

import json

import pytest

from ssh_mcp.server import AppState, create_server
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from tests.conftest import PASSWORD, TOKEN, USERNAME


@pytest.fixture
def app(settings, fake_service, ssh_server):
    import httpx2

    from ssh_mcp.credentials.client import CredentialClient

    credentials = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    connector = Connector(
        settings,
        KnownHostsStore(settings.known_hosts_path),
        AuthStateStore(settings.auth_state_path),
        KeyStore(settings.keys_dir),
    )
    pool = ConnectionPool(settings, connector)
    pool.start_reaper()
    state = AppState(settings=settings, credentials=credentials, pool=pool)
    return create_server(settings, state=state)


async def call(app, name: str, **arguments):
    result = await app.call_tool(name, arguments)
    payload = result.structured_content
    assert isinstance(payload, dict)
    # The text block must carry the same JSON so non-structured clients see it.
    assert json.loads(result.content[0].text) == payload
    return payload, result.is_error


@pytest.mark.asyncio
async def test_list_servers(app):
    payload, is_error = await call(app, "list_servers")
    assert is_error is False
    assert payload["total"] == 1
    row = payload["servers"][0]
    assert set(row) == {"server_id", "alias", "encrypted_blob_ref", "auth_type", "group_name"}
    assert PASSWORD not in json.dumps(payload)


@pytest.mark.asyncio
async def test_resolve_server_is_redacted(app, ssh_server):
    payload, is_error = await call(app, "resolve_server", server_id="1")
    assert is_error is False
    assert payload["host"] == "127.0.0.1"
    assert payload["port"] == ssh_server.port
    assert payload["username"] == USERNAME
    assert payload["auth_type"] == "password"
    rendered = json.dumps(payload)
    assert PASSWORD not in rendered
    # auth_type is a label, not a secret; no credential value may appear.
    assert "password_value" not in rendered


@pytest.mark.asyncio
async def test_connect_returns_handle(app):
    payload, is_error = await call(app, "connect", server_id="1")
    assert is_error is False
    assert payload["status"] == "connected"
    assert payload["auth_method"] in {"password", "publickey"}
    assert payload["connection_handle"]
    assert PASSWORD not in json.dumps(payload)


@pytest.mark.asyncio
async def test_connect_reuses_handle(app):
    first, _ = await call(app, "connect", server_id="1")
    second, _ = await call(app, "connect", server_id="1")
    assert first["connection_handle"] == second["connection_handle"]


@pytest.mark.asyncio
async def test_resolve_unknown_server(app):
    payload, is_error = await call(app, "resolve_server", server_id="42")
    assert is_error is True
    assert payload["error"] == "server_not_found"


@pytest.mark.asyncio
async def test_execute_command_roundtrip(app):
    connect, _ = await call(app, "connect", server_id="1")
    payload, is_error = await call(
        app, "execute_command", connection_handle=connect["connection_handle"], command="echo hello"
    )
    assert is_error is False
    assert payload["stdout"].strip() == "hello"
    assert payload["exit_code"] == 0


@pytest.mark.asyncio
async def test_execute_command_timeout_is_structured(app):
    connect, _ = await call(app, "connect", server_id="1")
    payload, is_error = await call(
        app,
        "execute_command",
        connection_handle=connect["connection_handle"],
        command="sleep 30",
        timeout_seconds=1,
    )
    assert is_error is True
    assert payload["error"] == "command_timeout"
    assert payload["timed_out"] is True
    assert payload["terminated"] is True
    assert payload["retryable"] is True


@pytest.mark.asyncio
async def test_upload_and_download_via_tools(app, settings, ssh_server):
    connect, _ = await call(app, "connect", server_id="1")
    handle = connect["connection_handle"]
    local = settings.allowed_local_roots[0] / "tool.bin"
    local.write_bytes(b"tool-payload" * 100)

    uploaded, is_error = await call(
        app,
        "upload_file",
        connection_handle=handle,
        local_path=str(local),
        remote_path="/tool.bin",
        verify="sha256",
    )
    assert is_error is False
    assert uploaded["bytes_transferred"] == len(local.read_bytes())

    target = settings.allowed_local_roots[0] / "back.bin"
    downloaded, is_error = await call(
        app, "download_file", connection_handle=handle, remote_path="/tool.bin", local_path=str(target)
    )
    assert is_error is False
    assert target.read_bytes() == local.read_bytes()


@pytest.mark.asyncio
async def test_overwrite_requires_confirmation(app, settings):
    connect, _ = await call(app, "connect", server_id="1")
    local = settings.allowed_local_roots[0] / "c.bin"
    local.write_bytes(b"x")
    payload, is_error = await call(
        app,
        "upload_file",
        connection_handle=connect["connection_handle"],
        local_path=str(local),
        remote_path="/c.bin",
        overwrite=True,
    )
    assert is_error is True
    assert payload["error"] == "confirmation_required"
    assert payload["action"] == "upload_file(overwrite)"


@pytest.mark.asyncio
async def test_download_outside_allowlist_is_rejected(app):
    connect, _ = await call(app, "connect", server_id="1")
    payload, is_error = await call(
        app,
        "download_file",
        connection_handle=connect["connection_handle"],
        remote_path="/etc/hostname",
        local_path="C:/Windows/System32/hostname.txt",
    )
    assert is_error is True
    assert payload["error"] == "path_not_allowed"


@pytest.mark.asyncio
async def test_disconnect_requires_confirmation(app):
    connect, _ = await call(app, "connect", server_id="1")
    payload, is_error = await call(app, "disconnect", connection_handle=connect["connection_handle"])
    assert is_error is True
    assert payload["error"] == "confirmation_required"

    payload, is_error = await call(app, "disconnect", connection_handle=connect["connection_handle"], confirm=True)
    assert is_error is False
    assert payload["status"] == "disconnected"

    after, is_error = await call(
        app, "execute_command", connection_handle=connect["connection_handle"], command="echo hi"
    )
    assert is_error is True
    assert after["error"] == "connection_not_found"


@pytest.mark.asyncio
async def test_file_management_tools(app, ssh_server):
    connect, _ = await call(app, "connect", server_id="1")
    handle = connect["connection_handle"]

    made, err = await call(app, "make_directory", connection_handle=handle, path="/work/sub", parents=True)
    assert err is False and made["created"] is True
    assert (ssh_server.home / "work" / "sub").is_dir()

    (ssh_server.home / "work" / "sub" / "a.txt").write_text("hi")
    listing, err = await call(app, "list_directory", connection_handle=handle, path="/work/sub")
    assert err is False
    assert [e["name"] for e in listing["entries"]] == ["a.txt"]

    stat, err = await call(app, "stat_file", connection_handle=handle, path="/work/sub/a.txt")
    assert err is False
    assert stat["type"] == "file" and stat["size"] == 2

    renamed, err = await call(
        app,
        "rename_path",
        connection_handle=handle,
        old_path="/work/sub/a.txt",
        new_path="/work/sub/b.txt",
        confirm=True,
    )
    assert err is False and renamed["new_path"] == "/work/sub/b.txt"

    chmod, err = await call(
        app, "change_permissions", connection_handle=handle, path="/work/sub/b.txt", mode="600", confirm=True
    )
    assert err is False and chmod["mode"] == "0600"

    removed, err = await call(
        app, "remove_path", connection_handle=handle, path="/work/sub", recursive=True, confirm=True
    )
    assert err is False and removed["removed"] == "dir"
    assert not (ssh_server.home / "work" / "sub").exists()


@pytest.mark.asyncio
async def test_remove_without_confirm_does_nothing(app, ssh_server):
    connect, _ = await call(app, "connect", server_id="1")
    (ssh_server.home / "keep.txt").write_text("x")
    payload, is_error = await call(
        app, "remove_path", connection_handle=connect["connection_handle"], path="/keep.txt"
    )
    assert is_error is True and payload["error"] == "confirmation_required"
    assert (ssh_server.home / "keep.txt").exists()


@pytest.mark.asyncio
async def test_change_permissions_rejects_bad_mode(app):
    connect, _ = await call(app, "connect", server_id="1")
    payload, is_error = await call(
        app,
        "change_permissions",
        connection_handle=connect["connection_handle"],
        path="/whatever",
        mode="u+x",
        confirm=True,
    )
    assert is_error is True
    assert payload["error"] == "invalid_argument"


@pytest.mark.asyncio
async def test_batch_upload_reports_per_item(app, settings, ssh_server):
    connect, _ = await call(app, "connect", server_id="1")
    root = settings.allowed_local_roots[0]
    (root / "one.bin").write_bytes(b"one")
    (root / "two.bin").write_bytes(b"two")
    payload, is_error = await call(
        app,
        "upload_files",
        connection_handle=connect["connection_handle"],
        files=[
            {"local_path": str(root / "one.bin"), "remote_path": "/one.bin"},
            {"local_path": str(root / "missing.bin"), "remote_path": "/two.bin"},
        ],
    )
    assert is_error is True
    assert payload["error"] == "batch_partial_failure"
    assert payload["succeeded"] == 1
    assert payload["failed"] == 1
    assert (ssh_server.home / "one.bin").read_bytes() == b"one"
