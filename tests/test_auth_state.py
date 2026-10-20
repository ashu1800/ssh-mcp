"""Authentication state machine, host-key pinning, and connection pool."""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.auth_state import AuthState
from ssh_mcp.ssh.connector import ConnectFailure
from ssh_mcp.ssh.pool import ConnectionPool
from tests import fake_ssh_server
from tests.conftest import PASSWORD, USERNAME


@pytest.mark.asyncio
async def test_first_connect_uses_password_and_installs_key(connector, credential_payload, settings):
    result = await connector.connect(credential_payload)
    try:
        assert result.auth_method == "password"
        assert result.warning is None or "公钥" in result.warning
        key_path = settings.keys_dir / f"{_key_id(credential_payload)}.key"
        assert key_path.is_file()
        installed = fake_ssh_server.read_authorized_keys(_ssh_home(settings, connector))
        assert installed, "public key should be installed on the remote"
        record = connector._auth_state.get(*credential_payload.key)
        assert record.state is AuthState.KEY_READY
    finally:
        result.conn.close()
        await result.conn.wait_closed()


@pytest.mark.asyncio
async def test_second_connect_uses_publickey(connector, credential_payload):
    first = await connector.connect(credential_payload)
    first.conn.close()
    await first.conn.wait_closed()

    second = await connector.connect(credential_payload)
    try:
        assert second.auth_method == "publickey"
    finally:
        second.conn.close()
        await second.conn.wait_closed()


@pytest.mark.asyncio
async def test_revoked_key_falls_back_to_password_and_is_reinstalled(
    connector, credential_payload, ssh_server, settings
):
    first = await connector.connect(credential_payload)
    first.conn.close()
    await first.conn.wait_closed()

    fake_ssh_server.remove_authorized_keys(ssh_server.home)
    third = await connector.connect(credential_payload)
    try:
        assert third.auth_method == "password"
        assert third.warning and "失效" in third.warning
        record = connector._auth_state.get(*credential_payload.key)
        assert record.state is AuthState.KEY_READY
        assert record.invalid_at is not None
        assert fake_ssh_server.read_authorized_keys(ssh_server.home)
    finally:
        third.conn.close()
        await third.conn.wait_closed()


@pytest.mark.asyncio
async def test_private_key_payload_uses_publickey_without_provisioning(settings, ssh_server, connector):
    from ssh_mcp.models import CredentialPayload

    key = asyncssh.generate_private_key("ssh-ed25519")
    fake_ssh_server.install_public_key(ssh_server.home, key)
    exported = key.export_private_key("openssh").decode()
    payload = CredentialPayload(
        server_id="2",
        host="127.0.0.1",
        port=ssh_server.port,
        username=USERNAME,
        auth={"type": "private_key", "private_key": exported, "passphrase": ""},
    )
    result = await connector.connect(payload)
    try:
        assert result.auth_method == "publickey"
        assert not (settings.keys_dir / f"{_key_id(payload)}.key").exists()
    finally:
        result.conn.close()
        await result.conn.wait_closed()


@pytest.mark.asyncio
async def test_host_key_is_pinned_once(connector, credential_payload, settings):
    first = await connector.connect(credential_payload)
    first.conn.close()
    await first.conn.wait_closed()
    text = settings.known_hosts_path.read_text(encoding="utf-8")
    assert f"[127.0.0.1]:{credential_payload.port}" in text

    second = await connector.connect(credential_payload)
    second.conn.close()
    await second.conn.wait_closed()
    lines = [ln for ln in settings.known_hosts_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_changed_host_key_is_refused(connector, credential_payload, settings, tmp_path):
    first = await connector.connect(credential_payload)
    first.conn.close()
    await first.conn.wait_closed()

    # Replace the pinned key with a different one, as a MITM would present.
    other = asyncssh.generate_private_key("ssh-ed25519")
    pattern = f"[127.0.0.1]:{credential_payload.port}"
    settings.known_hosts_path.write_text(f"{pattern} {other.export_public_key().decode().strip()}\n", encoding="utf-8")

    with pytest.raises(ConnectFailure) as excinfo:
        await connector.connect(credential_payload)
    assert excinfo.value.error == "host_key_mismatch"
    assert excinfo.value.retryable is False


# -- pool ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pool_reuses_one_connection(pool, credential_payload):
    first = await pool.connect(credential_payload)
    second = await pool.connect(credential_payload)
    assert first.conn is second.conn
    assert first.handle == second.handle


@pytest.mark.asyncio
async def test_concurrent_connects_open_one_connection(pool, credential_payload):
    opener = ConnectionPool(pool._settings, pool._connector)
    try:
        entries = await asyncio.gather(*(opener.connect(credential_payload) for _ in range(10)))
        connections = {id(entry.conn) for entry in entries}
        assert len(connections) == 1
        assert opener.stats()["count"] == 1
    finally:
        await opener.aclose()


@pytest.mark.asyncio
async def test_unknown_handle_is_rejected(pool):
    with pytest.raises(ToolFailure) as excinfo:
        await pool.acquire("nope")
    assert excinfo.value.error == "connection_not_found"
    assert excinfo.value.retryable is True


@pytest.mark.asyncio
async def test_disconnect_closes_and_forgets(pool, credential_payload):
    entry = await pool.connect(credential_payload)
    handle = entry.handle
    conn = entry.conn
    assert conn is not None
    await pool.disconnect(handle)
    assert conn.is_closed()
    assert pool.stats()["count"] == 0
    with pytest.raises(ToolFailure):
        await pool.acquire(handle)


@pytest.mark.asyncio
async def test_reaper_evicts_idle_entries(pool, credential_payload, settings):
    entry = await pool.connect(credential_payload)
    conn = entry.conn
    settings.pool_idle_timeout = 0.01
    await asyncio.sleep(0.05)
    closed = await pool.reap_once()
    assert closed == [credential_payload.key]
    assert conn is not None and conn.is_closed()
    assert pool.stats()["count"] == 0


@pytest.mark.asyncio
async def test_reaper_skips_busy_entries(pool, credential_payload, settings):
    entry = await pool.connect(credential_payload)
    settings.pool_idle_timeout = 0.01
    acquired = await pool.acquire(entry.handle)
    await asyncio.sleep(0.05)
    assert await pool.reap_once() == []
    pool.release(acquired.entry)
    await asyncio.sleep(0.05)
    assert await pool.reap_once() == [credential_payload.key]


@pytest.mark.asyncio
async def test_dead_connection_is_rebuilt(pool, credential_payload):
    entry = await pool.connect(credential_payload)
    old_handle = entry.handle
    entry.conn.close()
    await entry.conn.wait_closed()
    rebuilt = await pool.connect(credential_payload)
    assert rebuilt.conn is not None and not rebuilt.conn.is_closed()
    assert rebuilt.handle != old_handle
    with pytest.raises(ToolFailure):
        await pool.acquire(old_handle)


def _key_id(payload) -> str:
    from ssh_mcp.ssh.keys import key_id_for

    return key_id_for(*payload.key)


def _ssh_home(settings, connector):
    """The fake server's home is the parent of the SFTP chroot temp dir."""
    from pathlib import Path

    # The fixture creates <tmp>/home; settings.state_dir is <tmp>/state.
    return settings.state_dir.parent / "home"
