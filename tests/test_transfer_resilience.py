"""Transient failures must cost time, not the whole transfer.

The engine used to abort on the first dropped write: one bad minute on an
uplink threw away a transfer that was still making progress, and the caller had
to notice the ``.part`` file and retry by hand. These tests pin the behaviour
that replaced it -- an adaptive stall budget, and automatic resume in-process.
"""

from __future__ import annotations

import asyncio
import contextlib
import time

import asyncssh
import pytest

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh import transfer as transfer_mod
from ssh_mcp.ssh.transfer import SftpTransferEngine, _StallGuard

pytestmark = pytest.mark.asyncio

CHUNK = 128 * 1024


@pytest.fixture
async def sftp(pool, credential_payload):
    entry = await pool.connect(credential_payload)
    return await pool.sftp_for(entry)


@pytest.fixture
def app(settings, fake_service, ssh_server):
    """The full server, so a test can go through the real tool boundary."""
    import httpx2

    from ssh_mcp.credentials.client import CredentialClient
    from ssh_mcp.ssh.auth_state import AuthStateStore
    from ssh_mcp.ssh.connector import Connector
    from ssh_mcp.ssh.keys import KeyStore
    from ssh_mcp.ssh.known_hosts import KnownHostsStore
    from ssh_mcp.ssh.pool import ConnectionPool
    from ssh_mcp.server import AppState, create_server

    credentials = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
    connector = Connector(
        settings,
        KnownHostsStore(settings.known_hosts_path),
        AuthStateStore(settings.auth_state_path),
        KeyStore(settings.keys_dir),
    )
    pool = ConnectionPool(settings, connector, credentials)
    pool.start_reaper()
    return create_server(settings, state=AppState(settings=settings, credentials=credentials, pool=pool))


def _payload(size: int, seed: int = 0) -> bytes:
    return bytes((i * 31 + seed) % 256 for i in range(size))


# -- the adaptive budget ------------------------------------------------------


async def test_guard_widens_budget_after_a_slow_step():
    guard = _StallGuard(floor=0.5)
    assert guard.budget == 0.5

    async def slow():
        await asyncio.sleep(0.1)
        return b"x"

    await guard.step(slow())
    # Four times the observed step, so a link that is merely slow never trips
    # the timeout that was sized for a peer that went silent.
    assert guard.budget > 0.4
    assert guard.steps == 1


async def test_guard_reports_a_stall_with_its_budget():
    guard = _StallGuard(floor=0.01)

    async def never():
        await asyncio.sleep(10)

    with pytest.raises(transfer_mod._IdleStall) as excinfo:
        await guard.step(never(), stall_factory=transfer_mod._stall("upload"))
    assert excinfo.value.allowed <= 0.01 * 4
    assert excinfo.value.direction == "upload"


async def test_guard_keeps_the_total_deadline():
    guard = _StallGuard(floor=60.0, deadline=time.monotonic() + 0.05)

    async def never():
        await asyncio.sleep(10)

    with pytest.raises(transfer_mod._TotalTimeout):
        await guard.step(never())


# -- retry and resume ---------------------------------------------------------


async def test_upload_resumes_after_a_dropped_connection(engine, sftp, ssh_server, settings, monkeypatch):
    """A write failing mid-transfer must continue from the bytes already on disk."""
    data = _payload(600_000)
    local = settings.allowed_local_roots[0] / "flaky.bin"
    local.write_bytes(data)
    monkeypatch.setattr(settings, "sftp_retry_delay", 0.0)

    original = transfer_mod.SftpTransferEngine._upload_body
    calls = {"n": 0}

    async def drop_once(self, client, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # Let a couple of chunks land, then break the session exactly as a
            # lost connection would.
            reached = await original(self, client, *args, **kwargs)
            raise asyncssh.SFTPConnectionLost("simulated drop")
        return await original(self, client, *args, **kwargs)

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_upload_body", drop_once)

    result = await engine.upload(sftp, local, "/flaky.bin")

    assert calls["n"] == 2
    assert result.bytes_transferred == len(data)
    assert (ssh_server.home / "flaky.bin").read_bytes() == data
    # The retry resumed instead of restarting from zero.
    assert result.resumed_from == 0  # first attempt started at 0


async def test_retry_uses_the_offset_that_reached_disk(engine, sftp, ssh_server, settings, monkeypatch):
    """When an attempt dies after writing N bytes, the next one resumes at N."""
    data = _payload(400_000)
    local = settings.allowed_local_roots[0] / "offset.bin"
    local.write_bytes(data)
    monkeypatch.setattr(settings, "sftp_retry_delay", 0.0)

    original = transfer_mod.SftpTransferEngine._upload_body
    offsets: list[int] = []

    async def record_then_drop(self, client, local_path, part_path, *args, **kwargs):
        offsets.append(kwargs.get("resumed_from", args[1] if len(args) > 1 else None))
        if len(offsets) == 1:
            await original(self, client, local_path, part_path, *args, **kwargs)
            raise asyncssh.SFTPConnectionLost("simulated drop")
        return await original(self, client, local_path, part_path, *args, **kwargs)

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_upload_body", record_then_drop)

    await engine.upload(sftp, local, "/offset.bin")

    assert offsets[0] == 0
    assert offsets[1] == len(data), "the retry must resume from the .part size, not 0"


async def test_non_transient_sftp_error_is_not_retried(engine, sftp, ssh_server, settings, monkeypatch):
    """A permission denial answers the same way every time; retrying wastes minutes."""
    local = settings.allowed_local_roots[0] / "denied.bin"
    local.write_bytes(b"payload")
    monkeypatch.setattr(settings, "sftp_retry_delay", 0.0)

    calls = {"n": 0}

    async def refuse(self, client, *args, **kwargs):
        calls["n"] += 1
        raise asyncssh.SFTPPermissionDenied("nope")

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_upload_body", refuse)

    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, local, "/denied.bin")

    assert calls["n"] == 1
    assert excinfo.value.error == "transfer_failed"


async def test_retries_can_be_disabled(engine, sftp, ssh_server, settings, monkeypatch):
    local = settings.allowed_local_roots[0] / "noretry.bin"
    local.write_bytes(b"payload")
    monkeypatch.setattr(settings, "sftp_retry_attempts", 0)

    calls = {"n": 0}

    async def drop(self, client, *args, **kwargs):
        calls["n"] += 1
        raise asyncssh.SFTPConnectionLost("drop")

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_upload_body", drop)

    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, local, "/noretry.bin")

    assert calls["n"] == 1
    assert excinfo.value.retryable is True
    assert excinfo.value.details.get("resumable") is True


async def test_recover_connection_replans_from_disk(engine, sftp, ssh_server, settings):
    """After a break, the resume offset is whatever the .part actually holds."""
    part = ssh_server.home / "replan.bin.part"
    part.write_bytes(b"x" * 1234)

    async def refresh():
        return sftp

    offset, client = await engine._recover_connection(
        "upload", "local.bin", "/replan.bin", 9999, 100_000, refresh, sftp
    )

    assert offset == 1234
    assert client is sftp


async def test_recover_connection_without_refresh_keeps_the_client(engine, sftp):
    offset, client = await engine._recover_connection(
        "upload", "local.bin", "/x.bin", 500, 1000, None, sftp
    )
    assert offset == 500
    assert client is sftp


async def test_download_resumes_after_a_stall(engine, sftp, ssh_server, settings, monkeypatch):
    """A stall is retried too: it is the same "no progress" case as a drop."""
    data = _payload(300_000)
    (ssh_server.home / "stall.bin").write_bytes(data)
    local = settings.allowed_local_roots[0] / "stall.bin"
    monkeypatch.setattr(settings, "sftp_retry_delay", 0.0)

    original = transfer_mod.SftpTransferEngine._download_body
    calls = {"n": 0}

    async def stall_once(self, client, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise transfer_mod._IdleStall("download", 0.5)
        return await original(self, client, *args, **kwargs)

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_download_body", stall_once)

    result = await engine.download(sftp, "/stall.bin", local)

    assert calls["n"] == 2
    assert local.read_bytes() == data


# -- end to end: a real dropped connection, through the tool layer ------------


async def test_tool_upload_survives_a_real_dropped_connection(app, settings, ssh_server, monkeypatch):
    """The whole stack: drop the SSH connection mid-upload, expect success anyway.

    This exercises the part the unit tests above stub out -- the socket really
    goes away, the cached SFTP channel is really dead, and the retry has to
    rebuild both through the pool before it can resume.
    """
    from tests.test_tools import call

    connect, _ = await call(app, "connect", server_id="1")
    handle = connect["connection_handle"]
    data = bytes((i * 31 + 7) % 256 for i in range(500_000))
    local = settings.allowed_local_roots[0] / "resilient.bin"
    local.write_bytes(data)
    monkeypatch.setattr(settings, "sftp_retry_delay", 0.0)

    entry = app._ssh_mcp_state.pool._entries[next(iter(app._ssh_mcp_state.pool._entries))]
    original = transfer_mod.SftpTransferEngine._upload_body
    dropped = {"done": False}

    async def drop_after_partial(self, client, *args, **kwargs):
        if dropped["done"]:
            return await original(self, client, *args, **kwargs)
        # Let some bytes land, then take the transport away for real.
        result = await original(self, client, *args, **kwargs)
        entry.conn.close()
        await entry.conn.wait_closed()
        entry.sftp = None
        dropped["done"] = True
        raise asyncssh.ConnectionLost("connection dropped by test")

    monkeypatch.setattr(transfer_mod.SftpTransferEngine, "_upload_body", drop_after_partial)

    payload, is_error = await call(
        app, "upload_file", connection_handle=handle, local_path=str(local), remote_path="/resilient.bin"
    )

    assert dropped["done"] is True
    assert is_error is False, payload
    assert payload["bytes_transferred"] == len(data)
    assert (ssh_server.home / "resilient.bin").read_bytes() == data
