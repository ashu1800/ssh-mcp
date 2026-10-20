"""SFTP transfer engine: streaming, resume, atomic commit, verification, cancel."""

from __future__ import annotations

import asyncio
import hashlib
import os

import asyncssh
import pytest

from ssh_mcp.config import PathNotAllowed
from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.transfer import SftpTransferEngine, resolve_local_target


@pytest.fixture
async def sftp(pool, credential_payload):
    entry = await pool.connect(credential_payload)
    return await pool.sftp_for(entry)


def _payload(size: int, seed: int = 0) -> bytes:
    return bytes((i * 31 + seed) % 256 for i in range(size))


@pytest.mark.asyncio
async def test_upload_roundtrip(engine, sftp, ssh_server, tmp_path, settings):
    local = settings.allowed_local_roots[0] / "up.bin"
    data = _payload(300_000)
    local.write_bytes(data)

    result = await engine.upload(sftp, local, "/data/up.bin", create_parent_dirs=True)

    assert result.bytes_transferred == len(data)
    assert result.resumed_from == 0
    assert result.verified == "size"
    assert (ssh_server.home / "data" / "up.bin").read_bytes() == data
    assert not (ssh_server.home / "data" / "up.bin.part").exists()
    assert result.remote_path == "/data/up.bin"


@pytest.mark.asyncio
async def test_download_roundtrip(engine, sftp, ssh_server, settings):
    data = _payload(250_000, seed=5)
    (ssh_server.home / "down.bin").write_bytes(data)
    local = settings.allowed_local_roots[0] / "nested" / "down.bin"

    result = await engine.download(sftp, "/down.bin", local)

    assert result.bytes_transferred == len(data)
    assert local.read_bytes() == data
    assert not local.with_name(local.name + ".part").exists()


@pytest.mark.asyncio
async def test_upload_refuses_existing_target_before_transfer(engine, sftp, ssh_server, settings):
    local = settings.allowed_local_roots[0] / "exists.bin"
    local.write_bytes(b"new")
    (ssh_server.home / "exists.bin").write_bytes(b"old")

    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, local, "/exists.bin")

    assert excinfo.value.error == "remote_exists"
    assert (ssh_server.home / "exists.bin").read_bytes() == b"old"
    assert not (ssh_server.home / "exists.bin.part").exists()


@pytest.mark.asyncio
async def test_download_refuses_existing_target(engine, sftp, ssh_server, settings):
    (ssh_server.home / "r.bin").write_bytes(b"remote")
    local = settings.allowed_local_roots[0] / "l.bin"
    local.write_bytes(b"keep")

    with pytest.raises(ToolFailure) as excinfo:
        await engine.download(sftp, "/r.bin", local)

    assert excinfo.value.error == "local_exists"
    assert local.read_bytes() == b"keep"


@pytest.mark.asyncio
async def test_upload_overwrite_is_allowed_with_flag(engine, sftp, ssh_server, settings):
    local = settings.allowed_local_roots[0] / "ov.bin"
    local.write_bytes(b"brand new")
    (ssh_server.home / "ov.bin").write_bytes(b"stale")

    result = await engine.upload(sftp, local, "/ov.bin", overwrite=True)

    assert result.bytes_transferred == len(b"brand new")
    assert (ssh_server.home / "ov.bin").read_bytes() == b"brand new"


@pytest.mark.asyncio
async def test_upload_resumes_from_partial(engine, sftp, ssh_server, settings):
    data = _payload(600_000)
    local = settings.allowed_local_roots[0] / "resume.bin"
    local.write_bytes(data)
    # Simulate an interrupted transfer: first 200 000 bytes already on .part.
    (ssh_server.home / "resume.bin.part").write_bytes(data[:200_000])

    result = await engine.upload(sftp, local, "/resume.bin", create_parent_dirs=False)

    assert result.resumed_from == 200_000
    assert result.bytes_transferred == len(data)
    assert (ssh_server.home / "resume.bin").read_bytes() == data


@pytest.mark.asyncio
async def test_download_resumes_from_partial(engine, sftp, ssh_server, settings):
    data = _payload(500_000, seed=9)
    (ssh_server.home / "dresume.bin").write_bytes(data)
    local = settings.allowed_local_roots[0] / "dresume.bin"
    part = local.with_name(local.name + ".part")
    part.write_bytes(data[:123_456])

    result = await engine.download(sftp, "/dresume.bin", local)

    assert result.resumed_from == 123_456
    assert local.read_bytes() == data


@pytest.mark.asyncio
async def test_oversized_part_is_discarded(engine, sftp, ssh_server, settings):
    data = _payload(1000)
    local = settings.allowed_local_roots[0] / "big.bin"
    local.write_bytes(data)
    (ssh_server.home / "big.bin.part").write_bytes(b"x" * 5000)

    result = await engine.upload(sftp, local, "/big.bin")

    assert result.resumed_from == 0
    assert (ssh_server.home / "big.bin").read_bytes() == data


@pytest.mark.asyncio
async def test_resume_false_discards_part(engine, sftp, ssh_server, settings):
    data = _payload(2000)
    local = settings.allowed_local_roots[0] / "nofalse.bin"
    local.write_bytes(data)
    (ssh_server.home / "nofalse.bin.part").write_bytes(data[:500])

    result = await engine.upload(sftp, local, "/nofalse.bin", resume=False)
    assert result.resumed_from == 0
    assert (ssh_server.home / "nofalse.bin").read_bytes() == data


@pytest.mark.asyncio
async def test_sha256_verification_matches(engine, sftp, ssh_server, settings):
    data = _payload(80_000, seed=3)
    local = settings.allowed_local_roots[0] / "hash.bin"
    local.write_bytes(data)

    result = await engine.upload(sftp, local, "/hash.bin", verify="sha256")

    expected = hashlib.sha256(data).hexdigest()
    assert result.verified == "sha256"
    assert result.local_hash == expected
    assert result.remote_hash == expected
    assert result.hash_seconds is not None


@pytest.mark.asyncio
async def test_sha256_download_verification(engine, sftp, ssh_server, settings):
    data = _payload(90_000, seed=11)
    (ssh_server.home / "dh.bin").write_bytes(data)
    local = settings.allowed_local_roots[0] / "dh.bin"

    result = await engine.download(sftp, "/dh.bin", local, verify="sha256")

    assert result.local_hash == result.remote_hash == hashlib.sha256(data).hexdigest()


@pytest.mark.asyncio
async def test_verification_failure_removes_part(engine, sftp, ssh_server, settings, monkeypatch):
    local = settings.allowed_local_roots[0] / "bad.bin"
    local.write_bytes(b"content")

    real_sha = engine._settings  # keep a reference so the attribute path is obvious
    import ssh_mcp.ssh.transfer as transfer_mod

    async def wrong_hash(sftp_client, path, conn=None):
        return "0" * 64

    monkeypatch.setattr(transfer_mod, "_sha256_remote", wrong_hash)

    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, local, "/bad.bin", verify="sha256")

    assert excinfo.value.error == "verification_failed"
    assert not (ssh_server.home / "bad.bin.part").exists()
    assert not (ssh_server.home / "bad.bin").exists()


@pytest.mark.asyncio
async def test_upload_missing_local_file(engine, sftp, settings):
    missing = settings.allowed_local_roots[0] / "nope.bin"
    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, missing, "/nope.bin")
    assert excinfo.value.error == "local_file_missing"


@pytest.mark.asyncio
async def test_download_missing_remote_file(engine, sftp, settings):
    with pytest.raises(ToolFailure) as excinfo:
        await engine.download(sftp, "/missing.bin", settings.allowed_local_roots[0] / "m.bin")
    assert excinfo.value.error == "remote_not_found"


@pytest.mark.asyncio
async def test_download_remote_directory_is_rejected(engine, sftp, ssh_server, settings):
    (ssh_server.home / "adir").mkdir()
    with pytest.raises(ToolFailure) as excinfo:
        await engine.download(sftp, "/adir", settings.allowed_local_roots[0] / "adir")
    assert excinfo.value.error == "remote_is_directory"


@pytest.mark.asyncio
async def test_nul_in_remote_path_is_rejected(engine, sftp, settings):
    local = settings.allowed_local_roots[0] / "n.bin"
    local.write_bytes(b"x")
    with pytest.raises(ToolFailure) as excinfo:
        await engine.upload(sftp, local, "/bad\x00name")
    assert excinfo.value.error == "invalid_argument"


@pytest.mark.asyncio
async def test_download_cancel_keeps_part(engine, sftp, ssh_server, settings):
    size = 4 * 1024 * 1024
    (ssh_server.home / "big.bin").write_bytes(_payload(size, seed=2))
    local = settings.allowed_local_roots[0] / "big.bin"
    part = local.with_name(local.name + ".part")

    task = asyncio.create_task(engine.download(sftp, "/big.bin", local))
    for _ in range(200):
        if part.exists() and part.stat().st_size > 0:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert part.exists(), "cancelling must keep the .part file for resume"
    assert not local.exists()

    # A retry resumes rather than restarts.
    resumed = await engine.download(sftp, "/big.bin", local)
    assert resumed.resumed_from > 0
    assert local.read_bytes() == (ssh_server.home / "big.bin").read_bytes()


@pytest.mark.asyncio
async def test_transfer_reports_progress(engine, sftp, ssh_server, settings):
    data = _payload(700_000)
    (ssh_server.home / "progress.bin").write_bytes(data)
    local = settings.allowed_local_roots[0] / "progress.bin"
    seen: list[tuple[int, int | None]] = []

    async def report(done: int, total: int | None) -> None:
        seen.append((done, total))

    await engine.download(sftp, "/progress.bin", local, progress=report)
    assert seen
    assert seen[-1][0] == len(data)
    assert all(total == len(data) for _, total in seen)
    assert seen == sorted(seen), "progress values must increase"


@pytest.mark.asyncio
async def test_block_size_adapts_to_server_limits(engine, sftp):
    size = engine._block_size(sftp)
    assert 16 * 1024 <= size <= engine._settings.sftp_block_size


# -- local path allowlist -----------------------------------------------------


def test_allowed_root_accepts_children(settings):
    root = settings.allowed_local_roots[0]
    resolved = resolve_local_target(settings, str(root / "a" / "b.txt"))
    assert resolved.is_relative_to(root)


def test_outside_root_is_rejected(settings):
    with pytest.raises(ToolFailure) as excinfo:
        resolve_local_target(settings, "C:/Windows/System32/drivers/etc/hosts")
    assert excinfo.value.error == "path_not_allowed"


def test_parent_traversal_is_rejected(settings):
    root = settings.allowed_local_roots[0]
    with pytest.raises(ToolFailure):
        resolve_local_target(settings, str(root / ".." / ".." / "outside.txt"))


def test_symlink_escape_is_rejected(settings, tmp_path):
    root = settings.allowed_local_roots[0]
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation needs elevated privileges on this Windows host")
    with pytest.raises(ToolFailure):
        resolve_local_target(settings, str(link / "file.txt"))


def test_nul_in_local_path_is_rejected(settings):
    with pytest.raises(ToolFailure):
        resolve_local_target(settings, "bad\x00path")
