"""1 GB-class transfer baseline: memory must not grow with file size.

Marked ``large`` and skipped by default (run with ``-m large``). The file is
generated on the fly so the test itself stays cheap on disk.
"""

from __future__ import annotations

import os

import pytest

from ssh_mcp.ssh.transfer import SftpTransferEngine

pytestmark = [pytest.mark.large, pytest.mark.asyncio]

SIZE = 1024 * 1024 * 1024
CHUNK = 1024 * 1024


def _write_pattern(path, size: int) -> None:
    block = bytes(range(256)) * (CHUNK // 256)
    with path.open("wb") as handle:
        written = 0
        while written < size:
            take = min(CHUNK, size - written)
            handle.write(block[:take])
            written += take


def _rss_mb() -> float:
    import psutil

    return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)


@pytest.mark.skipif(os.environ.get("SSH_MCP_RUN_LARGE") != "1", reason="set SSH_MCP_RUN_LARGE=1")
async def test_one_gigabyte_download_keeps_memory_flat(engine, pool, credential_payload, ssh_server, settings, tmp_path):
    source = ssh_server.home / "big1g.bin"
    _write_pattern(source, SIZE)
    local = settings.allowed_local_roots[0] / "big1g.bin"

    entry = await pool.connect(credential_payload)
    sftp = await pool.sftp_for(entry)

    before = _rss_mb()
    result = await engine.download(sftp, "/big1g.bin", local)
    after = _rss_mb()

    assert result.bytes_transferred == SIZE
    assert local.stat().st_size == SIZE
    growth = after - before
    assert growth < 50, f"resident memory grew by {growth:.1f} MB during a 1 GB transfer"

    local.unlink()

