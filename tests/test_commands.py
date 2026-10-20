"""``execute_command`` behaviour: output, truncation, timeout, cancellation."""

from __future__ import annotations

import asyncio
import pytest

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.commands import CommandRunner

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def handle(pool, credential_payload):
    entry = await pool.connect(credential_payload)
    return entry.handle


@pytest.fixture
def runner(settings, pool):
    return CommandRunner(settings, pool)


@pytest.mark.asyncio
async def test_runs_command_and_returns_streams(runner, handle):
    result = await runner.run(handle, "echo out; echo err >&2; exit 3")
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"
    assert result.exit_code == 3
    assert result.truncated is False
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_empty_command_is_rejected(runner, handle):
    with pytest.raises(ToolFailure) as excinfo:
        await runner.run(handle, "   ")
    assert excinfo.value.error == "invalid_argument"


@pytest.mark.asyncio
async def test_nul_in_command_is_rejected(runner, handle):
    with pytest.raises(ToolFailure) as excinfo:
        await runner.run(handle, "echo a\x00b")
    assert excinfo.value.error == "invalid_argument"


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["top", "vim /etc/hosts", "sudo htop", "cat x | less", "watch -n1 ls"])
async def test_interactive_commands_are_refused(runner, handle, command):
    with pytest.raises(ToolFailure) as excinfo:
        await runner.run(handle, command)
    assert excinfo.value.error == "interactive_command_rejected"
    assert "allow_interactive" in excinfo.value.hint


@pytest.mark.asyncio
async def test_interactive_can_be_forced(runner, handle):
    result = await runner.run(handle, "echo allowed", allow_interactive=True)
    assert result.stdout.strip() == "allowed"


@pytest.mark.asyncio
async def test_output_is_truncated_and_counts_total(runner, handle, ssh_server):
    (ssh_server.home / "blob.txt").write_bytes(b"a" * 20000)
    result = await runner.run(handle, "cat blob.txt", max_output_bytes=2048)
    assert result.truncated is True
    assert result.total_stdout_bytes == 20000
    assert "[truncated, total 20000 bytes]" in result.stdout
    assert len(result.stdout.encode()) < 2100


@pytest.mark.asyncio
async def test_timeout_terminates_remote_process(runner, handle, ssh_server):
    marker = ssh_server.home / "sleeping"
    result = await runner.run(handle, f"touch {marker}; sleep 30", timeout_seconds=1)
    assert result.timed_out is True
    assert result.terminated is True
    # The shell exits once the sleep is signalled; the marker proves it started.
    assert marker.exists()
    # No lingering sleep for this fake home: re-running a quick command must
    # still work (the connection was not poisoned by the timeout).
    follow_up = await runner.run(handle, "echo alive", timeout_seconds=5)
    assert follow_up.stdout.strip() == "alive"


@pytest.mark.asyncio
async def test_timeout_is_capped_by_settings(settings, runner, handle):
    settings.command_timeout_max = 1.0
    result = await runner.run(handle, "sleep 30", timeout_seconds=600)
    assert result.timed_out is True


@pytest.mark.asyncio
async def test_cancel_terminates_remote_process(runner, handle, ssh_server):
    marker = ssh_server.home / "cancelled"
    task = asyncio.create_task(runner.run(handle, f"touch {marker}; sleep 30", timeout_seconds=60))
    for _ in range(50):
        if marker.exists():
            break
        await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    follow_up = await runner.run(handle, "echo alive", timeout_seconds=5)
    assert follow_up.stdout.strip() == "alive"


@pytest.mark.asyncio
async def test_unknown_handle_is_structured(runner):
    with pytest.raises(ToolFailure) as excinfo:
        await runner.run("missing", "echo hi")
    assert excinfo.value.error == "connection_not_found"
    assert excinfo.value.retryable is True


@pytest.mark.asyncio
async def test_timeout_returns_promptly_without_waiting_for_the_command(runner, handle, ssh_server):
    """A timed-out command must not block until the remote process finishes."""
    import time

    started = time.monotonic()
    result = await runner.run(handle, "sleep 30; echo never", timeout_seconds=1)
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed < 8, f"timeout took {elapsed:.1f}s; it must not wait for the command"
