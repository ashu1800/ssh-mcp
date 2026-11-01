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
from tests.conftest import PASSWORD, USERNAME


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
    pool = ConnectionPool(settings, connector, credentials)
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
    assert set(row) == {"server_id", "alias", "encrypted_blob_ref", "auth_type", "group_name", "last_used"}
    assert row["last_used"] is None
    assert PASSWORD not in json.dumps(payload)


@pytest.mark.asyncio
async def test_connect_result_is_redacted(app, ssh_server):
    """The connect payload doubles as the old resolve summary: redacted."""
    payload, is_error = await call(app, "connect", server="1")
    assert is_error is False
    assert payload["host"] == "127.0.0.1"
    assert payload["port"] == ssh_server.port
    assert payload["username"] == USERNAME
    rendered = json.dumps(payload)
    assert PASSWORD not in rendered


@pytest.mark.asyncio
async def test_connect_returns_handle(app):
    payload, is_error = await call(app, "connect", server="1")
    assert is_error is False
    assert payload["status"] == "connected"
    assert payload["auth_method"] in {"password", "publickey"}
    assert payload["connection_handle"]
    assert PASSWORD not in json.dumps(payload)


@pytest.mark.asyncio
async def test_connect_without_server_reuses_history(settings, fake_service, ssh_server):
    """0 参数 connect 重连最近一次成功连接的服务器（历史持久化到 state_dir）。"""
    import httpx2

    from ssh_mcp.credentials.client import CredentialClient
    from ssh_mcp.server import AppState, create_server
    from ssh_mcp.ssh.auth_state import AuthStateStore
    from ssh_mcp.ssh.connector import Connector
    from ssh_mcp.ssh.keys import KeyStore
    from ssh_mcp.ssh.known_hosts import KnownHostsStore
    from ssh_mcp.ssh.pool import ConnectionPool

    def build():
        credentials = CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler))
        connector = Connector(
            settings,
            KnownHostsStore(settings.known_hosts_path),
            AuthStateStore(settings.auth_state_path),
            KeyStore(settings.keys_dir),
        )
        pool = ConnectionPool(settings, connector, credentials)
        state = AppState(settings=settings, credentials=credentials, pool=pool)
        return create_server(settings, state=state)

    app1 = build()
    payload, is_error = await call(app1, "connect", server="1")
    assert is_error is False

    # A brand-new server instance (simulating a restart) recalls the history.
    app2 = build()
    payload, is_error = await call(app2, "connect")
    assert is_error is False
    assert payload["status"] == "connected"

    # And an instance pointed at an absent history file gets a structured error.
    settings.history_path = settings.state_dir / "nope.json"
    empty_pool = ConnectionPool(
        settings,
        Connector(
            settings,
            KnownHostsStore(settings.known_hosts_path),
            AuthStateStore(settings.auth_state_path),
            KeyStore(settings.keys_dir),
        ),
    )
    app3 = create_server(
        settings,
        state=AppState(
            settings=settings,
            credentials=CredentialClient(settings, transport=httpx2.MockTransport(fake_service.handler)),
            pool=empty_pool,
        ),
    )
    payload, is_error = await call(app3, "connect")
    assert is_error is True
    assert payload["error"] == "no_connection_history"


@pytest.mark.asyncio
async def test_list_servers_annotates_last_used(app):
    await call(app, "connect", server="1")
    payload, is_error = await call(app, "list_servers")
    assert is_error is False
    row = payload["servers"][0]
    assert row["server_id"] == "1"
    assert row["last_used"] is not None


@pytest.mark.asyncio
async def test_connect_reuses_handle(app):
    first, _ = await call(app, "connect", server="1")
    second, _ = await call(app, "connect", server="1")
    assert first["connection_handle"] == second["connection_handle"]


@pytest.mark.asyncio
async def test_connect_unknown_server_lists_candidates(app):
    """resolve_server was folded into connect; a bad name self-corrects."""
    payload, is_error = await call(app, "connect", server="42")
    assert is_error is True
    assert payload["error"] == "server_not_found"
    assert payload["candidates"]


@pytest.mark.asyncio
async def test_execute_command_roundtrip(app):
    connect, _ = await call(app, "connect", server="1")
    payload, is_error = await call(
        app, "execute_command", connection_handle=connect["connection_handle"], command="echo hello"
    )
    assert is_error is False
    assert payload["stdout"].strip() == "hello"
    assert payload["exit_code"] == 0


@pytest.mark.asyncio
async def test_execute_command_timeout_is_structured(app):
    connect, _ = await call(app, "connect", server="1")
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
    connect, _ = await call(app, "connect", server="1")
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
async def test_overwrite_defaults_to_refusal_and_true_means_confirm(app, settings):
    """One switch: overwrite omitted refuses an existing target; =true overwrites."""
    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]
    local = settings.allowed_local_roots[0] / "c.bin"
    local.write_bytes(b"x")

    # First upload creates the target.
    payload, is_error = await call(
        app, "upload_file", connection_handle=handle, local_path=str(local), remote_path="/c.bin"
    )
    assert is_error is False

    # Second upload without overwrite refuses the now-existing target.
    payload, is_error = await call(
        app, "upload_file", connection_handle=handle, local_path=str(local), remote_path="/c.bin"
    )
    assert is_error is True
    assert payload["error"] == "remote_exists"
    assert "overwrite=true" in payload["hint"]

    payload, is_error = await call(
        app,
        "upload_file",
        connection_handle=handle,
        local_path=str(local),
        remote_path="/c.bin",
        overwrite=True,
    )
    assert is_error is False
    assert payload["bytes_transferred"] == 1


@pytest.mark.asyncio
async def test_download_outside_allowlist_is_rejected(app):
    connect, _ = await call(app, "connect", server="1")
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
    connect, _ = await call(app, "connect", server="1")
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
    connect, _ = await call(app, "connect", server="1")
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
    connect, _ = await call(app, "connect", server="1")
    (ssh_server.home / "keep.txt").write_text("x")
    payload, is_error = await call(
        app, "remove_path", connection_handle=connect["connection_handle"], path="/keep.txt"
    )
    assert is_error is True and payload["error"] == "confirmation_required"
    assert (ssh_server.home / "keep.txt").exists()


@pytest.mark.asyncio
async def test_change_permissions_rejects_bad_mode(app):
    connect, _ = await call(app, "connect", server="1")
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
async def test_read_file_windows_and_refusals(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]
    target = ssh_server.home / "app.log"
    target.write_text("\n".join(f"line {i}" for i in range(1, 201)), encoding="utf-8")

    payload, is_error = await call(app, "read_file", connection_handle=handle, path="/app.log")
    assert is_error is False
    assert payload["total_lines"] == 200
    assert payload["lines"][0] == {"n": 1, "text": "line 1"}
    assert payload["truncated"] is True

    payload, _ = await call(app, "read_file", connection_handle=handle, path="/app.log", offset=-50)
    assert payload["lines"][0]["n"] == 151
    assert payload["lines"][-1]["text"] == "line 200"
    assert payload["truncated"] is False

    payload, is_error = await call(app, "read_file", connection_handle=handle, path="/nope.log")
    assert is_error is True and payload["error"] == "remote_not_found"

    (ssh_server.home / "big.bin").write_bytes(b"0" * 9 * 1024 * 1024)
    payload, is_error = await call(app, "read_file", connection_handle=handle, path="/big.bin")
    assert is_error is True and payload["error"] == "file_too_large"


@pytest.mark.asyncio
async def test_write_file_refuses_existing_without_confirm(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]

    payload, is_error = await call(
        app,
        "write_file",
        connection_handle=handle,
        path="/etc/app.conf",
        content="key=value\n",
        create_parent_dirs=True,
    )
    assert is_error is False
    assert payload["existed"] is False
    assert (ssh_server.home / "etc" / "app.conf").read_text(encoding="utf-8") == "key=value\n"

    # Without create_parent_dirs a missing parent is a structured error.
    payload, is_error = await call(
        app, "write_file", connection_handle=handle, path="/opt/x/app2.conf", content="a\n"
    )
    assert is_error is True and payload["error"] == "remote_parent_not_found"

    payload, is_error = await call(
        app, "write_file", connection_handle=handle, path="/etc/app.conf", content="key=other\n"
    )
    assert is_error is True and payload["error"] == "confirmation_required"
    # Content unchanged after the refusal.
    assert (ssh_server.home / "etc" / "app.conf").read_text(encoding="utf-8") == "key=value\n"

    payload, is_error = await call(
        app, "write_file", connection_handle=handle, path="/etc/app.conf", content="extra\n", append=True, confirm=True
    )
    assert is_error is False and payload["appended"] is True
    assert (ssh_server.home / "etc" / "app.conf").read_text(encoding="utf-8") == "key=value\nextra\n"


@pytest.mark.asyncio
async def test_search_files_matches_by_glob(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    logs = ssh_server.home / "var" / "log"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "app-1.log").write_text("a")
    (logs / "app-2.log").write_text("b")
    (logs / "readme.txt").write_text("c")
    (ssh_server.home / "top.log").write_text("d")

    payload, is_error = await call(
        app, "search_files", connection_handle=connect["connection_handle"], path="/", pattern="*.log"
    )
    assert is_error is False
    found = {m["path"] for m in payload["matches"]}
    assert "/var/log/app-1.log" in found and "/var/log/app-2.log" in found and "/top.log" in found
    assert payload["total_matches"] == 3
    assert all(not m["path"].endswith(".txt") for m in payload["matches"])


@pytest.mark.asyncio
async def test_background_command_runs_to_completion(app):
    """End-to-end on POSIX; on the Windows fake server (no setsid) it must
    fail with the structured error instead of crashing."""
    import sys as _sys

    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]

    payload, is_error = await call(
        app, "start_background_command", connection_handle=handle, command="echo bg-hello; echo bg-err >&2"
    )
    if _sys.platform == "win32":
        assert is_error is True
        assert payload["error"] == "background_unsupported"
        return
    assert is_error is False, payload
    job_id = payload["job_id"]
    assert payload["status"] == "running"

    deadline = 10.0
    import asyncio as _asyncio

    while deadline > 0:
        await _asyncio.sleep(0.3)
        deadline -= 0.3
        payload, is_error = await call(app, "get_background_command", connection_handle=handle, job_id=job_id)
        assert is_error is False, payload
        if payload["status"] == "finished":
            break
    assert payload["status"] == "finished"
    assert payload["exit_code"] == 0
    assert "bg-hello" in payload["stdout_tail"]
    assert "bg-err" in payload["stderr_tail"]

    payload, is_error = await call(
        app, "get_background_command", connection_handle=handle, job_id=job_id, cleanup=True
    )
    assert is_error is False and payload.get("cleaned") is True

    payload, is_error = await call(app, "get_background_command", connection_handle=handle, job_id="bad;id")
    assert is_error is True and payload["error"] == "invalid_argument"


@pytest.mark.asyncio
async def test_background_rejects_interactive(app):
    connect, _ = await call(app, "connect", server="1")
    payload, is_error = await call(
        app, "start_background_command", connection_handle=connect["connection_handle"], command="top"
    )
    assert is_error is True
    assert payload["error"] == "interactive_command_rejected"


@pytest.mark.asyncio
async def test_batch_upload_reports_per_item(app, settings, ssh_server):
    connect, _ = await call(app, "connect", server="1")
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


# -- regressions --------------------------------------------------------------


@pytest.mark.asyncio
async def test_recursive_chmod_terminates_and_stays_inside_tree(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]
    (ssh_server.home / "tree" / "sub").mkdir(parents=True)
    (ssh_server.home / "tree" / "sub" / "a.txt").write_text("a")

    payload, is_error = await call(
        app, "change_permissions", connection_handle=handle, path="/tree", mode="700",
        recursive=True, confirm=True,
    )

    assert is_error is False
    assert payload["affected"] == 3  # /tree, /tree/sub, /tree/sub/a.txt; "." and ".." excluded
    assert ssh_server.home.exists()


@pytest.mark.asyncio
async def test_rename_failure_keeps_the_existing_target(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    (ssh_server.home / "important.txt").write_text("keep me")

    payload, is_error = await call(
        app, "rename_path", connection_handle=connect["connection_handle"],
        old_path="/missing.txt", new_path="/important.txt", overwrite=True, confirm=True,
    )

    assert is_error is True
    assert (ssh_server.home / "important.txt").read_text() == "keep me"


@pytest.mark.asyncio
async def test_make_directory_failures_are_structured(app, ssh_server):
    connect, _ = await call(app, "connect", server="1")
    handle = connect["connection_handle"]

    missing_parent, is_error = await call(app, "make_directory", connection_handle=handle, path="/no/such/dir")
    assert is_error is True and missing_parent["error"] == "remote_parent_not_found"

    (ssh_server.home / "blocker").write_text("file")
    not_a_dir, is_error = await call(app, "make_directory", connection_handle=handle, path="/blocker")
    assert is_error is True and not_a_dir["error"] == "remote_not_a_directory"


@pytest.mark.asyncio
async def test_connect_failure_returns_a_structured_error(app, monkeypatch):
    from ssh_mcp.errors import ToolFailure

    async def failing_connect(*args, **kwargs):
        raise ToolFailure("auth_failed", stage="password", hint="密码认证失败", retryable=False)

    monkeypatch.setattr(app._ssh_mcp_state.pool, "connect", failing_connect)

    payload, is_error = await call(app, "connect", server="1")

    assert is_error is True
    assert payload["error"] == "auth_failed"
    assert payload["stage"] == "password"


@pytest.mark.asyncio
async def test_connect_timeout_is_forwarded(app, monkeypatch):
    seen = {}
    original = app._ssh_mcp_state.pool.connect

    async def recording_connect(*args, **kwargs):
        seen.update(kwargs)
        return await original(*args, **kwargs)

    monkeypatch.setattr(app._ssh_mcp_state.pool, "connect", recording_connect)

    await call(app, "connect", server="1", timeout_seconds=7.5)

    assert seen["timeout"] == 7.5


@pytest.mark.asyncio
async def test_large_default_output_is_truncated_not_rejected(app, ssh_server, settings):
    connect, _ = await call(app, "connect", server="1")
    (ssh_server.home / "big.txt").write_bytes(b"a" * 700_000)

    payload, is_error = await call(
        app, "execute_command", connection_handle=connect["connection_handle"], command="cat big.txt"
    )

    assert is_error is False
    assert payload["truncated"] is True
    assert payload["stdout_total_bytes"] == 700_000


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    ["python3 manage.py migrate", "node build.js", "mysql -e 'select 1'", "top -b -n1"],
)
async def test_non_interactive_invocations_are_allowed(app, command):
    connect, _ = await call(app, "connect", server="1")
    payload, is_error = await call(
        app, "execute_command", connection_handle=connect["connection_handle"], command=command
    )
    assert payload.get("error") != "interactive_command_rejected"


@pytest.mark.asyncio
async def test_connection_handle_can_be_omitted_after_connect(app):
    """connect establishes the implicit target, so later calls need no handle."""
    await call(app, "connect", server="1")
    payload, is_error = await call(app, "get_system_overview")
    # The fake server's shell answers only a few builtins, so the parsed fields
    # may be empty; what matters is that the handle resolved at all.
    assert payload.get("error") != "connection_not_found"
    assert is_error is False or "error" not in payload


@pytest.mark.asyncio
async def test_omitted_handle_without_a_connection_is_actionable(app):
    payload, is_error = await call(app, "get_system_overview")
    assert is_error is True
    assert payload["error"] == "connection_not_found"
    assert payload["next_actions"] == ["call_connect"]
    assert "先调用 connect" in payload["hint"]


@pytest.mark.asyncio
async def test_connection_stats_reports_the_pool(app):
    await call(app, "connect", server="1")
    payload, is_error = await call(app, "get_connection_stats")
    assert is_error is False
    assert payload["count"] == 1
    assert payload["counters"]["connections_established"] >= 1
    entry = payload["entries"][0]
    assert set(entry) >= {"host", "port", "username", "alive", "in_flight"}


@pytest.mark.asyncio
async def test_handle_survives_idle_reaping(app, settings):
    """The reported bug: an idle-pooled connection must not invalidate the handle.

    Reaping closes the socket after `pool_idle_timeout`; before this, it also
    dropped the mapping, so every later call with the handle the model was
    holding failed with `connection_not_found`.
    """
    connect_payload, _ = await call(app, "connect", server="1")
    handle = connect_payload["connection_handle"]

    # Force the reaper to consider the entry idle, then run it.
    settings.pool_idle_timeout = 0.01
    import asyncio

    await asyncio.sleep(0.05)
    pool = app._ssh_mcp_state.pool
    closed = await pool.reap_once()
    assert len(closed) == 1
    assert pool.stats()["count"] == 1  # entry kept, socket closed

    # The same handle still works: transparently reconnected.
    payload, is_error = await call(app, "get_system_overview", connection_handle=handle)
    assert payload.get("error") != "connection_not_found"
