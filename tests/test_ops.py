"""Semantic inspection tools: parsing and validation.

The fake SSH server runs commands through a small interpreter, so these tests
cover the parsing helpers and the argument guards; the real commands are
exercised against a live host separately.
"""

from __future__ import annotations

import json

import httpx2
import pytest

from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.errors import ToolFailure
from ssh_mcp.server import AppState, create_server
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.tools.ops import _parse_overview, _unit_name


@pytest.fixture
def app(settings, fake_service, ssh_server):
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


async def call(app, tool_name: str, **arguments):
    result = await app.call_tool(tool_name, arguments)
    payload = result.structured_content
    assert isinstance(payload, dict)
    return payload, result.is_error


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("nginx", "nginx.service"),
        ("nginx.service", "nginx.service"),
        ("  cron  ", "cron.service"),
        ("postgres@main", "postgres@main.service"),
    ],
)
def test_unit_name_normalisation(raw, expected):
    assert _unit_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "/etc/passwd", "--all", "-x"])
def test_unit_name_rejects_injection(raw):
    with pytest.raises(ToolFailure) as excinfo:
        _unit_name(raw)
    assert excinfo.value.error == "invalid_argument"


def test_overview_parses_the_real_script_output():
    text = """\
--- host ---
web-01
Linux 6.8.0-117-generic
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
--- uptime ---
2310472.31 8000000.00
 10:00:00 up 26 days,  2:14,  1 user,  load average: 0.08, 0.12, 0.10
--- mem ---
              total        used        free      shared  buff/cache   available
Mem:     8000000000  2000000000  3000000000           0  3000000000  5500000000
Swap:             0           0           0
--- cpu ---
4
"""
    parsed = _parse_overview(text)
    assert parsed["hostname"] == "web-01"
    assert parsed["kernel"] == "Linux 6.8.0-117-generic"
    # Quotes from /etc/os-release must not survive into the result.
    assert parsed["os"] == "Ubuntu 24.04.4 LTS"
    assert parsed["os_version"] == "24.04"
    assert parsed["uptime_seconds"] == pytest.approx(2310472.31)
    assert parsed["load"] == [0.08, 0.12, 0.10]
    assert parsed["logged_in_users"] == 1
    assert parsed["memory"]["total_bytes"] == 8000000000
    assert parsed["memory"]["available_bytes"] == 5500000000
    assert parsed["cpu_count"] == 4


def test_overview_tolerates_missing_sections():
    """A minimal container may lack free(1) or /proc/uptime; absent keys stay absent."""
    parsed = _parse_overview("--- host ---\nbox\nLinux 6.1\n")
    assert parsed["hostname"] == "box"
    assert parsed["kernel"] == "Linux 6.1"
    assert parsed["os"] is None
    assert "memory" not in parsed
    assert "cpu_count" not in parsed


@pytest.mark.asyncio
async def test_service_status_rejects_a_bogus_unit(app):
    payload, is_error = await call(app, "get_service_status", name="../etc/shadow")
    assert is_error is True
    assert payload["error"] == "invalid_argument"


@pytest.mark.asyncio
async def test_tail_log_requires_a_source(app):
    payload, is_error = await call(app, "tail_log")
    assert is_error is True
    assert "unit 与 path 至少给一个" in payload["hint"]


@pytest.mark.asyncio
async def test_list_services_rejects_an_unknown_state(app):
    payload, is_error = await call(app, "list_services", state="exploded")
    assert is_error is True
    assert "running、failed 或 all" in payload["hint"]


@pytest.mark.asyncio
async def test_list_processes_rejects_an_unknown_sort(app):
    payload, is_error = await call(app, "list_processes", sort_by="vibes")
    assert is_error is True
    assert "cpu、mem 或 pid" in payload["hint"]
