"""Semantic inspection tools: parsing and validation.

The fake SSH server runs commands through a small interpreter, so these tests
cover the parsing helpers and the argument guards; the real commands are
exercised against a live host separately.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

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

from ssh_mcp.tools.ops import (
    _health_warnings,
    _is_helper_command,
    _parse_certificates,
    _parse_containers,
    _parse_df,
    _parse_overview,
    _parse_ports,
    _parse_ps_rows,
    _parse_top_rows,
    _unit_name,
)


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


SWAP_OVERVIEW = """--- host ---
box
Linux 6.1
--- uptime ---
100.0 200.0
 10:00:00 up 1 day,  1:00,  1 user,  load average: 0.00, 0.00, 0.00
--- mem ---
              total        used        free      shared  buff/cache   available
Mem:     8000000000  2000000000  3000000000           0  3000000000  5500000000
Swap:    2048000000   500000000  1548000000
--- cpu ---
2
"""


def test_overview_reports_swap():
    parsed = _parse_overview(SWAP_OVERVIEW)
    assert parsed["swap"] == {
        "total_bytes": 2048000000,
        "used_bytes": 500000000,
        "free_bytes": 1548000000,
    }


TOP_SNAPSHOT = """top - 18:28:16 up 14 days,  7:32,  1 user,  load average: 0.01, 0.02, 0.00
Tasks: 143 total,   1 running, 142 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id
MiB Mem :   1612.0 total,    100.1 free,    678.2 used
MiB Swap:   2048.0 total,   1554.3 free,    493.7 used.

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  168140  12976   8444 S   0.0   0.8   0:03.11 systemd
  155645 mysql     20   0 1240548  57400   4624 S   0.5   3.4  12:31.02 mysqld
  1123858 65532     20   0   64056  64056   3020 S  12.3   3.8   1:20.11 magpie-bun
"""


def test_top_parser_keeps_only_the_last_snapshot():
    stale = TOP_SNAPSHOT.replace("155645 mysql", "999999 ghost")
    rows = _parse_top_rows(stale + TOP_SNAPSHOT)
    assert 999999 not in {row["pid"] for row in rows}
    mysql = next(row for row in rows if row["pid"] == 155645)
    assert mysql["user"] == "mysql"
    assert mysql["cpu_percent"] == 0.5
    assert mysql["mem_percent"] == 3.4
    assert mysql["rss_bytes"] == 57400 * 1024
    assert mysql["command"] == "mysqld"
    assert rows[0]["command"] == "systemd"


def test_top_parser_keeps_arguments_with_spaces():
    text = TOP_SNAPSHOT.replace("mysqld", "/usr/bin/python3 -m http.server")
    python_row = next(row for row in _parse_top_rows(text) if row["pid"] == 155645)
    assert python_row["command"] == "/usr/bin/python3 -m http.server"


def test_top_parser_gives_up_on_unknown_layouts():
    assert _parse_top_rows("busybox top\n  1 root 0 0 0 S 0 0") == []


def test_ps_rows_keep_the_printed_order():
    text = """    PID USER     %CPU %MEM   RSS COMMAND
      1 root      0.0  0.8 12976 systemd
  155645 mysql     0.5  3.4 57400 mysqld
"""
    rows = _parse_ps_rows(text)
    assert [row["pid"] for row in rows] == [1, 155645]
    assert rows[1]["rss_bytes"] == 57400 * 1024
    assert rows[1]["command"] == "mysqld"


def test_helper_commands_are_recognised():
    assert _is_helper_command("ps -eo pid,user,pcpu,pmem,rss,args --sort=-pcpu")
    assert _is_helper_command("ss -lntup")
    assert _is_helper_command("top")
    assert _is_helper_command("/bin/bash -c setsid sh -c 'top -b -n2' & echo $! > /tmp/.ssh-mcp-abc.pgid")
    assert not _is_helper_command("mysqld --defaults-file=/etc/mysql/my.cnf")


SS_PORTS = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1080982,fd=5),("nginx",pid=1080980,fd=5))
tcp   LISTEN 0      511             [::]:80           [::]:*    users:(("nginx",pid=1080982,fd=6))
tcp   LISTEN 0      4096       127.0.0.1:3306      0.0.0.0:*    users:(("mysqld",pid=155645,fd=23))
udp   UNCONN 0      0          127.0.0.54:53          0.0.0.0:*   users:(("systemd-resolve",pid=1080973,fd=16))
"""


def test_ports_merge_the_ipv4_and_ipv6_listener():
    ports = _parse_ports(SS_PORTS)
    port_80 = next(item for item in ports if item["port"] == 80)
    assert port_80["addresses"] == ["0.0.0.0", "[::]"]
    assert port_80["public"] is True
    assert port_80["process"] == "nginx(1080982), nginx(1080980)"
    assert port_80["processes"] == [
        {"name": "nginx", "pid": 1080982},
        {"name": "nginx", "pid": 1080980},
    ]


def test_ports_mark_loopback_as_not_public():
    ports = _parse_ports(SS_PORTS)
    mysql = next(item for item in ports if item["port"] == 3306)
    assert mysql["public"] is False
    assert mysql["address"] == "127.0.0.1"
    assert mysql["process"] == "mysqld(155645)"


def test_ports_support_a_port_filter():
    ports = _parse_ports(SS_PORTS, 3306)
    assert [item["port"] for item in ports] == [3306]


def test_parse_df_converts_blocks_to_bytes():
    text = """Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/vda3         41882940 12063912  27883292      31% /
"""
    rows = _parse_df(text)
    assert rows[0]["size_bytes"] == 41882940 * 1024
    assert rows[0]["used_bytes"] == 12063912 * 1024
    assert rows[0]["use_percent"] == 31
    assert rows[0]["mount"] == "/"


def test_certificates_report_days_left():
    soon = datetime.now(timezone.utc) + timedelta(days=10)
    text = f"a.example|{soon.strftime('%b %d %H:%M:%S %Y GMT')}" + "\n" + "b.example|garbage"
    certificates = _parse_certificates(text)
    assert [item["domain"] for item in certificates] == ["a.example"]
    assert 9 <= certificates[0]["days_left"] <= 10


def test_containers_flag_unhealthy_status():
    text = "\n".join(
        [
            "\t".join(["web", "nginx:latest", "Up 2 weeks (healthy)"]),
            "\t".join(["db", "postgres:16", "Up 3 hours (unhealthy)"]),
        ]
    )
    containers = _parse_containers(text)
    assert containers[0]["healthy"] is True
    assert containers[1]["healthy"] is False


def test_health_warnings_name_the_problems():
    summary = {
        "disk": {"worst": {"mount": "/", "use_percent": 91}},
        "resources": {
            "memory": {"total_bytes": 1000, "available_bytes": 50},
            "swap": {"total_bytes": 100, "used_bytes": 90},
            "load": [4.0, 1.0, 0.5],
            "cpu_count": 2,
        },
        "services": {"failed": ["nginx"]},
        "certificates": [{"domain": "x.example", "days_left": 3}],
        "containers": [{"name": "db", "status": "Up 3 hours (unhealthy)", "healthy": False}],
    }
    warnings = _health_warnings(summary)
    assert len(warnings) == 7
    assert any("91%" in item for item in warnings)
    assert any("交换分区" in item for item in warnings)
    assert any("nginx" in item for item in warnings)
    assert any("x.example" in item for item in warnings)


def test_health_warnings_silent_on_a_healthy_host():
    summary = {
        "disk": {"worst": {"mount": "/", "use_percent": 31}},
        "resources": {
            "memory": {"total_bytes": 1000, "available_bytes": 600},
            "swap": {"total_bytes": 100, "used_bytes": 0},
            "load": [0.1],
            "cpu_count": 4,
        },
        "services": {"failed": []},
        "certificates": [],
        "containers": [],
    }
    assert _health_warnings(summary) == []
