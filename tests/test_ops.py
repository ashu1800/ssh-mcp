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
from mcp.server import MCPServer

from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.errors import ToolFailure
from ssh_mcp.server import AppState, create_server
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.commands import CommandResult
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from ssh_mcp.ssh.pool import ConnectionPool

from ssh_mcp.tools.ops import (
    OpsTools,
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


class _CannedRunner:
    """Returns canned stdout for every command, recording what was asked."""

    def __init__(self, stdout: str, *, respond=None, truncated: bool = False, fail_for=None) -> None:
        self.stdout = stdout
        self.respond = respond
        self.truncated = truncated
        self.fail_for = fail_for
        self.commands: list[str] = []

    async def run(self, handle, command, *, timeout_seconds=None, **_kwargs) -> CommandResult:
        self.commands.append(command)
        if self.fail_for is not None and self.fail_for(command):
            raise ToolFailure(
                "connection_lost", stage="execute", hint="stub channel refused", retryable=True
            )
        stdout = self.respond(command) if self.respond is not None else self.stdout
        return CommandResult(
            stdout=stdout,
            stderr="",
            exit_code=0,
            exit_signal=None,
            truncated=self.truncated,
            total_stdout_bytes=len(stdout),
            total_stderr_bytes=0,
            duration_seconds=0.0,
        )


@pytest.mark.asyncio
async def test_list_processes_filters_on_the_full_command_line():
    """`name_filter` must see arguments, not just the bare program name.

    The CPU path samples ``top``; without ``-c`` that output has the program
    name only, so a multi-token filter matched nothing while the same call with
    ``sort_by="mem"`` (which goes through ``ps ... args``) matched.
    """
    with_arguments = TOP_SNAPSHOT.replace("mysqld", "/usr/bin/python3 -m http.server 8080")

    def sample(command: str) -> str:
        # ``top`` prints the bare program name unless it is given ``-c``.
        return with_arguments if "-c" in command.split() else TOP_SNAPSHOT

    server = MCPServer("stub")
    runner = _CannedRunner(with_arguments, respond=sample)
    OpsTools(server, None, runner)

    result = await server.call_tool("list_processes", {"name_filter": "http.server 8080"})
    payload = result.structured_content

    assert payload["source"] == "top"
    assert [row["pid"] for row in payload["processes"]] == [155645]
    assert payload["processes"][0]["command"] == "/usr/bin/python3 -m http.server 8080"
    # Whatever the sample command looks like, it has to ask for full command lines.
    assert "-c" in runner.commands[0].split()


def test_top_sample_command_is_still_recognised_as_a_helper():
    # ``-c`` puts the arguments into COMMAND, so the helper markers see them.
    assert _is_helper_command("top -b -c -n2 -d 0.5 -w512")


@pytest.mark.asyncio
async def test_list_processes_ignores_a_truncated_top_sample():
    """A capped sample has lost the second iteration, i.e. the delta.

    Parsing what is left would report CPU-since-boot as if it were the current
    load, so the tool must fall back to ``ps`` instead.
    """
    first_iteration_only = TOP_SNAPSHOT
    ps_rows = "    PID USER     %CPU %MEM   RSS COMMAND\n  155645 mysql     0.5  3.4 57400 mysqld\n"

    def respond(command: str) -> str:
        return ps_rows if command.startswith("ps -eo") else first_iteration_only

    server = MCPServer("stub")
    runner = _CannedRunner(first_iteration_only, respond=respond, truncated=True)
    OpsTools(server, None, runner)

    result = await server.call_tool("list_processes", {"sort_by": "cpu"})
    payload = result.structured_content

    assert payload["source"] == "ps"
    assert [row["pid"] for row in payload["processes"]] == [155645]


@pytest.mark.asyncio
async def test_list_processes_sorts_pid_highest_first():
    """``head`` keeps the first rows, so the flag has to sort by descending pid."""
    server = MCPServer("stub")
    runner = _CannedRunner("")
    OpsTools(server, None, runner)

    await server.call_tool("list_processes", {"sort_by": "pid"})

    assert "--sort=-pid" in runner.commands[0]


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


def test_health_warnings_survive_an_unreadable_load_line():
    # BSD/macOS ``uptime`` does not print comma-separated floats, so the parser
    # keeps ``None``; comparing it to the CPU count used to raise TypeError and
    # take the whole summary down with it.
    summary = {"resources": {"load": [None, None, None], "cpu_count": 4}}
    assert _health_warnings(summary) == []


HEALTH_DF = """Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/sda1          1000000  910000     90000       91% /
"""


@pytest.mark.asyncio
async def test_health_summary_survives_one_dead_channel():
    """`MaxSessions 1` refuses the parallel execs; the rest must still answer."""

    def respond(command: str) -> str:
        if command.startswith("df -P -k"):
            return HEALTH_DF
        if command.startswith("systemctl list-units"):
            return ""
        if command.startswith("if [ -d /etc/letsencrypt"):
            return ""
        return SWAP_OVERVIEW

    server = MCPServer("stub")
    runner = _CannedRunner(SWAP_OVERVIEW, respond=respond, fail_for=lambda c: c.startswith("docker ps"))
    OpsTools(server, None, runner)

    result = await server.call_tool("get_health_summary", {})
    payload = result.structured_content

    assert result.is_error is False
    assert payload["degraded"] == ["containers"]
    assert payload["host"]["hostname"] == "box"
    assert payload["disk"]["worst"]["use_percent"] == 91
    assert payload["services"]["failed_count"] == 0
    assert any("91%" in item for item in payload["warnings"])


@pytest.mark.asyncio
async def test_health_summary_degrades_every_failing_section():
    server = MCPServer("stub")
    runner = _CannedRunner("", fail_for=lambda command: True)
    OpsTools(server, None, runner)

    result = await server.call_tool("get_health_summary", {})

    payload = result.structured_content
    assert result.is_error is False
    assert payload["degraded"] == ["overview", "disk", "services", "containers", "certificates"]
    assert payload["disk"]["worst"] is None
    assert payload["warnings"] == []


def test_containers_accept_a_literal_backslash_t():
    # ``docker --format`` normally expands ``\t``; when it does not, the parser
    # must not silently report "no containers".
    text = "web\tnginx:1.25\tUp 3 hours\ncache\tredis:7\tUp 3 hours (healthy)\n"
    for variant in (text, text.replace("\t", "\t")):
        assert [row["name"] for row in _parse_containers(variant)] == ["web", "cache"]
