"""Semantic operations tools: inspection tasks the model should not hand-roll.

Every one of these exists because the equivalent shell one-liner was a trap:
``top`` needs ``-b -n1``, ``systemctl`` output needs ``--no-pager``, and a
service inspector that runs ``systemctl status`` opens a pager and hangs.
Encoding the command here means the model asks for what it wants ("is nginx
running?") instead of assembling a pipeline whose quoting and flags it has to
get exactly right -- which is how the interactive-command guard used to reject
perfectly good inspection commands.

They all go through :class:`~ssh_mcp.ssh.commands.CommandRunner`, so they inherit
the same timeout, output cap and process-group termination as ``execute_command``.
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import Annotated

from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.commands import CommandRunner
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)

Handle = Annotated[
    str | None,
    Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
]


def _parse_key_values(text: str, *, separator: str = "=") -> dict[str, str]:
    """Turn ``KEY=VALUE`` lines into a dict, ignoring anything malformed."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or separator not in line:
            continue
        key, _, value = line.partition(separator)
        out[key.strip()] = value.strip()
    return out


class OpsTools:
    """Registers the semantic inspection tools."""

    def __init__(self, app, pool: ConnectionPool, runner: CommandRunner) -> None:
        self._pool = pool
        self._runner = runner

        # -- services ---------------------------------------------------------

        @app.tool(
            name="get_service_status",
            title="查看 systemd 服务状态",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def get_service_status(
            name: Annotated[str, Field(description="服务名，不带 .service 后缀也可以，例如 nginx。")],
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """查询单个 systemd 服务的运行状态、开机自启、主进程与最近日志行。
            返回 {name, load_state, active_state, sub_state, unit_file_state, main_pid, restarts, memory_bytes, recent_log}。
            Use when 需要判断某个服务是否在运行、是否开机自启，或需要它最近的报错。
            """
            try:
                unit = _unit_name(name)
                result = await self._runner.run(
                    connection_handle,
                    f"systemctl show {shlex.quote(unit)} "
                    "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,"
                    "ExecMainStartTimestamp,MemoryCurrent,ActiveEnterTimestamp,NRestarts "
                    "--no-pager",
                    timeout_seconds=20,
                )
                if result.exit_code != 0:
                    raise ToolFailure(
                        "service_not_found",
                        stage="execute",
                        hint=f"没有找到 systemd 单元 {unit}。可先用 list_services 查看已安装的服务。",
                        retryable=False,
                        unit=unit,
                        detail=result.stderr.strip()[:500],
                    )
                props = _parse_key_values(result.stdout)
                log = await self._runner.run(
                    connection_handle,
                    f"journalctl -u {shlex.quote(unit)} --no-pager -n 20 -o cat",
                    timeout_seconds=20,
                )
                return tool_ok(
                    {
                        "name": unit,
                        "load_state": props.get("LoadState"),
                        "active_state": props.get("ActiveState"),
                        "sub_state": props.get("SubState"),
                        "unit_file_state": props.get("UnitFileState"),
                        "main_pid": _int_or_none(props.get("MainPID")),
                        "exec_main": props.get("ExecMainStartTimestamp"),
                        "since": props.get("ActiveEnterTimestamp"),
                        "restarts": _int_or_none(props.get("NRestarts")),
                        "memory_bytes": _int_or_none(props.get("MemoryCurrent")),
                        "recent_log": log.stdout.strip().splitlines() if log.exit_code == 0 else [],
                    }
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="list_services",
            title="列出 systemd 服务",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def list_services(
            state: Annotated[
                str, Field(description="筛选状态：running（默认）、failed、或 all。")
            ] = "running",
            name_filter: Annotated[
                str | None, Field(description="只保留名称包含该子串的服务，例如 nginx。")
            ] = None,
            limit: Annotated[int, Field(description="最多返回条数，默认 100，上限 1000。")] = 100,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """列出 systemd 服务及其状态，按运行状态筛选。
            返回 {services: [{name, load, active, sub, description}], total, truncated}。
            Use when 需要了解机器上跑了哪些服务，或找出失败的服务（state=failed）。
            """
            try:
                if state not in {"running", "failed", "all"}:
                    raise ToolFailure(
                        "invalid_argument",
                        stage="validate",
                        hint="state 只能是 running、failed 或 all。",
                        retryable=False,
                    )
                cmd = "systemctl list-units --type=service --all --no-pager --no-legend --plain"
                if state != "all":
                    cmd += f" --state={state}"
                result = await self._runner.run(connection_handle, cmd, timeout_seconds=25)
                services = []
                for line in result.stdout.splitlines():
                    parts = line.split(None, 4)
                    if len(parts) < 4 or not parts[0].endswith(".service"):
                        continue
                    entry = {
                        "name": parts[0].removesuffix(".service"),
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4].strip() if len(parts) > 4 else "",
                    }
                    if name_filter and name_filter.lower() not in entry["name"].lower():
                        continue
                    services.append(entry)
                cap = max(1, min(int(limit), 1000))
                return tool_ok(
                    {"services": services[:cap], "total": len(services), "truncated": len(services) > cap}
                )
            except ToolFailure as exc:
                return tool_err(exc)

        # -- logs -------------------------------------------------------------

        @app.tool(
            name="tail_log",
            title="查看日志尾部",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def tail_log(
            lines: Annotated[int, Field(description="返回最后多少行，默认 100，上限 5000。")] = 100,
            unit: Annotated[
                str | None, Field(description="systemd 单元名，走 journalctl -u。给了就不再读文件。")
            ] = None,
            path: Annotated[
                str | None, Field(description="日志文件绝对路径，走 tail -n（不是 -f，不会跟随）。")
            ] = None,
            since: Annotated[
                str | None,
                Field(description="journalctl 时间过滤，如 '1 hour ago'、'2026-10-21 10:00'。"),
            ] = None,
            priority: Annotated[
                str | None, Field(description="journalctl 优先级过滤，如 err、warning。")
            ] = None,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """读取日志尾部，支持 systemd 单元或普通文件，永不跟随刷新（tail -f 会挂起）。
            返回 {source, lines: [...], truncated}。
            Use when 需要看服务报错或文件日志末尾。
            """
            try:
                if not unit and not path:
                    raise ToolFailure(
                        "invalid_argument",
                        stage="validate",
                        hint="unit 与 path 至少给一个：systemd 服务用 unit，普通日志文件用 path。",
                        retryable=False,
                    )
                count = max(1, min(int(lines), 5000))
                if unit:
                    target = _unit_name(unit)
                    cmd = ["journalctl", "-u", target, "--no-pager", "-n", str(count), "-o", "short-iso"]
                    if since:
                        cmd += ["--since", since]
                    if priority:
                        cmd += ["-p", priority]
                    source = f"journalctl:{target}"
                else:
                    cmd = ["tail", "-n", str(count), str(path)]
                    source = str(path)
                result = await self._runner.run(
                    connection_handle, " ".join(shlex.quote(part) for part in cmd), timeout_seconds=30
                )
                if result.exit_code != 0 and not result.stdout:
                    raise ToolFailure(
                        "log_unavailable",
                        stage="execute",
                        hint=f"无法读取日志：{result.stderr.strip()[:300]}",
                        retryable=False,
                        source=source,
                    )
                return tool_ok(
                    {"source": source, "lines": result.stdout.splitlines(), "truncated": result.truncated}
                )
            except ToolFailure as exc:
                return tool_err(exc)

        # -- disk / system ----------------------------------------------------

        @app.tool(
            name="get_disk_usage",
            title="查看磁盘占用",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def get_disk_usage(
            path: Annotated[
                str | None, Field(description="只看包含该路径的文件系统，例如 /var。默认列出全部。")
            ] = None,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """查看文件系统使用率，返回每块盘的容量、已用、可用与使用百分比。
            返回 {filesystems: [{filesystem, size_bytes, used_bytes, available_bytes, use_percent, mount}], total, warning}。
            Use when 需要判断磁盘是否将满，或定位哪个挂载点占用过高。
            """
            try:
                cmd = "df -P -k"
                if path:
                    cmd += f" {shlex.quote(path)}"
                result = await self._runner.run(connection_handle, cmd, timeout_seconds=20)
                if result.exit_code != 0:
                    raise ToolFailure(
                        "path_not_found",
                        stage="execute",
                        hint=f"df 无法统计 {path or '文件系统'}：{result.stderr.strip()[:300]}",
                        retryable=False,
                    )
                rows = []
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 6 or not parts[1].isdigit():
                        continue
                    rows.append(
                        {
                            "filesystem": parts[0],
                            "size_bytes": int(parts[1]) * 1024,
                            "used_bytes": int(parts[2]) * 1024,
                            "available_bytes": int(parts[3]) * 1024,
                            "use_percent": int(parts[4].rstrip("%")),
                            "mount": " ".join(parts[5:]),
                        }
                    )
                # Surface the worst mount so the model does not have to scan.
                worst = max(rows, key=lambda r: r["use_percent"], default=None)
                return tool_ok(
                    {
                        "filesystems": rows,
                        "total": len(rows),
                        "warning": (
                            f"{worst['mount']} 已使用 {worst['use_percent']}%"
                            if worst and worst["use_percent"] >= 85
                            else None
                        ),
                    }
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="get_system_overview",
            title="查看系统概览",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def get_system_overview(connection_handle: Handle = None) -> CallToolResult:
            """一次拿到主机名、内核、发行版、运行时长、负载、内存与 CPU 核数。
            返回 {hostname, kernel, os, uptime_seconds, load, memory, cpu_count, logged_in_users}。
            Use when 需要先了解一台机器的基本情况，替代 uname/free/uptime 等多条命令。
            """
            try:
                result = await self._runner.run(
                    connection_handle,
                    "echo '--- host ---'; hostname; uname -sr; "
                    "cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)=' ; "
                    "echo '--- uptime ---'; cat /proc/uptime 2>/dev/null; uptime; "
                    "echo '--- mem ---'; free -b 2>/dev/null; "
                    "echo '--- cpu ---'; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
                    timeout_seconds=20,
                )
                return tool_ok(_parse_overview(result.stdout))
            except ToolFailure as exc:
                return tool_err(exc)

        # -- processes --------------------------------------------------------

        @app.tool(
            name="list_processes",
            title="列出进程",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def list_processes(
            sort_by: Annotated[str, Field(description="排序字段：cpu（默认）、mem 或 pid。")] = "cpu",
            limit: Annotated[int, Field(description="返回条数，默认 20，上限 200。")] = 20,
            name_filter: Annotated[
                str | None, Field(description="只保留命令含该子串的进程。")
            ] = None,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """列出占用最高的进程（批处理模式，不是交互式 top）。
            返回 {processes: [{pid, user, cpu_percent, mem_percent, rss_bytes, command}], total}。
            Use when 需要定位 CPU/内存占用高的进程；不要用 top/htop。
            """
            try:
                key = {"cpu": "-pcpu", "mem": "-pmem", "pid": "pid"}.get(sort_by)
                if key is None:
                    raise ToolFailure(
                        "invalid_argument",
                        stage="validate",
                        hint="sort_by 只能是 cpu、mem 或 pid。",
                        retryable=False,
                    )
                count = max(1, min(int(limit), 200))
                result = await self._runner.run(
                    connection_handle,
                    f"ps -eo pid,user,pcpu,pmem,rss,args --sort={key} | tail -n {count + 1}",
                    timeout_seconds=20,
                )
                processes = []
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split(None, 5)
                    if len(parts) < 6 or not parts[0].isdigit():
                        continue
                    entry = {
                        "pid": int(parts[0]),
                        "user": parts[1],
                        "cpu_percent": _float_or_none(parts[2]),
                        "mem_percent": _float_or_none(parts[3]),
                        "rss_bytes": int(parts[4]) * 1024 if parts[4].isdigit() else None,
                        "command": parts[5],
                    }
                    if name_filter and name_filter.lower() not in entry["command"].lower():
                        continue
                    processes.append(entry)
                # ps --sort is ascending: the heaviest is last, so flip it.
                processes.reverse()
                return tool_ok({"processes": processes[:count], "total": len(processes)})
            except ToolFailure as exc:
                return tool_err(exc)

        # -- ports ------------------------------------------------------------

        @app.tool(
            name="list_listening_ports",
            title="列出监听端口",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def list_listening_ports(
            port_filter: Annotated[
                int | None, Field(description="只看某个端口，例如 443。")
            ] = None,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """列出本机正在监听的 TCP/UDP 端口及其进程。
            返回 {ports: [{protocol, address, port, process}], total}。
            Use when 需要确认某个服务是否在监听、端口被谁占用，替代 ss/netstat 手写管道。
            """
            try:
                result = await self._runner.run(
                    connection_handle,
                    "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null",
                    timeout_seconds=20,
                )
                ports = []
                for line in result.stdout.splitlines():
                    if not re.match(r"^(tcp|udp)", line, re.IGNORECASE):
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    address, _, port_text = parts[4].rpartition(":")
                    if not port_text.isdigit():
                        continue
                    port = int(port_text)
                    if port_filter is not None and port != port_filter:
                        continue
                    ports.append(
                        {
                            "protocol": parts[0].lower(),
                            "address": address or "*",
                            "port": port,
                            "process": parts[6] if len(parts) > 6 else None,
                        }
                    )
                ports.sort(key=lambda item: item["port"])
                return tool_ok({"ports": ports, "total": len(ports)})
            except ToolFailure as exc:
                return tool_err(exc)


# -- parsing helpers ----------------------------------------------------------


def _unit_name(name: str) -> str:
    """Normalise a unit name the way systemctl does, rejecting anything odd."""
    cleaned = name.strip()
    if not cleaned or "/" in cleaned or cleaned.startswith("-"):
        raise ToolFailure(
            "invalid_argument",
            stage="validate",
            hint=f"服务名不合法：{name!r}。只接受单元名，例如 nginx 或 nginx.service。",
            retryable=False,
        )
    return cleaned if cleaned.endswith(".service") else f"{cleaned}.service"


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _float_or_none(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _parse_overview(text: str) -> dict:
    """Turn the combined overview script output into structured fields."""
    sections: dict[str, list[str]] = {"host": [], "uptime": [], "mem": [], "cpu": []}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("--- ") and line.endswith(" ---"):
            current = line.strip("- ").strip()
            sections.setdefault(current, [])
            continue
        if current and line:
            sections[current].append(line)

    host_lines = sections.get("host", [])
    os_info = _parse_key_values("\n".join(host_lines))
    # ``/etc/os-release`` quotes its values (PRETTY_NAME="Ubuntu 24.04 LTS").
    def _unquote(value: str | None) -> str | None:
        if value and len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    result: dict = {
        "hostname": host_lines[0] if host_lines else None,
        "kernel": host_lines[1] if len(host_lines) > 1 else None,
        "os": _unquote(os_info.get("PRETTY_NAME")),
        "os_version": _unquote(os_info.get("VERSION_ID")),
    }

    uptime_lines = sections.get("uptime", [])
    if uptime_lines:
        first = uptime_lines[0].split()
        if first:
            result["uptime_seconds"] = _float_or_none(first[0])
        if len(uptime_lines) > 1:
            load_text = uptime_lines[1]
            match = re.search(r"load average[s]?:\s*([\d.,\s]+)", load_text)
            if match:
                result["load"] = [_float_or_none(v) for v in match.group(1).split(",")]
            match = re.search(r"(\d+) users?,", load_text)
            if match:
                result["logged_in_users"] = int(match.group(1))

    mem_lines = sections.get("mem", [])
    if len(mem_lines) >= 2:
        parts = mem_lines[1].split()
        if len(parts) >= 3:
            result["memory"] = {
                "total_bytes": _int_or_none(parts[1]),
                "used_bytes": _int_or_none(parts[2]),
                "available_bytes": _int_or_none(parts[6]) if len(parts) > 6 else None,
            }

    cpu_lines = sections.get("cpu", [])
    if cpu_lines:
        result["cpu_count"] = _int_or_none(cpu_lines[-1])
    return result
