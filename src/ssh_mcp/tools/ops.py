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

import asyncio
import logging
import re
import shlex
from datetime import datetime, timezone
from typing import Annotated

from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.errors import ToolFailure
from ssh_mcp.ssh.commands import CommandResult, CommandRunner
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)

# One round trip for everything a host summary needs.
_OVERVIEW_SCRIPT = (
    "echo '--- host ---'; hostname; uname -sr; "
    "cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)=' ; "
    "echo '--- uptime ---'; cat /proc/uptime 2>/dev/null; uptime; "
    "echo '--- mem ---'; free -b 2>/dev/null; "
    "echo '--- cpu ---'; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo"
)

# Certificates only when certbot actually left something behind.
_CERT_SCRIPT = (
    "if [ -d /etc/letsencrypt/live ]; then "
    'for d in /etc/letsencrypt/live/*/; do [ -f "$d/fullchain.pem" ] || continue; '
    'n=$(basename "$d"); '
    'e=$(openssl x509 -enddate -noout -in "$d/fullchain.pem" 2>/dev/null | cut -d= -f2); '
    '[ -n "$e" ] && echo "$n|$e"; '
    "done; fi"
)

# Addresses that mean "every interface": reachable from outside if the firewall
# allows it. Loopback and docker bridges are not.
_PUBLIC_BINDINGS = {"0.0.0.0", "*", "[::]", "::"}

# Order of the parallel exec requests in ``get_health_summary``; also the section
# names reported as ``degraded`` when one of them fails.
_HEALTH_SECTIONS = ("overview", "disk", "services", "containers", "certificates")

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
                rows = _parse_df(result.stdout)
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
            """一次拿到主机名、内核、发行版、运行时长、负载、内存、交换与 CPU 核数。
            返回 {hostname, kernel, os, uptime_seconds, load, memory, swap, cpu_count, logged_in_users}。
            Use when 需要先了解一台机器的基本情况，替代 uname/free/uptime 等多条命令。
            """
            try:
                result = await self._runner.run(
                    connection_handle, _OVERVIEW_SCRIPT, timeout_seconds=20
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
                str | None,
                Field(description="只保留命令含该子串的进程；匹配的是完整命令行，可以写成 'java -jar app.jar'。"),
            ] = None,
            include_helpers: Annotated[
                bool,
                Field(
                    description="为 true 时保留本服务器自己的 ps/ss/top 辅助进程；默认过滤掉，避免占满结果。"
                ),
            ] = False,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """列出占用最高的进程；CPU 用两次 top 采样算瞬时值，不是 ps 的启动以来均值。
            返回 {processes: [{pid, user, cpu_percent, mem_percent, rss_bytes, command}], total, source}。
            Use when 需要定位 CPU/内存占用高的进程；不要自己拼 top/ps 管道。
            """
            try:
                if sort_by not in {"cpu", "mem", "pid"}:
                    raise ToolFailure(
                        "invalid_argument",
                        stage="validate",
                        hint="sort_by 只能是 cpu、mem 或 pid。",
                        retryable=False,
                    )
                count = max(1, min(int(limit), 200))
                rows: list[dict] = []
                source = "ps"
                if sort_by == "cpu":
                    # ``ps`` reports %CPU averaged over the whole lifetime, so a
                    # daemon that is busy right now still reads 0.0. Two top
                    # iterations give the delta over the sample window. The
                    # previous implementation also piped ``--sort=-pcpu`` into
                    # ``tail`` and reversed it, returning the *coldest* rows.
                    # ``-c`` prints the full command line. Without it the
                    # COMMAND column holds the bare program name, so a filter
                    # such as "java -jar app.jar" matched nothing here while
                    # the ``ps ... args`` path below matched the same process.
                    # The width is attached (``-w512``) because procps-ng takes
                    # an *optional* argument: ``-w 512`` would leave ``512`` as
                    # a stray argv and top would exit without printing anything.
                    sampled = await self._runner.run(
                        connection_handle,
                        "top -b -c -n2 -d 0.5 -w512 2>/dev/null",
                        timeout_seconds=20,
                    )
                    if sampled.truncated:
                        # ``drain`` keeps the *first* bytes, so a truncated
                        # sample has lost the second iteration -- the one that
                        # carries the delta. Parsing what is left would report
                        # CPU-since-boot as if it were instantaneous.
                        logger.debug("top sample truncated; falling back to ps")
                        rows = []
                    else:
                        rows = _parse_top_rows(sampled.stdout)
                    if rows:
                        source = "top"
                if not rows:
                    flag = {"cpu": "-pcpu", "mem": "-pmem", "pid": "-pid"}[sort_by]
                    # Over-fetch so helper processes can be filtered without
                    # shrinking the result below `limit`.
                    fetch = min(500, max(count * 5, 20))
                    listed = await self._runner.run(
                        connection_handle,
                        f"ps -eo pid,user,pcpu,pmem,rss,args --sort={flag} | head -n {fetch + 1}",
                        timeout_seconds=20,
                    )
                    rows = _parse_ps_rows(listed.stdout)
                if name_filter:
                    needle = name_filter.lower()
                    rows = [row for row in rows if needle in row["command"].lower()]
                elif not include_helpers:
                    rows = [row for row in rows if not _is_helper_command(row["command"])]
                return tool_ok(
                    {"processes": rows[:count], "total": len(rows), "source": source}
                )
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
            """列出本机正在监听的 TCP/UDP 端口及其进程；同一端口的 IPv4/IPv6 监听合并成一条。
            返回 {ports: [{protocol, port, address, addresses, public, process, processes}], total, public_total}。
            public=true 表示绑定在 0.0.0.0/*/[::]，是否真的能从公网访问还要看防火墙与安全组。
            Use when 需要确认某个服务是否在监听、端口被谁占用，替代 ss/netstat 手写管道。
            """
            try:
                result = await self._runner.run(
                    connection_handle,
                    "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null",
                    timeout_seconds=20,
                )
                ports = _parse_ports(result.stdout, port_filter)
                return tool_ok(
                    {
                        "ports": ports,
                        "total": len(ports),
                        "public_total": sum(1 for item in ports if item["public"]),
                    }
                )
            except ToolFailure as exc:
                return tool_err(exc)

        # -- whole-host health ------------------------------------------------

        @app.tool(
            name="get_health_summary",
            title="查看主机健康总览",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def get_health_summary(
            include_certificates: Annotated[
                bool,
                Field(description="为 true 时附带 /etc/letsencrypt 下证书的剩余天数（目录与 openssl 都存在时才有效）。"),
            ] = True,
            connection_handle: Handle = None,
        ) -> CallToolResult:
            """一次拿到主机状态：系统概览、内存/交换、磁盘、失败服务、Docker 容器、证书到期与告警。
            返回 {host, resources, disk, services, containers, certificates, degraded, warnings}。
            degraded 列出没能取到的部分（例如 docker 未安装或并发通道被拒），其余部分仍会返回。
            Use when 需要一眼判断机器是否健康，替代 overview + disk + services + docker 的多次调用。
            """
            try:
                jobs = [
                    self._runner.run(connection_handle, _OVERVIEW_SCRIPT, timeout_seconds=20),
                    self._runner.run(connection_handle, "df -P -k", timeout_seconds=20),
                    self._runner.run(
                        connection_handle,
                        "systemctl list-units --type=service --state=failed "
                        "--no-pager --no-legend --plain",
                        timeout_seconds=25,
                    ),
                    self._runner.run(
                        connection_handle,
                        "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Status}}' 2>/dev/null || true",
                        timeout_seconds=20,
                    ),
                ]
                if include_certificates:
                    jobs.append(self._runner.run(connection_handle, _CERT_SCRIPT, timeout_seconds=25))
                # ``return_exceptions``: one dead channel (``MaxSessions 1``, a
                # handshake blip) must not cost the sections that did answer.
                raw = await asyncio.gather(*jobs, return_exceptions=True)
                results: list[CommandResult | None] = []
                degraded: list[str] = []
                for name, item in zip(_HEALTH_SECTIONS, raw):
                    if isinstance(item, ToolFailure):
                        logger.warning("health summary: %s unavailable (%s)", name, item.error)
                        degraded.append(name)
                        results.append(None)
                    elif isinstance(item, BaseException):
                        raise item
                    else:
                        results.append(item)
                overview, disk, failed, containers, *rest = results

                overview_payload = _parse_overview(overview.stdout) if overview else {}
                filesystems = _parse_df(disk.stdout) if disk else []
                worst = max(filesystems, key=lambda row: row["use_percent"], default=None)
                failed_units = _parse_failed_units(failed.stdout) if failed else []
                summary = {
                    "host": {
                        key: overview_payload.get(key)
                        for key in ("hostname", "os", "os_version", "kernel", "uptime_seconds")
                    },
                    "resources": {
                        "load": overview_payload.get("load"),
                        "cpu_count": overview_payload.get("cpu_count"),
                        "memory": overview_payload.get("memory"),
                        "swap": overview_payload.get("swap"),
                    },
                    "disk": {"worst": worst, "filesystems": filesystems},
                    "services": {"failed_count": len(failed_units), "failed": failed_units},
                    "containers": _parse_containers(containers.stdout) if containers else [],
                    "certificates": _parse_certificates(rest[0].stdout) if rest and rest[0] else [],
                    "degraded": degraded,
                    "warnings": [],
                }
                summary["warnings"] = _health_warnings(summary)
                return tool_ok(summary)
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


_SIZE_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def _parse_size(value: str | None, *, bare_unit: str = "k") -> int | None:
    """Parse ``1234`` / ``12m`` / ``1.5g`` into bytes.

    ``top`` prints a bare RES number in KiB, so the default unit is ``k``; the
    suffix wins when one is present (``1.5g``).
    """
    if not value:
        return None
    text = value.strip().lower()
    suffix = text[-1] if text[-1].isalpha() else ""
    number = text[:-1] if suffix else text
    unit = _SIZE_UNITS[suffix] if suffix else _SIZE_UNITS[bare_unit]
    try:
        return int(float(number) * unit)
    except (TypeError, ValueError):
        return None


def _parse_df(text: str) -> list[dict]:
    """Parse ``df -P -k`` rows into byte counts."""
    rows = []
    for line in text.splitlines()[1:]:
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
    return rows


def _parse_ps_rows(text: str) -> list[dict]:
    """Parse ``ps -eo pid,user,pcpu,pmem,rss,args`` output in the printed order.

    ``ps --sort=-pcpu`` already prints the heaviest first; earlier code piped it
    into ``tail`` and reversed the rows, which returned the *coldest* processes.
    """
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6 or not parts[0].isdigit():
            continue
        rows.append(
            {
                "pid": int(parts[0]),
                "user": parts[1],
                "cpu_percent": _float_or_none(parts[2]),
                "mem_percent": _float_or_none(parts[3]),
                "rss_bytes": int(parts[4]) * 1024 if parts[4].isdigit() else None,
                "command": parts[5],
            }
        )
    return rows


def _parse_top_rows(text: str) -> list[dict]:
    """Parse the final snapshot of a ``top -b -c -n2`` run.

    Only the last iteration matters: the first one reports CPU since boot, so
    its numbers are just ``ps`` again. Returns an empty list on layouts this
    parser does not recognise, which sends the caller to the ``ps`` fallback.
    """
    blocks = re.split(r"^top - ", text, flags=re.MULTILINE)
    if len(blocks) < 2:
        return []
    lines = blocks[-1].splitlines()
    header_index = None
    for index, line in enumerate(lines):
        stripped = line.split()
        if stripped and stripped[0] == "PID" and "%CPU" in stripped:
            header_index = index
            break
    if header_index is None:
        return []
    header = lines[header_index].split()
    columns = {name: index for index, name in enumerate(header)}
    if not {"PID", "USER", "%CPU", "%MEM", "RES", "COMMAND"} <= set(columns):
        return []
    rows = []
    for line in lines[header_index + 1 :]:
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        if len(parts) <= columns["COMMAND"]:
            continue
        rows.append(
            {
                "pid": int(parts[0]),
                "user": parts[columns["USER"]],
                "cpu_percent": _float_or_none(parts[columns["%CPU"]]),
                "mem_percent": _float_or_none(parts[columns["%MEM"]]),
                "rss_bytes": _parse_size(parts[columns["RES"]]),
                "command": " ".join(parts[columns["COMMAND"] :]),
            }
        )
    return rows


# Command lines this server itself prints while answering a call. Without this
# filter the caller reads its own ``ps``/``ss``/``top`` helpers as "busy".
_HELPER_MARKERS = (
    "ps -eo",
    "ss -lntup",
    "ss -l",
    "top -b",
    ".ssh-mcp-",
    "systemctl list-units",
    "df -P -k",
)


def _is_helper_command(command: str) -> bool:
    text = command.strip()
    # ``top`` itself shows up as a bare program name: its own arguments are not
    # in the COMMAND column, so the marker check below cannot see them.
    if text.rsplit("/", 1)[-1] in {"top", "ps", "ss", "htop"}:
        return True
    return any(marker in text for marker in _HELPER_MARKERS)


def _parse_ss_processes(raw: str) -> list[dict]:
    """Turn ``users:(("sshd",pid=7,fd=3),...)`` into ``[{name, pid}]``."""
    if not raw:
        return []
    found: list[dict] = []
    for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', raw):
        entry = {"name": name, "pid": int(pid)}
        if entry not in found:
            found.append(entry)
    return found


def _parse_ports(text: str, port_filter: int | None = None) -> list[dict]:
    """Group ``ss -lntup`` lines by port so the IPv4/IPv6 pair is one entry."""
    grouped: dict[tuple[str, int], dict] = {}
    for line in text.splitlines():
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
        protocol = parts[0].lower()
        entry = grouped.setdefault(
            (protocol, port),
            {
                "protocol": protocol,
                "port": port,
                "address": address or "*",
                "addresses": [],
                "public": False,
                "processes": [],
            },
        )
        address = address or "*"
        if address not in entry["addresses"]:
            entry["addresses"].append(address)
        if address in _PUBLIC_BINDINGS:
            entry["public"] = True
        for item in _parse_ss_processes(parts[6] if len(parts) > 6 else ""):
            if item not in entry["processes"]:
                entry["processes"].append(item)
    ports = sorted(grouped.values(), key=lambda item: (item["port"], item["protocol"]))
    for entry in ports:
        entry["process"] = (
            ", ".join(
                f"{item['name']}({item['pid']})" if item["pid"] else item["name"]
                for item in entry["processes"]
            )
            or None
        )
    return ports


def _parse_failed_units(text: str) -> list[str]:
    units = []
    for line in text.splitlines():
        parts = line.split(None, 1)
        if parts and parts[0].endswith(".service"):
            units.append(parts[0].removesuffix(".service"))
    return units


def _parse_containers(text: str) -> list[dict]:
    containers = []
    for line in text.splitlines():
        # Docker's CLI expands ``\t`` in ``--format``; a build that hands the two
        # characters through literally would otherwise leave this list empty.
        parts = line.replace("\\t", "\t").split("\t")
        if len(parts) < 3 or not parts[0].strip():
            continue
        status = parts[2].strip()
        containers.append(
            {
                "name": parts[0].strip(),
                "image": parts[1].strip(),
                "status": status,
                "healthy": "unhealthy" not in status.lower()
                and "restarting" not in status.lower()
                and "exited" not in status.lower(),
            }
        )
    return containers


def _parse_certificates(text: str) -> list[dict]:
    """``openssl -enddate`` (``Jan 29 01:44:47 2027 GMT``) into days left."""
    now = datetime.now(timezone.utc)
    certificates = []
    for line in text.splitlines():
        domain, _, end = line.partition("|")
        if not domain.strip() or not end.strip():
            continue
        try:
            expires = datetime.strptime(end.strip(), "%b %d %H:%M:%S %Y GMT").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        certificates.append(
            {
                "domain": domain.strip(),
                "expires_at": expires.isoformat(),
                "days_left": (expires - now).days,
            }
        )
    certificates.sort(key=lambda item: item["days_left"])
    return certificates


def _health_warnings(summary: dict) -> list[str]:
    """Name what is actually worth looking at; an empty list means "nothing"."""
    warnings: list[str] = []
    worst = (summary.get("disk") or {}).get("worst")
    if worst and worst["use_percent"] >= 85:
        warnings.append(f"磁盘 {worst['mount']} 已用 {worst['use_percent']}%")

    resources = summary.get("resources") or {}
    memory = resources.get("memory") or {}
    total = memory.get("total_bytes") or 0
    available = memory.get("available_bytes")
    if total and available is not None and available * 100 // total < 10:
        warnings.append(f"可用内存仅 {available // (1024 * 1024)} MiB")

    swap = resources.get("swap") or {}
    swap_total = swap.get("total_bytes") or 0
    swap_used = swap.get("used_bytes") or 0
    if swap_total and swap_used * 100 // swap_total > 50:
        warnings.append(f"交换分区已用 {swap_used * 100 // swap_total}%")

    load = resources.get("load") or []
    cpu_count = resources.get("cpu_count")
    # ``_parse_overview`` keeps ``None`` for entries it could not read (BSD's
    # ``load averages: 1.2 1.3 1.4`` line), so guard before comparing.
    if load and load[0] is not None and cpu_count and load[0] > cpu_count * 1.5:
        warnings.append(f"1 分钟负载 {load[0]} 高于 {cpu_count} 核")

    failed = (summary.get("services") or {}).get("failed") or []
    if failed:
        warnings.append(f"{len(failed)} 个服务处于 failed：{'、'.join(failed[:5])}")

    for certificate in summary.get("certificates") or []:
        if certificate["days_left"] <= 14:
            warnings.append(
                f"证书 {certificate['domain']} 将在 {certificate['days_left']} 天后到期"
            )

    for container in summary.get("containers") or []:
        if not container["healthy"]:
            warnings.append(f"容器 {container['name']} 状态异常：{container['status']}")
    return warnings


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
        if len(mem_lines) >= 3:
            swap = mem_lines[2].split()
            if len(swap) >= 3:
                result["swap"] = {
                    "total_bytes": _int_or_none(swap[1]),
                    "used_bytes": _int_or_none(swap[2]),
                    "free_bytes": _int_or_none(swap[3]) if len(swap) > 3 else None,
                }

    cpu_lines = sections.get("cpu", [])
    if cpu_lines:
        result["cpu_count"] = _int_or_none(cpu_lines[-1])
    return result
