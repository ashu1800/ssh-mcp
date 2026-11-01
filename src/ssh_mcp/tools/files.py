"""Remote file-system inspection and management tools."""

from __future__ import annotations

import asyncio
import logging
import posixpath
from typing import Annotated

import asyncssh
from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.errors import ConfirmationRequired, ToolFailure, validate_remote_path
from ssh_mcp.ssh.pool import ConnectionPool, borrow
from ssh_mcp.ssh.sftp_ops import replace_file
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)

# read_file refuses files above this size: a 100 MiB log would blow the 512 KiB
# tool-result budget anyway, and download_file is the right tool for those.
_READ_FILE_MAX_BYTES = 8 * 1024 * 1024
# write_file is for configs and scripts, not artifacts; the transfer engine
# owns anything bigger.
_WRITE_FILE_MAX_BYTES = 2 * 1024 * 1024
# search_files walks at most this many directories per call so a typo in
# ``path`` (say, /) cannot turn one tool call into a full-disk crawl.
_SEARCH_DIR_BUDGET = 500


def validate_remote_path(path: str, field: str = "path") -> str:
    if not path or not path.strip():
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能为空。", retryable=False)
    if "\x00" in path:
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能包含 NUL 字符。", retryable=False)
    return path


def _mode_string(permissions: int | None, file_type: str) -> str:
    perms = (permissions or 0) & 0o777
    return f"{file_type}{perms:04o}"


def _entry_type(attrs: asyncssh.SFTPAttrs) -> str:
    kind = attrs.type
    if kind == asyncssh.FILEXFER_TYPE_DIRECTORY:
        return "dir"
    if kind == asyncssh.FILEXFER_TYPE_SYMLINK:
        return "link"
    if kind == asyncssh.FILEXFER_TYPE_REGULAR:
        return "file"
    if kind == asyncssh.FILEXFER_TYPE_SPECIAL:
        return "special"
    return "unknown"


def _attrs_to_dict(path: str, attrs: asyncssh.SFTPAttrs) -> dict:
    kind = _entry_type(attrs)
    perms = (attrs.permissions or 0) & 0o777
    return {
        "name": posixpath.basename(path.rstrip("/")) or path,
        "path": path,
        "type": kind,
        "size": int(attrs.size or 0),
        "permissions": f"{perms:04o}",
        "mode": _mode_string(attrs.permissions, "d" if kind == "dir" else "l" if kind == "link" else "-"),
        "uid": attrs.uid,
        "gid": attrs.gid,
        "owner": attrs.owner,
        "group": attrs.group,
        "modified_at": int(attrs.mtime) if attrs.mtime else None,
    }


class FileTools:
    """Registers list_directory / stat_file / read_file / write_file / search_files / make_directory / remove_path / rename_path / change_permissions."""

    def __init__(self, app, pool: ConnectionPool, settings) -> None:
        self._pool = pool
        self._settings = settings

        # -- read / write ------------------------------------------------------

        @app.tool(
            name="read_file",
            title="读取远端文本文件",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def read_file(
            path: Annotated[str, Field(description="远端文件路径。")],
            offset: Annotated[int, Field(description="起始行号（1 起）。负数表示从文件末尾倒数，如 -50 = 最后 50 行。")] = 1,
            limit: Annotated[int, Field(description="最多返回的行数，默认 100，上限 2000。")] = 100,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """按行读取远端文本文件（支持负 offset 从末尾倒数），适合看配置与日志而不会撑爆上下文。
            返回 {path, total_lines, offset, lines: [{n, text}], truncated, size_bytes}；文件超过 8 MiB 时拒绝（用 download_file）。
            Use when 需要查看远端配置文件、日志或脚本内容；大文件先看尾部（offset=-50），需要更多再往前翻。
            """
            if limit < 1 or limit > 2000:
                return tool_err(
                    ToolFailure("invalid_argument", stage="validate", hint="limit 必须在 1..2000 之间。", retryable=False)
                )
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    try:
                        attrs = await sftp.stat(path)
                    except asyncssh.SFTPNoSuchFile:
                        return tool_err(
                            ToolFailure(
                                "remote_not_found", stage="read", hint=f"远端文件不存在：{path}", retryable=False, path=path
                            )
                        )
                    if _entry_type(attrs) == "dir":
                        return tool_err(
                            ToolFailure(
                                "remote_not_a_file",
                                stage="read",
                                hint=f"远端路径是目录：{path}。要列目录请用 list_directory。",
                                retryable=False,
                                path=path,
                            )
                        )
                    if (attrs.size or 0) > _READ_FILE_MAX_BYTES:
                        return tool_err(
                            ToolFailure(
                                "file_too_large",
                                stage="read",
                                hint=f"文件 {attrs.size} 字节，超过 read_file 上限（{_READ_FILE_MAX_BYTES}）。请用 download_file 取回本地后分段查看。",
                                retryable=False,
                                path=path,
                                size_bytes=attrs.size,
                            )
                        )
                    async with sftp.open(path, "rb") as handle:
                        raw = await handle.read()
                text = raw.decode("utf-8", "replace")
                lines = text.splitlines()
                total = len(lines)
                if offset < 0:
                    start = max(0, total + offset)
                else:
                    start = max(0, offset - 1)
                window = lines[start : start + limit]
                truncated = start + len(window) < total
                payload = {
                    "path": path,
                    "total_lines": total,
                    "offset": start + 1,
                    "lines": [{"n": start + i + 1, "text": line} for i, line in enumerate(window)],
                    "truncated": truncated,
                    "size_bytes": int(attrs.size or 0),
                }
                if truncated:
                    payload["hint"] = (
                        f"显示第 {start + 1}-{start + len(window)} 行，共 {total} 行。"
                        f"继续读用 offset={start + len(window) + 1}；看末尾用负数如 offset=-100。"
                    )
                return tool_ok(payload)
            except ToolFailure as exc:
                return tool_err(exc)
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure("read_failed", stage="read", hint=f"读取失败：{exc}", retryable=False, path=path)
                )

        @app.tool(
            name="write_file",
            title="写入远端文本文件",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def write_file(
            path: Annotated[str, Field(description="远端目标文件路径。")],
            content: Annotated[str, Field(description="完整的 UTF-8 文本内容。")],
            append: Annotated[bool, Field(description="为 true 时追加到文件末尾而不是覆盖。默认 false。")] = False,
            confirm: Annotated[
                bool, Field(description="覆盖或追加到已有文件属于破坏性操作，必须为 true 才会执行。")
            ] = False,
            create_parent_dirs: Annotated[bool, Field(description="为 true 时递归创建缺失的父目录。默认 false。")] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """把 UTF-8 文本整块写入远端文件（覆盖或追加），替代在 shell 里拼 heredoc/sed。
            覆盖写先落 <path>.ssh-mcp.tmp 再原子重命名，不会出现半截文件；追加则直接 O_APPEND。
            返回 {path, bytes_written, appended, existed}。
            Use when AI 需要创建或修改远端配置文件、脚本；覆盖已有文件前必须先向用户确认并传 confirm=true。
            """
            try:
                validate_remote_path(path)
                if not content:
                    return tool_err(
                        ToolFailure("invalid_argument", stage="validate", hint="content 不能为空（清空文件请用 remove_path 后重建）。", retryable=False)
                    )
                raw = content.encode("utf-8")
                if len(raw) > _WRITE_FILE_MAX_BYTES:
                    return tool_err(
                        ToolFailure(
                            "content_too_large",
                            stage="validate",
                            hint=f"内容 {len(raw)} 字节，超过 write_file 上限（{_WRITE_FILE_MAX_BYTES}）。大文件请用 upload_file。",
                            retryable=False,
                        )
                    )
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    existed = True
                    try:
                        await sftp.stat(path, follow_symlinks=False)
                    except asyncssh.SFTPNoSuchFile:
                        existed = False
                    if existed and not confirm:
                        return tool_err(
                            ConfirmationRequired(
                                "write_file", f"将{'追加到' if append else '覆盖'}远端已有文件 {path}", path=path, append=append
                            )
                        )
                    if create_parent_dirs:
                        parent = posixpath.dirname(path)
                        if parent and parent != "/":
                            try:
                                await sftp.makedirs(parent, exist_ok=True)
                            except asyncssh.SFTPError:
                                pass
                    if append:
                        async with sftp.open(path, "ab") as handle:
                            await handle.write(raw)
                    else:
                        tmp = f"{path}.ssh-mcp.tmp"
                        async with sftp.open(tmp, "wb") as handle:
                            await handle.write(raw)
                        try:
                            await sftp.chmod(tmp, 0o644)
                        except asyncssh.SFTPError:
                            pass
                        await replace_file(sftp, tmp, path)
                    return tool_ok({"path": path, "bytes_written": len(raw), "appended": append, "existed": existed})
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure(
                        "remote_parent_not_found",
                        stage="write",
                        hint=f"父目录不存在：{posixpath.dirname(path)}。如需一并创建请传 create_parent_dirs=true。",
                        retryable=False,
                        path=path,
                    )
                )
            except asyncssh.SFTPPermissionDenied:
                return tool_err(
                    ToolFailure("permission_denied", stage="write", hint=f"没有权限写入远端：{path}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure("write_failed", stage="write", hint=f"写入失败：{exc}", retryable=False, path=path)
                )

        # -- search ------------------------------------------------------------

        @app.tool(
            name="search_files",
            title="按通配符搜索远端文件",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def search_files(
            path: Annotated[str, Field(description="起始目录。")],
            pattern: Annotated[str, Field(description="glob 通配符，只匹配文件名：* 任意串、? 单字符、[seq] 字符集。如 *.log、nginx*.conf。")],
            recursive: Annotated[bool, Field(description="为 true 时递归搜索子目录。默认 true。")] = True,
            max_results: Annotated[int, Field(description="最多返回条数，默认 100，上限 1000。")] = 100,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """在远端目录树里按文件名通配符找文件，返回匹配条目的路径与元信息。
            返回 {path, pattern, matches: [{path, type, size, modified_at}], total_matches, truncated}。
            Use when 需要定位日志、配置或产物的实际位置（“找到日志在哪”），不必一层层 list_directory 或跑 find。
            """
            import fnmatch

            if not pattern or any(ch in pattern for ch in "\x00/"):
                return tool_err(
                    ToolFailure("invalid_argument", stage="validate", hint="pattern 只匹配文件名，不能包含 / 或 NUL。", retryable=False)
                )
            max_results = max(1, min(max_results, 1000))
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    matches: list[dict] = []
                    total = 0
                    truncated = False
                    stack = [path]
                    visited = 0
                    while stack:
                        current = stack.pop()
                        visited += 1
                        if visited > _SEARCH_DIR_BUDGET:
                            truncated = True
                            break
                        try:
                            entries = [entry async for entry in sftp.scandir(current)]
                        except asyncssh.SFTPNotADirectory:
                            continue
                        except asyncssh.SFTPPermissionDenied:
                            continue
                        for entry in entries:
                            name = entry.filename
                            if isinstance(name, bytes):
                                name = name.decode("utf-8", "replace")
                            if name in (".", ".."):
                                continue
                            child = posixpath.join(current, name)
                            kind = _entry_type(entry.attrs)
                            if kind == "dir":
                                if recursive:
                                    stack.append(child)
                                continue
                            if fnmatch.fnmatch(name.lower(), pattern.lower()):
                                total += 1
                                if len(matches) < max_results:
                                    matches.append(
                                        {
                                            "path": child,
                                            "type": kind,
                                            "size": int(entry.attrs.size or 0),
                                            "modified_at": int(entry.attrs.mtime) if entry.attrs.mtime else None,
                                        }
                                    )
                    truncated = truncated or total > len(matches)
                    payload = {
                        "path": path,
                        "pattern": pattern,
                        "matches": matches,
                        "total_matches": total,
                        "truncated": truncated,
                    }
                    if truncated:
                        payload["hint"] = (
                            f"结果超过 max_results={max_results} 或目录数超预算，已截断。请用更具体的 path 或 pattern 缩小范围。"
                        )
                    return tool_ok(payload)
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="search", hint=f"远端目录不存在：{path}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="list_directory",
            title="列出远端目录内容",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def list_directory(
            path: Annotated[str, Field(description="远端目录路径，默认当前用户主目录。")] = ".",
            max_entries: Annotated[
                int, Field(description="返回的最大条目数，默认取服务配置（500），超出部分通过 truncated 标记。")
            ] = 0,
            include_hidden: Annotated[bool, Field(description="为 false 时跳过以 . 开头的隐藏条目。默认 true。")] = True,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """列出远端目录下的条目及其类型、大小、权限与修改时间，不递归、不返回文件内容。
            返回 {path, entries: [{name, type, size, mode, modified_at}], total, truncated}。
            Use when 需要了解远端目录结构、确认文件是否存在或查找目标文件路径时。
            """
            limit = max_entries or self._settings.directory_page_limit
            limit = max(1, min(limit, 10_000))
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    entries: list[dict] = []
                    total = 0
                    base = path.rstrip("/") or "/"
                    # The page is filled at ``limit``; keep counting so that
                    # ``total`` stays the real entry count.
                    async for entry in sftp.scandir(path):
                        name = entry.filename
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", "replace")
                        # AsyncSSH reports the server's raw directory entries,
                        # which typically include "." and "..".
                        if name in (".", ".."):
                            continue
                        if not include_hidden and name.startswith("."):
                            continue
                        total += 1
                        if len(entries) >= limit:
                            continue
                        child = posixpath.join(base, name) if base != "/" else f"/{name}"
                        entries.append(_attrs_to_dict(child, entry.attrs))
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure(
                        "remote_not_found", stage="list", hint=f"远端目录不存在：{path}", retryable=False, path=path
                    )
                )
            except asyncssh.SFTPNotADirectory:
                return tool_err(
                    ToolFailure(
                        "remote_not_a_directory",
                        stage="list",
                        hint=f"远端路径不是目录：{path}",
                        retryable=False,
                        path=path,
                    )
                )
            except ToolFailure as exc:
                return tool_err(exc)
            entries.sort(key=lambda item: (item["type"] != "dir", item["name"].lower()))
            truncated = total > len(entries)
            return tool_ok({"path": path, "entries": entries, "total": total, "truncated": truncated})

        @app.tool(
            name="stat_file",
            title="查询远端文件元信息",
            annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": True},
        )
        async def stat_file(
            path: Annotated[str, Field(description="远端文件或目录路径。")],
            follow_symlinks: Annotated[bool, Field(description="为 false 时查询符号链接本身的属性。默认 true。")] = True,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """查询远端单个路径的属性：类型、大小、权限、属主与修改时间，不读取文件内容。
            返回 {path, type, size, permissions, mode, owner, group, modified_at}。
            Use when 需要确认文件是否存在、大小或权限是否符合预期，或在传输前核对目标状态时。
            """
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path, follow_symlinks=follow_symlinks)
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="stat", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok(_attrs_to_dict(path, attrs))

        @app.tool(
            name="make_directory",
            title="创建远端目录",
            annotations={
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,  # an existing directory is success
                "openWorldHint": True,
            },
        )
        async def make_directory(
            path: Annotated[str, Field(description="要创建的远端目录路径。")],
            parents: Annotated[bool, Field(description="为 true 时递归创建缺失的父目录。默认 false。")] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """在远端创建一个目录，可选递归创建父目录；已存在的目录视为成功。
            返回 {path, created, created_parents}。
            Use when 需要为上传、日志或发布产物准备远端目录时。
            """
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    try:
                        existing = await sftp.stat(path)
                    except asyncssh.SFTPNoSuchFile:
                        existing = None
                    if existing is not None:
                        if _entry_type(existing) == "dir":
                            return tool_ok({"path": path, "created": False, "already_existed": True})
                        return tool_err(
                            ToolFailure(
                                "remote_not_a_directory",
                                stage="mkdir",
                                hint=f"远端已存在同名文件，无法创建目录：{path}",
                                retryable=False,
                                path=path,
                            )
                        )
                    try:
                        if parents:
                            await sftp.makedirs(path, exist_ok=True)
                        else:
                            await sftp.mkdir(path)
                    except asyncssh.SFTPNoSuchFile:
                        return tool_err(
                            ToolFailure(
                                "remote_parent_not_found",
                                stage="mkdir",
                                hint=f"父目录不存在：{path}。如需一并创建，请传 parents=true。",
                                retryable=False,
                                path=path,
                            )
                        )
                    except asyncssh.SFTPPermissionDenied:
                        return tool_err(
                            ToolFailure(
                                "permission_denied",
                                stage="mkdir",
                                hint=f"没有权限在远端创建目录：{path}",
                                retryable=False,
                                path=path,
                            )
                        )
                    except asyncssh.SFTPFileAlreadyExists:
                        # Lost a race with another creator: the directory exists now.
                        return tool_ok({"path": path, "created": False, "already_existed": True})
                    except asyncssh.SFTPNotADirectory:
                        return tool_err(
                            ToolFailure(
                                "remote_not_a_directory",
                                stage="mkdir",
                                hint=f"父路径中存在同名文件，无法创建目录：{path}",
                                retryable=False,
                                path=path,
                            )
                        )
                    except asyncssh.SFTPError as exc:
                        return tool_err(
                            ToolFailure(
                                "mkdir_failed", stage="mkdir", hint=f"创建目录失败：{exc}", retryable=False, path=path
                            )
                        )
                    return tool_ok({"path": path, "created": True, "created_parents": parents})
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="remove_path",
            title="删除远端文件或目录",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def remove_path(
            path: Annotated[str, Field(description="要删除的远端文件或目录路径。")],
            recursive: Annotated[bool, Field(description="为 true 时递归删除目录及其全部内容。默认 false，仅删除空目录。")] = False,
            confirm: Annotated[bool, Field(description="破坏性操作，必须为 true 才会执行。")] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """删除远端文件、符号链接或目录（默认仅限空目录），返回删除的类型与路径。
            递归删除会连同子目录中的全部内容一起永久删除，且无法恢复。
            Use when 需要清理远端临时文件或目录；必须先向用户确认删除范围，尤其是 recursive=true 时。
            """
            consequence = (
                f"将递归删除 {path} 及其全部子内容（不可恢复）" if recursive else f"将删除远端 {path}（空目录或文件）"
            )
            if not confirm:
                return tool_err(ConfirmationRequired("remove_path", consequence, path=path, recursive=recursive))
            try:
                validate_remote_path(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path, follow_symlinks=False)
                    kind = _entry_type(attrs)
                    if kind == "dir":
                        if recursive:
                            await sftp.rmtree(path)
                            return tool_ok({"path": path, "removed": "dir", "recursive": True})
                        await sftp.rmdir(path)
                        return tool_ok({"path": path, "removed": "dir", "recursive": False})
                    await sftp.remove(path)
                    return tool_ok({"path": path, "removed": kind, "recursive": False})
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="remove", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except asyncssh.SFTPFailure as exc:
                if not recursive:
                    return tool_err(
                        ToolFailure(
                            "directory_not_empty",
                            stage="remove",
                            hint=f"目录非空：{path}。确认要递归删除时传 recursive=true 与 confirm=true。",
                            retryable=False,
                            path=path,
                            detail=str(exc),
                        )
                    )
                return tool_err(
                    ToolFailure("remove_failed", stage="remove", hint=f"删除失败：{exc}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="rename_path",
            title="重命名或移动远端路径",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def rename_path(
            old_path: Annotated[str, Field(description="远端原路径。")],
            new_path: Annotated[str, Field(description="远端新路径（可跨目录移动）。")],
            overwrite: Annotated[bool, Field(description="目标已存在时是否覆盖。默认 false，会直接拒绝。")] = False,
            confirm: Annotated[bool, Field(description="覆盖目标或移动目录属于破坏性操作，必须为 true 才会执行。")] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """在远端重命名或移动文件/目录，目标已存在时默认拒绝，除非 overwrite=true。
            返回 {old_path, new_path, overwritten}。
            Use when 需要调整远端文件布局、归档日志或替换配置；必须先向用户确认目标路径。
            """
            if not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "rename_path",
                        f"将把远端 {old_path} 移动/重命名为 {new_path}" + ("，并覆盖已存在的目标" if overwrite else ""),
                        old_path=old_path,
                        new_path=new_path,
                    )
                )
            try:
                validate_remote_path(old_path, "old_path")
                validate_remote_path(new_path, "new_path")
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    target_exists = False
                    try:
                        await sftp.stat(new_path, follow_symlinks=False)
                        target_exists = True
                    except asyncssh.SFTPNoSuchFile:
                        target_exists = False
                    if target_exists and not overwrite:
                        return tool_err(
                            ToolFailure(
                                "remote_exists",
                                stage="rename",
                                hint=f"目标路径已存在：{new_path}。确认覆盖请传 overwrite=true。",
                                retryable=False,
                                new_path=new_path,
                            )
                        )
                    if target_exists:
                        await replace_file(sftp, old_path, new_path)
                    else:
                        await sftp.rename(old_path, new_path)
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure(
                        "remote_not_found", stage="rename", hint=f"原路径不存在：{old_path}", retryable=False, old_path=old_path
                    )
                )
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure(
                        "rename_failed", stage="rename", hint=f"重命名失败：{exc}", retryable=False, old_path=old_path
                    )
                )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok({"old_path": old_path, "new_path": new_path, "overwritten": target_exists})

        @app.tool(
            name="change_permissions",
            title="修改远端文件权限",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def change_permissions(
            path: Annotated[str, Field(description="远端文件或目录路径。")],
            mode: Annotated[str, Field(description="八进制权限字符串，如 \"644\"、\"755\"、\"600\"。")],
            recursive: Annotated[bool, Field(description="为 true 时递归应用到目录下的所有条目。默认 false。")] = False,
            confirm: Annotated[bool, Field(description="破坏性操作，必须为 true 才会执行。")] = False,
            connection_handle: Annotated[
                str | None,
                Field(description="connect 返回的 connection_handle；省略则使用最近一次使用的连接。"),
            ] = None,
        ) -> CallToolResult:
            """修改远端文件或目录的 POSIX 权限位，返回新权限与受影响的条目数。
            权限设置错误可能导致服务无法访问文件或暴露敏感数据。
            Use when 需要为脚本添加可执行位、收紧配置文件权限或修复上传后的权限问题时；执行前必须先向用户确认。
            """
            if not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "change_permissions", f"将把远端 {path} 的权限改为 {mode}", path=path, mode=mode
                    )
                )
            try:
                validate_remote_path(path)
                numeric = _parse_mode(mode)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path)
                    if _entry_type(attrs) == "dir" and recursive:
                        affected = await _chmod_tree(sftp, path, numeric)
                    else:
                        await sftp.chmod(path, numeric)
                        affected = 1
                    return tool_ok({"path": path, "mode": f"{numeric:04o}", "recursive": recursive, "affected": affected})
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="chmod", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure("chmod_failed", stage="chmod", hint=f"修改权限失败：{exc}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)


async def _chmod_tree(sftp: asyncssh.SFTPClient, root: str, numeric: int) -> int:
    """Apply ``numeric`` to ``root`` and everything below it; returns the count.

    Each directory costs one ``scandir`` plus one pipelined ``chmod`` batch for
    its files; awaiting every entry individually made a deep tree cost one
    network round trip per file.
    """
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        await sftp.chmod(current, numeric)
        count += 1
        files: list[str] = []
        dirs: list[str] = []
        async for entry in sftp.scandir(current):
            name = entry.filename
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
            # ``scandir`` returns the server's raw entries, which include "."
            # and ".."; following them would walk up the tree forever.
            if name in (".", ".."):
                continue
            child = posixpath.join(current, name)
            (dirs if _entry_type(entry.attrs) == "dir" else files).append(child)
        if files:
            await asyncio.gather(*(sftp.chmod(child, numeric) for child in files))
            count += len(files)
        stack.extend(dirs)
    return count


def _parse_mode(mode: str) -> int:
    text = str(mode).strip().lower()
    if text.startswith("0o"):
        text = text[2:]
    if not text or any(ch not in "01234567" for ch in text) or len(text) > 4:
        raise ToolFailure(
            "invalid_argument",
            stage="validate",
            hint=f"mode 必须是八进制权限字符串，例如 \"644\" 或 \"0755\"，收到 {mode!r}。",
            retryable=False,
        )
    return int(text, 8)
